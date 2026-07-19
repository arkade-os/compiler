# Near-Intents-Style Asset Bridging for Arkade

Contracts that replicate how [Near Intents](https://docs.near-intents.org)
lets users deposit and withdraw assets from other chains, adapted to
Arkade's UTXO + covenant model. They provide the bridging leg for the
non-interactive swap protocol launch: foreign assets (ETH, SOL, USDT, ...)
enter Arkade as wrapped assets, trade via
`examples/non_interactive_swap/non_interactive_swap.ark`, and exit back to
their native chains.

## How Near Intents does it (study summary)

Near Intents has three moving parts:

1. **Verifier contract** (`intents.near`) — an escrow holding every
   deposited asset as a NEP-245 multitoken balance. Users sign *intents*
   (e.g. `token_diff` for swaps, `ft_withdraw` for withdrawals); solvers
   co-sign the mirror image; one `execute_intents` call settles the whole
   batch atomically or reverts it.
   ([verifier docs](https://docs.near-intents.org/integration/verifier-contract/introduction))
2. **PoA bridge** (Defuse Labs) — the widest-coverage deposit/withdrawal
   path. The user asks the bridge for a **per-user deposit address** on the
   source chain and sends funds there with an ordinary wallet. The
   operator's indexer observes the deposit, sweeps it into a published
   treasury address, and calls the PoA factory (`omft.near`), whose
   owner-only `ft_deposit` **mints** the NEAR-side representation
   (e.g. `btc.omft.near`) and forwards it into `intents.near` credited to
   the user. Withdrawals are the reverse: an `ft_withdraw` intent with a
   `WITHDRAW_TO:<address>` memo **burns** the wrapped tokens; the operator
   indexes the burn event and pays out from its treasury on the destination
   chain. There is no on-chain payout proof and no timeout — refunds are
   purely operational.
   ([PoA bridge](https://docs.near-intents.org/near-intents/poa-bridge),
   [deposit/withdrawal service](https://docs.near-intents.org/integration/market-makers/deposit-withdrawal-service),
   [factory/token contracts](https://github.com/near/intents/tree/main/contracts/poa))
3. **Omni Bridge** (chain signatures) — the trust-minimized path for major
   chains: inbound transfers are proven on NEAR via light clients
   (Ethereum, Bitcoin) or Wormhole attestations (Solana, L2s); outbound
   transfers are threshold-signed by an MPC network and finalized by
   permissionless relayers.
   ([omni-bridge](https://github.com/Near-One/omni-bridge),
   [how it works](https://docs.near.org/chain-abstraction/omnibridge/how-it-works))

The essential mechanics to replicate are therefore:

- **deposit** = operator-attested event on the source chain → **mint** of a
  wrapped asset credited to the user, with the mint authority gated;
- **withdrawal** = user-initiated **burn** carrying a destination address →
  operator payout on the destination chain;
- **settlement** = signed orders matched atomically, independent of the
  bridge.

## Mapping to Arkade

| Near Intents | Arkade |
|---|---|
| `intents.near` NEP-245 balances | Native Arkade assets held in VTXOs — no central balance contract needed |
| PoA factory `omft.near` + owner-only `ft_deposit` mint | `bridge_mint.ark` — control-asset-gated mint, released by custodian quorum attestation |
| Per-user deposit address on source chain | Same off-chain operator infrastructure; the attested `depositId` binds the observed deposit |
| `DepositMessage.execute_intents` (deposit chained into intents) | Attestation commits to an arbitrary 34-byte script pubkey — a deposit can mint directly into a `NonInteractiveSwap` offer |
| `ft_withdraw` + `WITHDRAW_TO:` memo → `FtBurn` | `bridge_withdrawal.ark` — escrow committing to `destHash`; release burns the wrapped tokens |
| Operational refunds (`REJECTED`/`RETURNED` statuses) | On-chain `refund()` after `refundTime` — the user reclaims unilaterally if the bridge stalls |
| Single PoA operator (owner key) | k-of-n custodian quorum (`pubkey[] custodians`, `int threshold`); n=1 degenerates to exact PoA |
| `execute_intents` atomic settlement | Bitcoin transaction atomicity + `non_interactive_swap.ark` introspection |
| Permit2-style nonce replay protection | Monotonic `nonce` in `BridgeMint` state; unique `withdrawalId` per escrow |

## Contracts

### `bridge_mint.ark` — deposit leg

One `BridgeMint` UTXO per wrapped asset, holding the asset's **control
asset** (mint authority). State = `(custodians, threshold, nonce)`.

```
foreign chain                      Arkade
─────────────                      ──────
user → per-user deposit addr
        │ observed + confirmed
        ▼
custodians sign
sha256(depositId ‖ recipientSpk ‖ amount ‖ nonce)
        │
        ▼
                          mint() spend:
                            input[0]  BridgeMint (ctrl asset, nonce)
                            output[0] BridgeMint (ctrl asset, nonce+1)
                            output[1] amount wrapped tokens → recipientSpk
```

Covenant checks:

- k-of-n `checkSigFromStack` quorum over the attestation, reconstructed
  on stack (`OP_CAT` + `OP_SHA256`) so every field is pinned;
- `tokenGroup.delta == amount` under the correct control asset — supply
  grows by exactly the attested amount;
- `ctrlGroup.delta == 0` and control-asset continuation — mint authority
  can neither inflate nor escape;
- recipient output pinned to the attested script pubkey;
- state continuation with `nonce + 1` — an attestation is single-use, so a
  mint transaction cannot be replayed.

`depositId` should be derived off-chain with domain separation, e.g.
`sha256("arkade-bridge-deposit-v1" || chain || txid || vout)`, so custodian
signatures can never be confused across protocols or directions.

### `bridge_withdrawal.ark` — withdrawal leg

One escrow UTXO per withdrawal. The user locks `amount` wrapped tokens,
committing to `destHash = sha256("arkade-bridge-withdrawal-v1" || chain || address)`
and a unique `withdrawalId`; the plaintext destination is given to the
operator off-chain (the analog of the `WITHDRAW_TO:` memo).

```
release (happy path)                     refund (bridge stalled)
────────────────────                     ───────────────────────
operator pays out on dest chain          refundTime reached
custodians sign                          user signs
sha256(withdrawalId ‖ destHash ‖ amount)
        │                                        │
        ▼                                        ▼
burn ≥ amount wrapped tokens             user reclaims wrapped tokens
(supply shrinks to match payout)
```

- `release()` — quorum attestation + `sumInputs >= sumOutputs + amount`
  burn check. Burning needs no control asset (as in
  `controlled_mint.ark`): supply only shrinks.
- `refund()` — `tx.time >= refundTime` (block height) + owner signature.
  This is the improvement over Near's PoA bridge: custodial risk on the
  withdrawal leg is bounded by the refund window instead of resting on an
  off-chain `RETURNED` status. Operator policy must stop honoring payouts
  as `refundTime` approaches (the standard HTLC safety delta).
- `unilateral` — standard CSV exit for the owner.

`withdrawalId` is unique per escrow, so a release attestation for one
escrow can never release another — even for identical destination and
amount.

### Settlement leg (already shipped)

No new contract is needed for the Verifier's `token_diff` role: once a
foreign asset exists as a wrapped Arkade asset, `non_interactive_swap.ark`
plays the solver-fill role — the maker's signed offer is the intent, the
taker is the solver, and transaction atomicity replaces `execute_intents`.
A full user story:

1. deposit USDT from Ethereum → `BridgeMint.mint()` credits wrapped USDT
   (optionally directly into a swap offer);
2. swap wrapped USDT for BTC via `NonInteractiveSwap.swap()`;
3. withdraw: lock the received asset in `BridgeWithdrawal`, operator pays
   out on the destination chain, quorum releases and burns.

## Trust model

| Property | Near Intents PoA | These contracts |
|---|---|---|
| Mint authority | operator owner key | k-of-n custodian quorum, enforced by covenant |
| Supply integrity | trust in factory code + operator | control-asset accounting checked on every spend |
| Attestation replay | off-chain sequencing | on-chain `nonce` / `withdrawalId` binding |
| Withdrawal refund | operational (manual) | consensus-enforced timeout refund |
| L1 asset custody | operator treasury addresses | unchanged — custodians hold foreign-chain funds (publish addresses, as Near does) |

The foreign-chain side remains custodial, exactly as in Near's PoA bridge:
Arkade script cannot verify an Ethereum or Solana payout. What moves
on-chain is everything the Arkade side *can* enforce — gated supply, exact
attested amounts, pinned recipients, single-use attestations, and timeout
refunds.

## Future work

- **Light-client / MPC attesters** (Omni Bridge parity): replace the
  custodian quorum with an MPC network's single key (n=1 threshold over a
  chain-signatures-style signer), or verify source-chain SPV proofs once
  the introspector exposes the needed primitives.
- **Custodian rotation**: a quorum-attested `rotate()` transition to a new
  `custodians`/`threshold` state. Requires domain-tagged attestation
  messages so rotation signatures cannot be replayed as mints.
- **Fee handling**: Near's `withdrawal_fee` maps naturally to a
  `takeFee`-style basis-points parameter with 330-sat dust routing, as in
  `stability_offer.ark`.
- **Batch mints**: several deposits per `mint()` spend, one output each,
  amortizing the state transition.

## Local checks

```bash
cargo run -- examples/bridge/bridge_mint.ark -o /tmp/bridge_mint.json
cargo run -- examples/bridge/bridge_withdrawal.ark -o /tmp/bridge_withdrawal.json
cargo test --test examples compilation_roundtrip
./playground/generate_contracts.sh   # refresh playground bundle
```
