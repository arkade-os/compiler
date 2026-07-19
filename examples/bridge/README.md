# Advanced Bridge for Arkade

Contracts that bring foreign-chain assets (ETH, SOL, USDT, ...) onto Arkade
as wrapped assets and send them back to their native chains. They provide
the bridging leg for the non-interactive swap protocol: a foreign asset
enters Arkade as a wrapped asset, trades via
`examples/non_interactive_swap/non_interactive_swap.ark`, and exits back to
its native chain — all without either party being online at the same time.

The design keeps the unavoidable trust (foreign-chain custody) where it has
to live, and moves everything the Arkade side *can* enforce on-chain:
capped supply, exact attested amounts, pinned recipients, single-use
attestations, and a consensus-enforced withdrawal refund. A colluding
custodian quorum can still fail to honor foreign-chain payouts, but it
cannot inflate the wrapped supply, mint to the wrong recipient, replay an
attestation, or block a stuck withdrawal from being refunded.

## Design

Two contracts, one per direction, plus the existing swap contract for
settlement.

- **Deposit** = a k-of-n custodian quorum observes a confirmed deposit on
  the source chain and attests it → the covenant **mints** exactly the
  attested amount of the wrapped asset to the depositor.
- **Withdrawal** = the user escrows wrapped tokens against a destination
  commitment → the bridge pays out the native asset → the quorum attests
  the payout and **burns** the escrow. A timeout **refund** protects the
  user if the payout never happens.
- **Settlement** = once a foreign asset exists as a wrapped Arkade asset,
  `non_interactive_swap.ark` matches signed orders atomically. No new
  contract is needed.

### `bridge_mint.ark` — deposit leg

One `BridgeMint` UTXO per wrapped asset, holding that asset's **control
asset** (its mint authority). State = `(custodians, threshold, nonce)`.

```
source chain                       Arkade
────────────                       ──────
user → per-user deposit addr
        │ observed + confirmed
        ▼
each custodian signs off-line
sha256(depositId ‖ recipientSpk ‖ amount ‖ nonce)
        │
        ▼
                          mint() spend:
                            input[0]  BridgeMint (ctrl asset, nonce)
                            output[0] BridgeMint (ctrl asset, nonce+1)
                            output[1] amount wrapped tokens → recipientSpk
```

Covenant checks:

- k-of-n `checkSigFromStack` quorum over the attestation, reconstructed on
  stack (`OP_CAT` + `OP_SHA256`) so every field is pinned;
- `tokenGroup.delta == amount` under the correct control asset — supply
  grows by exactly the attested amount;
- `ctrlGroup.delta == 0` and control-asset continuation — mint authority
  can neither inflate nor escape;
- recipient output pinned to the attested script pubkey;
- state continuation with `nonce + 1` — an attestation is single-use, so a
  mint transaction cannot be replayed.

`depositId` is derived off-chain with domain separation, e.g.
`sha256("arkade-bridge-deposit-v1" || chain || txid || vout)`, so custodian
signatures can never be confused across protocols or directions.

Because the attestation commits to an arbitrary 34-byte script pubkey (not
just a key), a deposit can be minted straight into another contract — e.g. a
`NonInteractiveSwap` offer — letting a cross-chain deposit and an on-chain
trade compose in a single step.

### `bridge_withdrawal.ark` — withdrawal leg

One escrow UTXO per withdrawal. The user locks `amount` wrapped tokens,
committing to `destHash = sha256("arkade-bridge-withdrawal-v1" || chain || address)`
and a unique `withdrawalId`; the plaintext destination is given to the
operator off-chain.

```
release (happy path)                     refund (bridge stalled)
────────────────────                     ───────────────────────
operator pays out on dest chain          refundTime reached
custodians sign off-line                 user signs
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
  Custodial risk on the withdrawal leg is bounded by the refund window
  rather than resting on an off-chain promise. Operator policy must stop
  honoring payouts as `refundTime` approaches (the standard HTLC safety
  delta).
- `unilateral` — standard CSV exit for the owner.

`withdrawalId` is unique per escrow, so a release attestation for one escrow
can never release another — even for identical destination and amount.

### Settlement leg (already shipped)

Once a foreign asset is a wrapped Arkade asset, `non_interactive_swap.ark`
matches signed orders: the maker's signed offer is the order, the taker
fills it, and Bitcoin transaction atomicity guarantees the exchange settles
or reverts as a whole. A full user story:

1. deposit USDT from its source chain → `BridgeMint.mint()` credits wrapped
   USDT (optionally directly into a swap offer);
2. swap wrapped USDT for BTC via `NonInteractiveSwap.swap()`;
3. withdraw: lock the received asset in `BridgeWithdrawal`, operator pays
   out on the destination chain, quorum releases and burns.

## Trust model (honest)

The foreign-chain side is **custodial** and cannot be otherwise: Arkade
script cannot verify an Ethereum or Solana payout, so someone must hold the
native funds and honor deposits/withdrawals. What the contracts do is
minimize and bound that trust.

| Property | Guarantee | Enforced by |
|---|---|---|
| Foreign-chain custody | **Trusted.** The custodian set holds native funds and must honor payouts. Publish the treasury addresses for transparency. | Off-chain / operational |
| Wrapped supply cap | Supply grows only by quorum-attested deposits, only by the exact attested amount | Covenant: `tokenGroup.delta == amount` under the control asset |
| Mint authority containment | Mint authority cannot inflate freely or escape the contract | Covenant: `ctrlGroup.delta == 0` + control-asset continuation |
| Correct recipient | Minted tokens land only on the attested script pubkey | Covenant: `outputs[1].scriptPubKey == recipientSpk` |
| No attestation replay | Each deposit attestation mints once; each withdrawal releases once | Covenant: monotonic `nonce` / unique `withdrawalId` |
| Withdrawal liveness | User reclaims escrowed tokens if the payout never happens | Covenant: `tx.time >= refundTime` refund path |

What a fully-colluding quorum **can** do: refuse to honor a foreign-chain
payout (the residual custodial risk). What it **cannot** do, even fully
colluding: mint more wrapped tokens than deposits attest, mint to a
recipient the attestation didn't name, replay an attestation, or prevent a
stuck withdrawal from being refunded after the timeout.

Choosing `threshold` and `n` is a policy dial: `n=1` is a single-operator
bridge; larger `k-of-n` removes any single point of key compromise on the
attestation path.

## How this improves opsec

The load-bearing choice is that custodians sign a **small fixed attestation
message** (`checkSigFromStack` over `sha256(fields)`), not the live spending
transaction. That single decision buys most of the operational-security
wins:

- **Keys stay off the transaction path.** A custodian signs a 32-byte
  digest of `(depositId, recipientSpk, amount, nonce)`. The signing key
  never has to see, build, or hold the actual Arkade transaction, so it can
  live in an HSM or air-gapped signer with a minimal, auditable signing
  surface — the operator reviews a few human-readable fields before
  approving, not raw script.
- **Signers are non-interactive and asynchronous.** Each custodian attests
  the moment it independently confirms the source-chain deposit; they never
  need to be online together, coordinate a signing round, or agree on a
  transaction. This removes the availability coupling and the interactive
  round-trip that live multisig co-signing requires.
- **Relay is permissionless.** Anyone can collect the `threshold`
  attestations and broadcast the mint or release. Custodians therefore run
  no hot transaction infrastructure — no node that must be online to sign
  and push, and thus no always-on key. A relayer that misbehaves can only
  submit a transaction the covenant already fully constrains.
- **Blast radius is capped by the covenant, not by signer discipline.**
  Because supply, recipient, amount, and single-use are enforced on-chain,
  a compromised or malicious quorum is limited to the residual custodial
  risk. Compromise of the transaction-building/relay layer grants nothing —
  it cannot move value the attestations didn't authorize.
- **Attestations are portable and idempotent.** A fixed message signed
  once can be re-broadcast if a transaction is dropped, without re-engaging
  the signers, and the `nonce` / `withdrawalId` binding makes re-submission
  harmless.
- **Key rotation is contained.** The custodian set lives in contract state;
  rotating it (future `rotate()` transition) changes who can attest going
  forward without touching user funds or the wrapped supply.

The trade-off is deliberate: `checkSigFromStack` attestations require the
covenant's introspection (asset-group accounting, output pinning, state
continuation). A plain tapscript multisig would be simpler but would make
the signers co-sign live transactions (interactive, hot keys) and would
enforce none of the supply, recipient, or replay guarantees — it would be a
spending key, not a bridge. The covenant is what turns k-of-n signers into
an attest-only oracle set with a bounded blast radius.

## Future work

- **Light-client / MPC attesters**: replace the custodian quorum with an
  MPC network's aggregate key (n=1 threshold over a chain-signatures-style
  signer), or verify source-chain SPV proofs directly once the introspector
  exposes the needed primitives — removing custodial trust on chains that
  support it.
- **Custodian rotation**: a quorum-attested `rotate()` transition to a new
  `custodians`/`threshold` state, with domain-tagged attestation messages
  so rotation signatures cannot be replayed as mints.
- **Fee handling**: a `takeFee`-style basis-points parameter with 330-sat
  dust routing, as in `stability_offer.ark`.
- **Batch mints**: several deposits per `mint()` spend, one output each,
  amortizing the state transition.

## Local checks

```bash
cargo run -- examples/bridge/bridge_mint.ark -o /tmp/bridge_mint.json
cargo run -- examples/bridge/bridge_withdrawal.ark -o /tmp/bridge_withdrawal.json
cargo test --test examples compilation_roundtrip
cargo test --test examples bridge
./playground/generate_contracts.sh   # refresh playground bundle
```
