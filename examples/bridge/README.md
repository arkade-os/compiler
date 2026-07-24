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

Contracts for both directions, in two trust flavors for the deposit leg,
plus the existing swap contract for settlement.

- **Deposit (attested)** = a k-of-n custodian quorum observes a confirmed
  deposit on the source chain and attests it → the covenant **mints**
  exactly the attested amount of the wrapped asset to the depositor
  (`bridge_mint.ark`).
- **Deposit (trustless SPV)** = the covenant itself verifies an on-chain
  Simplified Payment Verification proof — merkle inclusion + proof-of-work +
  confirmation depth — with **no signer at all** (`bridge_spv.ark`). This is
  the "more trustless" deposit path: no one can attest a deposit that did
  not happen.
- **Withdrawal** = the user escrows wrapped tokens against a destination
  commitment → the bridge pays out the native asset → the quorum attests
  the payout and **burns** the escrow. A timeout **refund** protects the
  user if the payout never happens (`bridge_withdrawal.ark`).
- **Settlement** = once a foreign asset exists as a wrapped Arkade asset,
  `non_interactive_swap.ark` matches signed orders atomically. No new
  contract is needed.
- **Fast-transfer swap** = for a one-shot cross-chain swap with no wrapper
  and no treasury, a solver fronts the destination asset and the whole route
  is chained by one Lightning payment secret (`swap_htlc.ark`). Best for the
  LN → Arkade → EVM flow.
- **Payout bridge-out** = spend a wrapped token on Arkade with a merchant
  commitment; a liquidity-pool contract on the destination chain reads the
  commitment and releases the real asset (`wlvga_payout.ark`). The spend is
  the authorization — no quorum signs the release. Two modes: transfer the
  claim to the liquidity provider (two parties) or burn it (integrated).

The attested and SPV deposit legs are interchangeable: both mint the same
wrapped asset under the same control-asset accounting. Pick the quorum for
chains without usable SPV (fast-finality / non-PoW chains, or where header
relaying is impractical), and the SPV path for Bitcoin and other PoW chains.

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

### `bridge_spv.ark` — trustless deposit leg (SPV)

`BridgeSpv` credits a Bitcoin/PoW deposit by verifying an SPV proof **in the
covenant itself** — the custodian quorum of `bridge_mint.ark` is gone. No
one signs the deposit; the proof either verifies against proof-of-work or it
does not. State = `(depositScript, powTarget, expectedBits, nonce)`.

```
source chain                                Arkade — mintFromDeposit()
────────────                                ─────────────────────────
user pays depositScript in tx T             1. INCLUSION  fold txid ↑ branch
T mined into block B                           via hash256 == B.merkleRoot
B buried under conf blocks                   2. WORK       hash256(B) ≤ powTarget
        │  (anyone relays the                3. DEPTH      conf headers chain +
        │   headers + proof)                    each meet powTarget
        ▼                                    4. PAYMENT    T pays depositScript
                                                ≥ mintAmount; hash256(T)==txid
                                             5. MINT       mintAmount → recipient
                                                under control asset, nonce+1
```

What the covenant does with the introspector's byte/hash opcodes:

| Step | How | Opcodes |
|---|---|---|
| Merkle inclusion | fold `txid` with the branch, untagged double-SHA256, order by per-level direction bit, compare to `substr(header, 36, 32)` | `OP_HASH256`, `OP_CAT`, `OP_SUBSTR` |
| Proof of work | `hash256(header)` as an unsigned 256-bit BigNum `≤ powTarget` (trailing `0x00` sign byte forces a positive reading) | `OP_HASH256`, `OP_CAT`, `OP_NUM2BIN`, `OP_BIN2NUM`, `≤` |
| Confirmation depth | each `confHeaders[i]` chains by `prevBlockHash` and meets the target | `OP_SUBSTR`, `OP_HASH256`, `OP_BIN2NUM` |
| Payment binding | `hash256(depositTx) == txid`; output at prover offset pays `depositScript` ≥ `mintAmount` | `OP_HASH256`, `OP_SUBSTR`, `OP_BIN2NUM` |
| Mint | `delta == mintAmount` under control asset; recipient + continuation pinned | `OP_FINDASSETGROUPBYASSETID`, `OP_INSPECTOUTPUTSCRIPTPUBKEY` |

Two facts about the emulator's opcode set shaped this contract (verified
against `arkade-os/emulator`, `pkg/arkade/opcode.go`):

- **`OP_HASH256` is Bitcoin's `sha256(sha256(x))`**, so txids, block hashes,
  and merkle steps are exact. This required exposing `hash256()` (and
  `reverseBytes()`) as first-class expressions in the compiler — previously
  `hash256` only parsed inside `require(hash256(x) == y)`. See
  `tests/features/new_opcodes.rs`.
- **`OP_MERKLEBRANCHVERIFY` is unusable for Bitcoin.** Its handler uses
  BIP-340 *tagged* hashing and *lexicographic sorted-pair* ordering (a
  Taproot/OpenZeppelin-style tree), not Bitcoin's untagged
  `sha256(sha256(left‖right))` ordered by index bit. So the merkle fold is
  hand-rolled with `hash256` + `cat`, not that opcode.

**Difficulty is governance-pinned.** An Arkade covenant cannot perform
Bitcoin's 2016-block difficulty retarget on-chain (it needs the whole
window and big-integer retarget math). So `powTarget`/`expectedBits` live in
contract state and must be kept current as the network retargets. The proof
pins the header's `nBits` to `expectedBits` so it cannot claim an easier
target than the pinned difficulty.

**Known limitations (v1, honest):**

- *Replay protection* across multiple mints needs a spent-deposit registry
  (accumulator or per-txid marker asset). This contract advances `nonce` for
  state continuation but does not yet prove a given txid is unspent —
  treat it as demonstrative until that registry is added.
- *Loop-carried accumulators* (the merkle `node`, the confirmation
  `tipHash`) use the same reassignment idiom as `threshold_oracle.ark`'s
  `valid` counter; the compiler represents these with `<name>` placeholders
  resolved by the emulator (stack-position tracking is a documented deferred
  phase in `src/compiler/mod.rs`). The emitted opcodes are asserted in
  tests; end-to-end execution should be confirmed on the emulator.
- *BigNum comparisons* (the `≤` PoW check on 256-bit values) require the
  emulator's arbitrary-precision arithmetic — i.e. the opcode-emission sync
  in PR #51 (standard `OP_LESSTHANOREQUAL` on BigNums, not the removed
  Elements `*64` family). Land/rebase on that for correct 256-bit compares.

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

## Fast-transfer HTLC route (LN → Arkade → EVM)

Everything above *wraps* a foreign asset into a persistent Arkade token. For
a one-shot cross-chain swap there is a lighter model that matches Arkade's
native Lightning/HTLC swaps: a **solver** holds the destination asset and
fronts it, receiving BTC on Arkade in return. **No wrapped token and no
bridge treasury** — and, crucially, **no chain has to verify another
chain's consensus.**

The trick is one **shared payment secret** `s` (hash `H = sha256(s)`). Every
leg is an HTLC locked to the *same* `H`, and Lightning hands you `H` for
free (an LN invoice's payment hash *is* `sha256(preimage)`). Revealing `s`
on the destination leg cascades back and unlocks every upstream leg. The
preimage is self-proving, so — unlike the SPV path — nothing needs a light
client or an attestation.

`swap_htlc.ark` is the **Arkade leg**. `htlc.ark` already gives a hashlock;
`swap_htlc.ark` adds the introspection that makes completion permissionless:

### Worked example

**User** has sats on Lightning, wants **LVGA** on **SwissLedger** (an
EVM-compatible chain). **Solver** holds LVGA inventory, wants BTC.

```
        payment hash H = sha256(s)  — identical across all three legs

  User ──sats──▶ LN invoice(H) ─────────────────────▶ Solver paid over LN
                                                        (its BTC leg)
  User's value ──▶ BTC VTXO on Arkade = SwapHtlc(H) ◀── solver claims with s
  Solver ──LVGA──▶ EVM HTLC(H) on SwissLedger ───────▶ User claims LVGA,
                                                        revealing s
```

1. Solver locks LVGA in a standard **EVM HTLC** on SwissLedger: claimable by
   the user with `s`, refundable to the solver after `T_evm`.
2. The user's BTC sits in `SwapHtlc` on Arkade under the same `H`.
3. User claims LVGA on SwissLedger, **revealing `s`**.
4. Anyone (a watchtower, or the always-online Arkade operator) reads `s` and
   completes `SwapHtlc.claim(s)` — the BTC can only go to the solver.
5. Any leg that stalls refunds independently after its timeout.

### `swap_htlc.ark` — the introspection-gated Arkade leg

- `claim(preimage)` (covenant) — SHA256 hashlock **plus** the payout output
  pinned to `solverPk`. Because the destination is fixed by the covenant, no
  solver signature is needed: any relayer/watchtower/operator can complete
  it once `s` is public, and it can only pay the solver.
- `refund()` (covenant) — after `refundTime` the BTC returns, pinned to
  `userPk`; likewise permissionless and non-redirectable.
- L1 `claim`/`refund` tapscript leaves re-enforce the hashlock / timelock for
  the unilateral path; `unilateral` is the user's CSV operator-offline exit.

### Timelock ordering (must hold)

`s` is revealed at the destination and cascades upstream, so timeouts
increase upstream — each hop keeps time to claim after the one below reveals:

| Leg | Locked by | Unlocks on | Refund timeout |
|---|---|---|---|
| LVGA on SwissLedger | solver | user shows `s` | `T_evm` (shortest) |
| BTC on Arkade (`swap_htlc`) | user | solver shows `s` | `refundTime` = `T_ark` > `T_evm` |
| Lightning | user | solver shows `s` | `T_ln` > `T_ark` (longest) |

### What introspection does and does not fix

- **Liveness — improved.** Pinning the payout removes *beneficiary*
  liveness: the solver need not be online to be paid. Completion is
  permissionless, so a watchtower or the Ark operator can finish it. It is
  **not** zero-liveness — the base layer still needs *some* party to
  broadcast before `T_ark` — but that role is delegatable and has nothing to
  gain by cheating.
- **Free option — unchanged.** Whoever reveals `s` holds a short-dated
  option (complete, or let it refund on a price move) for the duration of
  the timelock window. That window exists because the legs are on different
  ledgers; introspection changes who may *execute* a spend, not who
  *controls the secret*. Only a **same-ledger** single-tx swap
  (`non_interactive_swap.ark`, both assets native Arkade) removes it. Across
  ledgers it is inherent — priced away with a short `T_evm` and a taker
  premium, not removed by covenants.

## Payout bridge-out (Arkade wLVGA → SwissLedger LVGA)

A merchant-payment bridge-out where the destination asset (real **LVGA**)
sits in a **liquidity pool on SwissLedger** and wrapped **wLVGA** — a
BTC-backed bearer claim — is issued on Arkade. Paying a merchant in real LVGA
spends the wLVGA on Arkade with a commitment naming the merchant; the pool
reads it and releases LVGA. The spend + commitment *is* the authorization —
no Arkade-side quorum signs the release.

**Hard requirement — LVGA is transfer-restricted.** Only whitelisted
addresses hold LVGA, and it flows one way (pool → merchant): **wLVGA can never
be redeemed for LVGA.** So wLVGA is *not* a wrapper you unwrap — it is a
BTC-backed bearer instrument, liquidatable for BTC only. The BTC side and the
LVGA side are connected solely through the liquidity provider's balance
sheet, which is why the payout must compensate the LP in BTC (below), not in
LVGA.

### Closing the loop: who is paid for the released LVGA

The wLVGA is a claim on the BTC a user locked at mint time. Two roles may be
**separate parties**: the BTC side (issued the wLVGA, holds the BTC backing)
and the **LVGA liquidity provider (LP)** who funds the SwissLedger pool. A
naive burn destroys the wLVGA and compensates no one — so if those parties
differ, the LP bleeds out. `wlvga_payout.ark` has two modes:

- **`payOut()` — two parties (default).** The wLVGA claim is **transferred to
  the LP**, not destroyed. The LP releases LVGA on SwissLedger and receives
  the BTC-backed claim on Arkade (redeemable for BTC, never for LVGA), so the
  BTC side and the LP can be different entities and the LP stays solvent.
- **`burnOut()` — same party (option).** The wLVGA is **burned**. Only
  solvent when the LP is *also* the party that received the BTC at mint time
  (an integrated market maker). Kept for deployments where that is legally
  and operationally one entity.

**LP economics.** Because LVGA is one-way, the LP is a market maker, not a
custodian round-tripping a wrapper. Per payout it: gives up **LVGA** (a
CHF-pegged position), receives **BTC** via the wLVGA claim (hedgeable to
USDT), and earns **fees** priced into its quote (the payer spends slightly
more wLVGA/BTC than the LVGA released is worth). Net, the LP is taking
**CHF/BTC exposure for fee income** — a normal FX/inventory book, with the
covenant guaranteeing it is paid in BTC for every LVGA payout it services.

```
 BTC ──▶ wLVGA on Arkade            (BTC-backed claim; pool holds LVGA on SwissLedger)
              │
              ▼  payOut(): CSFS(merchant key) + transfer wLVGA → LP + OP_RETURN commit
   ┌─────────────────────────────────────────────────────────────┐
   │ Arkade tx                                                     │
   │  - checkSigFromStack(merchantSig, merchantPk, payoutMsg)      │
   │  - output[0]: wLVGA claim → LP        (LP compensation)       │
   │  - OP_RETURN: protocolTag ‖ merchantEvmAddr ‖ amount          │
   └─────────────────────────────────────────────────────────────┘
              │  webhook: a monitoring node sees the payout
              ▼
   SwissLedger pool contract:
     recompute payoutMsg → ecrecover(payoutMsg, merchantSig) → merchant
     require recovered == committed evmAddr → transfer `amount` LVGA
```

(`burnOut()` is identical except output[0] is replaced by a supply-shrinking
burn, `sumInputs >= sumOutputs + amount`.)

### One key, two chains

EVM and Bitcoin/Arkade both use **secp256k1**, so a single merchant key is
verified two ways over the *same* message:

- on Arkade — `checkSigFromStack(sig, merchantPk, payoutMsg)` (this contract),
- on SwissLedger — `ecrecover(payoutMsg, sig) == merchantEvmAddr` (the pool).

The Arkade side proves the payout is merchant-authorized; the EVM side
independently recovers who to pay. The 20-byte `merchantEvmAddr` is committed
in the OP_RETURN so the payee is explicit and auditable on Arkade, and the
signature rides the witness (and is relayed) for the EVM `ecrecover`.

### `wlvga_payout.ark`

Both modes share `(amount, merchantEvmAddr, merchantPk, merchantSig, burnNonce, commitIndex)`:

- **Authorize** — `checkSigFromStack` over
  `payoutMsg = sha256(protocolTag ‖ merchantEvmAddr ‖ amount ‖ burnNonce)`.
- **Settle** — `payOut` pins `output[0]` to `SingleSig(lpPk)` carrying the
  wLVGA (LP compensation); `burnOut` instead does
  `sumInputs >= sumOutputs + amount` (supply shrinks).
- **Commit** — pin an OP_RETURN output whose script equals
  `protocolTag ‖ merchantEvmAddr ‖ num2bin(amount, 8)`, so the pool can
  recompute the message, `ecrecover`, and match the committed payee.

Implementation notes (honest):

- `merchantPk`/`merchantSig` (pubkey/signature types) appear **only** inside
  `checkSigFromStack` — never in a `+` concat — because those types are not
  byte-strings for concatenation. Everything hashed or committed is
  bytes/int, so `+` lowers to `OP_CAT` and the digest matches the merchant's
  off-chain signing and the EVM reconstruction byte-for-byte.
- **Relay is permissionless**: the OP_RETURN commitment plus the merchant
  signature are self-authenticating, so *anyone* can submit the SwissLedger
  tx — the monitoring node/webhook is a convenience, not a trusted party.
- **Replay** is bounded by `burnNonce` (a unique per-payment id bound into
  both the signed message and the commitment); the pool pays each payout once.

### Automated release on SwissLedger

The payout does not depend on a human releasing funds. The destination-chain
pool is a contract (`swissledger_pool.md`) that a **reporter** calls with the
Arkade payout; it re-binds the destination, amount, and uniqueness and
transfers LVGA automatically — the pool operator cannot withhold or redirect
an individual payment. This is **Flavor A**: a trusted reporter attests the
Arkade burn/transfer happened, but the contract's `ecrecover` + whitelist +
`paid[burnNonce]` checks keep the reporter contained to **liveness**, not
correctness. With reporter = pool operator the trust is incentive-aligned (a
false report drains the operator's own pool for no BTC). (Flavor B replaces
the trusted reporter with an on-EVM Bitcoin SPV proof of the burn — no
reporter trust, heavier verifier; see `swissledger_pool.md`.)

### Trust model

| Property | Where the trust sits |
|---|---|
| Payout authorization | **On-chain** — a valid spend + merchant signature is the authorization; no quorum signs the release |
| Who can trigger the payout | **Anyone** — commitment + signature are self-authenticating (the monitoring node/reporter is just liveness) |
| LP solvency (two-party) | `payOut` **transfers** the BTC-backed claim to the LP, so the LP is paid **in BTC** for the LVGA it releases (LVGA is one-way, never redeemed); the BTC side and the LP may differ |
| Pool liquidity | The **SwissLedger pool** must hold enough LVGA to service payouts; wLVGA issuance is BTC-backed and capped to the LVGA payout capacity the LP is willing to provide |
| Release automation | The SwissLedger pool contract releases automatically on a valid report (`swissledger_pool.md`); no per-payment discretion. Residual: a **trusted reporter** attests the burn (Flavor A) — liveness only, contained by `ecrecover`/whitelist/nonce |
| Correct payee | `ecrecover` on EVM + the committed `evmAddr`; the merchant key binds both chains |

This is the mirror image of the SPV deposit leg: SPV makes the *inbound*
trustless by proving a foreign deposit on Arkade; the payout bridge-out makes
the *outbound* authorization on-chain by committing it in the spend, and the
SwissLedger pool contract releases against it automatically. The two-party
mode fixes **solvency** (the LP is compensated); Flavor A automation removes
per-payment **discretion** (leaving only reporter liveness); full release
trustlessness is Flavor B (SPV-on-EVM) or the `swap_htlc.ark` preimage route.

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

### Attested quorum vs. trustless SPV (deposit leg)

The SPV deposit path (`bridge_spv.ark`) removes the signing quorum entirely
— its trust is Bitcoin's proof-of-work plus two operational assumptions:

| Assumption | Attested (`bridge_mint`) | SPV (`bridge_spv`) |
|---|---|---|
| Who can authorize a mint | k-of-n custodians (can attest anything they collude on) | **No one** — only a valid PoW/merkle proof mints |
| Forging a fake deposit | possible if ≥k keys collude | requires out-mining the network (economic, not a key) |
| Difficulty source | n/a | governance-pinned `powTarget` (no on-chain retarget) |
| Liveness | custodians attest | anyone relays headers + proof (permissionless) |
| Finality | as soon as k attest | `minConfirmations` deep — economic, a majority-hashrate fork can still fool a light verifier |

So SPV trades "trust k-of-n signers" for "trust PoW + a pinned-difficulty
oracle + a header relayer's liveness." Strictly less authority in anyone's
hands (no one can fabricate a deposit), at the cost of the pinned-difficulty
and relayer-liveness assumptions and economic (not absolute) finality. Use
SPV for PoW chains; keep the quorum for fast-finality/non-PoW chains where
SPV doesn't apply.

### Four shapes, four trust profiles

| | Wrap bridge (`bridge_mint`/`withdrawal`) | SPV bridge (`bridge_spv`) | Fast-transfer swap (`swap_htlc`) | Payout bridge-out (`wlvga_payout`) |
|---|---|---|---|---|
| Persistent wrapped token | yes | yes | **no** | yes (transferred to LP, or burned) |
| Pooled custody | treasury | inbound custody | **no** — solver inventory | destination-chain liquidity pool |
| Who authorizes release | k-of-n quorum | PoW proof | HTLC preimage | **the spend itself** (+ merchant sig) |
| Cross-chain verification | attestation | on-chain SPV (PoW inbound) | **none** — shared secret | commitment + `ecrecover` on EVM |
| Who can trigger | quorum | anyone (relay proof) | watchtower/operator | **anyone** (self-authenticating) |
| Residual trust | quorum honesty | pinned difficulty + relayer | free option + liveness | pool/LP release honesty + relayer liveness (LP solvency handled by the transfer) |
| Best for | any chain, holdable balances | BTC/PoW inbound | one-shot LN → Arkade → EVM | merchant payouts to an EVM pool |

The fast-transfer route is the least-trust option *when it applies* (a live
counterparty willing to front the destination asset for a single swap); the
wrap and SPV bridges are what you use when a user needs to **hold** a
bridged balance across many later transactions.

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

- **SPV replay registry**: a spent-deposit accumulator (or per-txid marker
  asset) so `bridge_spv.ark` provably credits each deposit at most once.
- **On-chain difficulty tracking**: a header-relay covenant maintaining the
  best chain and retarget so `powTarget` is no longer governance-pinned —
  the remaining trust reduction for the SPV path.
- **Deposit-tx output parsing**: replace the prover-supplied output offset
  with real varint-aware output-vector parsing so the paid output cannot be
  mis-pointed.
- **Custodian rotation**: a quorum-attested `rotate()` transition to a new
  `custodians`/`threshold` state, with domain-tagged attestation messages
  so rotation signatures cannot be replayed as mints.
- **Fee handling**: a `takeFee`-style basis-points parameter with 330-sat
  dust routing, as in `stability_offer.ark`.
- **Batch mints**: several deposits per mint spend, one output each,
  amortizing the state transition.

## Local checks

```bash
cargo run -- examples/bridge/bridge_mint.ark -o /tmp/bridge_mint.json
cargo run -- examples/bridge/bridge_withdrawal.ark -o /tmp/bridge_withdrawal.json
cargo run -- examples/bridge/bridge_spv.ark -o /tmp/bridge_spv.json
cargo run -- examples/bridge/swap_htlc.ark -o /tmp/swap_htlc.json
cargo run -- examples/bridge/wlvga_payout.ark -o /tmp/wlvga_payout.json
cargo test --test examples bridge          # incl. SPV + swap-HTLC + burn-out assertions
cargo test --test features new_opcodes     # hash256/reverseBytes primitives
./playground/generate_contracts.sh         # refresh playground bundle
```
