# Bonds — Fixed-Maturity Bond Market

Spec for `examples/bonds/repayment_pool.ark` and `examples/bonds/bond_mint.ark`.

A UTXO-native fixed-maturity bond market on Arkade. Borrowers self-issue 1:1
credit and debit tokens against collateral; credit is sold for USDT on the
order book (via `non_interactive_swap` — that *is* the borrower's loan and the
lender's entry point). NO interest rate; the yield is whatever discount the
market sets at sale time.

A vault closes through one of three paths:

1. **`repay`** — voluntary, pre-maturity, borrower-signed.
2. **`liquidate`** (margin call) — permissionless, pre-maturity, fires as soon
   as `collateralValue < liqThresholdBps × mintedAmount / 10000`. Oracle-priced
   sale; collateral → auctioneer; USDT → pool. This is the invariant that
   keeps every vault in the pool covenant-thresholded healthy at every block,
   which is what makes credit tokens **genuinely fungible** on the order book:
   a lender doesn't need to know WHICH vault backs the credit they bought
   because the covenant guarantees every vault is above the health floor.
3. **`auction`** — permissionless, post-maturity, in the auction window. For
   vaults whose borrowers did not repay. Same oracle-priced sale.

After the auction window closes, credit holders redeem pro-rata for the
accumulated USDT.

A borrower can also **roll** their loan to the next maturity without fronting
capital — a documented multi-tx pattern (see §Loan roll).

This document is the high-level spec. Source is canonical; comments in the
`.ark` files are the source of truth for opcode-level invariants.

---

## Roles

| Role | What they do | On-chain identity |
|---|---|---|
| **Borrower** | Mints credit + debit + posts collateral via `issue`; sells credit for USDT on the order book; repays via `repay` before maturity, or rolls to the next maturity (§Loan roll), or has their vault auctioned. | `borrowerPk` per vault |
| **Lender** | Buys credit on the order book; redeems credit for pro-rata USDT after the auction window via `redeem`. | `holderPk` per redemption |
| **Auctioneer** | Runs `liquidate` (margin call) on any vault that drops below the health threshold, OR runs `acceptAuction` on any defaulted vault post-maturity. Paying USDT for the collateral at the oracle price minus the auction discount. Permissionless. | `auctioneerPk` per spend |
| **Oracle** | Publishes signed BTC/USDT price (Fuji-style). The contract verifies the signature on each oracle-using call. | `oraclePk` (constructor) |
| **Arkade operator** | Co-signs cooperative-path spends off-chain; supplies the `<SERVER_KEY>` injected by the runtime. Not a trust point in the active covenant — only required for fast off-chain settlement. | `<SERVER_KEY>` |

**Margin call and auction are both permissionless.** The phased timeline plus
each pool function's covenant invariants make the right pairing safe without
privileged signatures. Any party may execute; incentive is the on-chain
`auctionDiscountBps` spread (paid on both margin-call liquidations and
post-maturity auctions).

---

## Phased lifecycle

```
                    maturity                   maturity + auctionWindow
─────────[ REPAY phase ]────────[ AUCTION phase ]──────[ REDEEM phase ]─────►
issue                            acceptAuction         redeem
acceptRepayment                  (vault.auction)       (vault disallowed)
liquidate (margin call)
(vault.repay, vault.liquidate)
```

Each pool function is gated to exactly one phase:

| Function | Time gate | Extra gate | Caller |
|---|---|---|---|
| `issue` | `tx.time < maturity` | — | borrower (signed) + oracle witness |
| `acceptRepayment` | `tx.time < maturity` | — | borrower co-spends `BondMint.repay` |
| `liquidate` | `tx.time < maturity` | `collateralValue < liqThresholdBps × mintedAmount / 10000` | any auctioneer + oracle witness |
| `acceptAuction` | `tx.time >= maturity AND tx.time < maturity + auctionWindow` | — | any auctioneer + oracle witness |
| `redeem` | `tx.time >= maturity + auctionWindow` | — | credit holder (signed) |

Each `BondMint` function is gated to match:

| Function | Time gate | Caller |
|---|---|---|
| `repay` | `tx.time < maturity` | borrower (signed) |
| `liquidate` | `tx.time < maturity` | any auctioneer |
| `auction` | `tx.time >= maturity AND tx.time < maturity + auctionWindow` | any auctioneer |

**Pre-maturity co-spend safety.** Three pool functions share the pre-maturity
phase: `issue`, `acceptRepayment`, `liquidate`. They're safely co-spendable
with the relevant vault function because each one's covenant invariants
conflict with the others' in any combined tx:

- `vault.repay` pairs with `pool.acceptRepayment` (intended): borrower-signed,
  burns debit, returns collateral → borrower. Cannot pair with `pool.issue`
  (debit-delta arithmetic forces mintedAmount=0 in vault, impossible). Cannot
  pair with `pool.liquidate` (output[1] script must be both borrower and
  auctioneer — conflict).
- `vault.liquidate` pairs with `pool.liquidate` (intended): permissionless,
  burns debit, collateral → auctioneer, requires `collateralValue < healthFloor`.
  Cannot pair with `pool.issue` (debit-delta conflict) or
  `pool.acceptRepayment` (output[1] script conflict).

**In-window co-spend safety.** `vault.auction` pairs only with
`pool.acceptAuction` — the other four pool functions all fail their time
gates in the auction window.

**Redeem-phase safety.** Only `redeem` can fire; no vault function applies.

The phasing + the co-spend invariants are what bind settlement to the right
pool function without any privileged signatures.

---

## State

`RepaymentPool` is a per-maturity singleton with three mutable integers:

| Field | Meaning | Increases on | Decreases on |
|---|---|---|---|
| `usdtBalance` | USDT collected | `acceptRepayment`, `liquidate`, `acceptAuction` | `redeem` |
| `totalCreditOutstanding` | Lender claims still outstanding | `issue` | `redeem` |
| `totalDebitOutstanding` | Borrower obligations still outstanding | `issue` | `acceptRepayment`, `liquidate`, `acceptAuction` |

`BondMint` is per-issuance and carries `mintedAmount` + `collateral` +
`maturity` + `auctionWindow` + `borrowerPk`. It custodies `mintedAmount`
debit tokens.

---

## Settlement math

### Repay (over-collateralized borrower honors the loan)

```
borrower pays   = mintedAmount USDT  → pool
vault burns     = mintedAmount debit
collateral      = mintedAmount BTC sats → borrower
```

### Liquidate (margin call) — same math as auction, pre-maturity, with a health gate

The health gate is the only thing that distinguishes `liquidate` from
`acceptAuction`. Pre-maturity, `liquidate` is allowed ONLY when

```
collateralValue < liqThresholdBps × mintedAmount / 10000
```

i.e. the vault has fallen below the health threshold (e.g. `liqThresholdBps =
11000` triggers at 110% coverage). Below that gate, the two-branch payout is
identical to `acceptAuction`:

### Auction / Liquidate — over-collateralized branch (`collateralValue >= mintedAmount`)

```
collateralValue   = collateral * oraclePrice / 1e8
collateralSold    = mintedAmount * 1e8 / oraclePrice        → auctioneer
excess            = collateral - collateralSold             → borrower (if ≥ 330 sats)
poolReceives      = mintedAmount * (10000 - auctionDiscountBps) / 10000  → pool
auctioneer profit = mintedAmount - poolReceives = mintedAmount * discountBps / 10000
vault burns        = mintedAmount debit
```

For `liquidate` the "over-collateralized" branch covers the band between the
init ratio (e.g. 150%) and the health threshold (e.g. 110%) — the borrower
has fallen out of the healthy band but the collateral still covers the par.

### Auction / Liquidate — shortfall branch (`collateralValue < mintedAmount`)

```
poolReceives      = collateralValue * (10000 - auctionDiscountBps) / 10000  → pool
all collateral                                                              → auctioneer
auctioneer profit = collateralValue * discountBps / 10000
shortfall         = mintedAmount - poolReceives   ← socialised via redemption rate
vault burns        = mintedAmount debit (full obligation extinguished)
```

For `liquidate` this branch should be rare in practice — by definition
`liquidate` is triggered as soon as the health threshold is breached, so
collateral typically lands somewhere between `mintedAmount` and the threshold
(in the over-collateralized branch). A shortfall at liquidation means an
abrupt price move outran the keeper bots.

### Redeem

```
payout = amount * usdtBalance / totalCreditOutstanding   → holder (SingleSig)
pool burns = amount credit
```

The rate `usdtBalance / totalCreditOutstanding` is fixed by the time `redeem`
opens (no more deposits or issuances can change it), so it is fair for every
ordering of redemption transactions — no late-redeemer advantage.

---

## Margin call vs. auction (solvency vs. default)

The pre-maturity margin call (`liquidate`) and the post-maturity auction
(`acceptAuction`) are TWO DIFFERENT settlement events triggered by TWO
DIFFERENT failure modes:

| | Margin call | Auction |
|---|---|---|
| **Trigger** | Vault's health: `collateralValue < liqThresholdBps × mintedAmount / 10000`. | Borrower didn't repay by maturity. |
| **When** | At any block pre-maturity. | In `[maturity, maturity + auctionWindow)`. |
| **What it does** | Closes an *insolvent* vault before the bad debt can grow. | Closes a *defaulted* vault. |
| **Why it exists** | Keeps every vault in the pool covenant-thresholded healthy at every block. | Closes positions that didn't voluntarily settle. |

**Both are necessary.** Without `liquidate`, a vault whose collateral has
crashed mid-term silently degrades the value of every outstanding credit
token in the pool — credit tokens are fungible by symbol, but unhealthy
underlying vaults make them mispriced as claims. Lenders can't tell which
credit came from a healthy vault and which from a sinking one, so the order
book either misprices uniformly or fragments. `liquidate` removes the bad
debt before it propagates, so the covenant guarantees a homogeneous, healthy
underlying pool — and credit tokens trade as a single fungible asset with a
single price.

Without `acceptAuction`, defaulted vaults sit unsettled past maturity and
credit holders can't `redeem` while debit remains outstanding.

### Why not just `liquidate` at maturity too?

`acceptAuction` is a *time-triggered* path that doesn't need to check
collateral health — non-repayment IS the trigger. `liquidate` is a
*health-triggered* path that requires the oracle to confirm the threshold
breach. Different triggers, different gates; the two paths are kept distinct
to keep each function's invariant minimal.

### Mid-term volatility buffer

`initRatioBps` (e.g. 15000 = 150%) is the headroom between origination
collateral and the health-call trigger (`liqThresholdBps`, e.g. 11000 =
110%). The bigger the gap, the rarer margin calls are; the smaller the gap,
the more capital-efficient the loan but the more frequent the margin calls
on volatile collateral.

---

## Loan roll

A borrower nearing maturity can extend their loan to the next maturity
without fronting USDT — the order book is the bridge:

```
Tx 1 (open new + sell new credit, atomic on-chain):
  inputs:
    - new pool (state)
    - swap order(s) on non_interactive_swap matching the roll size
    - borrower SingleSig sats for new collateral (or sourced separately)
  outputs:
    - new pool (state advanced: issue)
    - new credit → swap-fill destination (the new lender receives credit)
    - USDT → borrower SingleSig (the bridge cash from the swap fill)
    - new BondMint vault (newCollateral + newAmount debit)

Tx 2 (close old position):
  inputs:
    - borrower SingleSig USDT (from Tx 1)
    - old BondMint vault
    - old pool (state)
  outputs:
    - old pool (state advanced: acceptRepayment)
    - old vault's collateral sats → borrower SingleSig
```

After Tx 2 the borrower has migrated their position from maturity H₁ to H₂.
Net capital required: zero (the order book provides the USDT bridge); net
collateral movement: from old to new, plus whatever new collateral the
borrower added in Tx 1.

If the borrower wants to **reuse** the old vault's collateral as the new
vault's collateral, they need a brief secondary capital source for Tx 1's
new vault (e.g. a flashloan, or a position-rolling assistant), then Tx 2
returns the old collateral to settle. Atomic single-tx loan roll is a
follow-up (E5 in §Follow-ups) requiring multi-covenant tx composition
machinery that the Arkade DSL does not currently expose.

---

## Trust model

| Trust | Surface | Notes |
|---|---|---|
| **Oracle correctness** | `issue`, `liquidate`, and `acceptAuction` verify an oracle-signed price (`ticker || price || time` → `checkSigFromStack(sig, oraclePk, sha256(msg))` + freshness check). | A wrong oracle price corrupts origination (over-/under-collateralisation), the margin-call trigger, AND auction proceeds. Mitigate with multisig or threshold oracle. |
| **Arkade cooperative path** | `serverSig` co-signs the off-chain cooperative spend. | Standard Arkade liveness assumption. Unilateral fallback via CSV-timelocked exit variant. |
| **Server front-running on settlement** | The Arkade server co-signs every cooperative-path tx and sees both `liquidate` and `acceptAuction` txs before relaying them. Because neither requires an auctioneer signature (`auctioneerPk` is a witness pubkey), the server can refuse to co-sign a third party's settlement tx and submit its own with `auctioneerPk` set to a server-controlled key — capturing the `auctionDiscountBps` spread on every margin call and every default. | Mitigated, not eliminated, by the unilateral exit path: after `<exit>` blocks an auctioneer can broadcast on-chain bypassing the server. Within the cooperative window the server has a financial incentive to extract this spread; the magnitude is bounded by `auctionDiscountBps × (defaulted + margin-called) collateral-value` per pool. Acceptable for an MVP with a trusted operator; a self-sovereign deployment runs its own server or keeps `auctionDiscountBps` small enough that the extraction surface is negligible. |

---

## Unilateral exits (Arkade operator unavailable)

Every Arkade contract emits two ASM variants per function: a cooperative
*server variant* (covenant + Arkade co-sign) and an *exit variant* that drops
the covenant and gates the spend on an N-of-N + `<exit>`-block CSV. The exit
variant is the on-chain fallback when the off-chain operator is unavailable.

### BondMint per-vault — CLEAN

The vault is per-borrower. Its exit signers come from the function's pubkey
parameters; the borrower is the only practically-relevant signer. After
`<exit>` blocks, the borrower can sweep the collateral unilaterally.
**Lasting state per vault is self-sovereign.**

### RepaymentPool aggregate — RESOLVES VIA REDEEM

The pool's exit variants are technically the N-of-N over the function's
pubkey parameters (e.g. `borrowerPk + oraclePk` for `issue`,
`holderPk + oraclePk` for `redeem`, etc.). Spending the pool unilaterally
without the covenant is a soft-custody surface — but it is **transient by
construction**:

1. Pre-maturity: the pool is mostly empty of value (USDT only accumulates as
   repayments come in late in the term).
2. Auction phase: the pool fills with auction USDT.
3. **Redeem phase: every credit holder calls `redeem` to drain the pool
   into a `SingleSig(holderPk)` UTXO in their own wallet.** Each of those
   single-sig outputs has its own clean single-owner exit path (see
   `single_sig.ark`). Once every holder has redeemed, the pool is empty and
   the aggregate exit surface is zero.

**The redemption phase is itself the resolution.** The covenant guides
funds into per-holder, single-owner UTXOs; the aggregate state never
persists past the maturity term.

A future iteration could harden this further by adding an explicit
per-holder receipt contract (a tiny covenant with a single-owner unilateral
exit) so holders can lock in their entitlement BEFORE the redeem phase opens
— useful only if the pool stays meaningfully funded for long stretches.

---

## Monetisation

`auctionDiscountBps` is the only revenue surface wired today. Three more
are enumerated under §Follow-ups M1–M3.

| Surface | Status | Cost borne by | Comment |
|---|---|---|---|
| `auctionDiscountBps` | **Wired** | Credit holders (degraded redemption rate proportional to default fraction × discount) | On-chain economic incentive that elicits auction execution from any party. |

---

## Follow-ups

Tracked work that is NOT in this MVP but would harden, broaden, or monetise
the design. None are blocking; each is a concrete piece of work with a
defined deliverable. Inline `// FOLLOW-UP:` notes in the source mark the
exact lines where each one would land.

### Robustness / hardening

| # | Item | Why | Sketch |
|---|---|---|---|
| **R1** | Add `minCollateral` + `minAmount` constructor params; reject dust-sized issuances. | `issue` today accepts `collateral=1, amount=1`. The `required = amount * initRatioBps / 10000` collateralisation check rounds DOWN, so for `amount=1, initRatioBps=9999` the required floor is silently zero. An attacker can mint 1 credit + 1 debit for 1 sat, polluting the auction window with unprofitable defaults. | Add two int constructor params; `require(amount >= minAmount && collateral >= minCollateral)` at top of `issue`. |
| **R2** | Ceiling division on the origination collateral check. | Mitigates the rounding floor at the unit boundary even without R1's explicit minimums. | Replace `required = amount * initRatioBps / 10000` with `required = (amount * initRatioBps + 9999) / 10000`. |
| **R3** | Final-redemption residue path. | `redeem`'s `require(payout > 0)` rejects dust redemptions; the last few USDT are stranded forever once they round below the per-unit rate. | Add a `redeemAll(holderPk, holderSig)` branch gated on `amount == totalCreditOutstanding` that pays the full residual `usdtBalance` regardless of payout rounding. |
| **R4** | ASM-level assertion of the strict time gate on `redeem`. | `test_redeem_is_pro_rata_post_window` currently relies on the constructor-param surface, not the gate's actual ASM placement. A refactor removing the gate would not be caught by the test. | Pattern-match the comparison sequence in `redeem`'s ASM that proves `tx.time >= maturity + auctionWindow` is enforced. |

### Capacity ceilings (int64 overflow, fail-closed)

`OP_MUL64` aborts on overflow, so each ceiling fails CLOSED — scripts never
produce wrong outputs, but legitimate transactions above the ceiling cannot
execute. Inline `// FOLLOW-UP:` notes are at the affected sites.

| # | Site | Ceiling | Workaround |
|---|---|---|---|
| **C1** | `collateral * oraclePrice` in `issue` + `acceptAuction` | ~92 BTC at a $1M BTC oracle price | Chunked issuance/auctions, or rescale `oraclePrice` to a smaller denominator (e.g. 1e4 vs 1e8). |
| **C2** | `mintedAmount * 100000000` in `acceptAuction` over-cover branch | ~92 BTC of par | Chunk auctions, or rescale. |
| **C3** | `amount * usdtBalance` in `redeem` | Product space ~1e18 (pool size × redemption size) | Chunked redemptions, or divide-before-multiply with controlled precision loss. |

### Capability extensions

| # | Item | Why | Sketch |
|---|---|---|---|
| **E1** | Partial repays. | Today a borrower must repay the full `mintedAmount` or default. If their cashflow only covers half, they default and lose all collateral to auction. | `BondMint.repayPartial(amount, sig)`: split the vault into a new vault with `mintedAmount - amount` carrying forward the proportional collateral, and return the rest to the borrower. |
| **E2** | Per-holder redemption receipt. | A credit holder who wants to lock in their entitlement BEFORE the redeem phase opens has no on-chain way to do so today. Useful when the auction window is long or the holder is offline. | Add a `RedemptionReceipt` covenant and a `RepaymentPool.lock(amount, holderPk)` (auction-window-gated) that mints a single-owner receipt UTXO representing the holder's deferred claim. |
| **E3** | Explicit `finalize` snapshot. | The current design's redemption rate is fixed in practice (no late USDT additions can occur in the redeem phase). An explicit `finalize` would make the snapshot immutable in the pool state, hardening against future changes that re-open the auction phase. | One-shot `finalize` callable by anyone post-window; sets immutable `maturedTotalCredit`, `maturedTotalUsdt`; `redeem` then uses those. |
| **E4** | Configurable dust threshold. | Borrower-excess output is hard-coded to `>= 330` sats. If Bitcoin's dust policy changes or the deployer wants stricter/looser, the contract must be edited. | Add `dustThreshold` constructor param; use `if (excess >= dustThreshold)` instead. |
| **E5** | Atomic single-tx loan roll. | The documented loan-roll pattern is two transactions, which exposes the borrower to a brief window of holding both positions (or requires temporary capital to reuse old collateral). A single-tx atomic roll would compose new-pool `issue` + old-pool `acceptRepayment` + swap fill in one transaction. | Blocked by Arkade's single-output-index-per-covenant idiom: each pool function expects `output[0]` = self-recreation, and two covenants can't share index 0. Either extend the DSL with a multi-covenant output-discovery primitive, or write a meta-orchestrator covenant that proxies both pool calls and pins outputs to match. |

### Time-axis clarity

| # | Item | Why | Sketch |
|---|---|---|---|
| **T1** | Unify time axis or document the conversion. | `oracleMaxAge` is **seconds** (compared against `tx.offchainTime - oracleTime`); `maturity` / `auctionWindow` are **block heights** (compared against `tx.time`). Two axes invite off-by-one errors when deployers reason about the timeline. | Either gate oracle freshness on block height via a block-anchored attestation, OR rename `oracleMaxAge` → `oracleMaxAgeSeconds` and document the conversion factor prominently. |

### Monetisation surfaces (not yet wired)

| # | Item | Bearer | Recommendation |
|---|---|---|---|
| **M1** | Origination fee at `issue` (`originationBps`). | Borrower. | **Recommended.** Volume-correlated, doesn't touch lender yield. ~15 LoC: add `originationBps` + `feeSinkPk` constructor params, pin an extra output paying the fee. |
| **M2** | Redemption fee at `redeem`. | Lender. | Avoid — degrades the pure-discount yield story. |
| **M3** | Order-book fee in `non_interactive_swap`. | Both sides. | Orthogonal to bonds; belongs in the swap contract. |

### Trust hardening

| # | Item | Status | Notes |
|---|---|---|---|
| **H1** | Server auction front-running. | Documented in §Trust model. | Server can capture `auctionDiscountBps × defaulted-collateral-value` per default by refusing to co-sign third-party auctions and substituting its own `auctioneerPk`. Mitigated by the unilateral exit path (auctioneer can broadcast on-chain after `<exit>` blocks). A self-sovereign deployment runs its own server or keeps `auctionDiscountBps` small. |
| **H2** | Threshold oracle. | Today a single `oraclePk` per pool. | Replace `checkSigFromStack(sig, oraclePk, msg)` with a k-of-n threshold-oracle check; reduces single-key compromise impact on origination + auction pricing. |

### Test infrastructure cleanup

| # | Item |
|---|---|
| **K1** | Move duplicated test helpers (`asm_of`, `asm_variant`, `witness_names`) from `tests/bond_mint_test.rs` and `tests/repayment_pool_test.rs` into a shared `tests/common/mod.rs`. |
| **K2** | The `new RepaymentPool(...)` constructor list (16 args) appears in 5 reconstruction sites in `repayment_pool.ark`. The DSL has no parameter-list abstraction, so add a one-line `// All callers of new RepaymentPool(...) must update in lockstep` comment at the constructor declaration to make the maintenance burden discoverable. |

### Intentional scope choices (NOT follow-ups)

These are deliberate properties of the design, not deferred work:

- **One pool per maturity.** Liquidity fragmentation is a feature, not a bug; secondary markets (via the order book) compose multiple maturities into the desired yield curve.
- **`maturity` and `auctionWindow` immutable.** The whole product is a fixed-term bond; making them mutable would re-introduce a privileged role.
- **Maturity-only auction (no pre-maturity liquidation).** See §"Why maturity-only auction" above.

---

## Files

```
examples/bonds/repayment_pool.ark   — per-maturity singleton (5 functions:
                                       issue, acceptRepayment, liquidate,
                                       acceptAuction, redeem)
examples/bonds/bond_mint.ark        — per-issuance vault    (3 functions:
                                       repay, liquidate, auction)
docs/bonds.md                       — this spec
tests/repayment_pool_test.rs        — ASM-level pool tests
tests/bond_mint_test.rs             — ASM-level vault tests
```
