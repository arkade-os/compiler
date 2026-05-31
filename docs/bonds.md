# Bonds — Fixed-Maturity Bond Market

Spec for `examples/bonds/repayment_pool.ark` and `examples/bonds/bond_mint.ark`.

A UTXO-native fixed-maturity bond market on Arkade. Borrowers self-issue 1:1
credit and debit tokens against collateral; credit is sold for USDT on the
order book (via `non_interactive_swap` — that *is* the borrower's loan and the
lender's entry point). NO interest rate; the yield is whatever discount the
market sets at sale time. At maturity, repayments and oracle-priced auctions
of defaulted collateral fill a per-maturity USDT pool, which credit holders
redeem pro-rata.

This document is the high-level spec. Source is canonical; comments in the
`.ark` files are the source of truth for opcode-level invariants.

---

## Roles

| Role | What they do | On-chain identity |
|---|---|---|
| **Borrower** | Mints credit + debit + posts collateral via `issue`; sells credit for USDT on the order book; repays via `repay` before maturity (or defaults). | `borrowerPk` per vault |
| **Lender** | Buys credit on the order book; redeems credit for pro-rata USDT after the auction window via `redeem`. | `holderPk` per redemption |
| **Auctioneer** | At/after maturity, runs `acceptAuction` on any defaulted vault, paying USDT for the collateral at the oracle price (minus the discount). Permissionless. | `auctioneerPk` per auction |
| **Oracle** | Publishes signed BTC/USDT price (Fuji-style). The contract verifies the signature on each oracle-using call. | `oraclePk` (constructor) |
| **Arkade operator** | Co-signs cooperative-path spends off-chain; supplies the `<SERVER_KEY>` injected by the runtime. Not a trust point in the active covenant — only required for fast off-chain settlement. | `<SERVER_KEY>` |

**Auctions are permissionless.** The phased timeline (below) eliminates
adversarial co-spend pairings entirely, so no privileged signature is needed
to bind settlement to the right pool function. Any party may execute an
auction; incentive is the on-chain `auctionDiscountBps` spread.

---

## Phased lifecycle

```
                    maturity                   maturity + auctionWindow
─────────[ REPAY phase ]────────[ AUCTION phase ]──────[ REDEEM phase ]─────►
issue                            acceptAuction         redeem
acceptRepayment                  (vault.auction)       (vault disallowed)
(vault.repay)
```

Each pool function is gated to exactly one phase:

| Function | Time gate | Caller |
|---|---|---|
| `issue` | `tx.time < maturity` | borrower (signed) + oracle witness |
| `acceptRepayment` | `tx.time < maturity` | borrower co-spends `BondMint.repay` |
| `acceptAuction` | `tx.time >= maturity AND tx.time < maturity + auctionWindow` | any auctioneer + oracle witness |
| `redeem` | `tx.time >= maturity + auctionWindow` | credit holder (signed) |

Each `BondMint` function is gated to match:

| Function | Time gate | Caller |
|---|---|---|
| `repay` | `tx.time < maturity` | borrower (signed) |
| `auction` | `tx.time >= maturity AND tx.time < maturity + auctionWindow` | any auctioneer |

The phasing is what binds settlement to the right pool function. During the
auction window the only pool function that can fire is `acceptAuction`
(issue / acceptRepayment fail on pre-maturity; redeem fails before window
end), so `vault.auction`'s "pool co-spent" check is sufficient —
`acceptAuction` is the only candidate pool function it could be paired with.

---

## State

`RepaymentPool` is a per-maturity singleton with three mutable integers:

| Field | Meaning | Increases on | Decreases on |
|---|---|---|---|
| `usdtBalance` | USDT collected | `acceptRepayment`, `acceptAuction` | `redeem` |
| `totalCreditOutstanding` | Lender claims still outstanding | `issue` | `redeem` |
| `totalDebitOutstanding` | Borrower obligations still outstanding | `issue` | `acceptRepayment`, `acceptAuction` |

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

### Auction — over-collateralized branch (`collateralValue >= mintedAmount`)

```
collateralValue  = collateral * oraclePrice / 1e8
collateralSold   = mintedAmount * 1e8 / oraclePrice        → auctioneer
excess           = collateral - collateralSold             → borrower (if ≥ 330 sats)
auctionUsdt      = mintedAmount * (10000 - auctionDiscountBps) / 10000  → pool
auctioneer profit = mintedAmount - auctionUsdt = mintedAmount * discountBps / 10000
vault burns       = mintedAmount debit
```

### Auction — shortfall branch (`collateralValue < mintedAmount`)

```
auctionUsdt       = collateralValue * (10000 - auctionDiscountBps) / 10000  → pool
all collateral                                                              → auctioneer
auctioneer profit = collateralValue * discountBps / 10000
shortfall         = mintedAmount - auctionUsdt   ← socialised via redemption rate
vault burns       = mintedAmount debit (full obligation extinguished)
```

### Redeem

```
payout = amount * usdtBalance / totalCreditOutstanding   → holder (SingleSig)
pool burns = amount credit
```

The rate `usdtBalance / totalCreditOutstanding` is fixed by the time `redeem`
opens (no more deposits or issuances can change it), so it is fair for every
ordering of redemption transactions — no late-redeemer advantage.

---

## Why maturity-only auction (no Aave-style pre-maturity liquidation)

- Fixed-term product. The borrower's covenant is "repay USDT by `maturity`".
  Pre-maturity margin calls would break the term they paid for via the
  market discount.
- Credit token == the right to USDT at maturity. Lenders priced the discount
  around the H-block payoff; forced early repayment destroys the duration
  they bought.
- No interest accrual. Aave-style liquidation exists because debt grows over
  time and erodes the safety margin. With zero rate the obligation is static
  — only the spot price moves the collateral ratio, and the only moment that
  matters is maturity.
- Simpler ops, no oracle-spike griefing. A transient mid-term BTC dip is not
  a default.
- `initRatioBps` (e.g. 15000 = 150%) is the borrower's mid-term-volatility
  buffer; lender-side downside, if the buffer is exhausted by maturity, is
  socialised via the auction-proceeds redemption rate.

---

## Trust model

| Trust | Surface | Notes |
|---|---|---|
| **Oracle correctness** | `issue` and `acceptAuction` verify an oracle-signed price (`ticker || price || time` → `checkSigFromStack(sig, oraclePk, sha256(msg))` + freshness check). | A wrong oracle price corrupts both origination (over-/under-collateralisation) and auction proceeds. Mitigate with multisig or threshold oracle. |
| **Arkade cooperative path** | `serverSig` co-signs the off-chain cooperative spend. | Standard Arkade liveness assumption. Unilateral fallback via CSV-timelocked exit variant. |
| **Server auction front-running** | The Arkade server co-signs every cooperative-path tx and sees the auction tx before relaying it. Because `BondMint.auction` requires no auctioneer signature (`auctioneerPk` is a witness pubkey), the server can refuse to co-sign a third party's auction tx and instead submit its own with `auctioneerPk` set to a server-controlled key — pocketing the `auctionDiscountBps` spread on every default. | Mitigated, not eliminated, by the unilateral exit path: after `<exit>` blocks an auctioneer can broadcast on-chain bypassing the server. Within the cooperative window the server has a financial incentive to extract this spread; the magnitude is bounded by `auctionDiscountBps × defaulted-collateral-value` per pool. Acceptable for an MVP with a trusted operator; a self-sovereign deployment would either run its own server or set `auctionDiscountBps` small enough that the extraction surface is negligible. |

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
examples/bonds/repayment_pool.ark   — per-maturity singleton (4 functions)
examples/bonds/bond_mint.ark        — per-issuance vault    (2 functions)
docs/bonds.md                       — this spec
tests/repayment_pool_test.rs        — ASM-level pool tests
tests/bond_mint_test.rs             — ASM-level vault tests
```
