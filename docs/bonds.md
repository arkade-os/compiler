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

**There is NO keeper.** The phased timeline (below) makes the auction safely
permissionless: there is no adversarial co-spend pairing for the
covenants to defend against, so no signature trust is needed to bind the
right pool function.

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

The phasing is what eliminates the keeper. During the auction window the
only pool function that can fire is `acceptAuction` (issue / acceptRepayment
fail on pre-maturity; redeem fails before window end), so `vault.auction`'s
"pool co-spent" check is sufficient — `acceptAuction` is the only candidate
pool function it could be paired with.

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
| **No keeper** | — | Auction is permissionless; phased timeline prevents adversarial pairings without trust signatures. |
| **Server auction front-running** | The Arkade server co-signs every cooperative-path tx and sees the auction tx before relaying it. Because `BondMint.auction` requires no auctioneer signature (`auctioneerPk` is a witness pubkey), the server can refuse to co-sign a third party's auction tx and instead submit its own with `auctioneerPk` set to a server-controlled key — pocketing the `auctionDiscountBps` spread on every default. | Mitigated, not eliminated, by the unilateral exit path: after `<exit>` blocks an auctioneer can broadcast on-chain bypassing the server. Within the cooperative window the server has a financial incentive to extract this spread; the magnitude is bounded by `auctionDiscountBps × defaulted-collateral-value` per pool. Acceptable for an MVP with a trusted operator; a self-sovereign deployment would either run its own server or set `auctionDiscountBps` small enough that the extraction surface is negligible. |

---

## Unilateral exits (Arkade operator unavailable)

Every Arkade contract emits two ASM variants per function: a cooperative
*server variant* (covenant + Arkade co-sign) and an *exit variant* that drops
the covenant and gates the spend on an N-of-N + `<exit>`-block CSV. The exit
variant is the on-chain fallback when the off-chain operator is unavailable.

### BondMint per-vault — CLEAN

The vault is per-borrower. Its exit signers come from the function's
pubkey parameters; with the keeper gone, the borrower is the only
practically-relevant pubkey. After `<exit>` blocks, the borrower can sweep
the collateral unilaterally. **Lasting state per vault is self-sovereign.**

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

| Surface | Status | Cost borne by | Comment |
|---|---|---|---|
| `auctionDiscountBps` | **Wired** | Credit holders (degraded redemption rate proportional to default fraction × discount) | The trustlessness purchase: auctioneer's profit replaces the keeper's off-chain compensation. |
| Origination fee at `issue` | Follow-up | Borrowers | Recommended for protocol revenue. ~15 LoC: add `originationBps` + `feeSinkPk`, pin extra output. |
| Redemption fee at `redeem` | Follow-up | Lenders (directly) | Degrades the pure-discount yield story; generally avoid. |
| Order-book fee in `non_interactive_swap` | Orthogonal | Both sides of swap | Lives in the swap contract. |

---

## Known limitations (MVP)

1. **`int64` overflow ceilings.** `collateral * oraclePrice` (in `issue` and
   `acceptAuction`) and `amount * usdtBalance` (in `redeem`) cap at ~92 BTC
   par at a $1M BTC price. OP_MUL64 fails closed; workaround is chunked
   transactions. See `// FOLLOW-UP:` notes in `repayment_pool.ark`.
2. **No partial repays.** A borrower must repay the full `mintedAmount` in
   one transaction, or default. Partial-repay support would split a
   `BondMint` into two vaults on each repay; not implemented.
3. **Auctioneer incentive is bounded by `auctionDiscountBps`.** If set to 0,
   permissionless auctioning relies on a credit holder's self-interest to
   trigger (otherwise pre-redemption USDT is suboptimal). 50–100 bps is a
   reasonable default.
4. **One pool per maturity.** Liquidity fragments across maturity dates;
   secondary markets (via the order book) compose them.

---

## Files

```
examples/bonds/repayment_pool.ark   — per-maturity singleton (4 functions)
examples/bonds/bond_mint.ark        — per-issuance vault    (2 functions)
docs/bonds.md                       — this spec
tests/repayment_pool_test.rs        — ASM-level pool tests
tests/bond_mint_test.rs             — ASM-level vault tests
```
