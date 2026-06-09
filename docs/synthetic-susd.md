# Perpetual BTC/sUSD Synthetic — Design Direction

**Status:** design note for internal review (pre-Andrew). Direction, not a spec.
The contract architecture has open questions (§9); this note frames the shape and
the decisions.

This note argues that the right primitive for **bootstrapping BTC↔fiat swap
liquidity in our wallets** — and, as a by-product, for solver inventory hedging —
is a **perpetual, oracle-marked BTC/sUSD synthetic with dynamic funding**, not
`StabilityVault` and not the dated `bonds`/`options` shapes. It captures the
conclusion of the internal thread.

---

## 1. Why not Stability (the network-effect argument)

In `StabilityVault` the **Seeker is structurally a taker**. A large, cheap
Provider attracts only more Seekers (more takers) and, if anything, *repels* other
Providers — they'd compete the fee down. Liquidity does not beget liquidity:
**no bootstrap.** Stability is *bilateral lending*, not a market. Its "take fee"
(~0.2%) is acceptable for low-frequency lending entry/exit but is an order of
magnitude wide of the swap bar (a comparable synthetic competitor quotes ~0.025%
from mid).

The deeper point: a synthetic market and a lending market are the **same book,
coupled by the funding rate**. Long spot + short synthetic = a synthetic-USD
position; the funding *is* the lending rate (cash-and-carry / basis). So one
friendly maker quoting tight near mid bootstraps **both** at once — not two
uncorrelated capital deployments that happen to help each other, but one
instrument viewed two ways, linked by no-arbitrage. That coupling is exactly what
Stability lacks and what gives a synthetic its self-reinforcing flywheel
(borrowers and lenders show up, some become makers).

| | StabilityVault | Perpetual synthetic |
|---|---|---|
| Structure | bilateral lend (1 Seeker ↔ 1 Provider) | two-sided pooled market |
| Stable leg | a per-vault USD claim | **fungible sUSD token** |
| Network effect | none (Seekers are takers) | two-sided, self-reinforcing |
| Funding | fixed, bilaterally negotiated, floored ≥0 | **dynamic, imbalance-driven** |
| Good for | private residual hedge | swap rail + lending + hedge |

## 2. What it is

A perpetual (no maturity) synthetic where BTC collateral backs a fungible
**sUSD** token redeemable for BTC at the oracle price.

- **Short / lender side** — lock BTC, mint sUSD. You now hold a dollar-stable
  token: delta-flat in USD, self-custodied. This is the solver's hedge leg.
- **Long side** — wants BTC price exposure; funded against the pool. Pays funding
  to the short side when longs are crowded.
- **sUSD** circulates as a fungible Arkade Asset — *this is the swap rail*. A
  wallet swapping a user's USDT→BTC can route through sUSD; the token's
  tradeability is the network effect Stability can't produce.
- **Oracle-marked** via the existing Fuji pattern: `sha256(ticker + price + time)`
  signed by `oraclePk`, with `tx.offchainTime` freshness.

**Perpetual, deliberately.** Fixed maturity is out of scope — it fragments
liquidity across tenors and adds interest-rate risk (the reason the
`bonds`/`options` shapes don't fit a liquid swap rail).

## 3. Dynamic funding = Marco's "variable rate by inventory swing"

The variable-rate-by-inventory-swing idea *is* perpetual funding: a premium
component that moves funding to balance long/short open interest.

```
fundingRate = clamp( premiumIndex + interestComponent , -cap, +cap )
premiumIndex ∝ (markPrice - oraclePrice) / oraclePrice      # OI imbalance signal
longs crowded  -> funding > 0 -> longs pay shorts            # cools longs, pays lenders
shorts crowded -> funding < 0 -> shorts pay longs            # incentivizes longs back in
```

This is the mechanism that lets the synthetic **clear two-sided without a
permanent angel.** Stability's funding is fixed and floored at ≥0 (cannot
self-balance), which is precisely why it needs a charity Provider forever. The
floor question (§9) is the key economic decision: floor-at-0 is desk-friendly but
drains long-side liquidity when the basis inverts; allowing negative funding keeps
both sides present.

## 4. How it bootstraps swap + lending together

```
friendly maker quotes BTC/sUSD tight near mid (target ~0.025% from mid)
        │
        ▼
small swaps execute at low slippage  ──►  tight spread attracts origination
        │                                          volume (the swap flywheel)
        ▼
funding accrues to the short side    ──►  lenders earn yield, longs get exposure
        │                                          (the lending flywheel)
        ▼
both sides deepen; some participants become makers themselves  ──► self-sustaining
```

Christian's sizing intuition to respect: at ~1M origination volume **without**
anyone actively quoting, swaps below ~0.3% slippage are hard; **with** a maker
holding a tight spread, small swaps execute efficiently and the tight spread pulls
in new origination. The maker's capital does double duty — it supports the swap
market and the lending market simultaneously, because they're the same book (§1).

## 5. The solver hedge is a role inside it

The original ask — a solver hedging inventory without a CEX — falls out for free:

1. Internalize two-sided client flow; hedge only the **residual swing** (MMs don't
   hedge every trade).
2. To flatten a net-long residual, **mint sUSD against the residual BTC** — the
   solver takes the short side. Self-custodied, no CEX margin, no withdrawal-freeze
   exposure.
3. Net-short residual → hold/redeem sUSD for BTC (long side).

The solver becomes a *participant/maker* in the synthetic rather than a Seeker in a
private lend. Same delta-flat outcome, but the capital also contributes to the
public market it's hedging in. FX wrappers (sUSD / sCHF / sEUR) are a trivial
generalization — one synthetic per oracle `ticker`/numeraire, same contract.

## 6. Collateral & solvency — the architecture fork

Two viable shapes; this is the main net-new contract decision:

- **(A) Pooled debt (Synthetix/GLP-style).** One system pool is the counterparty
  to every position; sUSD is a claim on the pool. Maximum capital efficiency and
  always-available counterparty, but concentrates a tail "pool wipeout" risk and
  needs careful collateralization (Synthetix historically ran 400–600%+ — heavy).
- **(B) Matched perp with pooled liquidity buffer.** Longs and shorts are matched,
  funding flows between them, a buffer absorbs imbalance. Closer to a real perp;
  liquidation risk on leveraged legs.

Fully-collateralized (no-liquidation) variants exist but cap leverage/efficiency.
The delta-neutral 1:1 backing (Ethena-style: peg held by the hedge, not an
overcollateral buffer) is the capital-efficient target, with the well-known
caveat that **delta-neutral ≠ risk-free** — it shifts risk to funding,
counterparty, and oracle rather than removing it.

## 7. What's reusable vs net-new

**Reusable from existing contracts:**
- sUSD mint/burn ← `controlled_mint.ark` / `token_vault.ark` asset-group
  primitives (`tx.assetGroups.find(...).delta`, `assets.lookup`).
- Oracle Fuji pattern, `tx.offchainTime` freshness, two-tapleaf cooperative/exit,
  330-sat dust floor.
- Self-replacement state transitions and proportional `split`/`merge` math from
  `stability_vault.ark`.

**Net-new:**
- The pooled/matched collateral engine (§6) — the core new design.
- **Dynamic funding** driven by OI imbalance (§3) — Stability's funding is static.
- `markPrice` / premium-index machinery to feed funding.
- sUSD as a first-class, freely-tradeable asset with a swap-routing UX.

## 8. The swap rail (why sUSD tradeability matters)

The fungible sUSD token is what turns a hedging instrument into a swap market.
`non_interactive_swap.ark` already gives atomic sUSD↔BTC / sUSD↔USDT swaps, so a
wallet can offer "swap USDT→BTC" routed through sUSD without the user ever seeing
the synthetic. That routing is the network effect Christian points to and the
reason this bootstraps where Stability can't.

## 9. Decisions to pressure-test before Andrew

1. **Collateral architecture** — pooled-debt (A) vs matched-perp (B) (§6). This is
   the biggest fork and drives everything else.
2. **Funding floor** — allow negative funding (keeps long-side liquidity, true
   two-sided clearing) or floor at 0 (desk-friendly, but longs vanish on inverted
   basis)? §3.
3. **Long-side liquidity sourcing** — same binding constraint as the hedge note: a
   synthetic needs longs to exist. The flywheel (§4) is the answer *if* a friendly
   maker seeds it; quantify the seed capital and the spread it must hold.
4. **Oracle / operator liveness** — settlement enforceable only on the cooperative
   tapleaf; define the unilateral fallback for redemptions.
5. **Solvency of the stable leg** — what guarantees 1 sUSD ≈ \$1 of BTC under a
   fast drawdown; collateral ratio, liquidation vs fully-collateralized.

**Recommended first build:** the *thinnest* version that proves the flywheel —
sUSD mint/burn against a pooled buffer, dynamic funding, oracle mark, a single
friendly maker seeding tight quotes — instrumented to measure whether tight
spreads actually pull in third-party origination before we scale the collateral
engine.

---

## Appendix — wallet UX (Andrew's ask, scoped)

The UX mockup lives in the **wallet** repo (Arkade/Nuri), not this compiler repo.
The flows to mock, from this side:

- **Hold sUSD** — "Dollar balance" that's actually delta-flat BTC; show funding
  earned.
- **Swap** — USDT/BTC ↔ sUSD, one tap, slippage + spread shown against mid.
- **Solver/treasury view** — net inventory delta, residual hedged via sUSD,
  funding P&L.
- **Long BTC** — leveraged/exposure position, funding paid, liquidation/collateral
  state.

I can produce detailed flow/state descriptions here to hand to the wallet team if
useful.
