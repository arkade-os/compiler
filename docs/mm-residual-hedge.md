# Market-Maker Residual-Delta Hedge on StabilityVault

**Status:** design note for internal review (pre-Andrew). Not a spec.

This note describes how a BTC/USD RFQ desk can hedge its inventory delta
*natively on Arkade*, reusing the existing `StabilityVault` primitive, instead
of mirroring fills on a centralized exchange. It is meant to pressure-test one
assumption in particular — long-side liquidity sourcing — before we commit to a
build.

---

## 1. The problem

A desk that makes a two-sided BTC/USD market accumulates inventory delta. When a
client sells the desk BTC (desk pays USD), the desk is now **long BTC** and wants
to be flat in USD terms. The reflexive hedge is to short a BTC perpetual on a
CEX. That is:

- **Capital intensive** — margin cannot be netted across venues; a desk must
  pre-fund every exchange it hedges on, inflating required capital (~2.5× in
  commonly cited prime-brokerage examples). The short also ties up margin and
  can be liquidated on a sharp rally.
- **Freeze-prone** — funds on a CEX are an unsecured custodial claim. FTX,
  Celsius, Voyager, and Mt. Gox all froze withdrawals; even solvent exchanges
  (Binance, KuCoin) halt withdrawals ad hoc during congestion or outages.

We want a hedge that keeps BTC in self-custody and never routes capital to an
exchange.

## 2. The insight: the desk is a Seeker

`StabilityVault` already splits a BTC UTXO into a senior USD claim and a
leveraged long:

| StabilityVault role | What it holds | Delta |
|---|---|---|
| **Seeker** | deposits `S` BTC, holds a USD-denominated claim `targetUSD` | **flat in USD** |
| **Provider** | locks additional collateral, takes the residual BTC upside | long BTC |
| funding | `fundingRatePerSec > 0` ⇒ **Provider pays Seeker** | — |

So a desk that is **net-long BTC takes the Seeker leg**: it deposits its
residual inventory, converts it to a USD claim of equal value, and — because
funding is conventionally positive — *gets paid* to be delta-flat. A desk that is
**net-short takes the Provider leg.** The vault is symmetric enough to absorb
residual delta in either direction.

This is structurally the Ethena USDe delta-neutral trade (long spot + short
synthetic), executed peer-to-peer and non-custodially, with two real edges:

1. **Funding floored at zero for the desk.** `settleAndUpdateFunding` enforces
   `newFundingRatePerSec >= 0`, so the Provider can never charge the Seeker. The
   desk's worst case is zero funding income (then it `seekerExit`s). Ethena, by
   contrast, *eats* negative funding out of a finite reserve fund.
2. **No perp-spot basis.** Settlement is at the oracle/index price directly
   (`seekerExit`: `seekerRaw = newTargetUSD * 1e8 / P`), not against a separately
   floating perp mark.

### Downside protection is bounded by the collateral ratio

At a 1.5:1 ratio the Seeker deposits `S`, the Provider adds `1.5·S`, total
collateral `2.5·S`. The Seeker's claim in sats at price `P` is
`targetUSD·1e8/P = S·P0/P`, which stays `<= 2.5·S` as long as
`P >= 0.4·P0`. **The desk is made whole down to a ~60% BTC drawdown**; beyond
that the Provider's buffer is exhausted and the desk eats the tail. This is the
single most important number to size against the freshness of the funding/margin
top-up cycle (`addCapital`, `removeCapital`'s ratio check).

## 3. The efficient flow: internalize → hedge residual → resize

The mistake would be to open a vault per fill. The FX dealing literature is
unambiguous: top desks **internalize 80–90%+** of flow and externally hedge only
the residual. The efficient construction mirrors that:

```
1. INTERNALIZE
   Net client buys against sells on the desk's own book.
   Skew quotes (Avellaneda-Stoikov reservation-price skew) to attract
   inventory-reducing flow. Most flow never needs an external hedge.

2. SIZE THE RESIDUAL
   Track net inventory delta D (signed, in sats).
   Open / adjust a hedge only when |D| breaches a position limit
   (Barzykin-Gueant externalization threshold).

3. HEDGE
   D > 0 (net long)  -> hold Seeker claim of notional |D|
   D < 0 (net short) -> hold Provider leg of notional |D|

4. RESIZE, don't churn
   As D drifts, reshape the existing position:
     split    -> peel off part of the USD claim when D shrinks
     merge     -> combine positions when D grows
     transfer  -> reassign a leg
   The hedge tracks moving inventory without unwind/reopen.
```

Internalisation is what makes the native hedge viable: it shrinks the residual
that needs a counterparty by ~5–10×, which is exactly the part that is hard to
source on Arkade (§5).

## 4. What exists today vs. what's missing

**Reusable as-is from `stability_vault.ark`:**

- Seeker USD claim + Provider collateral in one UTXO; funding accrual.
- `seekerExit` / `providerExit` oracle-priced settlement with clamping.
- `split` / `merge` / `transfer` for resizing (step 4 above).
- `addCapital` / `removeCapital` with a collateral-ratio guard.
- Fuji-style oracle (`sha256(ticker + price + time)`), `tx.offchainTime`
  freshness, two-tapleaf cooperative/exit.

**Missing for an efficient desk workflow:**

- **Pooled Provider side.** The current vault is a 1:1 Seeker↔Provider match. A
  desk needs to open a hedge on demand, which requires a *pool* of Providers
  (GMX-GLP / Synthetix-debt-pool shape) rather than finding one counterparty per
  hedge. This is the same pooling primitive as the covered-call vault discussion
  and is the main net-new contract work.
- **Residual-delta accounting** lives off-chain in the desk's risk engine; the
  vault only needs to represent the hedge once sized. No contract change.
- **Net-short via Provider leg** is mechanically supported but the UX/templates
  for a desk taking the Provider side need to be defined.

## 5. The assumption to pressure-test (and the honest tradeoffs)

**Long-side liquidity sourcing is the binding constraint.** A CEX perp book is
deep; a P2P/pooled vault is not. In a **sustained negative-funding regime, no
rational Provider will pay to be long** when a CEX would pay them instead — so
native hedge liquidity thins exactly when the market is one-sided. The
funding-floored-at-zero protection for the desk is the flip side of this same
coin. **This is the thing to model before building.**

Other tradeoffs, stated plainly:

- **Tail collateralization.** Protection only holds down to the ratio bound
  (~60% drawdown at 1.5:1). A Provider default on a violent down-move is the tail
  where the desk most needed the hedge. Pooling adds a pool-wipeout failure mode
  (cf. Hyperliquid HLP drawdown).
- **Oracle + operator liveness.** Settlement uses the Fuji oracle and
  `tx.offchainTime`, enforceable only on the cooperative tapleaf. If the Operator
  is down, the desk cannot settle the hedge at oracle price on demand via the
  unilateral exit path (no introspection there).
- **Risk-type shift, not removal.** We trade CEX custody/freeze/basis risk for
  Provider-default, oracle, funding-availability, and operator-liveness risk.
  "Delta-neutral" means price-neutral, not risk-free.

## 6. Decision points before involving Andrew

1. **Pooled vs. matched Provider side** — is a Provider pool in scope, or do we
   start with 1:1 matched hedges and accept thin coverage?
2. **Negative-funding regime** — keep funding floored at zero (desk-friendly,
   but Providers vanish when the basis inverts) or allow opt-in negative funding
   to retain Provider liquidity?
3. **Operator-down settlement** — is a coarse block-height emergency exit
   acceptable for a hedge, or do we need a pre-signed unilateral settlement path?

The cleanest first build is **(1) matched, (2) floored, (3) cooperative-only**,
with the pooled Provider side as a fast follow once the liquidity model is
validated.
