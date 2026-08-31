# The Capped Synthetic — a margined, RFQ-settled alternative to `InventoryHedge`

> **Status: design sketch.** Contract: [`examples/hedging/capped_synth.ark`](../examples/hedging/capped_synth.ark).
> This is a *response* to the adverse-selection critique in
> [`mm-residual-hedge.md` §9.b](./mm-residual-hedge.md). Read that first — this
> doc assumes the problem statement, the two-leg vault structure, the Fuji
> oracle pattern, and the int64 settlement ceiling described there.

## 1. Why another instrument

`InventoryHedge` is a **fully-funded forward**: the long leg over-collateralizes
a 1:1 fiat claim, and settlement clamps the payout into `[0, totalCollateral]`.
Two things motivate an alternative:

1. **Capital efficiency.** Locking ≥ 1:1 BTC to hedge residual delta is
   expensive for a market maker. Posting *margin* (a fraction of notional) frees
   the rest for market-making — the single strongest reason to want a "perp."
2. **Adverse selection (§9.b).** Settling at a lagging oracle hands the
   initiator a free option on the oracle delay. A true perp makes this *worse*,
   because it moves that lag onto every **liquidation** — the place where a
   manipulator's payoff is largest, and the reason oracle-priced perps died on
   Ethereum while order-book venues (dYdX, Hyperliquid) survived.

The capped synthetic takes the capital efficiency of a perp **without** building
the liquidation engine a perp needs — because on Bitcoin/Arkade you can have
self-custody *or* fast liquidations, not both.

## 2. The design rung

Think of a spectrum of BTC-settled synthetics for the same delta:

| Instrument | Collateral | Liquidation engine | Tail beyond pot | Fits Arkade? |
|---|---|---|---|---|
| **Forward** (`InventoryHedge`) | ≥ notional (over-coll.) | none | long leg eats it (capped) | yes, but capital-heavy |
| **Capped synthetic** (`CappedSynth`) | margin < notional | **none** | **unhedged (the cap)** | **yes — this doc** |
| **True perp** | margin < notional | required keeper | margin-called away | poorly — needs fast liquidation |

The capped synthetic keeps the forward's clamp as its *primary* mechanism rather
than a fallback: **the pot bounds the loss, so there is nothing to liquidate.**
The cost is an explicit payout **cap** — the tail beyond the pot is unhedged.
That is acceptable for a *delta-flat hedger*, whose underlying inventory loss is
itself bounded; it is not a consumer guarantee.

## 3. Margin / PnL model

Claim leg = short BTC / long fiat. Both legs post into one pot
`totalCollateral = claimMargin + longMargin`. With a strike `entryPrice` fixed at
open (RFQ-signed — see §5):

```
newNotionalFiat = notionalFiat × (1 + fundingRatePerSec × elapsed / 1e12)
entrySats       = newNotionalFiat × 1e8 / entryPrice     // notional value at strike
settleSats      = newNotionalFiat × 1e8 / settlePrice    // notional value now
claimPnL        = settleSats − entrySats                 // short gains as price falls
gross           = claimMargin + claimPnL
claimPayout     = clamp(gross, 0, totalCollateral)
longPayout      = totalCollateral − claimPayout
```

The clamp gives the bound that makes the whole thing work:

```
claim net = claimPayout − claimMargin  ∈  [ −claimMargin , +longMargin ]
```

Each leg can lose **at most its own margin** and gain at most the other's.
Neither side can ever go underwater, so no margin call and no liquidation are
reachable — by construction, not by monitoring.

Funding is inherited verbatim from `InventoryHedge`: it accrues into
`notionalFiat`, guarded `>= 0` at every `updateFunding`. (A truer perp transfers
margin between legs each interval rather than resizing notional; deferred, since
the resize roll-forward is the already-audited path.)

## 4. Settlement: cooperative first, oracle as a fee'd fallback

This is the §9.b fix in contract form.

**`settle` (primary, oracle-free).** Both legs co-sign the spending transaction,
whose outputs are derived from `settlePrice`. Neither party will sign a
transaction whose payouts use a price it rejects, so the price is **agreed by
construction** — there is no oracle to lag and therefore **zero adverse
selection**, and no fee. This is the bilateral analogue of an RFQ fill: the
counterparties quote and agree a price, the vault is just the settlement
container.

**`settleOracleClaim` (fallback, fee'd).** For an unresponsive counterparty, the
claim leg can still force settlement at a fresh oracle mark — but it **pays
`exitFeeBps` of its gross payout to the long leg**. That fee is the
adverse-selection premium named in §9.b (StabilityVault's `seekerExitFee`,
≈ 0.2–0.3 %), charged to the initiator who holds the timing option, not waved
away. The oracle here is a *guardrail*, not the mark.

> A symmetric long-initiated fallback mirrors this with the fee flowing the other
> way; omitted in the sketch. A production build would additionally **collar**
> `settlePrice` and/or gate the fallback behind a cooperative-settle **timeout**
> in blocks (`tx.time`), so the fee'd oracle path is only reachable after a
> genuine cooperative failure — see §6.

## 5. Open (RFQ) and the price-discovery boundary

The contract does **not** discover a price — it settles one. Pricing lives where
adverse selection lives: at open and at cooperative settle, both via signed
counterparty quotes (RFQ), not an oracle. At open, a dealer signs
`sha256(quoteId ‖ entryPrice ‖ fundingRate ‖ size ‖ expiry)`; the opening
transaction verifies it with `checkSigFromStack(quoteSig, dealerPk, …)` and
`tx.offchainTime <= expiry` — the *same opcodes* as the oracle path, but the
signer is the counterparty and the expiry is seconds, not 600. Multiple dealers
streaming quotes is an order book in the bilateral limit (this is how FX dealer
markets actually hedge — nobody hedges EUR/USD against an "oracle"). The opening
factory that mints a `CappedSynth` from such a quote is the natural next artifact
(≈ `stability_offer.ark` with the oracle key swapped for a dealer key).

## 6. Leaves

| Leaf | Role | Oracle | Fee |
|---|---|:--:|:--:|
| `transfer` | reassign the desk's leg (key swap) | — | — |
| `addMargin` | top up the pot (only raises the cap → always safe) | — | — |
| `updateFunding` | roll funding into notional, set rate ≥ 0 | — | — |
| **`settle`** | **cooperative close, both legs co-sign the price** | — | — |
| `settleOracleClaim` | fallback when the counterparty is dark | ✅ | `exitFeeBps` |

As in `InventoryHedge`, the oracle op (`checkSigFromStack`) compiles only into
the **server (cooperative) variant** of the oracle leaf; the unilateral exit
variant cannot price-introspect (`mm-residual-hedge.md` §9.4). The cooperative
`settle` carries no oracle in either variant.

## 7. Deliberately deferred

This is a sketch; the following are intentionally out of scope:

- **Margin-transfer funding** (vs. notional resize) — the truer perp model.
- **Long-initiated oracle fallback** — only the claim side is written.
- **`removeMargin`** — needs an oracle mark-to-market check (like
  `InventoryHedge.removeCapital`); `addMargin` needs none because more margin
  only raises the cap.
- **Price collar + cooperative-settle timeout** gating the oracle fallback.
- **Opening factory / RFQ offer contract** (§5) and a dedicated test +
  playground registration. The contract is currently covered only by the
  example-enumerating compilation/ASM suites.
- **int64 ceiling**: identical fail-closed behavior to `InventoryHedge`
  (`newNotionalFiat × 1e8` aborts the script on overflow rather than mispaying).

## 8. The honest one-liner

On Bitcoin you can have self-custody or fast liquidations, not both — so build
the instrument that needs no liquidations. The capped synthetic is that
instrument: a hedger trades an unhedged tail (the cap) for the removal of the
entire liquidation/keeper surface, and prices it by counterparty quote rather
than by oracle.
