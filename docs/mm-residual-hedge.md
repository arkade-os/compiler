# Market-Maker Inventory Hedging on a BTC-Settled Vault

**Status:** design note. Not a spec.

This note describes how a market-making / RFQ desk can hedge its net inventory
delta *natively and BTC-settled*, instead of mirroring fills on a centralized
exchange. The instrument is a generalization of `StabilityVault`: a
BTC-collateralized, oracle-marked vault with perpetual dynamic funding. The desk
holds one leg of the vault to convert residual BTC inventory into a
fiat-denominated claim — delta-flat, self-custodied, no CEX.

Scope is **hedging only**. Turning this into a public, tradeable swap market is a
separate layer (§8) and explicitly out of scope here.

---

## 1. The problem

A desk that makes a two-sided BTC/fiat market accumulates inventory delta. When a
client sells the desk BTC (desk pays fiat), the desk is **long BTC** and wants to
be flat in fiat terms. The reflexive hedge is to short a BTC perpetual on a CEX,
which is:

- **Capital intensive** — margin cannot be netted across venues, so the desk must
  pre-fund collateral at every venue it hedges on; the short also ties up margin
  and can be liquidated on a sharp rally.
- **Freeze-prone** — funds on a CEX are an unsecured custodial claim. Exchanges
  have frozen withdrawals in insolvency, and even solvent venues halt withdrawals
  during congestion or outages. Capital can be stranded or lost for years.

The goal is a hedge that keeps BTC in self-custody and never routes capital to an
exchange.

## 2. The instrument: the desk holds the claim leg

A `StabilityVault`-style vault splits a BTC UTXO into a senior fiat claim and a
leveraged long:

| Vault role | Holds | Delta |
|---|---|---|
| **Claim leg** | a fiat-denominated claim (`targetFiat`) backed by the pooled BTC | **flat in fiat** |
| **Long leg** | the residual BTC upside; posts the over-collateral | long BTC |
| funding | `fundingRate > 0` ⇒ **long leg pays claim leg** | — |

A desk that is **net-long BTC takes the claim leg**: it deposits its residual
inventory and converts it to a fiat claim of equal value, delta-flat, while the
BTC stays in self-custody as collateral. A desk that is **net-short takes the long
leg.** The vault is symmetric enough to absorb residual delta either direction.

Structurally this is the cash-and-carry hedge (long spot + offsetting synthetic),
executed peer-to-peer and BTC-settled, with two properties that beat a CEX perp:

1. **No perp-spot basis.** Settlement is at the oracle/index price directly
   (`seekerExit`: `claimRaw = newTargetFiat * 1e8 / P`), not against a separately
   floating perp mark.
2. **No exchange custody.** The hedge is a self-custodied UTXO; there is no
   withdrawal to freeze.

### Downside protection is bounded by the collateral ratio

At a 1.5:1 ratio the claim leg deposits `S`, the long leg adds `1.5·S`, total
collateral `2.5·S`. The claim in sats at price `P` is `targetFiat·1e8/P`, which
stays `<= 2.5·S` while `P >= 0.4·P0`. **The desk is made whole down to a ~60%
drawdown**; beyond that the buffer is exhausted and the desk carries the tail.
This bound, against the freshness of the funding/margin top-up cycle
(`addCapital` / `removeCapital`), is the number to size first.

## 3. Multi-currency reduces to one BTC-delta book

A desk that quotes several BTC/fiat pairs (USD, BRL, CHF, EUR, …) instantiates the
**same vault construction once per oracle ticker**. The currencies differ only in
which `BTC/<fiat>` feed the vault reads.

The key simplification: every fiat claim leg is, in BTC terms, **short BTC** — they
differ in *currency* but point the *same direction in BTC delta*. So the whole
desk collapses to:

> **N currencies, one number to balance: aggregate net BTC delta**, over one shared
> BTC collateral pool.

The currency dimension is handled by reading different oracles; the only thing
that must be *balanced* is BTC-longness vs BTC-shortness across the whole book.
Cross-currency exposure triangulates through BTC (`<fiatA>/<fiatB>` =
`(BTC/<fiatB>) / (BTC/<fiatA>)`), so no separate FX leg is needed.

## 4. Perpetual dynamic funding

Funding is **perpetual** (no maturity — dated hedges fragment liquidity across
tenors and add rate risk) and **dynamic**, driven by long/short imbalance:

```text
fundingRate = clamp( premiumIndex + carryComponent , -cap, +cap )
premiumIndex ∝ open-interest skew between claim and long legs
long leg crowded  -> funding up   -> longs pay the claim side   (cools long demand)
claim crowded     -> funding down -> claim side pays longs       (recruits longs)
```

Dynamic funding is what clears a one-sided book without a permanent dedicated
counterparty: when the desk's residual is heavily one direction, funding moves to
recruit the other side. (This is the perpetual-funding mechanism that
everlasting-style instruments use to replace expiry.) `StabilityVault`'s current
funding is a fixed negotiated rate; making it imbalance-driven is the main
behavioral change for a hedging book.

The funding **floor** is the key economic knob: floor at zero is desk-friendly but
drains long-side liquidity when the basis inverts; allowing negative funding keeps
both sides present. Choose per deployment.

## 5. The counterparty: a willing BTC holder

The one persistent constraint is that **someone must take the BTC-long leg.** For a
self-hosted hedge the natural provider is the firm's own **BTC treasury**: the
market-making book hedges *into* the treasury, the treasury holds the BTC-long leg
(exposure a BTC-long treasury wants anyway) and earns the funding. No external
provider, no CEX; funding is internal P&L allocation between books.

State this honestly: if the treasury is the only provider, the **firm remains net
long BTC** — the delta is *transferred* from the market-making book to the book
that wants it, not eliminated firm-wide. That is exactly correct for a desk whose
mandate is to stay flat while the firm's directional view lives in treasury. It is
**risk-transfer to a willing holder, not risk-elimination** — do not represent it
as a firm-level hedge.

When treasury appetite is exhausted, the fallbacks are: raise funding to recruit
external longs, or warehouse the residual unhedged (acceptable for a sophisticated
desk on a short horizon).

## 6. The efficient flow: internalize → hedge residual → resize

Do not open a vault per fill. Hedge only the residual swing:

```text
1. INTERNALIZE
   Net client buys against sells across the whole book.
   Skew quotes (inventory-aware reservation price) to attract
   inventory-reducing flow. Most flow never needs an external hedge.

2. SIZE THE RESIDUAL
   Track net BTC delta D (signed, aggregated across all currency pairs).
   Adjust the hedge only when |D| breaches a position limit.

3. HEDGE
   D > 0 (net long)  -> hold the claim leg of notional |D|
   D < 0 (net short) -> hold the long leg of notional |D|

4. RESIZE, don't churn
   As D drifts, reshape the existing position:
     split    -> peel off part of the claim when D shrinks
     merge    -> combine positions when D grows
     transfer -> reassign a leg
   The hedge tracks moving inventory without unwind/reopen.
```

Internalisation is what makes the native hedge viable: it shrinks the residual
that needs a counterparty by a large factor, which is exactly the part that is
hard to source (§5, §9).

## 7. What exists today vs. what's missing

**Reusable as-is from `stability_vault.ark`:**
- Claim leg + long leg in one UTXO; funding accrual; oracle-priced settlement with
  clamping (`seekerExit` / `providerExit`).
- `split` / `merge` / `transfer` for resizing.
- `addCapital` / `removeCapital` with a collateral-ratio guard.
- Fuji-style oracle (`sha256(ticker + price + time)`), `tx.offchainTime` freshness,
  two-tapleaf cooperative/exit, 330-sat dust floor.
- Per-currency instances are just the same contract with a different `ticker`.

**Net-new:**
- **Dynamic, imbalance-driven funding** (§4) — current funding is a static
  negotiated rate.
- Aggregate **BTC-delta accounting** across currency instances — lives in the
  desk's off-chain risk engine; no contract change.
- Treasury-as-provider tooling for the long leg (templates, internal funding
  accounting).

## 8. Scope boundary

This note covers the **hedging core** only. A useful decomposition:

> A public synthetic swap market = **(this hedging vault) + (a bootstrapping
> layer).**

The bootstrapping layer — a fungible, freely-tradeable claim token, a maker
quoting tight near mid, and the two-sided flywheel that pulls in third-party
liquidity — is what a *public market* needs. A private hedge needs none of it: it
needs a counterparty (§5) and a fair funding rate (§4). Making the claim a fungible
token and adding a maker is the upgrade path *if and when* a tradeable market
becomes a goal; it is out of scope for hedging.

## 9. Tradeoffs and risks

1. **Counterparty in risk-off.** A one-sided book needs the other leg. Treasury
   appetite is finite; when exhausted, funding spikes or the desk warehouses. A
   desk can warehouse temporarily; this is the binding constraint to model.
2. **Tail collateralization.** Protection holds only to the ratio bound (~60%
   drawdown at 1.5:1). Beyond it the claim leg carries the loss. For a hedging
   desk this is a consciously-accepted basis risk, not a consumer guarantee.
3. **Oracle per currency.** Each `BTC/<fiat>` feed adds oracle surface; thinner
   pairs are more manipulable, and high-rate currencies embed carry that funding
   must reflect.
4. **Oracle / operator liveness.** Settlement is enforceable only on the
   cooperative tapleaf; the unilateral exit path cannot price-introspect. Define
   the fallback for unwinding a hedge when the cooperative path is unavailable.
5. **Risk-type shift, not removal.** This trades CEX custody / freeze / basis risk
   for counterparty, oracle, funding-availability, and operator-liveness risk.
   Delta-flat means price-neutral, not risk-free.

## 10. Open decisions

1. **Funding floor** — allow negative funding (true two-sided clearing) or floor
   at zero (desk-friendly, but longs thin on inverted basis)?
2. **Counterparty model** — treasury-only to start, or a small provider set for
   redundancy?
3. **Operator-down unwind** — coarse block-height emergency exit, or a pre-signed
   unilateral settlement path?

The thinnest first build: a single-provider (treasury) hedge on one `BTC/<fiat>`
pair, perpetual dynamic funding, cooperative-only settlement, with the multi-
currency aggregation and additional providers as fast-follows once the
counterparty model is validated.

---

# Part II — Transaction flows (`InventoryHedge`)

The reference implementation of the §10 thinnest build is
[`examples/hedging/inventory_hedge.ark`](../examples/hedging/inventory_hedge.ark).
This part is the operational view: each spend path as an actual transaction —
who signs, what goes in the witness, and the exact input/output layout the
script enforces.

## The vault UTXO

A single `InventoryHedge` UTXO holds the pooled BTC and commits all state in its
scriptPubKey via Taproot. Two parties share it:

| Leg | Key | Holds | BTC delta |
|---|---|---|---|
| **claim** | `claimPk` | a fiat claim `targetFiat` | flat in fiat (short BTC) |
| **long**  | `longPk`  | residual BTC upside, posts the over-collateral | long BTC |

Committed state (all in the scriptPubKey):

- **Immutable** across the position's life: `claimPk` (until transferred),
  `longPk`, `oraclePk`, `ticker`, `collateralRatioPct`, `exit`.
- **Mutable** — re-committed in the next-state output on every transition:
  `targetFiat`, `totalCollateral`, `fundingRatePerSec`, `lastUpdate`.

Every non-terminal function is a **self-replacement**: it asserts
`tx.outputs[0].scriptPubKey == new InventoryHedge(...)` with the next state and
`tx.outputs[0].value >= <required sats>`. The vault thus walks forward as a chain
of UTXOs.

### Two tapleaves per function

`options { server = server; exit = exit; }` makes the compiler emit **two
variants** of every function:

- **Cooperative** (`serverVariant=true`): the caller's signature **plus** the
  Arkade Operator co-signature (`<SERVER_KEY>`, auto-injected — never a
  constructor param). Fast, off-chain-settled path.
- **Exit** (`serverVariant=false`): the caller's signature plus a CLTV timelock
  of `exit` blocks — the unilateral fallback when the operator is unavailable.

Both enforce identical settlement math. Settlement that price-introspects is only
meaningful on the cooperative leaf; the exit leaf is the liveness backstop
(this is the §9.4 operator-liveness caveat made concrete).

## Timebase and oracle

- `tx.offchainTime` — TEE-introspector wallclock (unix seconds). Used for funding
  accrual and oracle freshness. Not monotonic-guaranteed, so every use of
  `elapsed = tx.offchainTime - lastUpdate` (and `oracleAge`) is paired with a
  `>= 0` clock-regression guard.
- **Price oracle** (Fuji pattern): off-chain the oracle signs
  `msg = sha256(ticker || price || timestamp)` with `price`/`timestamp` as 8-byte
  LE. On-chain the contract rebuilds the digest and verifies
  `checkSigFromStack(oracleSig, oraclePk, msg)`. Freshness window: 600 seconds.
- **Funding rate** is *not* oracle-attested on-chain: the dynamic,
  imbalance-driven value of §4 is computed off-chain by the desk's risk engine
  and supplied to `updateFunding`; the script only enforces `>= 0` and the
  accrual roll-forward.

Funding accrual, interleaved `/1e6` twice to stay inside int64:

```text
elapsed       = tx.offchainTime - lastUpdate
rateElapsed   = fundingRatePerSec * elapsed / 1e6
delta         = targetFiat * rateElapsed / 1e6
newTargetFiat = targetFiat + delta          // = targetFiat × (1 + rate·elapsed/1e12)
```

## 1. `transfer` — reassign the claim leg

The desk hands its claim to a new key (the §6 "transfer" resize). Pure key swap;
no oracle, no funding roll.

```text
Signers : claimSig (+ SERVER_KEY | + CLTV exit)
Witness : claimSig, newClaimPk

in [0]  : InventoryHedge UTXO
out[0]  : InventoryHedge( claimPk:=newClaimPk, …all other state unchanged… )
          value >= totalCollateral
```

## 2. `updateFunding` — roll funding, set the new rate

The long leg rolls accrued funding into the claim and adopts the next
off-chain-computed rate (§4).

```text
Signers : longSig (+ SERVER_KEY | + CLTV exit)
Witness : longSig, newFundingRatePerSec

in [0]  : InventoryHedge UTXO
out[0]  : InventoryHedge(
            targetFiat       := newTargetFiat,        // old rate accrued in
            fundingRatePerSec:= newFundingRatePerSec, // must be >= 0
            lastUpdate       := tx.offchainTime,
            …collateral, keys, ticker unchanged… )
          value >= totalCollateral
```

Guards: `newFundingRatePerSec >= 0` (a negative rate would let the long leg drain
the desk), `newTargetFiat > 0` (claim not wiped), and the **anti-grief** rule —
if the *current* rate is non-zero the accrual must be non-zero, else advancing
`lastUpdate` would silently swallow funding owed to the desk. A zero-accrual roll
is legal only when the current rate is already 0 (resume-from-pause).

## 3. `addCapital` — treasury tops up collateral

More collateral is strictly better for the desk, so no ratio/oracle check
(the top-up side of the §2 margin cycle).

```text
Signers : longSig (+ SERVER_KEY | + CLTV exit)
Witness : longSig, amount

in [0]  : InventoryHedge UTXO
in [1+] : long-leg funding input(s)        (≥ amount sats, off-script)
out[0]  : InventoryHedge( totalCollateral := totalCollateral + amount, …rest unchanged… )
          value >= totalCollateral + amount
```

## 4. `removeCapital` — treasury reclaims excess, ratio-guarded

The long leg withdraws surplus collateral, but the remainder must still cover the
claim at `collateralRatioPct` *at the current mark* (the §2 collateral bound).
Accrual is computed **only for the guard** — `targetFiat` and `lastUpdate` are
deliberately **not** mutated, so a withdrawal never truncates funding (only
`updateFunding` moves the clock).

```text
Signers : longSig (+ SERVER_KEY | + CLTV exit)
Witness : longSig, amount, oraclePrice, oracleTime, oracleSig

in [0]  : InventoryHedge UTXO
out[0]  : InventoryHedge( totalCollateral := totalCollateral - amount, …rest unchanged… )
          value >= totalCollateral - amount
out[1]  : SingleSig(longPk)                value >= amount     // reclaimed sats
```

Guard (oracle-priced):

```text
accruedFiat        = targetFiat + delta
claimSats          = accruedFiat * 1e8 / oraclePrice
minCollateral      = claimSats * (100 + collateralRatioPct) / 100
require( totalCollateral - amount >= minCollateral )   // "would breach collateral ratio"
```

## 5. `redeem` — desk settles to BTC (terminal)

The desk redeems its fiat claim for BTC at the oracle mark. BTC-native settlement
at the index price (§2: no perp-spot basis). The vault terminates.

```text
Signers : claimSig (+ SERVER_KEY | + CLTV exit)
Witness : claimSig, oraclePrice, oracleTime, oracleSig

in [0]  : InventoryHedge UTXO
```

Payout is the claim clamped into `[0, totalCollateral]`:

```text
claimRaw = newTargetFiat * 1e8 / oraclePrice
```

| Branch | Condition | out[0] | out[1] |
|---|---|---|---|
| claim wiped | `claimRaw <= 0` | `SingleSig(longPk)` ≥ `totalCollateral` | — |
| fully covered | `claimRaw >= totalCollateral` | `SingleSig(claimPk)` ≥ `totalCollateral` | — |
| split | otherwise | `SingleSig(claimPk)` ≥ `claimRaw` | `SingleSig(longPk)` ≥ `totalCollateral − claimRaw` *(only if > 330 sats)* |

The 330-sat **Taproot dust floor**: the long-leg remainder output is asserted
only when it exceeds 330 sats; below that it routes to fees rather than a dust
output. "Fully collateralized" means this clamp always pays out of the pool — no
liquidation, no margin call on the claim side (the §2 / §9.2 tail bound).

## 6. `withdraw` — treasury-driven settlement (terminal)

Identical clamp math; the long leg initiates instead of the desk. Same output
table as §5 with `longSig` in place of `claimSig`. Lets the treasury close a
position the desk has gone quiet on, settling both legs fairly at the mark.

## Lifecycle at a glance

```text
            ┌────────────── updateFunding (roll funding, reprice) ───────────────┐
            │                                                                     │
            ▼                                                                     │
  open ─▶ InventoryHedge UTXO ──▶ addCapital / removeCapital (resize collateral) ─┘
            │  │
            │  └──▶ transfer (reassign claim leg)
            │
            ├──▶ redeem    ──▶ BTC to claim (+ remainder to long)   [terminal]
            └──▶ withdraw  ──▶ BTC to claim (+ remainder to long)   [terminal]
```

Off-chain, the desk nets client flow internally and only adjusts the hedge when
aggregate BTC delta breaches a limit (§6): `addCapital` / `removeCapital` /
`transfer` reshape the live position instead of unwind-and-reopen.

> **Deferred (fast-follow).** §6/§7 also list `split` (peel off part of the claim
> when delta shrinks) and `merge` (combine positions when delta grows). They are
> reusable from `stability_vault.ark` but **not** in this thinnest first build
> (§10) — `InventoryHedge` ships `transfer` for reassignment and leaves
> `split`/`merge` to a follow-up once the single-provider model is validated.

## Playground

The contract ships in the WASM playground under the **Hedging** project folder
(`playground/main.js`), sourced from `playground/contracts.js` (regenerate with
`./playground/generate_contracts.sh` after editing the `.ark`). Build and serve:

```text
./playground/build.sh          # wasm-pack build + contracts regen
./playground/serve.sh 8080     # static server
```

Then pick **Hedging → inventory_hedge.ark** to compile it live in the browser.
