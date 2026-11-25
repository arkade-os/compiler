# StabilityPool — Product Requirements Document (v0, exploration)

**Status:** Exploration / planning. Not yet approved for build.
**Variant chosen:** B — perpetual-bond (Seeker transfer-only, Provider exit
gated by leverage).
**Accrual model:** Index-based (monotone yield index published by
`FundingBeacon`).
**Funding rate source:** Standalone `FundingBeacon` (separate from
`PriceBeacon`).
**Replaces (when shipped):** `StabilityVault` + `StabilityOffer`
isolated/segregated model from `docs/stability-vault-prd.md`.

This document captures the design only. The accompanying contracts
(`examples/stability/funding_beacon.ark`, `examples/stability/stability_pool.ark`,
`examples/stability/provider_share.ark`) are Phase-1 / Phase-2 skeletons
and intentionally leave the deeper settlement math to later phases.

---

## 1. Motivation

The isolated model gives every position its own `fundingSatPerBlock` and its
own post-open leverage. Quant feedback (Christian, Slack 2026-05-XX):

- Positions are non-fungible, so Providers and Seekers churn continuously to
  capture best market conditions.
- Seekers redeeming when BTC drops acts as a margin call enforced *by* Seekers,
  forcing Providers to settle at the worst time.
- Settling in/out of BTC on every Seeker churn is operationally and
  economically painful.

The pooled model collapses isolated positions into a single covenant. Funding
rate is common to all users and set by an oracle. Leverage is a system-wide
ratio that gates entries and exits. Seekers in Variant B never redeem to BTC
on-chain — they transfer the claim, and exits to fiat happen through swap
services.

---

## 2. Actors

| Actor | Pooled-model role |
|---|---|
| **Seeker** | Holds a transferable USD-cent claim against the pool. Cannot redeem to BTC on-chain. |
| **Provider** | Holds a pro-rata claim on `providerCapital`. Can withdraw only when `leverage` is below a configured floor. |
| **Rate Oracle** | Publishes the cumulative `yieldIndex` on `FundingBeacon`. Trust-critical in Variant B. |
| **Price Oracle** | Unchanged. Publishes BTC/USD on `PriceBeacon`. |
| **Swap Service** | Bridge between Seeker claims and USDT/USDC. Primary Seeker exit path. |
| **Arkade Operator** | Co-signs cooperative spends. Same role as today. |

---

## 3. Economic model (pooled)

```
Pool state at any tx:
  totalCapital        = pool UTXO value in sats
  aggregateSeekerUSD  = Σ targetUSD of all live SeekerShares (cents)
  poolYieldIndex      = pool's last-snapshotted yield index
  currentPrice        = PriceBeacon.ticker quantity (cents/BTC)
  currentIndex        = FundingBeacon.yieldIndex quantity

Derived:
  seekerCapitalNominal = aggregateSeekerUSD × 1e8 / currentPrice
  fundingAccrued       = aggregateSeekerUSD × (currentIndex - poolYieldIndex) / INDEX_SCALE
  seekerCapital        = seekerCapitalNominal + fundingAccrued
  providerCapital      = totalCapital − seekerCapital
  leverage             = totalCapital / providerCapital
```

Notes:
- `INDEX_SCALE` is a fixed denominator (proposed: `1e8`) so the index
  can move with sat-precision per cent of USD.
- `seekerCapital` is a *claim*, not a held balance. The pool BTC stays fungible.
- Leverage uses the post-accrual derived values; deposits/withdrawals must
  refresh the index before gating.

### Gating constants (Variant B)

| Constant | Proposed value | Rationale |
|---|---|---|
| `MAX_LEVERAGE_X100` | 167 | Seekers cannot push leverage past 1.67×. |
| `PROVIDER_WITHDRAW_LEVERAGE_X100` | 150 | Providers can only exit if leverage ≤ 1.50×. Tighter than Seeker cap to keep system from skating the edge. |
| `INDEX_SCALE` | 100_000_000 | Sat-per-cent precision on funding accrual. |
| `STALE_BLOCKS` | 144 | Same as PriceBeacon. |

These are deploy-time constants for v0. Later they can be parameterised.

### Action table

| Action | Caller | Gate |
|---|---|---|
| Provider deposit | Provider | always allowed |
| Provider withdraw | Provider | `leverage_after ≤ PROVIDER_WITHDRAW_LEVERAGE_X100 / 100` |
| Seeker entry | Seeker (via swap service) | `leverage_after ≤ MAX_LEVERAGE_X100 / 100` |
| Seeker transfer | Seeker | always allowed |
| Seeker split | Seeker | always allowed |
| Seeker redeem to BTC | — | **disallowed in Variant B** |
| Force-unwind | anyone | `totalCapital < seekerCapital` (insolvency) |

---

## 4. Contract surface

```
PriceBeacon         — unchanged
FundingBeacon       — new, Phase 1
StabilityPool       — new, Phase 2 (singleton covenant)
ProviderShare       — new, Phase 2 (per-Provider UTXO)
SeekerShare         — new, Phase 3 (per-Seeker UTXO, transferable USD claim)
```

### 4.1 FundingBeacon (Phase 1)

Dual-asset oracle:
- `yieldTicker` quantity = cumulative `yieldIndex`, monotone non-decreasing.
- `yieldClock` quantity = block height of last update.

Functions: `update(oracleSig, newIndex, newHeight)`, `passthrough()`,
`migrate(oracleSig, newOraclePk)` — same shape as `PriceBeacon`.

The on-chain contract enforces only:
- `newIndex ≥ currentIndex` (monotone)
- `newHeight ≥ currentHeight` (monotone)
- `newHeight ≥ currentHeight` for the same Bitcoin block is permitted to
  support sub-block updates (same as PriceBeacon).

The off-chain oracle is trusted to compute
`newIndex - oldIndex = fundingSatPerBlock × INDEX_SCALE × (newHeight - oldHeight)`.

### 4.2 StabilityPool (Phase 2)

Constructor (immutables + state):

```
StabilityPool(
  bytes32 priceTicker,        // PriceBeacon ticker asset id
  bytes32 priceClock,         // PriceBeacon clock asset id
  bytes32 yieldTicker,        // FundingBeacon yield-index asset id
  bytes32 yieldClock,         // FundingBeacon clock asset id
  int     aggregateSeekerUSD, // STATE: Σ live SeekerShare.targetUSD (cents)
  int     poolYieldIndex,     // STATE: last-snapshotted yield index
  int     exit
)
```

`aggregateSeekerUSD` and `poolYieldIndex` are part of the script, so every
spend creates a new pool UTXO with updated state.

Tx layout convention (for all pool spends):

```
input[0]:  StabilityPool
input[1]:  PriceBeacon (passthrough)
input[2]:  FundingBeacon (passthrough)
input[3+]: Caller's UTXO(s) (provider deposit sats, share UTXO for withdraw, …)

output[0]: New StabilityPool
output[1]: PriceBeacon passthrough
output[2]: FundingBeacon passthrough
output[3+]: Caller's outputs (new ProviderShare, payout SingleSig, …)
```

Functions (Phase 2 — provider-only flows):

| Function | Inputs | Effects |
|---|---|---|
| `providerDeposit` | `int depositSats`, `pubkey providerPk` | pool.value += deposit; mint ProviderShare(providerPk, deposit, currentIndex) |
| `providerWithdraw` | `signature providerSig`, `int withdrawSats`, `int providerCapitalBefore` | check leverage gate; burn ProviderShare; pay sats to provider |

Functions (Phase 3+):

| Function | Notes |
|---|---|
| `seekerEntry` | Mints SeekerShare. Gated by `MAX_LEVERAGE_X100`. |
| `seekerTransfer` | Recursive — produces new SeekerShare with same `targetUSD` and `entryIndex`. No pool touch needed (pool state unchanged). |
| `seekerSplit` | Recursive — produces two SeekerShares with proportional `targetUSD` shares. |
| `accrue` | Refreshes `poolYieldIndex` against FundingBeacon. Anyone can call. |
| `forceUnwind` | Insolvency path. Permissionless. Pays out seekers pro-rata. |

### 4.3 ProviderShare (Phase 2)

```
ProviderShare(
  pubkey  providerPk,
  int     depositedSats,   // sats committed at entry
  int     entryIndex,      // FundingBeacon index at entry
  int     exit
)
```

Effective value at withdraw time = `depositedSats - (aggregateSeekerUSD-share × Δindex / scale)`.
Detailed math is deferred to Phase 2 implementation. The skeleton in this
PR documents the surface; the production math comes after the doc is
reviewed.

### 4.4 SeekerShare (Phase 3)

```
SeekerShare(
  pubkey  seekerPk,
  int     targetUSD,    // USD cents
  int     entryIndex,   // FundingBeacon index at entry
  int     exit
)
```

In Variant B, SeekerShare has `transfer` and `split` only. No
`seekerRedeem` function. Exit to fiat is via swap services.

---

## 5. Open design questions

1. **Provider equity dilution math.** With many providers entering at different
   `yieldIndex` values, fair payout on withdraw needs to weight each share by
   its time-in-pool. Two options to evaluate in Phase 2:
   (a) per-share `entryIndex` + simple linear depreciation, or
   (b) ERC-4626-style "share token" with a price-per-share. (a) is simpler in
   UTXO; (b) is fairer.

2. **Force-unwind partitioning.** A single tx cannot pay out all Seekers.
   Likely shape: a permissionless `redeemPro(seekerShareIn)` function active
   only when `totalCapital < seekerCapital`, paying the share's pro-rata claim
   on `totalCapital`. The pool itself does not unwind atomically; Seekers
   unwind their own shares against the halted pool.

3. **Anti-gaming.** 0.1% entry/exit fee + 1-block price-snapshot delay.
   Fee: skim into pool (helps Providers). Delay: require the price beacon
   read to be at least 1 block stale on Seeker entry / Provider withdraw.
   Cost: worsens UX. Defer until Phase 6.

4. **Sharding.** A singleton pool serializes all activity. If throughput
   becomes a problem, partition the pool by series (one pool per
   `(priceTicker, yieldTicker, series_id)`). v0 ships singleton.

5. **Rate-cap.** Christian flagged death-spiral risk if rate is unbounded in
   distress. Decide whether to cap the on-chain index growth rate. Strongly
   recommend yes for v0.

6. **Index unit.** `INDEX_SCALE = 1e8` gives sat-precision per cent of USD.
   Worth running the numbers at $1B aggregateSeekerUSD to confirm no
   overflow risk (Arkade ints are 64-bit signed → `1e10 × 1e8 = 1e18`, fits).

---

## 6. Build phases

| Phase | Output | Status |
|---|---|---|
| 0 | This PRD | In this PR |
| 1 | `FundingBeacon` contract + tests | In this PR (Phase 1 done) |
| 2 | `StabilityPool` skeleton (provider deposit/withdraw) + `ProviderShare` | In this PR (skeleton only) |
| 3 | `SeekerShare` (transfer + split) + `seekerEntry` on pool | Future PR |
| 4 | `accrue` function + index integration completeness | Future PR |
| 5 | `forceUnwind` insolvency path | Future PR |
| 6 | Anti-gaming (fees + price-snapshot delay) + rate cap | Future PR |

Each phase ships with integration tests in `tests/` and example fixtures in
`examples/stability/`.

---

## 7. What this PR explicitly does NOT do

- Does not delete the isolated `StabilityVault` / `StabilityOffer` / their
  tests. They remain shipping until the pooled model is feature-complete and
  audited.
- Does not implement Seeker-side flows on the pool.
- Does not implement the full provider-equity-dilution math; the
  ProviderShare skeleton currently encodes `(providerPk, depositedSats,
  entryIndex)` but the withdraw math is a TODO.
- Does not implement `accrue`, `forceUnwind`, or anti-gaming.
- Does not parameterise the gating constants. They are hard-coded for v0.
