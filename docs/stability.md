# Stability — How It Works

**Status:** v1 design complete

---

## What it is

A self-custodied USD position on Bitcoin. A **Seeker** deposits BTC and holds a fixed dollar value. A **Provider** matches that BTC with additional collateral and takes a leveraged long position. The Provider pays the Seeker a funding rate for the privilege of that leverage.

The Seeker's balance looks and feels like a dollar account. The BTC mechanics are invisible. The position is a Taproot UTXO — no bridge, no issuer, no exchange counterparty.

---

## The two contracts

| Contract | Purpose |
|---|---|
| `StabilityOffer` | Provider pre-commits collateral as a standing offer. Anyone can claim it non-interactively. |
| `StabilityVault` | The live position: Seeker's USD claim + Provider's collateral in one UTXO. |

Price arrives as a witness argument at settlement time, signed by an oracle key baked into the vault. The signed message is `sha256(ticker || price || timestamp)` — Fuji-style replay protection across feeds and time.

---

## Economics

At open with a 1.5:1 collateral ratio:

```
Seeker deposits:    S sats
Provider locks:     1.5 × S sats
Total collateral:   2.5 × S sats
Seeker's USD claim: S × entryPrice / 1e8  (cents, mutates via funding accrual)
```

### Funding accrual (USD-compound)

The Seeker's USD claim compounds in USD terms. At every settlement boundary:

```
elapsed       = tx.offchainTime − lastUpdate
newTargetUSD  = targetUSD × (1 + fundingRatePerSec × elapsed / 1e12)
```

- `fundingRatePerSec`: signed fixed-point fraction at scale 1e12.
- `lastUpdate`: unix-second timestamp of the last settlement.

`tx.offchainTime` is the TEE-introspector wallclock in unix seconds, distinct from `tx.time` (Bitcoin nLockTime, block height).

Conversion: `fundingRatePerSec = (annual_pct / 100) / 31536000 × 1e12`. Example: 0.5% APY → `158`; 5% APY → `1585`.

- `> 0`: Provider pays Seeker (expected default — cost of self-custodied leverage)
- `< 0`: Seeker pays Provider — only valid at offer-accept time, when the Seeker explicitly opts in. Updates via `settleAndUpdateFunding` enforce `>= 0`.

The on-chain compute is interleaved (`/1e6` twice) to keep the intermediate product inside int64.

### Settlement

At exit with oracle price `P`, the same `newTargetUSD` shape is used everywhere (settle, seekerExit, providerExit, removeCapital):

```
newTargetUSD  = targetUSD × (1 + fundingRatePerSec × elapsed / 1e12)
seekerRaw     = newTargetUSD × (1 − seekerExitFee/1e4) × 1e8 / P   [seekerExit]
seekerRaw     = newTargetUSD × 1e8 / P                              [providerExit]
seekerPayout  = clamp(seekerRaw, 0, totalCollateral)
providerPayout = totalCollateral − seekerPayout
```

The exit fee is applied in USD before conversion to sats, so it scales with position size (same shape as `fundingRatePerSec`). `seekerExitFee` is in basis points: `100` = 1%, `10000` = 100%.

The 60% single-period drop is the coverage ceiling. Beyond it the Seeker absorbs the residual — this must be disclosed in wallet UX.

### Provider leverage

At 1.5:1, a +20% BTC move yields ~+33% for the Provider (1.67× leverage). No forced liquidation, no margin calls. If BTC drops beyond the coverage ceiling the Provider can simply hold — when price recovers, the settlement branch restores automatically with no on-chain action.

### Fees

Both fees are basis-point fractions, fixed at offer creation and immutable across takes:

- `takeFee` — applied as `takeFee × userBTC / 1e4` sats, paid from the taker's deposit to the Provider when an offer is consumed.
- `seekerExitFee` — applied in USD as `(1 − seekerExitFee/1e4) × newTargetUSD` when `seekerExit` settles, with the difference flowing to the Provider. Propagates into every vault opened from the offer.

Both scale with position size, matching the % shape of `fundingRatePerSec`. Example: `seekerExitFee = 100` charges 1% of the USD claim on exit.

---

## StabilityOffer

Provider deploys an offer with their collateral locked. No signature is required to claim it — the offer is fully pre-committed.

**`take(userBTC, seekerPk, oraclePrice, oracleTime, oracleSig)`** — opens a StabilityVault at the oracle-signed price. Charges `takeFee` to the Provider. Reduces remaining offer capacity. If fully consumed, the offer UTXO is spent.

**`withdraw(providerSig)`** — Provider reclaims unused collateral at any time.

---

## StabilityVault

Constructor parameters: `seekerPk, providerPk, oraclePk, ticker, targetUSD, totalCollateral, fundingRatePerSec, lastUpdate, collateralRatioPct, seekerExitFee, exit`

`oraclePk`, `ticker`, `collateralRatioPct`, and `seekerExitFee` are invariant across all state transitions. `targetUSD`, `totalCollateral`, `fundingRatePerSec`, and `lastUpdate` evolve as the Provider settles funding or adjusts collateral.

### Functions

**`transfer(seekerSig, newSeekerPk)`** — full position to a new owner. No oracle call. Primary off-ramp: Seeker sends to a swap service in exchange for USDT/USDC.

**`split(seekerSig, amountUSD, newSeekerPk)`** — divides the USD claim proportionally into two independent vaults. Both halves must be above the 330-sat Taproot dust threshold.

**`settleAndUpdateFunding(providerSig, newFundingRatePerSec)`** — Provider rolls accrued funding into `targetUSD` and sets a new rate going forward. Enforces `newFundingRatePerSec >= 0`: a negative update would let the Provider unilaterally drain the Seeker. Worst case for the Seeker is rate = 0 (Provider suspends new interest); the Seeker can react with `seekerExit`.

**`addCapital(providerSig, amount)`** — Provider tops up collateral. No oracle required (more collateral is always strictly better for the Seeker).

**`removeCapital(providerSig, amount, oraclePrice, oracleTime, oracleSig)`** — Provider reclaims excess collateral. Oracle required: the contract recomputes `seekerBase` (including accrued funding) and rejects the withdrawal if the remaining collateral falls below `(100 + collateralRatioPct)%` of the Seeker's claim.

**`seekerExit(seekerSig, oraclePrice, oracleTime, oracleSig)`** — Seeker exits to BTC at the oracle-attested price. Pays `seekerExitFee` to the Provider out of own payout.

**`providerExit(providerSig, oraclePrice, oracleTime, oracleSig)`** — Provider exits at the oracle-attested price. Same settlement math, no exit fee. First-come, first-served.

### Settlement branches (after fees applied)

| Condition | Seeker gets | Provider gets |
|---|---|---|
| `seekerNet ≤ 0` | nothing | all collateral |
| `seekerNet ≥ totalCollateral` | all collateral | nothing |
| normal | `seekerNet` sats | remainder (if > 330 sats) |

---

## Oracle model

The oracle signs BTC/USD prices off-chain as `sha256(ticker || price || timestamp)` — `price` and `timestamp` are 8-byte little-endian unsigned ints. At settlement the caller provides `(oraclePrice, oracleTime, oracleSig)` as witness arguments. The contract:

1. Enforces freshness: `tx.offchainTime - oracleTime <= 600` seconds (10 minutes).
2. Reconstructs the message hash on-stack with `+` (OP_CAT) and one-shot `sha256` (OP_SHA256):
   ```ark
   let oracleMsg = sha256(ticker + oraclePrice + oracleTime);
   require(checkSigFromStack(oracleSig, oraclePk, oracleMsg), "invalid oracle signature");
   ```
   `+` dispatches on type: when at least one operand is bytes-like the compiler emits OP_CAT, auto-coercing int sides via OP_SCRIPTNUMTOLE64 to keep on-chain and off-chain hashing byte-identical.

Three layers of replay protection are baked into the signed message:

| Field | Replay it would prevent |
|---|---|
| `ticker` | A signature for one feed (e.g. ETH/USD) cannot be reused on another (BTC/USD). The vault binds to one ticker at creation. |
| `price` | The value being attested. |
| `timestamp` | Makes each oracle update unique. Combined with the 600-second freshness check, stale signatures are rejected. |

`oraclePk` and `ticker` are baked into the vault at creation time. There is no on-chain beacon UTXO to maintain, pass through, or go stale.

---

## Cooperative vs exit paths

Every function compiles to two tapleaves:

| Path | How it unlocks | Notes |
|---|---|---|
| Cooperative | Arkade Operator co-signs (instant) | Normal flow |
| Exit | CLTV after `exit` blocks, no operator needed | Fallback for operator offline |

Both paths enforce identical settlement math. The exit path is not a challenge window — it exists only so unilateral close is always possible.

Total tapleaves: **4** (StabilityOffer) + **14** (StabilityVault) = 18.

---

## Lifecycle

```
1. Provider deploys StabilityOffer (locks BTC collateral, binds to a ticker,
   sets takeFee and seekerExitFee).
2. Swap service calls take(userBTC, seekerPk, oraclePrice, oracleTime, oracleSig)
   → StabilityVault created at the oracle price, inheriting ticker and exit fee.
   → takeFee paid to provider out of taker's deposit.
3. Seeker circulates the vault:
     transfer → swap service (USDT/USDC out)
     split    → send partial balance to a friend
4. Provider services the position:
     settleAndUpdateFunding → roll accrued funding, change rate
     addCapital             → top up reserves
     removeCapital          → reclaim excess (oracle-checked min ratio)
5. Settlement (either party, any time):
     seekerExit or providerExit with a fresh oracle-signed (price, time)
     → two SingleSig outputs, vault consumed
     → seekerExit also pays seekerExitFee to provider
```

---

## Risk disclosures (wallet UX)

1. **Coverage ceiling:** Fully protected unless BTC drops more than 60% from deposit price. Beyond that, you receive all available collateral, which may be less than your original deposit.
2. **No issuer:** Backed by a Bitcoin smart contract, not company reserves.
3. **Oracle dependency:** USD value is determined by a public oracle. If the oracle is unavailable, settlement requires a fresh signature — cooperative path may be blocked until the oracle resumes.
4. **Either party settles at any time:** Provider can settle at the live oracle price at any time. So can you. No delay, no challenge period, first-come first-served.
5. **Provider can change the rate:** The Provider can call `settleAndUpdateFunding` to roll up accrued interest and set a new rate. The worst case is rate = 0 (no more interest accruing); negative updates are disallowed. If you don't like the new rate, exit.
6. **Exit fee:** `seekerExit` carries a fee set at offer creation. `transfer` does not — sending the position to a swap service is the cheaper off-ramp.
