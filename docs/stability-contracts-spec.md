# Stability Contracts — Technical Specification

**Contracts:** `price_beacon.ark`, `stability_offer.ark`, `stability_vault.ark`  
**Location:** `examples/stability/`

---

## 1. Overview

Three contracts work together to deliver a self-custodied USD position on Bitcoin:

| Contract | Role | Instances |
|---|---|---|
| `PriceBeacon` | Publishes BTC/USD price and block height as on-chain asset quantities | One per currency pair (shared globally) |
| `StabilityOffer` | Provider pre-commits collateral into a standing offer; anyone can claim it non-interactively | One per provider offer |
| `StabilityVault` | The live position: holds a Seeker's USD claim + Provider's collateral as a single BTC UTXO | One per position |

**Arkade asset-packet model.** Each UTXO on Arkade carries an asset packet: a set of `(bytes32 assetId, uint64 quantity)` pairs. The contracts use `OP_INSPECTINASSETLOOKUP` / `OP_INSPECTOUTASSETLOOKUP` to read and enforce values in these packets. This gives each UTXO a key-value store: `assetId = key`, `quantity = value`.

**`tx.time`.** Throughout all contracts, `tx.time` refers to Bitcoin's nLockTime expressed as a block height, not a unix timestamp. All timing arithmetic (`beaconAge`, `blocksElapsed`) is in blocks.

---

## 2. PriceBeacon

### 2.1 Constructor

```ark
contract PriceBeacon(
  bytes32 ticker,   // key whose quantity = BTC/USD price in cents
  bytes32 clock,    // key whose quantity = block height of last update
  pubkey  oraclePk, // sole authorized updater
  int     exit      // exit timelock in blocks
)
```

**State encoding.** PriceBeacon does not store price or timestamp in its script parameters. Instead it reads and writes them as Arkade asset quantities:

| Asset ID | Meaning | Unit |
|---|---|---|
| `ticker` | Current BTC/USD price | cents (e.g. `10_000_000_00` = $100,000.00) |
| `clock` | Block height of last update | Bitcoin block number |

Both values are updated atomically in every `update()` call.

### 2.2 Functions

#### `update(signature oracleSig, int newPrice, int newBlockHeight)`

The oracle publishes a new price and block height.

**Checks:**
1. `checkSig(oracleSig, oraclePk)` — only the oracle key can publish
2. `newPrice > 0` — price must be positive
3. `newBlockHeight >= tx.inputs[0].assets.lookup(clock)` — block height is non-decreasing (back-dating rejected; same-block updates permitted for sub-block cadence)

**Output requirements:**
- `output[0].scriptPubKey == new PriceBeacon(ticker, clock, oraclePk, exit)` — beacon script preserved
- `output[0].assets.lookup(ticker) == newPrice` — exact new price written
- `output[0].assets.lookup(clock) == newBlockHeight` — exact new height written

**Sub-block cadence.** Because Arkade is an off-chain network, the oracle is not gated on Bitcoin's 10-minute block time. Multiple updates within the same Bitcoin block are valid — they all carry the same `clock` value (the current block height). The `>=` monotonicity check permits this while still rejecting any rollback to a prior block.

#### `passthrough()`

Used by any transaction that reads the beacon without updating it (e.g. transfer, split).

**Output requirements:**
- `output[0].scriptPubKey == new PriceBeacon(ticker, clock, oraclePk, exit)` — script preserved
- `output[0].assets.lookup(ticker) >= input[0].assets.lookup(ticker)` — price non-decreasing
- `output[0].assets.lookup(clock) >= input[0].assets.lookup(clock)` — height non-decreasing

#### `migrate(signature oracleSig, pubkey newOraclePk)`

Transfers oracle signing authority to a new key without changing the asset IDs.

**Checks:** `checkSig(oracleSig, oraclePk)`

**Output requirements:**
- `output[0].scriptPubKey == new PriceBeacon(ticker, clock, newOraclePk, exit)` — new key baked in
- `output[0].assets.lookup(ticker) == currentPrice` — price preserved exactly
- `output[0].assets.lookup(clock) == currentHeight` — height preserved exactly

**Why this matters.** Consumers (StabilityVault, StabilityOffer) authenticate the beacon by `ticker` and `clock` asset IDs, not by `oraclePk`. After `migrate()`, the asset IDs are unchanged, so all existing positions remain valid without any update.

### 2.3 Oracle authentication model

Consumers **do not** verify `oraclePk`. They verify:
- `tx.inputs[1].assets.lookup(ticker) > 0` — the input carries the ticker asset
- `tx.inputs[1].assets.lookup(clock)` — the input carries the clock asset

The `bytes32` asset IDs are derived from the oracle's genesis issuance transaction. They are globally unique and cannot be forged — any UTXO claiming to carry `ticker` or `clock` assets with values the oracle did not issue cannot exist. This is the "contract ID via genesis asset" pattern.

### 2.4 Freshness check

All consumers enforce:

```ark
int beaconHeight = tx.inputs[1].assets.lookup(clock);
int beaconAge    = tx.time - beaconHeight;
require(beaconAge <= 144, "stale oracle");
```

144 blocks ≈ 24 hours. If the oracle is offline for more than 144 blocks, settlement and transfers are blocked until the oracle resumes. Both `tx.time` and `beaconHeight` are Bitcoin block heights, so the arithmetic is unit-consistent.

---

## 3. StabilityOffer

### 3.1 Constructor

```ark
contract StabilityOffer(
  pubkey  providerPk,         // offer creator
  bytes32 ticker,             // PriceBeacon ticker asset ID
  bytes32 clock,              // PriceBeacon clock asset ID
  int     fundingSatPerBlock, // signed; >0 = provider pays seeker per block
  int     maxExposureBTC,     // remaining capacity in sats
  int     collateralRatioPct, // provider collateral as % of seekerBTC (min 100)
  int     exit                // exit timelock in blocks
)
```

### 3.2 Collateral structure

```
Provider pre-locks:    maxExposureBTC × collateralRatioPct / 100  sats
Per-position vault:    userBTC × (100 + collateralRatioPct) / 100  sats

Examples:
  collateralRatioPct = 150  → vault = 2.5× userBTC (60% drop coverage, 1.67× leverage)
  collateralRatioPct = 200  → vault = 3.0× userBTC (67% drop coverage, 1.5× leverage)
  collateralRatioPct = 100  → vault = 2.0× userBTC (50% drop coverage, 2.0× leverage, minimum)
```

Higher ratio protects the Seeker more; lower ratio gives the Provider more leverage. The market sets the equilibrium.

### 3.3 Functions

#### `take(int userBTC, pubkey seekerPk)`

Non-interactive: no provider signature required. Anyone (swap service or direct Seeker) can call this.

**Transaction layout:**

```
input[0]:  StabilityOffer UTXO
input[1]:  PriceBeacon UTXO (pass-through)
input[2]:  taker's BTC (userBTC sats)

If remainingCapacity > 0 (partial fill):
  output[0]: StabilityVault (new position)
  output[1]: StabilityOffer (reduced capacity)
  output[2]: PriceBeacon pass-through

If remainingCapacity == 0 (full fill):
  output[0]: StabilityVault (new position)
  output[1]: PriceBeacon pass-through
```

**Checks:**
1. `userBTC > 0`
2. `userBTC <= maxExposureBTC` — cannot exceed remaining capacity
3. `collateralRatioPct >= 100` — minimum ratio enforced
4. Beacon price `> 0` and freshness `<= 144` blocks

**Computed values:**
```
entryPrice       = tx.inputs[1].assets.lookup(ticker)       // cents per BTC
beaconHeight     = tx.inputs[1].assets.lookup(clock)        // block height
targetUSD        = userBTC × entryPrice / 100_000_000       // seeker's USD claim in cents
totalCollateral  = userBTC × (100 + collateralRatioPct) / 100  // sats
remainingCapacity = maxExposureBTC - userBTC
```

**Output[0] — StabilityVault:**
```ark
new StabilityVault(
  seekerPk, providerPk, ticker, clock,
  targetUSD, totalCollateral, fundingSatPerBlock,
  tx.time,   // openHeight = current block height
  exit
)
```
Value must be `>= totalCollateral`.

**Output[1] — remaining StabilityOffer (partial fill only):**
```ark
new StabilityOffer(
  providerPk, ticker, clock,
  fundingSatPerBlock, remainingCapacity, collateralRatioPct, exit
)
```
Value must be `>= remainingCapacity × collateralRatioPct / 100`.

**Beacon pass-through (at `output[2]` if partial fill, `output[1]` if full):**
- `assets.lookup(ticker) >= entryPrice`
- `assets.lookup(clock) >= beaconHeight`

#### `withdraw(signature providerSig)`

Provider reclaims unused collateral. Only check: `checkSig(providerSig, providerPk)`. No constraints on outputs.

---

## 4. StabilityVault

### 4.1 Constructor

```ark
contract StabilityVault(
  pubkey  seekerPk,           // current USD-claim holder
  pubkey  providerPk,         // collateral provider, long side
  bytes32 ticker,             // PriceBeacon ticker asset ID
  bytes32 clock,              // PriceBeacon clock asset ID
  int     targetUSD,          // seeker's USD claim in cents (invariant across transfers)
  int     totalCollateral,    // total sats locked (invariant across transfers)
  int     fundingSatPerBlock, // signed funding rate
  int     openHeight,         // block height at position open (basis for funding accrual)
  int     exit                // exit timelock in blocks
)
```

`targetUSD` and `totalCollateral` are **invariant** across transfers — they are set once at vault creation and preserved through every `transfer` call. `openHeight` is also preserved through transfers (funding accrues continuously). It is reset on `split`.

### 4.2 Settlement math

Used by `seekerRedeem` and `providerExit`:

```
blocksElapsed  = tx.time - openHeight
seekerBase     = targetUSD × 100_000_000 / currentPrice   (integer division)
fundingAccrued = fundingSatPerBlock × blocksElapsed
seekerRaw      = seekerBase + fundingAccrued

seekerPayout   = clamp(seekerRaw, 0, totalCollateral)
providerPayout = totalCollateral - seekerPayout
```

Three settlement branches:

| Condition | Seeker gets | Provider gets | Dust check |
|---|---|---|---|
| `seekerRaw <= 0` | nothing | `totalCollateral` (all to provider) | n/a |
| `seekerRaw >= totalCollateral` | `totalCollateral` (all to seeker) | nothing | n/a |
| normal | `seekerRaw` | `totalCollateral - seekerRaw` | if `providerPayout <= 330` sats, no provider output |

**Taproot dust threshold: 330 sats.** If `providerPayout <= 330`, no provider output is created — all sats go to the seeker output.

### 4.3 Beacon convention in vault transactions

All four functions place the PriceBeacon at `input[1]`. The beacon passthrough output index shifts based on how many payout outputs are present:

| Function | Payout outputs | Beacon output index |
|---|---|---|
| `transfer` | 1 (new vault) | `output[1]` |
| `split` | 2 (both vaults) | `output[2]` |
| `seekerRedeem` / `providerExit` — normal, 2 payouts | 2 (seeker + provider) | `output[2]` |
| `seekerRedeem` / `providerExit` — dust/capped, 1 payout | 1 | `output[1]` |

### 4.4 Functions

#### `transfer(signature seekerSig, pubkey newSeekerPk)`

Assigns the entire position to a new pubkey.

**Transaction layout:**
```
input[0]:  StabilityVault UTXO
input[1]:  PriceBeacon UTXO

output[0]: new StabilityVault (newSeekerPk, all other params preserved)
output[1]: PriceBeacon pass-through
```

**Checks:**
1. `checkSig(seekerSig, seekerPk)`
2. Beacon: `currentPrice > 0`, `beaconAge <= 144`
3. `output[0].scriptPubKey == new StabilityVault(newSeekerPk, providerPk, ticker, clock, targetUSD, totalCollateral, fundingSatPerBlock, openHeight, exit)`
4. `output[0].value >= totalCollateral`
5. Beacon survival: `ticker >= currentPrice`, `clock >= beaconHeight`

`openHeight` is **unchanged** — funding continues accruing as if no transfer occurred.

#### `split(signature seekerSig, int amountUSD, pubkey newSeekerPk)`

Divides the USD claim proportionally into two independent vaults.

**Transaction layout:**
```
input[0]:  StabilityVault UTXO
input[1]:  PriceBeacon UTXO

output[0]: StabilityVault for newSeekerPk (amountUSD slice)
output[1]: StabilityVault for seekerPk (remainder)
output[2]: PriceBeacon pass-through
```

**Checks:**
1. `checkSig(seekerSig, seekerPk)`
2. `amountUSD > 0` and `amountUSD < targetUSD`
3. Beacon: `currentPrice > 0`, `beaconAge <= 144`

**Proportional collateral:**
```
collateralA = totalCollateral × amountUSD / targetUSD
collateralB = totalCollateral - collateralA
```

Both outputs must be `>= 330` sats (dust check). Both vaults preserve `openHeight` from the parent.

**Output specs:**
```ark
// output[0]
new StabilityVault(newSeekerPk, providerPk, ticker, clock,
  amountUSD, collateralA, fundingSatPerBlock, openHeight, exit)

// output[1]
new StabilityVault(seekerPk, providerPk, ticker, clock,
  remainingUSD, collateralB, fundingSatPerBlock, openHeight, exit)
```

#### `seekerRedeem(signature seekerSig)`

Seeker initiates settlement at the live oracle price.

**Transaction layout (normal, two payout outputs):**
```
input[0]:  StabilityVault UTXO
input[1]:  PriceBeacon UTXO

output[0]: SingleSig(seekerPk)   — value >= seekerRaw
output[1]: SingleSig(providerPk) — value >= providerPayout  (if > 330 sats)
output[2]: PriceBeacon pass-through
```

**Transaction layout (single payout — dust or capped):**
```
output[0]: SingleSig(seekerPk or providerPk)
output[1]: PriceBeacon pass-through
```

Full branch logic: see settlement math in §4.2.

#### `providerExit(signature providerSig)`

Provider initiates settlement. Economically **identical** to `seekerRedeem` — same beacon read, same payout formula, same output shapes. The only difference is the signing key (`providerPk` instead of `seekerPk`).

**First-come, first-served.** Both functions can be broadcast at any time; the contract enforces the same math regardless of who initiates. Neither party can force a different price. There is no challenge window.

---

## 5. Full lifecycle

### 5.1 Deployment

```
Oracle deploys PriceBeacon(ticker, clock, oraclePk, exit)
  └─ Funds UTXO with BTC
  └─ Writes initial price into ticker asset, initial block height into clock asset

Provider deploys StabilityOffer(providerPk, ticker, clock, fundingSatPerBlock,
                                maxExposureBTC, collateralRatioPct, exit)
  └─ Locks maxExposureBTC × collateralRatioPct / 100 sats as collateral
```

### 5.2 Opening a position (via swap service)

```
Swap service broadcasts take(userBTC, seekerPk):
  input[0]:  StabilityOffer
  input[1]:  PriceBeacon (pass-through)
  input[2]:  Seeker's BTC

  Contract reads entryPrice from beacon
  Contract computes targetUSD = userBTC × entryPrice / 1e8

  output[0]: StabilityVault(seekerPk, providerPk, ..., targetUSD, totalCollateral, ...)
  output[1]: reduced StabilityOffer  (if partial fill)
  output[N]: PriceBeacon pass-through
```

### 5.3 Circulating the position

```
Seeker → Swap service:
  seekerSig signs transfer(seekerSig, swapServicePk)
  → new StabilityVault owned by swap service

Swap service → Seeker (resale):
  swap service signs transfer(swapServiceSig, newSeekerPk)
  → position changes hands

Seeker splits to send partial balance:
  split(seekerSig, amountUSD, friendPk)
  → two independent vaults
```

### 5.4 Settlement

```
Either party broadcasts seekerRedeem or providerExit:
  input[0]:  StabilityVault
  input[1]:  PriceBeacon (pass-through for beacon, read for price)

  currentPrice = tx.inputs[1].assets.lookup(ticker)
  beaconAge    = tx.time - tx.inputs[1].assets.lookup(clock)

  → Contract enforces payout split per settlement math
  → Both parties receive SingleSig outputs
  → PriceBeacon survives to output[1] or output[2]
```

### 5.5 Oracle update

```
Oracle broadcasts update(oracleSig, newPrice, newBlockHeight):
  input[0]:  current PriceBeacon
  output[0]: updated PriceBeacon (same script, new asset quantities)

  Monotonicity: newBlockHeight >= currentHeight (no rollback)
  Sub-block:    multiple updates per Bitcoin block are valid (same height OK)
```

---

## 6. Security properties

| Property | Mechanism |
|---|---|
| Oracle authentication | Consumers check `ticker` + `clock` asset IDs (genesis-committed, globally unique); do not check `oraclePk` |
| Oracle key rotation | `migrate()` preserves asset IDs; existing vaults/offers unaffected |
| Staleness enforcement | `tx.time - clock <= 144` on every settlement/transfer |
| Price back-dating | `update()` enforces `newBlockHeight >= currentHeight` |
| Seeker payout protection | `seekerPayout = clamp(seekerRaw, 0, totalCollateral)` — always bounded |
| Provider can't steal seeker's claim | Settlement math is deterministic; neither party can choose a different price |
| Offer non-interactivity | `take()` requires no provider signature — provider pre-commits at deployment |
| Dust handling | No output created when `providerPayout <= 330` sats |
| Re-collateralization | No forced liquidation — provider can hold position through a price dip; when price recovers, settlement restores automatically |

---

## 7. Compiler output (function variants)

All non-internal functions compile to **two tapleaves**:

| Variant | `server_variant` | How it unlocks |
|---|---|---|
| Cooperative | `true` | Arkade Operator co-signs (`<SERVER_KEY>`) — instant |
| Exit | `false` | CLTV at `exit` blocks — no operator required |

Both variants enforce **identical settlement math**. The exit path exists solely so a unilateral close is always possible when the Arkade Operator is offline; it is not a counterparty-challenge window.

Total tapleaves per contract:

| Contract | Functions | Variants | Tapleaves |
|---|---|---|---|
| `PriceBeacon` | 3 (update, passthrough, migrate) | 2 | 6 |
| `StabilityOffer` | 2 (take, withdraw) | 2 | 4 |
| `StabilityVault` | 4 (transfer, split, seekerRedeem, providerExit) | 2 | 8 |

---

## 8. Parameter reference

### StabilityVault invariants across transfers

| Parameter | Changes on `transfer`? | Changes on `split`? |
|---|---|---|
| `seekerPk` | Yes (new owner) | Yes (two different keys) |
| `providerPk` | No | No |
| `ticker` | No | No |
| `clock` | No | No |
| `targetUSD` | No | Yes (proportionally divided) |
| `totalCollateral` | No | Yes (proportionally divided) |
| `fundingSatPerBlock` | No | No |
| `openHeight` | No | No (preserved for continuous accrual) |
| `exit` | No | No |

### Funding rate sign convention

| Value | Direction | Typical scenario |
|---|---|---|
| `> 0` | Provider pays Seeker | Normal: Provider pays for self-custodied leverage |
| `= 0` | No fee | Rare; only if both parties agree |
| `< 0` | Seeker pays Provider | Bear market; Seeker pays for stability |
