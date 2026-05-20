# Stability — How It Works

**Status:** v1 design complete

---

## What it is

A self-custodied USD position on Bitcoin. A **Seeker** deposits BTC and holds a fixed dollar value. A **Provider** matches that BTC with additional collateral and takes a leveraged long position. The Provider pays the Seeker a funding rate for the privilege of that leverage.

The Seeker's balance looks and feels like a dollar account. The BTC mechanics are invisible. The position is a Taproot UTXO — no bridge, no issuer, no exchange counterparty.

---

## The three contracts

| Contract | Purpose |
|---|---|
| `StabilityOffer` | Provider pre-commits collateral as a standing offer. Anyone can claim it non-interactively. |
| `StabilityVault` | The live position: Seeker's USD claim + Provider's collateral in one UTXO. |

The on-chain beacon UTXO is gone. Price arrives as a witness argument at settlement time, signed by an oracle key baked into the vault. The signed message is `sha256(ticker || price || timestamp)` — Fuji-style replay protection across feeds and time.

---

## Economics

At open with a 1.5:1 collateral ratio:

```
Seeker deposits:    S sats
Provider locks:     1.5 × S sats
Total collateral:   2.5 × S sats
Seeker's USD claim: S × entryPrice / 1e8  (in cents, fixed at open)
```

At settlement with oracle price P:

```
seekerBase     = targetUSD × 1e8 / P                                    (integer division)
fundingAccrued = fundingRatePerBlock × seekerBase × (tx.time − openHeight) / 1e10
seekerRaw      = seekerBase + fundingAccrued
seekerPayout   = clamp(seekerRaw, 0, totalCollateral)
providerPayout = totalCollateral − seekerPayout
```

The 60% single-period drop is the coverage ceiling. Beyond it the Seeker absorbs the residual — this must be disclosed in wallet UX.

### Funding rate

`fundingRatePerBlock` is a signed fixed-point fraction at scale 1e10, agreed at open. Because funding scales with `seekerBase`, the effective APY is invariant to position size — a Seeker who partially fills a 1 BTC offer pays the same rate as one who consumes it entirely.

```
fundingRatePerBlock = (annual_pct / 100) / 52560 × 1e10
```

- `> 0`: Provider pays Seeker (expected default — cost of self-custodied leverage)
- `< 0`: Seeker pays Provider (discount offer in low-demand periods)

Example values: 0.5% APY → `950`; 5% APY → `9500`. The on-chain divide is interleaved (`/1e5` twice) to keep the intermediate product inside int64 across realistic position sizes.

### Provider leverage

At 1.5:1, a +20% BTC move yields ~+33% for the Provider (1.67× leverage). No forced liquidation, no margin calls. If BTC drops beyond the coverage ceiling the Provider can simply hold — when price recovers, the settlement branch restores automatically with no on-chain action.

---

## StabilityOffer

Provider deploys an offer with their collateral locked. No signature is required to claim it — the offer is fully pre-committed.

**`take(userBTC, seekerPk, oraclePrice, oracleTime, oracleSig)`** — opens a StabilityVault at the oracle-signed price. Reduces remaining offer capacity. If fully consumed, the offer UTXO is spent.

**`withdraw(providerSig)`** — Provider reclaims unused collateral at any time.

---

## StabilityVault

Constructor parameters: `seekerPk, providerPk, oraclePk, ticker, targetUSD, totalCollateral, fundingRatePerBlock, openHeight, exit`

`targetUSD`, `totalCollateral`, `oraclePk`, and `ticker` are invariant across transfers.

### Functions

**`transfer(seekerSig, newSeekerPk)`** — full position to a new owner. No oracle call needed — no payout is computed, just a key swap. This is the primary exit path: Seeker sends to a swap service in exchange for USDT/USDC.

**`split(seekerSig, amountUSD, newSeekerPk)`** — divides the USD claim proportionally into two independent vaults. Both halves must be above the 330-sat Taproot dust threshold.

**`seekerExit(seekerSig, oraclePrice, oracleTime, oracleSig)`** — Seeker exits to BTC at the oracle-attested price.

**`providerExit(providerSig, oraclePrice, oracleTime, oracleSig)`** — Provider exits to collateral at the oracle-attested price. Identical payout math to `seekerExit`. First-come, first-served — no challenge window.

### Settlement branches

| Condition | Seeker gets | Provider gets |
|---|---|---|
| `seekerRaw ≤ 0` | nothing | all collateral |
| `seekerRaw ≥ totalCollateral` | all collateral | nothing |
| normal | `seekerRaw` sats | remainder (if > 330 sats) |

---

## Oracle model

The oracle signs BTC/USD prices off-chain as `sha256(ticker || price || timestamp)` — `price` and `timestamp` are 8-byte little-endian unsigned ints. At settlement the caller provides `(oraclePrice, oracleTime, oracleSig)` as witness arguments. The contract:

1. Enforces freshness: `tx.time - oracleTime <= 144` blocks (≈24 hours).
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
| `timestamp` | Makes each oracle update unique. Combined with the 144-block freshness check, stale signatures are rejected. |

`oraclePk` and `ticker` are baked into the vault at creation time. There is no on-chain beacon UTXO to maintain, pass through, or go stale.

---

## Cooperative vs exit paths

Every function compiles to two tapleaves:

| Path | How it unlocks | Notes |
|---|---|---|
| Cooperative | Arkade Operator co-signs (instant) | Normal flow |
| Exit | CLTV after `exit` blocks, no operator needed | Fallback for operator offline |

Both paths enforce identical settlement math. The exit path is not a challenge window — it exists only so unilateral close is always possible.

Total tapleaves: **4** (StabilityOffer) + **8** (StabilityVault) = 12.

---

## Lifecycle

```
1. Provider deploys StabilityOffer (locks BTC collateral, binds to a ticker)
2. Swap service calls take(userBTC, seekerPk, oraclePrice, oracleTime, oracleSig)
   → StabilityVault created at the oracle price, inheriting the ticker
3. Seeker circulates the vault:
     transfer → swap service (USDT/USDC out)
     split    → send partial balance to a friend
4. Settlement (either party, any time):
     seekerExit or providerExit with a fresh oracle-signed (price, time)
     → two SingleSig outputs, vault consumed
```

---

## Risk disclosures (wallet UX)

1. **Coverage ceiling:** Fully protected unless BTC drops more than 60% from deposit price. Beyond that, you receive all available collateral, which may be less than your original deposit.
2. **No issuer:** Backed by a Bitcoin smart contract, not company reserves.
3. **Oracle dependency:** USD value is determined by a public oracle. If the oracle is unavailable, settlement requires a fresh signature — cooperative path may be blocked until the oracle resumes.
4. **Either party settles at any time:** Provider can settle at the live oracle price at any time. So can you. No delay, no challenge period, first-come first-served.
5. **Funding rate is fixed at open:** Rate cannot change without closing and reopening.
