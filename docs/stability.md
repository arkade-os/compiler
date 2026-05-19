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

The on-chain beacon UTXO is gone. Price arrives as a witness argument at settlement time, signed by an oracle key baked into the vault.

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
seekerBase     = targetUSD × 1e8 / P          (integer division)
fundingAccrued = fundingSatPerBlock × (tx.time - openHeight)
seekerRaw      = seekerBase + fundingAccrued
seekerPayout   = clamp(seekerRaw, 0, totalCollateral)
providerPayout = totalCollateral − seekerPayout
```

The 60% single-period drop is the coverage ceiling. Beyond it the Seeker absorbs the residual — this must be disclosed in wallet UX.

### Funding rate

`fundingSatPerBlock` is signed and agreed at open:
- `> 0`: Provider pays Seeker (expected default — cost of self-custodied leverage)
- `< 0`: Seeker pays Provider (discount offer in low-demand periods)

10 sats/block ≈ 0.5% APY on a $100k position.

### Provider leverage

At 1.5:1, a +20% BTC move yields ~+33% for the Provider (1.67× leverage). No forced liquidation, no margin calls. If BTC drops beyond the coverage ceiling the Provider can simply hold — when price recovers, the settlement branch restores automatically with no on-chain action.

---

## StabilityOffer

Provider deploys an offer with their collateral locked. No signature is required to claim it — the offer is fully pre-committed.

**`take(userBTC, seekerPk, oraclePrice, oracleSig)`** — opens a StabilityVault at the oracle-signed price. Reduces remaining offer capacity. If fully consumed, the offer UTXO is spent.

**`withdraw(providerSig)`** — Provider reclaims unused collateral at any time.

---

## StabilityVault

Constructor parameters: `seekerPk, providerPk, oraclePk, targetUSD, totalCollateral, fundingSatPerBlock, openHeight, exit`

`targetUSD` and `totalCollateral` are invariant across transfers.

### Functions

**`transfer(seekerSig, newSeekerPk)`** — full position to a new owner. No oracle call needed — no payout is computed, just a key swap. This is the primary exit path: Seeker sends to a swap service in exchange for USDT/USDC.

**`split(seekerSig, amountUSD, newSeekerPk)`** — divides the USD claim proportionally into two independent vaults. Both halves must be above the 330-sat Taproot dust threshold.

**`seekerRedeem(seekerSig, oraclePrice, oracleSig)`** — Seeker exits to BTC at the oracle-attested price.

**`providerExit(providerSig, oraclePrice, oracleSig)`** — Provider initiates settlement. Identical payout math to `seekerRedeem`. First-come, first-served — no challenge window.

### Settlement branches

| Condition | Seeker gets | Provider gets |
|---|---|---|
| `seekerRaw ≤ 0` | nothing | all collateral |
| `seekerRaw ≥ totalCollateral` | all collateral | nothing |
| normal | `seekerRaw` sats | remainder (if > 330 sats) |

---

## Oracle model

The oracle signs BTC/USD prices off-chain using `oraclePk`. At settlement the caller provides `(oraclePrice, oracleSig)` as witness arguments. The contract verifies:

```ark
require(checkSigFromStack(oracleSig, oraclePk, oraclePrice), "invalid oracle signature");
```

`oraclePk` is baked into the vault at creation time. There is no on-chain beacon UTXO to maintain, pass through, or go stale. Clients are responsible for using a sufficiently fresh oracle update; the Arkade Operator enforces freshness on the cooperative path.

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
1. Provider deploys StabilityOffer (locks BTC collateral)
2. Swap service calls take(userBTC, seekerPk, oraclePrice, oracleSig)
   → StabilityVault created at the oracle price
3. Seeker circulates the vault:
     transfer → swap service (USDT/USDC out)
     split    → send partial balance to a friend
4. Settlement (either party, any time):
     seekerRedeem or providerExit with a fresh oracle-signed price
     → two SingleSig outputs, vault consumed
```

---

## Risk disclosures (wallet UX)

1. **Coverage ceiling:** Fully protected unless BTC drops more than 60% from deposit price. Beyond that, you receive all available collateral, which may be less than your original deposit.
2. **No issuer:** Backed by a Bitcoin smart contract, not company reserves.
3. **Oracle dependency:** USD value is determined by a public oracle. If the oracle is unavailable, settlement requires a fresh signature — cooperative path may be blocked until the oracle resumes.
4. **Either party settles at any time:** Provider can settle at the live oracle price at any time. So can you. No delay, no challenge period, first-come first-served.
5. **Funding rate is fixed at open:** Rate cannot change without closing and reopening.
