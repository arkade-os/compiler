# StabilityVault — Product Requirements Document

**Status:** Design complete, ready for prototype build
**Scope:** v1 wallet-facing product. StabilityYield (under-collateralised, monthly lockup)
is explicitly out of scope and tracked separately.

---

## 1. Problem

Arkade Wallet users want to hold a USD balance on Bitcoin. Today the only path is
a USDT/USDC swap into BTC, which immediately exposes them to BTC price volatility.
This is a deal-breaker for everyday spending use cases.

The wallet needs an asset that:
- Feels like a deposit, not a swap
- Shows a stable dollar balance
- Stays self-custodied on Bitcoin
- Can be sent to friends or swap services without friction

---

## 2. Product Vision

A wallet user taps "Add USD", sends USDT/USDC from anywhere, and sees a dollar
balance with a yield figure beneath it. The BTC mechanics are invisible. Behind
the scenes a Provider locks 1.5x the Seeker's BTC as collateral and takes a
leveraged BTC long position. The Provider pays the Seeker a funding rate for the
privilege of that leverage. The Seeker holds a USD-denominated claim backed by
2.5x their BTC in collateral — protected against a 60% price drop. They can
spend it, send it, or swap it back to USDT at any time via a swap service. They
never need to think about Bitcoin price or funding mechanics.

---

## 3. Actors

| Actor | Role | Primary action |
|---|---|---|
| **Seeker** | Wallet user holding the USD claim | Open, send, or hand off to swap service |
| **Provider** | BTC holder taking the leveraged long side | Open offers, hold position, exit for profit |
| **Swap Service** | Bridges USDT/USDC ↔ StabilityVault positions | Holds inventory float, quotes spreads |
| **Oracle** | Operates the PriceBeacon, publishes BTC/USD price | Update beacon every block |
| **Arkade Operator** | Co-signs cooperative transactions on the Arkade network | Facilitate cooperative paths |

### Seeker motivations
- Wants USD stability without leaving Bitcoin
- Does not want exchange, bridge, or issuer risk
- Expects wallet UX identical to a USD bank balance

### Provider motivations
- Wants self-custodied 1.67x BTC leverage with no exchange counterparty risk
- Pays a funding rate to Seeker (the cost of leverage; cheaper than alternatives)
- No forced liquidation: exits voluntarily at the block and price of their choosing
- No margin calls, no cascading failures, no race conditions with liquidation bots

### Swap Service role
The swap service is a first-class participant, not an afterthought. It:
- Accepts incoming StabilityVault positions from Seekers wanting USDT/USDC
- Issues USDT/USDC in exchange (captures a small spread)
- Holds positions as USD-denominated inventory (backed by 2.5x BTC collateral)
- Rebalances inventory by exiting positions (`seekerRedeem`) when needed
- Creates a liquidity flywheel: more inventory → tighter spreads → more Seekers → more Providers

---

## 4. The Economic Model

```
At open (1.5:1 Provider collateral ratio):
  Seeker locks:       S sats        (e.g. 1 BTC at $100k)
  Provider locks:     1.5 * S sats  (1.5x Seeker's BTC)
  totalCollateral:    2.5 * S sats
  targetUSD:          S * entryPrice / 1e8  (in cents; Seeker's claim only)

At settlement, with oracle price P (cents per BTC):
  seekerBase     = targetUSD * 1e8 / P           (sats owed to seeker)
  fundingAccrued = fundingSatPerBlock * elapsed   (positive = paid to seeker)
  seekerRaw      = seekerBase + fundingAccrued

  seekerPayout   = min(max(seekerRaw, 0), totalCollateral)
  providerPayout = totalCollateral - seekerPayout
```

### Price scenarios (1 BTC Seeker, $100k entry, funding ignored for clarity)

| BTC move | totalCollateral | seekerPayout | providerPayout | Seeker status |
|---|---|---|---|---|
| Flat ($100k) | 2.5 BTC | 1.00 BTC | 1.50 BTC | Fully covered |
| +20% ($120k) | 2.5 BTC | 0.83 BTC | 1.67 BTC | Fully covered |
| -30% ($70k) | 2.5 BTC | 1.43 BTC | 1.07 BTC | Fully covered |
| -60% ($40k) | 2.5 BTC | 2.50 BTC | 0.00 BTC | Fully covered, exactly at ceiling |
| -70% ($30k) | 2.5 BTC | 2.50 BTC (cap) | 0.00 BTC | **Shortfall: seeker gets $75k not $100k** |

The 60% single-period drop is the hard coverage ceiling. Beyond it the Seeker
absorbs the residual loss. This must be disclosed clearly in UX.

### Provider leverage

```
BTC rises 20% ($100k → $120k), 1 BTC Seeker position:
  seekerPayout  = $100k / $120k = 0.833 BTC
  providerPayout = 2.5 - 0.833 = 1.667 BTC

  Provider put in:   1.5 BTC = $150k
  Provider receives: 1.667 BTC × $120k = $200k
  Provider gain:     $50k on $150k = +33% on a +20% BTC move = 1.67x leverage
  vs. holding 1.5 BTC spot: +20% = $30k gain
  Outperformance:    +$20k from holding the long side of the contract
```

### Funding rate (positive by default, Provider pays Seeker)

`fundingSatPerBlock` is a signed integer agreed at contract open:
- `> 0`: Provider pays Seeker — the expected default. Cost of self-custodied leverage.
- `= 0`: No fee either direction — rare, only if both parties agree.
- `< 0`: Seeker pays Provider — bear market, Seeker pays for stability like insurance.

**Why positive is necessary:** the Seeker gives up BTC upside appreciation.
Without compensation, rational Seekers won't participate. The Provider benefits
from 1.67x leverage; the funding rate is their cost for it.

**Reference rate:** 10 sats/block ≈ 0.5% APY on a $100k position. Providers
posting offers at 5–20 sats/block give Seekers 0.25–1% APY — meaningful yield
for a product with no exchange or issuer risk.

The off-chain matching marketplace discovers the rate. The contract enforces
whatever was agreed. Neither party can change it after open without closing and
reopening.

### Why both collateral and yield are required
Collateral alone is not enough. Seekers give up BTC upside to hold a USD
balance, so without compensation rational Seekers do not participate.
StabilityVault addresses both sides: 2.5x collateral coverage (60% price-drop
protection) plus a positive funding rate paid by the Provider to the Seeker.

---

## 5. User Flows

### 5.1 Seeker: Add USD to wallet

```
1. User taps "Add USD" in Arkade Wallet
2. Wallet shows deposit address (controlled by swap service)
3. User sends USDT/USDC from any source
4. Swap service:
   a. Finds an open StabilityOffer from a Provider
   b. Funds a StabilityVault: Seeker = user's pubkey, Provider = offer creator
   c. Transfers the initial position to user's wallet
5. Wallet shows "$X.XX" balance
```

The user sees step 1 and step 5 only. Everything else is invisible.

### 5.2 Seeker: Send USD to a friend

```
Full balance:
  1. User selects USD balance, enters recipient pubkey or address
  2. Wallet calls transfer(seekerSig, friendPk)
  3. Contract produces new StabilityVault owned by friend
  4. Friend's wallet shows incoming USD balance

Partial balance (e.g. send $50 of $5,000):
  1. User selects amount, enters recipient
  2. Wallet calls split(seekerSig, $50, friendPk)
  3. Contract produces two StabilityVaults:
       output[0]: $50 owned by friend
       output[1]: $4,950 retained by user
  4. User's balance updates. Friend sees +$50.
```

### 5.3 Seeker: Swap back to USDT/USDC

```
1. User taps "Withdraw USD"
2. Wallet routes to connected swap service
3. User calls transfer(seekerSig, swapServicePk)
4. Swap service receives the StabilityVault position
5. Swap service sends USDT/USDC to user's external address
6. User's in-wallet USD balance clears to zero
```

No settlement to BTC occurs. The position circulates to the swap service's
inventory. The swap service quotes a spread and settles off-chain with USDT.

### 5.4 Seeker: Emergency exit to BTC

```
1. User taps "Convert to BTC" (power user feature, not primary flow)
2. Wallet calls seekerRedeem(seekerSig)
3. Contract reads current PriceBeacon
4. Contract pays seekerPayout in BTC, providerPayout to provider
5. User's wallet shows +X BTC, USD balance clears
```

Wallet must warn: "If BTC has dropped more than 50% since you deposited, you
may receive less than your original USD value."

### 5.5 Provider: Post an offer

```
1. Provider creates StabilityOffer (locks BTC collateral, sets fundingSatPerBlock)
2. Offer sits on-chain, visible to any swap service
3. Swap service claims the offer when a Seeker deposits
4. Position is live: Provider holds 2x BTC long
```

### 5.6 Provider: Exit a position

```
Cooperative (instant, Arkade Operator co-signs):
  1. Provider calls providerExit(providerSig) — cooperative variant
  2. Contract reads the live beacon price, splits collateral
  3. Current Seeker/holder receives their USD equivalent in BTC
  4. Provider receives the remainder

Unilateral (operator offline, after exit timelock):
  1. Provider broadcasts providerExit — exit variant
  2. After `exit` blocks elapse (CLTV), Provider can spend without operator co-sign
  3. Settlement math is identical: live beacon read, payouts split per the
     same formula the cooperative variant enforces
```

There is no counterparty-challenge window. Either party can settle instantly
via the cooperative variant at any time — first come, first served. The exit
timelock is purely a fallback for when the Arkade Operator is offline; it
does not delay settlement when the Operator is available.

---

## 6. Contract Architecture

### 6.1 Contracts at play

| Contract | Instances | Purpose |
|---|---|---|
| `PriceBeacon` | 1 (shared globally) | Publishes BTC/USD price as an on-chain asset |
| `StabilityOffer` | 1 per Provider | Standing offer; creates a StabilityVault when claimed |
| `StabilityVault` | 1 per position | The live position; splits, transfers, or settles |
| `SingleSig` | created at settlement | Payout destination for Seeker and Provider |

Each is one Taproot output. A transaction touching a StabilityVault always
includes the PriceBeacon as a pass-through input (to read the price on-chain
without trusting the spender).

### 6.2 StabilityVault functions

| Function | Who signs | Recursive? | Description |
|---|---|---|---|
| `transfer` | seekerSig | Yes | Assign full position to new owner |
| `split` | seekerSig | Yes (×2) | Divide USD claim, proportional collateral |
| `seekerRedeem` | seekerSig | No | Seeker settles to BTC at the live oracle price |
| `providerExit` | providerSig | No | Provider settles to BTC at the live oracle price |

Each function compiles to two tapleaves: cooperative (Arkade Operator co-signs,
instant) and exit (CLTV at the `exit` block height, operator co-sign not
required). Both variants enforce identical settlement math. The exit variant
exists only so a unilateral close is always possible when the Operator is
offline; it is not a counterparty-challenge window.

**Total tapleaves: 8** (4 functions × 2 variants).

### 6.3 Recursion scope

Recursive covenants (output scriptPubKey == child StabilityVault) are used only
in `transfer` and `split`. Settlement functions are terminal — they pay out to
SingleSig outputs and the StabilityVault UTXO is consumed.

---

## 7. Settlement Math (Reference)

All arithmetic in sats and cents. No floating point.

```
targetUSD         — seeker's USD claim in cents (e.g. 10_000_000 = $100,000.00)
totalCollateral   — sats locked (= 2 × seekerBTC at open; invariant across transfers)
currentPrice      — cents per BTC from PriceBeacon (e.g. 10_000_000_00 = $100,000.00)
fundingSatPerBlock — signed int, zero by default
openHeight        — block height at last open or split (reset on split)
blocksElapsed     — tx.time - openHeight

seekerBase     = targetUSD × 100_000_000 / currentPrice   (integer division, truncates)
fundingAccrued = fundingSatPerBlock × blocksElapsed
seekerRaw      = seekerBase + fundingAccrued

seekerPayout   = clamp(seekerRaw, 0, totalCollateral)
providerPayout = totalCollateral − seekerPayout
```

Dust threshold: if `providerPayout <= 330 sats` (Taproot dust), no provider
output is created and the seeker output absorbs the residual.

### Why no liquidation

There is no liquidation mechanism. No bots, no margin calls, no race conditions.
Either party triggers settlement voluntarily by reading the public beacon at
that moment. The contract enforces the math; neither party can choose a
different price.

`seekerRedeem` and `providerExit` are economically symmetric — same beacon
read, same payout formula, same outputs. Whichever party broadcasts first wins
the race. There is no settlement delay and no challenge window: the live
beacon price is the only price either side can claim.

If BTC has dropped beyond the coverage ceiling, the Provider can simply hold
the position. There is no forced liquidation; when BTC recovers, the normal
settlement branch is restored automatically with no on-chain action.

---

## 8. Oracle

### PriceBeacon design
- One persistent on-chain UTXO per currency pair
- Asset quantity of `ticker` encodes the BTC/USD price in cents
- Asset quantity of `clock` encodes the block height of the last update
- Oracle updates both values atomically via the beacon's `update` function;
  block height is enforced to advance monotonically (no back-dating)
- Any transaction that reads the price must include the beacon as an input
  and pass it through as an output (enforced by the beacon's `passthrough`)
- Consumers verify the beacon's script
  (`tx.inputs[N].scriptPubKey == new PriceBeacon(ticker, clock, oraclePk, exit)`)
  to authenticate the feed

### Trust model (v1)
- Single oracle; trust is reputation-based and publicly verifiable on-chain
- Freshness is enforced on every read:
  `tx.time - tx.inputs[N].assets.lookup(clock) <= 144` (≈ 24 hours).
  A stale beacon blocks settlement until the oracle resumes.
- **v2 requirement (must ship before scale):** threshold-of-N oracle using the
  existing `ThresholdOracle` pattern. Target: 3-of-5 oracle quorum.

---

## 9. Risk Disclosure Requirements

The wallet UI must surface the following before a user opens a position:

1. **Coverage ceiling:** "Your USD balance is fully protected unless BTC drops
   more than 60% from your deposit price. If that happens, you receive all
   available collateral, which may be worth less than your original deposit."

2. **No FDIC / no issuer:** "This is not a bank account. Your balance is backed
   by Bitcoin locked in a smart contract, not by a company's reserves."

3. **Oracle dependency:** "The USD value of your balance is determined by a
   public price oracle. In the unlikely event the oracle is offline, you cannot
   settle until it resumes."

4. **Either party can settle at any time:** "Your counterparty (the BTC
   collateral provider) can settle the position at any time using the live
   oracle price. The same is true for you — neither side can force a
   different price. There is no delay or challenge period; whoever settles
   first locks in the live oracle price for both sides."

5. **Funding rate:** "You are earning [X% APY] on your USD balance, paid by
   your counterparty in exchange for their leveraged BTC position. This rate
   is fixed at deposit time and may differ if you close and re-open."

---

## 10. Build Scope

### In scope (v1)
- `examples/stability/stability_vault.ark`: transfer, split, seekerRedeem, providerExit
- `examples/stability/stability_offer.ark`: creates StabilityVault outputs at the live beacon price
- `examples/stability/price_beacon.ark`: dual-asset oracle (ticker + clock) with monotone block-height enforcement
- Integration tests covering parsing, ABI shape, and ASM emission for each contract
- Wallet UX flows 5.1–5.6 above

### Out of scope (tracked separately)

**StabilityYield** — savings account tier for sophisticated users:
- Under-collateralised (≈0.5:1), Provider gets ≈3x leverage
- Monthly epoch (≈4320 blocks), Seeker locked for duration
- Long epoch acts as a natural cure period for Provider margin recovery
- Higher `fundingSatPerBlock` compensates Seeker for tail risk beyond the 50% floor
- Seeker accepts: BTC drop >50% sustained through month-end impairs their balance
- Requires: explicit risk UX, separate contract, institutional-grade Swap Service integration

**v2 platform features:**
- Threshold-of-N oracle (3-of-5)
- `merge` function for Swap Service inventory consolidation
- Minimum-hold fee floor
- Cross-position aggregation in wallet UI

---

## 11. Success Metrics

| Metric | Target (3 months post-launch) |
|---|---|
| Active StabilityVault UTXOs | >500 |
| Total USD value locked | >$1M |
| Median position size | $500–$5,000 |
| Swap service spread | <0.2% |
| Seeker emergency exits to BTC | <5% of closures (rest go via swap service) |
| Oracle uptime | >99.9% |
