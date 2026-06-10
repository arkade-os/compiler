# InventoryHedge — Transaction Flows

Companion to [`docs/mm-residual-hedge.md`](../mm-residual-hedge.md) (design intent)
and the contract [`examples/hedging/inventory_hedge.ark`](../../examples/hedging/inventory_hedge.ark).

This note walks each spend path as an actual transaction: who signs, what goes
in the witness, and the exact input/output layout the script enforces. It is the
operational view — the "what does the tx look like" that the contract comments
abbreviate.

---

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
meaningful on the cooperative leaf; the exit leaf is the liveness backstop.

---

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
  imbalance-driven value is computed off-chain by the desk's risk engine (design
  note §4) and supplied to `updateFunding`; the script only enforces `>= 0` and
  the accrual roll-forward.

Funding accrual, interleaved `/1e6` twice to stay inside int64:

```
elapsed       = tx.offchainTime - lastUpdate
rateElapsed   = fundingRatePerSec * elapsed / 1e6
delta         = targetFiat * rateElapsed / 1e6
newTargetFiat = targetFiat + delta          // = targetFiat × (1 + rate·elapsed/1e12)
```

---

## 1. `transfer` — reassign the claim leg

The desk hands its claim to a new key (design note §6 "transfer" resize). Pure
key swap; no oracle, no funding roll.

```
Signers : claimSig (+ SERVER_KEY | + CLTV exit)
Witness : claimSig, newClaimPk

in [0]  : InventoryHedge UTXO
out[0]  : InventoryHedge( claimPk:=newClaimPk, …all other state unchanged… )
          value >= totalCollateral
```

State change: `claimPk → newClaimPk`. Everything else (collateral, funding,
clock) is preserved.

---

## 2. `updateFunding` — roll funding, set the new rate

The long leg rolls accrued funding into the claim and adopts the next
off-chain-computed rate.

```
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

---

## 3. `addCapital` — treasury tops up collateral

More collateral is strictly better for the desk, so no ratio/oracle check.

```
Signers : longSig (+ SERVER_KEY | + CLTV exit)
Witness : longSig, amount

in [0]  : InventoryHedge UTXO
in [1+] : long-leg funding input(s)        (≥ amount sats, off-script)
out[0]  : InventoryHedge( totalCollateral := totalCollateral + amount, …rest unchanged… )
          value >= totalCollateral + amount
```

State change: `totalCollateral += amount`. Funding clock untouched.

---

## 4. `removeCapital` — treasury reclaims excess, ratio-guarded

The long leg withdraws surplus collateral, but the remainder must still cover the
claim at `collateralRatioPct` *at the current mark*. Accrual is computed **only
for the guard** — `targetFiat` and `lastUpdate` are deliberately **not** mutated,
so a withdrawal never truncates funding (only `updateFunding` moves the clock).

```
Signers : longSig (+ SERVER_KEY | + CLTV exit)
Witness : longSig, amount, oraclePrice, oracleTime, oracleSig

in [0]  : InventoryHedge UTXO
out[0]  : InventoryHedge( totalCollateral := totalCollateral - amount, …rest unchanged… )
          value >= totalCollateral - amount
out[1]  : SingleSig(longPk)                value >= amount     // reclaimed sats
```

Guard (oracle-priced):

```
accruedFiat        = targetFiat + delta
claimSats          = accruedFiat * 1e8 / oraclePrice
minCollateral      = claimSats * (100 + collateralRatioPct) / 100
require( totalCollateral - amount >= minCollateral )   // "would breach collateral ratio"
```

---

## 5. `claimExit` — desk settles to BTC (terminal)

The desk unwinds the hedge at the oracle mark. BTC-native settlement at the index
price (design note §2: no perp-spot basis). The vault terminates.

```
Signers : claimSig (+ SERVER_KEY | + CLTV exit)
Witness : claimSig, oraclePrice, oracleTime, oracleSig

in [0]  : InventoryHedge UTXO
```

Payout is the claim clamped into `[0, totalCollateral]`:

```
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
liquidation, no margin call on the claim side.

---

## 6. `longExit` — treasury-driven settlement (terminal)

Identical clamp math; the long leg initiates instead of the desk. Same output
table as §5 with `longSig` in place of `claimSig`. Lets the treasury close a
position the desk has gone quiet on, settling both legs fairly at the mark.

---

## Lifecycle at a glance

```
            ┌────────────── updateFunding (roll funding, reprice) ───────────────┐
            │                                                                     │
            ▼                                                                     │
  open ─▶ InventoryHedge UTXO ──▶ addCapital / removeCapital (resize collateral) ─┘
            │  │
            │  └──▶ transfer (reassign claim leg)
            │
            ├──▶ claimExit  ──▶ BTC to claim (+ remainder to long)   [terminal]
            └──▶ longExit   ──▶ BTC to claim (+ remainder to long)   [terminal]
```

Off-chain, the desk nets client flow internally and only adjusts the hedge when
aggregate BTC delta breaches a limit (design note §6): `addCapital` /
`removeCapital` / `transfer` reshape the live position instead of unwind-and-reopen.

---

## Playground

The contract ships in the WASM playground under the **Hedging** project folder
(`playground/main.js`), sourced from `playground/contracts.js` (regenerate with
`./playground/generate_contracts.sh` after editing the `.ark`). Build the WASM
bundle and serve with:

```
./playground/build.sh          # wasm-pack build + contracts regen
./playground/serve.sh 8080     # static server
```

Then pick **Hedging → inventory_hedge.ark** to compile it live in the browser.
