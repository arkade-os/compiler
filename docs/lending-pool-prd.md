# Morpho-Style Lending Pool on UTXO

## Problem

Bitcoin's UTXO model forces each borrower position into an isolated UTXO. Capital
deployed from the LP vault into a `LendingMarket` is physically locked in that UTXO
until the borrower repays or gets liquidated. An LP who wants out while capital is
deployed has no immediate path — the vault's idle balance may be zero.

On EVM, Morpho Blue solves this with a shared contract: all positions share one
accounting store, idle capital is always visible, and LP withdrawal is instant up
to the aggregate idle balance. The UTXO model cannot replicate shared mutable
state, but it can replicate the product behaviour through three mechanisms:

1. **Correct pool accounting** — vault `totalAssets` tracks all capital (idle + deployed),
   not just idle. LP shares reflect the full economic position.
2. **Withdrawal bounded by idle** — LP can withdraw up to the vault's actual BTC balance.
   Beyond that, they wait for repayment or use mechanism 3.
3. **LP shares as Arkade Assets** — shares are a transferable fungible token. An LP
   who wants immediate liquidity sells shares on a secondary market without touching
   the vault covenant.

---

## Architecture

The system uses four contracts. No yield-routing layer is needed at this stage.

```
┌──────────────────────────────────────────────────────┐
│ VaultCovenant (VTXO)                                 │
│  totalAssets = idle + deployed  (invariant)          │
│  totalShares = LP share tokens outstanding           │
│  vault UTXO value = idle portion only                │
└───────┬──────────────────────────────────────────────┘
        │ SupplyFlow (one-shot atomic)
        ▼
┌──────────────────────────────────────────────────────┐
│ LendingMarket (VTXO, one per borrower)               │
│  collateralAmount / debtAmount / lltv                │
│  creditHolder = RepayFlow scriptPubKey               │
└───────┬──────────────────────────────────────────────┘
        │ repay() / liquidate()
        ▼
┌──────────────────────────────────────────────────────┐
│ RepayFlow (VTXO)                                     │
│  reclaim()        → VaultCovenant (keeper)           │
│  reclaimExpired() → VaultCovenant (LP, after 144 blk)│
└──────────────────────────────────────────────────────┘
```

### VaultCovenant

Recursive covenant tracking `(totalAssets, totalShares)`.

**Key invariant**: `totalAssets = vault.value + Σ(outstanding deployed capital)`.
Capital deployment via `SupplyFlow` does NOT decrement `totalAssets`. The vault's
UTXO value (physical BTC held) decreases; `totalAssets` stays flat. When
`RepayFlow.reclaim()` returns capital, `totalAssets` increases by the returned
amount (capturing interest/yield).

**LP share accounting** (ERC-4626 style):
```
sharesIssued = depositAmount * totalShares / totalAssets   (deposit)
assetsOut    = sharesIn * totalAssets / totalShares        (withdraw)
```

`totalShares` is also the total outstanding supply of the LP share Arkade Asset.

### LP Shares as Arkade Assets

LP shares are a fungible Arkade Asset issued at deposit and burned at withdrawal.
The asset ID is globally unique (committed at vault genesis). Shares are
transferable: an LP can sell their position on any Arkade-compatible secondary
market without coordinating with the vault or the keeper.

This is the primary liquidity mechanism when the vault is fully deployed. The
secondary market prices LP shares at a discount that reflects credit risk and
expected repayment timing.

### LendingMarket

One VTXO per borrower. Unchanged from the current implementation:
- `borrow()` anti-reborrow guards (`debtAmount == 0`, `collateralAmount == 0`)
- Value conservation: `tx.input.current.value == borrowAmount`
- Oracle-attested LLTV check via `checkSigFromStack`
- Liquidation waterfall: fee → keeper, face value → `creditHolder`, residual → borrower
- `transferCredit` locked on open positions

### SupplyFlow

One-shot atomic: moves capital from `VaultCovenant` → fresh `LendingMarket`.

**Change from current design**: does not decrement `vault.totalAssets`. The vault
output receives `inputVal - supplyAmount` in BTC value, but `totalAssets` stays
at its pre-supply value. The keeper is responsible for tracking deployed capital
off-chain (sum of outstanding `LendingMarket` debt values) to verify the invariant
at withdrawal time.

### RepayFlow

Unchanged. When `reclaim()` routes repayment back to `VaultCovenant`, the returned
amount is added to `totalAssets` — capturing any interest earned above principal.

---

## LP Liquidity Model

| Scenario | LP exit path |
|---|---|
| Idle capital available (utilization < 100%) | `VaultCovenant.withdraw()` — instant |
| Fully deployed (utilization = 100%) | Sell LP share tokens on secondary market |
| Keeper unresponsive, capital in RepayFlow | `reclaimExpired()` after 144 blocks |
| Keeper unresponsive, position still open | Wait for Ark exit timelock; borrower can repay trustlessly |

---

## Accounting Model: Current vs. Target

| | Current (in PR) | Target (Morpho-style) |
|---|---|---|
| `totalAssets` on supply | Decrements by `supplyAmount` | Stays flat |
| LP share value on supply | Decreases (shares track idle only) | Unchanged (shares track all capital) |
| LP withdrawal | Uncapped (accounting bug) | Capped at `vault.value` (idle) |
| LP liquidity at 100% util. | None | Secondary market for LP share tokens |
| Bad debt on liquidation shortfall | Not modelled | `totalAssets` decreases → share price falls |

---

## Why Not Loan-Receipt Basket

The alternative approach issues a per-loan Arkade Asset receipt at borrow time.
The vault holds a basket of receipts; LPs redeem shares for a proportional slice
of the basket.

**Rejected because:**

- Receipts are heterogeneous (different rates, collateral, oracle, maturity). Each
  receipt requires independent pricing. The secondary market fragments into N illiquid
  receipt markets rather than one liquid LP share market.
- LP withdrawal at full utilization delivers a basket of partially-matched receipts,
  not cash. The LP must then liquidate those receipts separately — worse UX than
  selling a fungible LP share.
- Bad debt requires per-receipt impairment decisions. LP share approach automatically
  socialises losses via `totalAssets` reduction.
- Implementation complexity: unique Arkade Asset ID per loan at issuance is
  significantly harder to coordinate than a single vault share asset.

---

## What Was Removed

`StrategyFragment` and `CompositeRouter` were removed from the vault+lending suite.
They implement a yield-routing layer (keeper-attested strategy weights aggregated
into a vault update) that is orthogonal to the LP liquidity problem. The yield
routing concern belongs in a separate product layer, not in the base lending pool.
The `CompositeRouter` also explicitly relies on keeper-supplied `currentTotalAssets`
without on-chain verification — an unnecessary trust assumption in a design that
already has the vault covenant enforce accounting.

---

## Implementation Checklist

- [ ] Update `VaultCovenant.withdraw()` to cap output value at `vault.value` via
      `tx.input.current.value` introspection
- [ ] Update `SupplyFlow.supply()`: keep `totalAssets` flat; only decrement vault BTC value
- [ ] Add LP share Arkade Asset issuance in `VaultCovenant.deposit()`
- [ ] Add LP share burn check in `VaultCovenant.withdraw()`
- [ ] Update `RepayFlow.reclaim()` accounting if interest accrual changes `totalAssets`
      beyond original supply amount
- [ ] Update tests: remove StrategyFragment / CompositeRouter; add pool accounting tests
- [ ] Update FLOWS.md to reflect corrected accounting model
