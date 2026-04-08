# Vault + Lending — UTXO Spending Flows

Each diagram shows one transaction. Inputs are on the left, outputs on the right.
`fn(...)` labels on edges name the covenant function being executed.

---

## 1. Deposit (LP → Vault)

```mermaid
graph LR
    I0["VaultCovenant\nkeeperPk, ownerPk\ntotalAssets, totalShares"]
    I1["SingleSig(ownerPk)\ndeposit value"]
    O0["VaultCovenant\nkeeperPk, ownerPk\ntotalAssets + deposit\ntotalShares + newShares"]

    I0 -->|"deposit(ownerSig, ...)"| O0
    I1 --> O0
```

---

## 2. Withdraw (Vault → LP)

```mermaid
graph LR
    I0["VaultCovenant\nkeeperPk, ownerPk\ntotalAssets, totalShares"]
    O0["VaultCovenant\nkeeperPk, ownerPk\ntotalAssets - withdraw\ntotalShares - burned"]
    O1["SingleSig(ownerPk)\nwithdraw value"]

    I0 -->|"withdraw(ownerSig, ...)"| O0
    I0 --> O1
```

---

## 3. Supply (Vault → LendingMarket)

`creditHolder` = precomputed `scriptPubKey` of `RepayFlow(keeperPk, ownerPk, totalAssets − supplyAmount, totalShares)`

```mermaid
graph LR
    I0["SupplyFlow\nkeeperPk, ownerPk, borrowerPk\ncreditHolder, supplyAmount, lltv\ntotalAssets, totalShares"]
    O0["VaultCovenant\nkeeperPk, ownerPk\ntotalAssets - supplyAmount\ntotalShares"]
    O1["LendingMarket\nborrowerPk, oraclePk, keeperPk\ncreditHolder = RepayFlow script\ncollateral=0, debt=0, lltv"]

    I0 -->|"supply(keeperSig)"| O0
    I0 --> O1
```

---

## 4. Borrow (LendingMarket → Borrower)

```mermaid
graph LR
    I0["LendingMarket\ncollateral=0, debt=0\ncreditHolder = RepayFlow script"]
    I1["SingleSig(borrowerPk)\ncollateral"]
    O0["LendingMarket\ncollateral, debt=borrowAmount\ncreditHolder = RepayFlow script"]
    O1["SingleSig(borrowerPk)\nborrowAmount"]

    I0 -->|"borrow(borrowerSig, oracleSig, ...)"| O0
    I1 --> O0
    I0 --> O1
```

---

## 5a. Full Repay (Borrower closes position)

```mermaid
graph LR
    I0["LendingMarket\ncollateral, debt\ncreditHolder = RepayFlow script"]
    I1["SingleSig(borrowerPk)\nrepayAmount"]
    O0["SingleSig(borrowerPk)\ncollateral released"]
    O1["RepayFlow\nkeeperPk, ownerPk\ntotalAssets, totalShares\nrepayAmount value"]

    I0 -->|"repay(borrowerSig, repayAmount, newDebt=0)"| O0
    I1 --> O0
    I0 --> O1
```

---

## 5b. Partial Repay (Borrower reduces debt)

```mermaid
graph LR
    I0["LendingMarket\ncollateral, debt\ncreditHolder = RepayFlow script"]
    I1["SingleSig(borrowerPk)\nrepayAmount"]
    O0["LendingMarket\ncollateral, debt - repayAmount\ncreditHolder unchanged"]
    O1["RepayFlow\nkeeperPk, ownerPk\ntotalAssets, totalShares\nrepayAmount value"]

    I0 -->|"repay(borrowerSig, repayAmount, newDebt)"| O0
    I1 --> O0
    I0 --> O1
```

---

## 6. Reclaim (RepayFlow → Vault)

`returnAmount` is derived from `tx.input.current.value` — no keeper input.

```mermaid
graph LR
    I0["RepayFlow\nkeeperPk, ownerPk\ntotalAssets, totalShares\nreturnAmount value"]
    O0["VaultCovenant\nkeeperPk, ownerPk\ntotalAssets + returnAmount\ntotalShares"]

    I0 -->|"reclaim(keeperSig)"| O0
```

---

## 6b. Reclaim Expired (LP unilateral — after 144-block exit timelock)

Keeper is unresponsive. LP calls `reclaimExpired()` without keeper co-sign.
LP supplies current vault `totalAssets`/`totalShares` (observable from vault VTXO on-chain).

```mermaid
graph LR
    I0["RepayFlow\nkeeperPk, ownerPk\ntotalAssets, totalShares\nreturnAmount value"]
    O0["VaultCovenant\nkeeperPk, ownerPk\ncurrentTotalAssets + returnAmount\ncurrentTotalShares"]

    I0 -->|"reclaimExpired(ownerSig, currentTotalAssets, currentTotalShares)"| O0
```

---

## 7. Liquidation (Keeper closes underwater position)

```mermaid
graph LR
    I0["LendingMarket\ncollateral, debt\nposition underwater"]
    O0["SingleSig(keeperPk)\nfee = collateral × 5%"]
    O1["RepayFlow\nkeeperPk, ownerPk\ntotalAssets, totalShares\ndebt value"]
    O2["SingleSig(borrowerPk)\ncollateral - fee - debt"]

    I0 -->|"liquidate(keeperSig, oracleSig, ...)"| O0
    I0 --> O1
    I0 --> O2
```

---

## 8. End-to-end lifecycle

```mermaid
sequenceDiagram
    participant LP
    participant Vault as VaultCovenant
    participant SF as SupplyFlow
    participant LM as LendingMarket
    participant RF as RepayFlow
    participant B as Borrower

    LP->>Vault: deposit()
    Note over Vault: totalAssets increases

    Note over SF: keeper creates SupplyFlow VTXO
    SF->>Vault: supply() → VaultCovenant(totalAssets − X)
    SF->>LM: supply() → LendingMarket(debt=0, creditHolder=RepayFlow script)

    B->>LM: borrow(collateral)
    LM-->>B: SingleSig(borrowerPk) borrowAmount
    Note over LM: collateral locked, debt recorded

    B->>LM: repay(repayAmount)
    LM-->>B: SingleSig(borrowerPk) collateral (full repay)
    LM-->>RF: RepayFlow VTXO created automatically

    RF->>Vault: reclaim()
    Note over Vault: totalAssets + returnAmount

    LP->>Vault: withdraw()
    Vault-->>LP: assets + accrued yield
```

---

## Liveness tradeoffs

| Actor | Keeper required? | Self-sovereign exit? | Notes |
|---|---|---|---|
| **Borrower** | Cooperative path only | Yes — after 144 blocks | `exit = 144` guarantees collateral recovery |
| **LP (idle vault assets)** | Cooperative path only | Yes — after 144 blocks | `VaultCovenant.withdraw()` unilateral after exit |
| **LP (deployed assets)** | `reclaim()` needs keeper | Yes — `reclaimExpired()` after 144 blocks | LP supplies current vault state; no keeper needed |
| **Liquidation** | Always keeper-gated | No | Underwater positions cannot be liquidated without keeper |
| **Yield reporting** | Always keeper-gated | No | `reportYield()` requires keeperSig; PPS freezes if keeper down (no loss) |
| **Credit transfer** | Always keeper-gated | No | `transferCredit()` rotates RepayFlow target; keeper-only |

**Key asymmetry**: borrowers always have a self-sovereign exit. LPs in deployed positions now also have one via `reclaimExpired()`. Liquidations remain fully keeper-dependent — if the keeper is offline while positions are underwater, the vault absorbs the loss.

---

## Key invariants

| Invariant | Enforced by |
|---|---|
| Repayment always lands in RepayFlow, never a bare pubkey | `creditHolder` is `bytes32` in LendingMarket; `repay` checks `outputs[1].scriptPubKey == creditHolder` |
| RepayFlow script committed at supply time | Off-chain: `creditHolder = scriptPubKey(RepayFlow(keeperPk, ownerPk, totalAssets − supplyAmount, totalShares))` |
| Vault accounting bound to actual settled value | `returnAmount = tx.input.current.value` in RepayFlow — no caller input |
| Collateral ratio enforced on every borrow | `collateral × price / 10000 >= borrowAmount × 10000 / lltv` |
| Strategy weights sum to 10000 | `weightSum == 10000` on-chain in CompositeRouter |
| Liquidation waterfall is solvent | `residual >= 0` guard before distributing outputs |
