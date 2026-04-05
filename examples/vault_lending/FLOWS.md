# Vault + Lending — UTXO Spending Flows

Each diagram shows one transaction: inputs on the left, outputs on the right.
Covenant names are the Arkade contracts. `→` means "spending path / function called".

---

## 1. Deposit (LP → Vault)

```mermaid
flowchart LR
    subgraph TX["deposit()"]
        direction LR
        I0["INPUT 0\nVaultCovenant\n(keeperPk, ownerPk,\ntotalAssets, totalShares)"]
        I1["INPUT 1\nSingleSig(ownerPk)\ndeposit value"]

        O0["OUTPUT 0\nVaultCovenant\n(keeperPk, ownerPk,\ntotalAssets + deposit,\ntotalShares + newShares)"]
    end

    I0 -->|"deposit(ownerSig, ...)"| O0
    I1 --> O0
```

---

## 2. Withdraw (Vault → LP)

```mermaid
flowchart LR
    subgraph TX["withdraw()"]
        direction LR
        I0["INPUT 0\nVaultCovenant\n(keeperPk, ownerPk,\ntotalAssets, totalShares)"]

        O0["OUTPUT 0\nVaultCovenant\n(keeperPk, ownerPk,\ntotalAssets - withdraw,\ntotalShares - burnedShares)"]
        O1["OUTPUT 1\nSingleSig(ownerPk)\nwithdraw value"]
    end

    I0 -->|"withdraw(ownerSig, ...)"| O0
    I0 --> O1
```

---

## 3. Supply (Vault → LendingMarket)

`creditHolder` is the precomputed scriptPubKey of `RepayFlow(keeperPk, ownerPk, totalAssets − supplyAmount, totalShares)`.

```mermaid
flowchart LR
    subgraph TX["supply()"]
        direction LR
        I0["INPUT 0\nSupplyFlow\n(keeperPk, ownerPk, borrowerPk,\noraclePk, creditHolder,\nsupplyAmount, lltv,\ntotalAssets, totalShares, ...)"]

        O0["OUTPUT 0\nVaultCovenant\n(keeperPk, ownerPk,\ntotalAssets − supplyAmount,\ntotalShares)"]
        O1["OUTPUT 1\nLendingMarket\n(borrowerPk, oraclePk, keeperPk,\ncreditHolder,\ncollateral=0, debt=0, lltv, ...)"]
    end

    I0 -->|"supply(keeperSig)"| O0
    I0 --> O1
```

---

## 4. Borrow (LendingMarket → Borrower)

```mermaid
flowchart LR
    subgraph TX["borrow()"]
        direction LR
        I0["INPUT 0\nLendingMarket\n(borrowerPk, oraclePk, keeperPk,\ncreditHolder,\ncollateral=0, debt=0, lltv, ...)"]
        I1["INPUT 1\nSingleSig(borrowerPk)\ncollateral"]

        O0["OUTPUT 0\nLendingMarket\n(borrowerPk, oraclePk, keeperPk,\ncreditHolder,\ncollateral, borrowAmount, lltv, ...)"]
        O1["OUTPUT 1\nSingleSig(borrowerPk)\nborrowAmount"]
    end

    I0 -->|"borrow(borrowerSig, oracleSig, ...)"| O0
    I1 --> O0
    I0 --> O1
```

---

## 5a. Full Repay (Borrower closes position)

```mermaid
flowchart LR
    subgraph TX["repay() — full"]
        direction LR
        I0["INPUT 0\nLendingMarket\n(..., collateral, debt, ...)"]
        I1["INPUT 1\nSingleSig(borrowerPk)\nrepayAmount"]

        O0["OUTPUT 0\nSingleSig(borrowerPk)\ncollateral"]
        O1["OUTPUT 1\nRepayFlow\n(keeperPk, ownerPk,\ntotalAssets, totalShares)\nrepayAmount"]
    end

    I0 -->|"repay(borrowerSig, repayAmount, 0)"| O0
    I1 --> O0
    I0 --> O1
```

---

## 5b. Partial Repay (Borrower reduces debt)

```mermaid
flowchart LR
    subgraph TX["repay() — partial"]
        direction LR
        I0["INPUT 0\nLendingMarket\n(..., collateral, debt, ...)"]
        I1["INPUT 1\nSingleSig(borrowerPk)\nrepayAmount"]

        O0["OUTPUT 0\nLendingMarket\n(..., collateral,\ndebt − repayAmount, ...)"]
        O1["OUTPUT 1\nRepayFlow\n(keeperPk, ownerPk,\ntotalAssets, totalShares)\nrepayAmount"]
    end

    I0 -->|"repay(borrowerSig, repayAmount, newDebt)"| O0
    I1 --> O0
    I0 --> O1
```

---

## 6. Reclaim (RepayFlow → Vault)

```mermaid
flowchart LR
    subgraph TX["reclaim()"]
        direction LR
        I0["INPUT 0\nRepayFlow\n(keeperPk, ownerPk,\ntotalAssets, totalShares)\nrepayAmount"]

        O0["OUTPUT 0\nVaultCovenant\n(keeperPk, ownerPk,\ntotalAssets + repayAmount,\ntotalShares)"]
    end

    I0 -->|"reclaim(keeperSig)"| O0
```

---

## 7. Liquidation (Keeper closes underwater position)

```mermaid
flowchart LR
    subgraph TX["liquidate()"]
        direction LR
        I0["INPUT 0\nLendingMarket\n(..., collateral, debt, ...)"]

        O0["OUTPUT 0\nSingleSig(keeperPk)\nfee = collateral × 5%"]
        O1["OUTPUT 1\nRepayFlow\n(keeperPk, ownerPk,\ntotalAssets, totalShares)\ndebt (face value)"]
        O2["OUTPUT 2\nSingleSig(borrowerPk)\ncollateral − fee − debt"]
    end

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
    Note over Vault: totalAssets ↑

    Vault->>SF: (keeper creates SupplyFlow VTXO)
    SF->>Vault: supply() → VaultCovenant(totalAssets − X)
    SF->>LM: supply() → LendingMarket(debt=0, creditHolder=RepayFlow script)

    B->>LM: borrow(collateral) → LendingMarket(debt=X)
    LM-->>B: SingleSig(borrowerPk) borrowAmount

    B->>LM: repay(repayAmount) → RepayFlow VTXO
    LM-->>B: SingleSig(borrowerPk) collateral (full repay)

    RF->>Vault: reclaim() → VaultCovenant(totalAssets + repayAmount)
    Note over Vault: totalAssets ↑ (yield accrued)

    Vault->>LP: withdraw()
    Note over LP: receives assets + yield
```

---

## Key invariants

| Invariant | Enforced by |
|---|---|
| Repayment always lands in RepayFlow, never a pubkey | `creditHolder` is `bytes32` in LendingMarket; repay sets `outputs[1].scriptPubKey == creditHolder` |
| RepayFlow script committed at supply time | Off-chain: `creditHolder = scriptPubKey(RepayFlow(keeperPk, ownerPk, totalAssets − supplyAmount, totalShares))` |
| Vault totalAssets only increases on reclaim by actual received value | `returnAmount = tx.input.current.value` in RepayFlow |
| Borrower collateral ratio checked against oracle | `collateral × price / 10000 >= borrowAmount × 10000 / lltv` |
| Weights sum to 10000 in CompositeRouter | `weightSum == 10000` enforced on-chain |
| No value escapes liquidation waterfall | `residual >= 0` guard + exact value checks on all outputs |
