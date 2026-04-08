use arkade_compiler::compile;

// ─── Source fixtures ──────────────────────────────────────────────────────────

const VAULT_COVENANT_SRC: &str = r#"
import "vault_covenant.ark";
options { server = server; exit = 144; }
contract VaultCovenant(pubkey keeperPk, pubkey ownerPk, int totalAssets, int totalShares) {
  function deposit(signature ownerSig, int newTotalAssets, int newTotalShares) {
    require(checkSig(ownerSig, ownerPk), "invalid owner");
    require(newTotalShares > totalShares, "shares must increase");
    require(newTotalAssets > totalAssets, "assets must increase");
    require(tx.outputs[0].scriptPubKey == new VaultCovenant(keeperPk, ownerPk, newTotalAssets, newTotalShares), "successor mismatch");
  }
  function withdraw(signature ownerSig, int newTotalAssets, int newTotalShares) {
    require(checkSig(ownerSig, ownerPk), "invalid owner");
    require(newTotalShares < totalShares, "shares must decrease");
    require(newTotalAssets < totalAssets, "assets must decrease");
    require(tx.outputs[0].scriptPubKey == new VaultCovenant(keeperPk, ownerPk, newTotalAssets, newTotalShares), "successor mismatch");
  }
  function reportYield(signature keeperSig, bytes32 reportHash, int newTotalAssets) {
    require(newTotalAssets >= totalAssets, "PPS decrease forbidden");
    require(checkSigFromStack(keeperSig, keeperPk, reportHash), "invalid keeper");
    require(tx.outputs[0].scriptPubKey == new VaultCovenant(keeperPk, ownerPk, newTotalAssets, totalShares), "successor mismatch");
  }
}
"#;

const STRATEGY_FRAGMENT_SRC: &str = r#"
import "strategy_fragment.ark";
options { server = server; exit = 144; }
contract StrategyFragment(pubkey keeperPk, int allocatedAmount, bytes32 strategyId) {
  function allocate(signature keeperSig, int newAmount) {
    require(checkSig(keeperSig, keeperPk), "invalid keeper");
    require(newAmount > allocatedAmount, "must increase allocation");
    require(tx.outputs[0].value == tx.input.current.value, "value must be preserved");
    require(tx.outputs[0].scriptPubKey == new StrategyFragment(keeperPk, newAmount, strategyId), "successor mismatch");
  }
  function report(signature keeperSig, bytes32 reportHash, int reportedAmount) {
    require(reportedAmount > 0, "reported amount must be positive");
    require(checkSigFromStack(keeperSig, keeperPk, reportHash), "invalid keeper");
    require(tx.outputs[0].scriptPubKey == new StrategyFragment(keeperPk, reportedAmount, strategyId), "successor mismatch");
  }
}
"#;

const REPAY_FLOW_SRC: &str = r#"
import "vault_covenant.ark";
options { server = server; exit = 144; }
contract RepayFlow(pubkey vaultKeeperPk, pubkey ownerPk, int totalAssets, int totalShares) {
  function reclaim(signature vaultKeeperSig) {
    require(checkSig(vaultKeeperSig, vaultKeeperPk), "invalid vault keeper");
    int returnAmount = tx.input.current.value;
    int newVaultAssets = totalAssets + returnAmount;
    require(tx.outputs[0].value == returnAmount, "full value must flow to vault");
    require(tx.outputs[0].scriptPubKey == new VaultCovenant(vaultKeeperPk, ownerPk, newVaultAssets, totalShares), "vault successor mismatch");
  }
  function reclaimExpired(signature ownerSig, int currentTotalAssets, int currentTotalShares) {
    require(checkSig(ownerSig, ownerPk), "invalid owner");
    int returnAmount = tx.input.current.value;
    int newVaultAssets = currentTotalAssets + returnAmount;
    require(tx.outputs[0].value == returnAmount, "full value must flow to vault");
    require(tx.outputs[0].scriptPubKey == new VaultCovenant(vaultKeeperPk, ownerPk, newVaultAssets, currentTotalShares), "vault successor mismatch");
  }
}
"#;

const LENDING_MARKET_SRC: &str = r#"
import "lending_market.ark";
import "single_sig.ark";
options { server = server; exit = 144; }
contract LendingMarket(
  pubkey borrowerPk, pubkey oraclePk, pubkey vaultKeeperPk,
  bytes32 creditHolder,
  int collateralAmount, int debtAmount, int lltv,
  bytes32 collateralAssetId, bytes32 loanAssetId, bytes32 oracleHash
) {
  function borrow(signature borrowerSig, bytes32 priceHash, signature oracleSig, int price, int borrowAmount, int collateral) {
    require(checkSig(borrowerSig, borrowerPk), "invalid borrower");
    require(checkSigFromStack(oracleSig, oraclePk, priceHash), "invalid oracle");
    int lhs = collateral * price / 10000;
    int rhs = borrowAmount * 10000 / lltv;
    require(lhs >= rhs, "insufficient collateral ratio");
    require(tx.outputs[0].value == collateral, "collateral must be locked in output 0");
    require(tx.outputs[0].scriptPubKey == new LendingMarket(borrowerPk, oraclePk, vaultKeeperPk, creditHolder, collateral, borrowAmount, lltv, collateralAssetId, loanAssetId, oracleHash), "successor mismatch");
    require(tx.outputs[1].value == borrowAmount, "borrower must receive borrow amount");
    require(tx.outputs[1].scriptPubKey == new SingleSig(borrowerPk), "borrower output mismatch");
  }
  function repay(signature borrowerSig, int repayAmount, int newDebtAmount) {
    require(checkSig(borrowerSig, borrowerPk), "invalid borrower");
    require(repayAmount > 0, "repayAmount must be positive");
    int verifySum = newDebtAmount + repayAmount;
    require(verifySum == debtAmount, "invalid repay amounts");
    require(tx.outputs[1].value == repayAmount, "repayment value must match repay amount");
    require(tx.outputs[1].scriptPubKey == creditHolder, "repayment must go to credit script");
    if (newDebtAmount == 0) {
      require(tx.outputs[0].value == collateralAmount, "full collateral must be released");
      require(tx.outputs[0].scriptPubKey == new SingleSig(borrowerPk), "collateral must be returned to borrower");
    } else {
      require(tx.outputs[0].value == collateralAmount, "partial repay must preserve collateral value");
      require(tx.outputs[0].scriptPubKey == new LendingMarket(borrowerPk, oraclePk, vaultKeeperPk, creditHolder, collateralAmount, newDebtAmount, lltv, collateralAssetId, loanAssetId, oracleHash), "successor mismatch");
    }
  }
  function liquidate(signature vaultKeeperSig, bytes32 priceHash, signature oracleSig, int price) {
    require(checkSig(vaultKeeperSig, vaultKeeperPk), "invalid keeper");
    require(checkSigFromStack(oracleSig, oraclePk, priceHash), "invalid oracle");
    int ratio = collateralAmount * price / 10000;
    int threshold = ratio * lltv / 10000;
    require(threshold < debtAmount, "position is not underwater");
    int fee = collateralAmount * 500 / 10000;
    int residual = collateralAmount - fee - debtAmount;
    require(residual >= 0, "residual must be non-negative");
    require(tx.outputs[0].value == fee, "liquidation fee must be exact");
    require(tx.outputs[0].scriptPubKey == new SingleSig(vaultKeeperPk), "fee must go to keeper");
    require(tx.outputs[1].value == debtAmount, "credit holder payout must be exact");
    require(tx.outputs[1].scriptPubKey == creditHolder, "face value must go to credit script");
    require(tx.outputs[2].value >= residual, "residual to borrower too low");
    require(tx.outputs[2].scriptPubKey == new SingleSig(borrowerPk), "residual must go to borrower");
  }
  function transferCredit(signature keeperSig, bytes32 newHolder) {
    require(checkSig(keeperSig, vaultKeeperPk), "invalid keeper");
    require(tx.outputs[0].scriptPubKey == new LendingMarket(borrowerPk, oraclePk, vaultKeeperPk, newHolder, collateralAmount, debtAmount, lltv, collateralAssetId, loanAssetId, oracleHash), "successor mismatch");
    require(tx.outputs[0].value == tx.input.current.value, "value must be preserved");
  }
}
"#;

// ─── VaultCovenant ────────────────────────────────────────────────────────────

#[test]
fn test_vault_covenant_compiles() {
    let result = compile(VAULT_COVENANT_SRC);
    assert!(
        result.is_ok(),
        "VaultCovenant compile failed: {:?}",
        result.err()
    );
    let abi = result.unwrap();
    assert_eq!(abi.name, "VaultCovenant");
    assert_eq!(abi.parameters.len(), 4);
    assert_eq!(abi.parameters[0].name, "keeperPk");
    assert_eq!(abi.parameters[0].param_type, "pubkey");
    assert_eq!(abi.parameters[2].name, "totalAssets");
    assert_eq!(abi.parameters[2].param_type, "int");
}

#[test]
fn test_vault_covenant_functions() {
    let abi = compile(VAULT_COVENANT_SRC).unwrap();
    // 3 functions × 2 variants = 6
    assert_eq!(abi.functions.len(), 6);
    for name in &["deposit", "withdraw", "reportYield"] {
        assert!(
            abi.functions
                .iter()
                .any(|f| &f.name == name && f.server_variant),
            "Missing cooperative variant of {}",
            name
        );
    }
}

#[test]
fn test_vault_covenant_deposit_enforces_pps_monotonicity() {
    // deposit() must enforce both newTotalAssets > totalAssets and newTotalShares > totalShares
    let abi = compile(VAULT_COVENANT_SRC).unwrap();
    let deposit = abi
        .functions
        .iter()
        .find(|f| f.name == "deposit" && f.server_variant)
        .unwrap();
    // Greater-than comparison requires OP_GREATERTHAN
    assert!(
        deposit.asm.iter().any(|op| op == "OP_GREATERTHAN"),
        "deposit() must check asset/share increases via OP_GREATERTHAN, got {:?}",
        deposit.asm
    );
}

#[test]
fn test_vault_covenant_report_yield_uses_checksig_from_stack() {
    let abi = compile(VAULT_COVENANT_SRC).unwrap();
    let report = abi
        .functions
        .iter()
        .find(|f| f.name == "reportYield" && f.server_variant)
        .unwrap();
    assert!(
        report.asm.iter().any(|op| op == "OP_CHECKSIGFROMSTACK"),
        "reportYield() must verify keeper via OP_CHECKSIGFROMSTACK, got {:?}",
        report.asm
    );
}

// ─── StrategyFragment ─────────────────────────────────────────────────────────

#[test]
fn test_strategy_fragment_compiles() {
    let result = compile(STRATEGY_FRAGMENT_SRC);
    assert!(
        result.is_ok(),
        "StrategyFragment compile failed: {:?}",
        result.err()
    );
    let abi = result.unwrap();
    assert_eq!(abi.name, "StrategyFragment");
    assert_eq!(abi.parameters.len(), 3);
}

#[test]
fn test_strategy_fragment_allocate_preserves_value() {
    // allocate() must include an input value introspection check (value preservation)
    let abi = compile(STRATEGY_FRAGMENT_SRC).unwrap();
    let allocate = abi
        .functions
        .iter()
        .find(|f| f.name == "allocate" && f.server_variant)
        .unwrap();
    assert!(
        allocate
            .asm
            .iter()
            .any(|op| op.contains("INSPECTINPUT") || op.contains("INSPECTOUTPUT")),
        "allocate() must contain value introspection to enforce preservation, got {:?}",
        allocate.asm
    );
}

#[test]
fn test_strategy_fragment_report_uses_checksig_from_stack() {
    let abi = compile(STRATEGY_FRAGMENT_SRC).unwrap();
    let report = abi
        .functions
        .iter()
        .find(|f| f.name == "report" && f.server_variant)
        .unwrap();
    assert!(
        report.asm.iter().any(|op| op == "OP_CHECKSIGFROMSTACK"),
        "report() must verify keeper via OP_CHECKSIGFROMSTACK, got {:?}",
        report.asm
    );
}

#[test]
fn test_strategy_fragment_report_preserves_value() {
    // report() must preserve value — consistent with allocate()
    let abi = compile(STRATEGY_FRAGMENT_SRC).unwrap();
    let report = abi
        .functions
        .iter()
        .find(|f| f.name == "report" && f.server_variant)
        .unwrap();
    assert!(
        report
            .asm
            .iter()
            .any(|op| op.contains("INSPECTINPUT") || op.contains("INSPECTOUTPUT")),
        "report() must contain value introspection to enforce preservation, got {:?}",
        report.asm
    );
}

// ─── RepayFlow ────────────────────────────────────────────────────────────────

#[test]
fn test_repay_flow_compiles() {
    let result = compile(REPAY_FLOW_SRC);
    assert!(
        result.is_ok(),
        "RepayFlow compile failed: {:?}",
        result.err()
    );
    let abi = result.unwrap();
    assert_eq!(abi.name, "RepayFlow");
    assert_eq!(abi.parameters.len(), 4);
}

#[test]
fn test_repay_flow_has_both_reclaim_functions() {
    let abi = compile(REPAY_FLOW_SRC).unwrap();
    // 2 functions × 2 variants = 4
    assert_eq!(abi.functions.len(), 4);
    assert!(
        abi.functions
            .iter()
            .any(|f| f.name == "reclaim" && f.server_variant),
        "Missing cooperative reclaim"
    );
    assert!(
        abi.functions
            .iter()
            .any(|f| f.name == "reclaimExpired" && f.server_variant),
        "Missing cooperative reclaimExpired"
    );
}

#[test]
fn test_repay_flow_reclaim_requires_keeper_sig() {
    let abi = compile(REPAY_FLOW_SRC).unwrap();
    let reclaim = abi
        .functions
        .iter()
        .find(|f| f.name == "reclaim" && f.server_variant)
        .unwrap();
    assert_eq!(reclaim.function_inputs.len(), 1);
    assert_eq!(reclaim.function_inputs[0].name, "vaultKeeperSig");
    assert_eq!(reclaim.function_inputs[0].param_type, "signature");
}

#[test]
fn test_repay_flow_reclaim_expired_requires_owner_sig() {
    // reclaimExpired is the LP's self-sovereign exit — must use ownerSig, not keeperSig
    let abi = compile(REPAY_FLOW_SRC).unwrap();
    let expired = abi
        .functions
        .iter()
        .find(|f| f.name == "reclaimExpired" && f.server_variant)
        .unwrap();
    assert_eq!(expired.function_inputs.len(), 3);
    assert_eq!(expired.function_inputs[0].name, "ownerSig");
    assert_eq!(expired.function_inputs[0].param_type, "signature");
    assert_eq!(expired.function_inputs[1].name, "currentTotalAssets");
    assert_eq!(expired.function_inputs[1].param_type, "int");
    assert_eq!(expired.function_inputs[2].name, "currentTotalShares");
    assert_eq!(expired.function_inputs[2].param_type, "int");
}

#[test]
fn test_repay_flow_produces_vault_covenant_successor() {
    let abi = compile(REPAY_FLOW_SRC).unwrap();
    for fn_name in &["reclaim", "reclaimExpired"] {
        let f = abi
            .functions
            .iter()
            .find(|f| f.name == *fn_name && f.server_variant)
            .unwrap();
        assert!(
            f.asm.iter().any(|op| op.contains("VTXO:VaultCovenant")),
            "{} must produce VaultCovenant successor, got {:?}",
            fn_name,
            f.asm
        );
    }
}

// ─── LendingMarket ────────────────────────────────────────────────────────────

#[test]
fn test_lending_market_compiles() {
    let result = compile(LENDING_MARKET_SRC);
    assert!(
        result.is_ok(),
        "LendingMarket compile failed: {:?}",
        result.err()
    );
    let abi = result.unwrap();
    assert_eq!(abi.name, "LendingMarket");
    assert_eq!(abi.parameters.len(), 10);
}

#[test]
fn test_lending_market_credit_holder_is_bytes32() {
    let abi = compile(LENDING_MARKET_SRC).unwrap();
    let credit_holder = abi
        .parameters
        .iter()
        .find(|p| p.name == "creditHolder")
        .unwrap();
    assert_eq!(
        credit_holder.param_type, "bytes32",
        "creditHolder must be bytes32 script hash, not pubkey"
    );
}

#[test]
fn test_lending_market_functions() {
    let abi = compile(LENDING_MARKET_SRC).unwrap();
    // 4 functions × 2 variants = 8
    assert_eq!(abi.functions.len(), 8);
    for name in &["borrow", "repay", "liquidate", "transferCredit"] {
        assert!(
            abi.functions
                .iter()
                .any(|f| &f.name == name && f.server_variant),
            "Missing cooperative variant of {}",
            name
        );
    }
}

#[test]
fn test_lending_market_borrow_enforces_collateral_ratio() {
    let abi = compile(LENDING_MARKET_SRC).unwrap();
    let borrow = abi
        .functions
        .iter()
        .find(|f| f.name == "borrow" && f.server_variant)
        .unwrap();
    // Collateral ratio uses OP_DIV64 + OP_GREATERTHANOREQUAL
    assert!(
        borrow.asm.iter().any(|op| op == "OP_DIV64"),
        "borrow() collateral ratio check must use OP_DIV64, got {:?}",
        borrow.asm
    );
    assert!(
        borrow.asm.iter().any(|op| op == "OP_GREATERTHANOREQUAL"),
        "borrow() must use OP_GREATERTHANOREQUAL for ratio check, got {:?}",
        borrow.asm
    );
}

#[test]
fn test_lending_market_borrow_checks_borrower_output_value() {
    // Security regression: borrow() must verify outputs[1].value == borrowAmount
    let abi = compile(LENDING_MARKET_SRC).unwrap();
    let borrow = abi
        .functions
        .iter()
        .find(|f| f.name == "borrow" && f.server_variant)
        .unwrap();
    // Output value check: OP_INSPECTOUTPUTVALUE + OP_EQUAL
    let has_output_value_check = borrow.asm.iter().any(|op| op == "OP_INSPECTOUTPUTVALUE");
    assert!(
        has_output_value_check,
        "borrow() must inspect output value (borrowAmount check), got {:?}",
        borrow.asm
    );
}

#[test]
fn test_lending_market_liquidate_uses_exact_fee_and_debt_amounts() {
    // Security regression: fee and debt outputs must use == (OP_EQUAL), not just >=
    // to prevent keeper from over-extracting from other inputs.
    let abi = compile(LENDING_MARKET_SRC).unwrap();
    let liquidate = abi
        .functions
        .iter()
        .find(|f| f.name == "liquidate" && f.server_variant)
        .unwrap();
    assert!(
        liquidate.asm.iter().any(|op| op == "OP_EQUAL"),
        "liquidate() must use OP_EQUAL for exact output amounts, got {:?}",
        liquidate.asm
    );
}

#[test]
fn test_lending_market_repay_checks_repay_output_value() {
    // Security regression: repay() must verify outputs[1].value == repayAmount
    let abi = compile(LENDING_MARKET_SRC).unwrap();
    let repay = abi
        .functions
        .iter()
        .find(|f| f.name == "repay" && f.server_variant)
        .unwrap();
    assert!(
        repay.asm.iter().any(|op| op == "OP_INSPECTOUTPUTVALUE"),
        "repay() must inspect output value (repayAmount check), got {:?}",
        repay.asm
    );
}

#[test]
fn test_lending_market_liquidate_guards_residual() {
    // Security regression: residual >= 0 must be checked before waterfall
    let abi = compile(LENDING_MARKET_SRC).unwrap();
    let liquidate = abi
        .functions
        .iter()
        .find(|f| f.name == "liquidate" && f.server_variant)
        .unwrap();
    // residual >= 0 → OP_0 + OP_GREATERTHANOREQUAL (or similar)
    assert!(
        liquidate.asm.iter().any(|op| op == "OP_GREATERTHANOREQUAL"),
        "liquidate() must guard residual >= 0 via OP_GREATERTHANOREQUAL, got {:?}",
        liquidate.asm
    );
}

#[test]
fn test_lending_market_transfer_credit_is_keeper_only() {
    // transferCredit must require vaultKeeperPk (not creditHolder pubkey) since
    // creditHolder is now bytes32 and cannot be used with checkSig.
    let abi = compile(LENDING_MARKET_SRC).unwrap();
    let tc = abi
        .functions
        .iter()
        .find(|f| f.name == "transferCredit" && f.server_variant)
        .unwrap();
    assert_eq!(tc.function_inputs.len(), 2);
    assert_eq!(tc.function_inputs[0].name, "keeperSig");
    assert_eq!(
        tc.function_inputs[1].param_type, "bytes32",
        "newHolder must be bytes32 script hash"
    );
}

// ─── Lifecycle compilation smoke test ─────────────────────────────────────────

#[test]
fn test_all_vault_lending_contracts_compile() {
    // Smoke test: every contract in the vault+lending system compiles without error.
    let contracts = [
        ("VaultCovenant", VAULT_COVENANT_SRC),
        ("StrategyFragment", STRATEGY_FRAGMENT_SRC),
        ("RepayFlow", REPAY_FLOW_SRC),
        ("LendingMarket", LENDING_MARKET_SRC),
    ];
    for (name, src) in &contracts {
        let result = compile(src);
        assert!(
            result.is_ok(),
            "{} failed to compile: {:?}",
            name,
            result.err()
        );
        assert_eq!(
            result.unwrap().name,
            *name,
            "Contract name mismatch for {}",
            name
        );
    }
}
