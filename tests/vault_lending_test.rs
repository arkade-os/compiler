use arkade_compiler::compile;

// ─── Source fixtures via include_str! ────────────────────────────────────────
// Tests compile the real example files rather than hand-maintained snapshots.

const VAULT_COVENANT_SRC: &str = include_str!("../examples/vault_lending/vault_covenant.ark");
const STRATEGY_FRAGMENT_SRC: &str = include_str!("../examples/vault_lending/strategy_fragment.ark");
const REPAY_FLOW_SRC: &str = include_str!("../examples/vault_lending/repay_flow.ark");
const LENDING_MARKET_SRC: &str = include_str!("../examples/vault_lending/lending_market.ark");
const COMPOSITE_ROUTER_SRC: &str = include_str!("../examples/vault_lending/composite_router.ark");
const SUPPLY_FLOW_SRC: &str = include_str!("../examples/vault_lending/supply_flow.ark");

/// Returns true if `needle` appears as a contiguous subsequence in `haystack`.
fn asm_contains_sequence(haystack: &[String], needle: &[&str]) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w.iter().zip(needle).all(|(a, b)| a == b))
}

/// Count occurrences of `op` in `asm`.
fn asm_count(asm: &[String], op: &str) -> usize {
    asm.iter().filter(|s| *s == op).count()
}

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
    // allocate() must include an output value check equal to current input value.
    // ASM pattern: OP_INSPECTOUTPUTVALUE … OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTVALUE OP_EQUAL
    let abi = compile(STRATEGY_FRAGMENT_SRC).unwrap();
    let allocate = abi
        .functions
        .iter()
        .find(|f| f.name == "allocate" && f.server_variant)
        .unwrap();
    assert!(
        asm_contains_sequence(
            &allocate.asm,
            &[
                "OP_PUSHCURRENTINPUTINDEX",
                "OP_INSPECTINPUTVALUE",
                "OP_EQUAL"
            ]
        ),
        "allocate() must verify output value == input value, got {:?}",
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
    // report() must also preserve value — consistent with allocate()
    let abi = compile(STRATEGY_FRAGMENT_SRC).unwrap();
    let report = abi
        .functions
        .iter()
        .find(|f| f.name == "report" && f.server_variant)
        .unwrap();
    assert!(
        asm_contains_sequence(
            &report.asm,
            &[
                "OP_PUSHCURRENTINPUTINDEX",
                "OP_INSPECTINPUTVALUE",
                "OP_EQUAL"
            ]
        ),
        "report() must verify output value == input value, got {:?}",
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
fn test_lending_market_borrow_guards_against_reborrow() {
    // borrow() must reject positions that already have debt or collateral.
    // ASM: <debtAmount> 0 OP_EQUAL and <collateralAmount> 0 OP_EQUAL
    let abi = compile(LENDING_MARKET_SRC).unwrap();
    let borrow = abi
        .functions
        .iter()
        .find(|f| f.name == "borrow" && f.server_variant)
        .unwrap();
    assert!(
        asm_contains_sequence(&borrow.asm, &["<debtAmount>", "0", "OP_EQUAL"]),
        "borrow() must check debtAmount == 0, got {:?}",
        borrow.asm
    );
    assert!(
        asm_contains_sequence(&borrow.asm, &["<collateralAmount>", "0", "OP_EQUAL"]),
        "borrow() must check collateralAmount == 0, got {:?}",
        borrow.asm
    );
}

#[test]
fn test_lending_market_borrow_enforces_value_conservation() {
    // borrow() must verify tx.input.current.value == borrowAmount.
    // ASM: OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTVALUE <borrowAmount> OP_EQUAL
    let abi = compile(LENDING_MARKET_SRC).unwrap();
    let borrow = abi
        .functions
        .iter()
        .find(|f| f.name == "borrow" && f.server_variant)
        .unwrap();
    assert!(
        asm_contains_sequence(
            &borrow.asm,
            &[
                "OP_PUSHCURRENTINPUTINDEX",
                "OP_INSPECTINPUTVALUE",
                "<borrowAmount>",
                "OP_EQUAL"
            ]
        ),
        "borrow() must verify input value == borrowAmount, got {:?}",
        borrow.asm
    );
}

#[test]
fn test_lending_market_borrow_enforces_collateral_ratio() {
    let abi = compile(LENDING_MARKET_SRC).unwrap();
    let borrow = abi
        .functions
        .iter()
        .find(|f| f.name == "borrow" && f.server_variant)
        .unwrap();
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
    // borrow() must verify outputs[1].value == borrowAmount.
    // ASM: 1 OP_INSPECTOUTPUTVALUE <borrowAmount> OP_EQUAL
    let abi = compile(LENDING_MARKET_SRC).unwrap();
    let borrow = abi
        .functions
        .iter()
        .find(|f| f.name == "borrow" && f.server_variant)
        .unwrap();
    assert!(
        asm_contains_sequence(
            &borrow.asm,
            &["1", "OP_INSPECTOUTPUTVALUE", "<borrowAmount>", "OP_EQUAL"]
        ),
        "borrow() must check outputs[1].value == borrowAmount, got {:?}",
        borrow.asm
    );
}

#[test]
fn test_lending_market_repay_checks_repay_output_value() {
    // repay() must verify outputs[1].value == repayAmount.
    // ASM: 1 OP_INSPECTOUTPUTVALUE <repayAmount> OP_EQUAL
    let abi = compile(LENDING_MARKET_SRC).unwrap();
    let repay = abi
        .functions
        .iter()
        .find(|f| f.name == "repay" && f.server_variant)
        .unwrap();
    assert!(
        asm_contains_sequence(
            &repay.asm,
            &["1", "OP_INSPECTOUTPUTVALUE", "<repayAmount>", "OP_EQUAL"]
        ),
        "repay() must check outputs[1].value == repayAmount, got {:?}",
        repay.asm
    );
}

#[test]
fn test_lending_market_liquidate_uses_exact_fee_and_debt_amounts() {
    // Fee output (index 0) and debt output (index 1) must use exact OP_EQUAL.
    // ASM: 0 OP_INSPECTOUTPUTVALUE <fee> OP_EQUAL
    //      1 OP_INSPECTOUTPUTVALUE <debtAmount> OP_EQUAL
    let abi = compile(LENDING_MARKET_SRC).unwrap();
    let liquidate = abi
        .functions
        .iter()
        .find(|f| f.name == "liquidate" && f.server_variant)
        .unwrap();
    assert!(
        asm_contains_sequence(
            &liquidate.asm,
            &["0", "OP_INSPECTOUTPUTVALUE", "<fee>", "OP_EQUAL"]
        ),
        "liquidate() must check outputs[0].value == fee exactly, got {:?}",
        liquidate.asm
    );
    assert!(
        asm_contains_sequence(
            &liquidate.asm,
            &["1", "OP_INSPECTOUTPUTVALUE", "<debtAmount>", "OP_EQUAL"]
        ),
        "liquidate() must check outputs[1].value == debtAmount exactly, got {:?}",
        liquidate.asm
    );
    // Total OP_EQUAL count: at least 2 for the exact checks above
    let equal_count = asm_count(&liquidate.asm, "OP_EQUAL");
    assert!(
        equal_count >= 2,
        "liquidate() must have >= 2 OP_EQUAL (got {})",
        equal_count
    );
}

#[test]
fn test_lending_market_liquidate_guards_residual() {
    // residual >= 0 must appear before the output waterfall.
    // ASM: <residual> OP_GREATERTHANOREQUAL 0
    let abi = compile(LENDING_MARKET_SRC).unwrap();
    let liquidate = abi
        .functions
        .iter()
        .find(|f| f.name == "liquidate" && f.server_variant)
        .unwrap();
    assert!(
        asm_contains_sequence(
            &liquidate.asm,
            &["<residual>", "OP_GREATERTHANOREQUAL", "0"]
        ),
        "liquidate() must check residual >= 0, got {:?}",
        liquidate.asm
    );
}

#[test]
fn test_lending_market_transfer_credit_is_keeper_only() {
    // transferCredit must check keeper sig and debtAmount == 0 (blocks rotation on open positions)
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
    // Must block rotation on open positions: <debtAmount> 0 OP_EQUAL
    assert!(
        asm_contains_sequence(&tc.asm, &["<debtAmount>", "0", "OP_EQUAL"]),
        "transferCredit() must check debtAmount == 0, got {:?}",
        tc.asm
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
        ("CompositeRouter", COMPOSITE_ROUTER_SRC),
        ("SupplyFlow", SUPPLY_FLOW_SRC),
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
