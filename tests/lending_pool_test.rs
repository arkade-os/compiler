use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_DIV64, OP_FINDASSETGROUPBYASSETID,
    OP_INSPECTASSETGROUPCTRL, OP_INSPECTASSETGROUPSUM, OP_INSPECTOUTASSETLOOKUP,
    OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_INSPECTOUTPUTVALUE, OP_LESSTHANOREQUAL, OP_MUL64,
};

const CODE: &str = include_str!("../examples/lending/lending_pool.ark");

fn asm_of(output: &arkade_compiler::models::ContractJson, name: &str) -> String {
    output
        .functions
        .iter()
        .find(|f| f.name == name && f.server_variant)
        .unwrap_or_else(|| panic!("{name} server variant not found"))
        .asm
        .join(" ")
}

#[test]
fn test_lending_pool_compiles() {
    let output = compile(CODE).expect("compilation failed");
    assert_eq!(output.name, "LendingPool");
    // 4 functions (deposit, withdraw, fillBond, settle) x 2 variants = 8
    assert_eq!(output.functions.len(), 8, "expected 8 functions");

    let names: Vec<&str> = output.parameters.iter().map(|p| p.name.as_str()).collect();
    for id in [
        "usdtAssetId",
        "shareAssetId",
        "shareCtrlId",
        "bondAssetId",
        "bondCtrlId",
    ] {
        assert!(
            names.contains(&format!("{id}_txid").as_str())
                && names.contains(&format!("{id}_gidx").as_str()),
            "{id} not decomposed into _txid/_gidx, got: {names:?}"
        );
    }
}

#[test]
fn test_deposit_accrues_and_mints_shares() {
    // deposit accrues interest (OP_MUL64), prices shares (OP_DIV64), and mints
    // shares gated by the control asset.
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "deposit");
    assert!(
        asm.contains(OP_MUL64) && asm.contains(OP_DIV64),
        "accrual + share pricing"
    );
    assert!(
        asm.contains(OP_INSPECTASSETGROUPCTRL),
        "deposit enforces the share control asset"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "deposit re-creates the pool covenant"
    );
    assert!(asm.contains(OP_CHECKSIG), "deposit needs lender sig");
}

#[test]
fn test_withdraw_conditional_on_idle_liquidity() {
    // Yield/liquidity tradeoff: withdrawal bounded by idle (OP_LESSTHANOREQUAL),
    // shares burned (OP_INSPECTASSETGROUPSUM).
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "withdraw");
    assert!(asm.contains(OP_LESSTHANOREQUAL), "withdraw bounded by idle");
    assert!(
        asm.contains(OP_INSPECTASSETGROUPSUM),
        "withdraw burns shares"
    );
    assert!(asm.contains(OP_INSPECTOUTASSETLOOKUP), "withdraw pays USDT");
}

#[test]
fn test_fill_bond_is_atomic() {
    // The centerpiece: fillBond atomically (1) accrues interest + draws principal
    // out of idle (OP_MUL64/OP_DIV64 + OP_LESSTHANOREQUAL), (2) mints the bond
    // gated by control (OP_FINDASSETGROUPBYASSETID + OP_INSPECTASSETGROUPCTRL),
    // (3) pays the borrower in USDT + delivers the bond (OP_INSPECTOUTASSETLOOKUP),
    // (4) locks collateral (OP_INSPECTOUTPUTVALUE), and (5) re-creates the residual
    // pool + LoanVault (OP_INSPECTOUTPUTSCRIPTPUBKEY) — all in one function.
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "fillBond");
    assert!(
        asm.contains(OP_MUL64) && asm.contains(OP_DIV64),
        "accrual + pricing"
    );
    assert!(
        asm.contains(OP_LESSTHANOREQUAL),
        "fillBond draws from idle, bounded by available liquidity"
    );
    assert!(
        asm.contains(OP_FINDASSETGROUPBYASSETID) && asm.contains(OP_INSPECTASSETGROUPCTRL),
        "fillBond mints the bond gated by its control asset"
    );
    assert!(
        asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "fillBond pays borrower USDT and delivers the bond"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTVALUE),
        "fillBond locks collateral in the loan vault"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "fillBond pins residual pool + borrower + bond dest + loan vault"
    );
    assert!(asm.contains(OP_CHECKSIG), "fillBond needs borrower sig");
}

#[test]
fn test_settle_folds_repayment_back() {
    // settle returns repaid USDT to idle and removes principal from totalLent,
    // re-creating the pool; surplus is realized lender yield.
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "settle");
    assert!(
        asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "settle restores pool USDT"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "settle re-creates the pool covenant"
    );
    assert!(asm.contains(OP_CHECKSIG), "settle needs keeper sig");
}

#[test]
fn test_all_functions_accrue_interest() {
    let output = compile(CODE).expect("compilation failed");
    for name in ["deposit", "withdraw", "fillBond", "settle"] {
        assert!(
            asm_of(&output, name).contains(OP_MUL64),
            "{name} should accrue interest"
        );
    }
}

#[test]
fn test_no_oracle_in_mvp() {
    // Oracle-priced liquidation is the deferred follow-up; nothing here verifies
    // an oracle-signed message yet.
    let output = compile(CODE).expect("compilation failed");
    for f in &output.functions {
        assert!(
            !f.asm.join(" ").contains(OP_CHECKSIGFROMSTACK),
            "{} unexpectedly uses an oracle signature",
            f.name
        );
    }
}

#[test]
fn test_lending_pool_cli() {
    use std::fs;
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    // The contract imports loan_vault.ark; place both side by side.
    fs::write(
        dir.path().join("loan_vault.ark"),
        include_str!("../examples/lending/loan_vault.ark"),
    )
    .unwrap();
    let input = dir.path().join("lending_pool.ark");
    fs::write(&input, CODE).unwrap();
    let out = dir.path().join("lending_pool.json");

    let result = std::process::Command::new(env!("CARGO_BIN_EXE_arkadec"))
        .arg(input.to_str().unwrap())
        .arg("-o")
        .arg(out.to_str().unwrap())
        .output()
        .expect("failed to run arkadec");

    assert!(
        result.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let json = fs::read_to_string(&out).unwrap();
    assert!(json.contains("\"contractName\": \"LendingPool\""));
}
