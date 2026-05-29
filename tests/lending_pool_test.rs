use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKSIG, OP_DIV64, OP_FINDASSETGROUPBYASSETID, OP_INSPECTASSETGROUPCTRL,
    OP_INSPECTASSETGROUPSUM, OP_INSPECTINPUTSCRIPTPUBKEY, OP_INSPECTOUTASSETLOOKUP,
    OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_INSPECTOUTPUTVALUE, OP_LESSTHAN, OP_LESSTHANOREQUAL, OP_MUL64,
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
    // 5 functions (deposit, withdraw, fillBond, repayLoan, settle) x 2 variants = 10
    assert_eq!(output.functions.len(), 10, "expected 10 functions");

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
fn test_deposit_mints_shares_at_price() {
    // deposit prices shares off totalAssets (amount * totalShares / assetsNext ->
    // OP_MUL64/OP_DIV64) and mints them gated by the control asset. There is no
    // time-based accrual (yield is the bond discount, realized at repayLoan).
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "deposit");
    assert!(
        asm.contains(OP_MUL64) && asm.contains(OP_DIV64),
        "share pricing math"
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
    // The centerpiece: fillBond atomically (1) computes principal from the
    // discount + draws it out of idle (OP_MUL64/OP_DIV64 + OP_LESSTHANOREQUAL),
    // (2) mints the bond gated by control (OP_FINDASSETGROUPBYASSETID +
    // OP_INSPECTASSETGROUPCTRL), (3) pays the borrower in USDT + delivers the bond
    // (OP_INSPECTOUTASSETLOOKUP), (4) locks collateral (OP_INSPECTOUTPUTVALUE),
    // and (5) re-creates the residual pool + LoanVault
    // (OP_INSPECTOUTPUTSCRIPTPUBKEY) — all in one function.
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "fillBond");
    assert!(
        asm.contains(OP_MUL64) && asm.contains(OP_DIV64),
        "principal-from-discount math"
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
    assert!(
        asm.contains(OP_LESSTHAN),
        "fillBond refuses an already-matured pool"
    );
    assert!(asm.contains(OP_CHECKSIG), "fillBond needs borrower sig");
}

#[test]
fn test_repay_loan_is_atomic() {
    // Atomic repay+settle: repayLoan validates the LoanVault input by
    // reconstructing its scriptPubKey (OP_INSPECTINPUTSCRIPTPUBKEY), burns the
    // bond (OP_INSPECTASSETGROUPSUM), returns par to the pool
    // (OP_INSPECTOUTASSETLOOKUP) while re-creating it with lent-=principal
    // (OP_MUL64/OP_DIV64 + OP_INSPECTOUTPUTSCRIPTPUBKEY), and returns collateral
    // to the borrower (OP_INSPECTOUTPUTVALUE) — all in one transaction.
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "repayLoan");
    assert!(
        asm.contains(OP_INSPECTINPUTSCRIPTPUBKEY),
        "repayLoan validates the LoanVault input"
    );
    assert!(
        asm.contains(OP_INSPECTASSETGROUPSUM),
        "repayLoan burns the bond"
    );
    assert!(
        asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "repayLoan returns par to the pool"
    );
    assert!(
        asm.contains(OP_MUL64) && asm.contains(OP_DIV64),
        "repayLoan computes principal from the discount"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTVALUE),
        "repayLoan returns collateral to the borrower"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "repayLoan re-creates the pool + pins collateral dest"
    );
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
