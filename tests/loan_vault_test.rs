use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CAT, OP_CHECKLOCKTIMEVERIFY, OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_DIV64,
    OP_INSPECTASSETGROUPSUM, OP_INSPECTINASSETLOOKUP, OP_INSPECTOUTPUTSCRIPTPUBKEY,
    OP_INSPECTOUTPUTVALUE, OP_LESSTHAN, OP_MUL64, OP_SHA256,
};

const CODE: &str = include_str!("../examples/lending/loan_vault.ark");

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
fn test_loan_vault_compiles() {
    let output = compile(CODE).expect("compilation failed");
    assert_eq!(output.name, "LoanVault");
    // 3 functions (repay, liquidate, claimDefault) x 2 variants = 6
    assert_eq!(output.functions.len(), 6, "expected 6 functions");

    // bondAssetId/bondCtrlId are used in asset lookups, so they decompose.
    let names: Vec<&str> = output.parameters.iter().map(|p| p.name.as_str()).collect();
    for id in ["bondAssetId", "bondCtrlId"] {
        assert!(
            names.contains(&format!("{id}_txid").as_str())
                && names.contains(&format!("{id}_gidx").as_str()),
            "{id} not decomposed, got: {names:?}"
        );
    }
}

#[test]
fn test_repay_is_atomic_with_pool() {
    // repay co-spends the genuine pool (identified by custody of the unique bond
    // control asset -> OP_INSPECTINASSETLOOKUP on the pool input), burns the bond
    // (OP_INSPECTASSETGROUPSUM), returns collateral to the borrower
    // (OP_INSPECTOUTPUTVALUE), and is gated before maturity (OP_LESSTHAN). par is
    // routed into the pool by the co-spent LendingPool.repayLoan, so this script
    // does NOT itself pay out USDT.
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "repay");
    assert!(
        asm.contains(OP_INSPECTINASSETLOOKUP),
        "repay verifies the pool is co-spent"
    );
    assert!(
        asm.contains(OP_INSPECTASSETGROUPSUM),
        "repay burns the bond"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTVALUE),
        "repay returns collateral"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "repay pins the collateral dest"
    );
    assert!(
        asm.contains(OP_LESSTHAN),
        "repay gated on tx.time < maturity"
    );
    assert!(asm.contains(OP_CHECKSIG), "repay needs borrower sig");
}

#[test]
fn test_liquidate_uses_oracle_price() {
    // Pre-maturity liquidation verifies an oracle-signed price
    // (OP_CHECKSIGFROMSTACK over sha256(ticker||price||time) -> OP_SHA256 + OP_CAT),
    // computes collateral value and compares to the threshold (OP_MUL64/OP_DIV64 +
    // OP_LESSTHAN), burns the bond, and seizes collateral to the keeper.
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "liquidate");
    assert!(
        asm.contains(OP_CHECKSIGFROMSTACK),
        "liquidate verifies oracle signature"
    );
    assert!(
        asm.contains(OP_SHA256) && asm.contains(OP_CAT),
        "liquidate rebuilds oracle msg"
    );
    assert!(
        asm.contains(OP_MUL64) && asm.contains(OP_DIV64),
        "liquidate computes collateral value"
    );
    assert!(
        asm.contains(OP_LESSTHAN),
        "liquidate checks collateralValue < threshold"
    );
    assert!(
        asm.contains(OP_INSPECTASSETGROUPSUM),
        "liquidate burns the bond"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTVALUE),
        "liquidate seizes collateral"
    );
    assert!(asm.contains(OP_CHECKSIG), "liquidate needs keeper sig");
}

#[test]
fn test_claim_default_after_maturity() {
    // claimDefault is gated on tx.time >= maturity (OP_CHECKLOCKTIMEVERIFY), burns
    // the bond, and sends the collateral to the keeper.
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "claimDefault");
    assert!(
        asm.contains(OP_CHECKLOCKTIMEVERIFY),
        "claimDefault enforces tx.time >= maturity"
    );
    assert!(
        asm.contains(OP_INSPECTASSETGROUPSUM),
        "claimDefault burns the bond"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTVALUE),
        "claimDefault seizes collateral"
    );
    assert!(asm.contains(OP_CHECKSIG), "claimDefault needs keeper sig");
}

#[test]
fn test_loan_vault_cli() {
    use std::fs;
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let input = dir.path().join("loan_vault.ark");
    fs::write(&input, CODE).unwrap();
    let out = dir.path().join("loan_vault.json");

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
    assert!(json.contains("\"contractName\": \"LoanVault\""));
}
