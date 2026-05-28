use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKLOCKTIMEVERIFY, OP_CHECKSIG, OP_INSPECTASSETGROUPSUM, OP_INSPECTOUTASSETLOOKUP,
    OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_INSPECTOUTPUTVALUE, OP_LESSTHAN,
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
    // 2 functions (repay, claimDefault) x 2 variants = 4
    assert_eq!(output.functions.len(), 4, "expected 4 functions");

    let names: Vec<&str> = output.parameters.iter().map(|p| p.name.as_str()).collect();
    for id in ["usdtAssetId", "bondAssetId"] {
        assert!(
            names.contains(&format!("{id}_txid").as_str())
                && names.contains(&format!("{id}_gidx").as_str()),
            "{id} not decomposed, got: {names:?}"
        );
    }
}

#[test]
fn test_repay_before_maturity_burns_bond_pays_par_returns_collateral() {
    // repay is gated on tx.time < maturity (OP_LESSTHAN), burns the bond
    // (OP_INSPECTASSETGROUPSUM), pays par USDT to the keeper, and returns the
    // collateral sats to the borrower.
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "repay");
    assert!(
        asm.contains(OP_LESSTHAN),
        "repay gated on tx.time < maturity"
    );
    assert!(
        asm.contains(OP_INSPECTASSETGROUPSUM),
        "repay burns the bond"
    );
    assert!(
        asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "repay pays par USDT"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTVALUE),
        "repay returns collateral"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "repay pins keeper + borrower"
    );
    assert!(asm.contains(OP_CHECKSIG), "repay needs borrower sig");
}

#[test]
fn test_claim_default_after_maturity_burns_bond_seizes_collateral() {
    // claimDefault is gated on tx.time >= maturity (OP_CHECKLOCKTIMEVERIFY),
    // burns the bond, and sends the collateral to the keeper.
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
    assert!(
        asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "claimDefault pins keeper output"
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
