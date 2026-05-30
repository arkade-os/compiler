use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_INSPECTASSETGROUPSUM, OP_INSPECTINASSETLOOKUP,
    OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_INSPECTOUTPUTVALUE, OP_LESSTHAN,
};

const CODE: &str = include_str!("../examples/lending/bond_mint.ark");

fn asm_of(output: &arkade_compiler::models::ContractJson, name: &str) -> String {
    asm_variant(output, name, true)
}

fn asm_variant(output: &arkade_compiler::models::ContractJson, name: &str, server: bool) -> String {
    output
        .functions
        .iter()
        .find(|f| f.name == name && f.server_variant == server)
        .unwrap_or_else(|| panic!("{name} (server={server}) variant not found"))
        .asm
        .join(" ")
}

#[test]
fn test_bond_mint_compiles() {
    let output = compile(CODE).expect("compilation failed");
    assert_eq!(output.name, "BondMint");
    // 2 functions (repay, auction) x 2 variants = 4
    assert_eq!(output.functions.len(), 4, "expected 4 functions");

    let names: Vec<&str> = output.parameters.iter().map(|p| p.name.as_str()).collect();
    for id in ["debitAssetId", "debitCtrlId"] {
        assert!(
            names.contains(&format!("{id}_txid").as_str())
                && names.contains(&format!("{id}_gidx").as_str()),
            "{id} not decomposed, got: {names:?}"
        );
    }
}

#[test]
fn test_repay_is_atomic_with_pool() {
    // repay is co-spent with RepaymentPool.acceptRepayment: it identifies the
    // genuine pool by debitCtrlId custody (OP_INSPECTINASSETLOOKUP on the pool
    // input), burns the vault's debit (OP_INSPECTASSETGROUPSUM), returns the
    // collateral (OP_INSPECTOUTPUTVALUE + OP_INSPECTOUTPUTSCRIPTPUBKEY), and is
    // gated to pre-maturity (OP_LESSTHAN on tx.time).
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "repay");
    assert!(
        asm.contains(OP_INSPECTINASSETLOOKUP),
        "repay verifies the pool is co-spent"
    );
    assert!(
        asm.contains(OP_INSPECTASSETGROUPSUM),
        "repay burns the debit"
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
fn test_auction_is_atomic_with_pool_after_maturity() {
    // auction co-spends acceptAuction post-maturity, burns the debit, and pins
    // the collateral output to the keeper. The oracle/USDT math lives on the
    // pool side; this script authorizes the spend (keeperSig).
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "auction");
    assert!(
        asm.contains(OP_INSPECTINASSETLOOKUP),
        "auction verifies the pool is co-spent"
    );
    assert!(
        asm.contains(OP_INSPECTASSETGROUPSUM),
        "auction burns the debit"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "auction pins the collateral dest to keeper"
    );
    assert!(asm.contains(OP_CHECKSIG), "auction needs keeper sig");
}

#[test]
fn test_exit_variant_is_unilateral_fallback() {
    // Non-server variant is the unilateral exit (N-of-N CHECKSIG + CSV),
    // carries no introspection by design.
    let output = compile(CODE).expect("compilation failed");
    for name in ["repay", "auction"] {
        let asm = asm_variant(&output, name, false);
        assert!(
            asm.contains(OP_CHECKSEQUENCEVERIFY),
            "{name} exit variant must be CSV-timelocked"
        );
        assert!(
            asm.contains(OP_CHECKSIG),
            "{name} exit variant must check sigs"
        );
        assert!(
            !asm.contains(OP_INSPECTOUTPUTVALUE) && !asm.contains(OP_INSPECTASSETGROUPSUM),
            "{name} exit variant must not carry covenant introspection"
        );
    }
}

#[test]
fn test_bond_mint_cli() {
    use std::fs;
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let input = dir.path().join("bond_mint.ark");
    fs::write(&input, CODE).unwrap();
    let out = dir.path().join("bond_mint.json");

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
    assert!(json.contains("\"contractName\": \"BondMint\""));
}
