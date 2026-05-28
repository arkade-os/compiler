use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_ADD64, OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_DIV64, OP_INSPECTINPUTSCRIPTPUBKEY,
    OP_INSPECTOUTASSETLOOKUP, OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_INSPECTOUTPUTVALUE, OP_MUL64,
    OP_PUSHCURRENTINPUTINDEX, OP_SUB64,
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
    // 4 functions (deposit, merge, borrow, withdraw) x 2 variants = 8
    assert_eq!(output.functions.len(), 8, "expected 8 functions");
}

#[test]
fn test_usdt_asset_id_decomposed() {
    let output = compile(CODE).expect("compilation failed");
    let names: Vec<&str> = output.parameters.iter().map(|p| p.name.as_str()).collect();
    assert!(
        names.contains(&"usdtAssetId_txid") && names.contains(&"usdtAssetId_gidx"),
        "usdtAssetId not decomposed into _txid/_gidx, got: {names:?}"
    );
}

#[test]
fn test_deposit_is_fan_in_recreation() {
    // deposit grows liquidity (OP_ADD64) and re-creates the pool scriptPubKey,
    // asserting the residual holds the new USDT balance.
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "deposit");
    assert!(asm.contains(OP_ADD64), "deposit should add to liquidity");
    assert!(
        asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "deposit should re-create the pool output"
    );
    assert!(
        asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "deposit should assert the pool's USDT balance"
    );
    assert!(asm.contains(OP_CHECKSIG), "deposit needs depositor sig");
}

#[test]
fn test_merge_is_fan_in_of_two_pools() {
    // merge sums two pool balances and uses activeInputIndex to identify the
    // sibling pool input.
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "merge");
    assert!(
        asm.contains(OP_PUSHCURRENTINPUTINDEX),
        "merge should reference this.activeInputIndex"
    );
    assert!(
        asm.contains(OP_INSPECTINPUTSCRIPTPUBKEY),
        "merge should verify the sibling pool input"
    );
    assert!(asm.contains(OP_ADD64), "merge should sum liquidity");
}

#[test]
fn test_borrow_is_fan_out_with_pricing() {
    // borrow prices principal = par * (1e4 - discount) / 1e4, draws down the
    // pool (OP_SUB64), and emits residual pool + borrower payout + loan vault.
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "borrow");
    assert!(
        asm.contains(OP_MUL64) && asm.contains(OP_DIV64),
        "borrow pricing math"
    );
    assert!(asm.contains(OP_SUB64), "borrow draws down liquidity");
    assert!(
        asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "borrow should pay borrower in USDT"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTVALUE),
        "borrow should lock collateral value in the loan vault"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "borrow should pin residual pool + payout + loan vault scripts"
    );
}

#[test]
fn test_no_oracle_anywhere() {
    // This MVP defers oracle-priced liquidation; no function should verify an
    // oracle-signed message.
    let output = compile(CODE).expect("compilation failed");
    for f in &output.functions {
        let asm = f.asm.join(" ");
        assert!(
            !asm.contains(OP_CHECKSIGFROMSTACK),
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
    // The contract imports loan_vault.ark; place both side by side so the
    // import resolves the same way the examples directory is laid out.
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
