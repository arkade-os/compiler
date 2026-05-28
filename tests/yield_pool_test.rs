use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKSIG, OP_DIV64, OP_FINDASSETGROUPBYASSETID, OP_INSPECTASSETGROUPCTRL,
    OP_INSPECTASSETGROUPSUM, OP_INSPECTOUTASSETLOOKUP, OP_INSPECTOUTPUTSCRIPTPUBKEY,
    OP_LESSTHANOREQUAL, OP_MUL64,
};

const CODE: &str = include_str!("../examples/lending/yield_pool.ark");

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
fn test_yield_pool_compiles() {
    let output = compile(CODE).expect("compilation failed");
    assert_eq!(output.name, "YieldPool");
    // 4 functions (deposit, withdraw, borrow, repay) x 2 variants = 8
    assert_eq!(output.functions.len(), 8, "expected 8 functions");

    let names: Vec<&str> = output.parameters.iter().map(|p| p.name.as_str()).collect();
    for id in ["usdtAssetId", "shareAssetId", "shareCtrlId"] {
        assert!(
            names.contains(&format!("{id}_txid").as_str())
                && names.contains(&format!("{id}_gidx").as_str()),
            "{id} not decomposed into _txid/_gidx, got: {names:?}"
        );
    }
}

#[test]
fn test_deposit_accrues_and_mints_shares() {
    // deposit accrues interest (debt * rate * elapsed -> OP_MUL64), prices shares
    // (amount * totalShares / assetsNext -> OP_DIV64), and mints exactly that many
    // shares gated by the control asset.
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "deposit");
    assert!(
        asm.contains(OP_MUL64),
        "deposit accrual + share pricing math"
    );
    assert!(
        asm.contains(OP_DIV64),
        "deposit share pricing divides by assets"
    );
    assert!(
        asm.contains(OP_FINDASSETGROUPBYASSETID),
        "deposit inspects the share asset group"
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
fn test_withdraw_is_conditional_on_idle_liquidity() {
    // The yield/liquidity tradeoff: a withdrawal is bounded by idle liquidity
    // (amount <= totalIdle -> OP_LESSTHANOREQUAL) and burns LP shares
    // (sumInputs >= sumOutputs + shares -> OP_INSPECTASSETGROUPSUM).
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "withdraw");
    assert!(
        asm.contains(OP_LESSTHANOREQUAL),
        "withdraw must bound payout by idle liquidity"
    );
    assert!(
        asm.contains(OP_INSPECTASSETGROUPSUM),
        "withdraw must burn LP shares"
    );
    assert!(
        asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "withdraw pays out USDT"
    );
}

#[test]
fn test_borrow_accrues_and_is_liquidity_bounded() {
    // borrow accrues interest first (OP_MUL64) and is bounded by idle liquidity.
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "borrow");
    assert!(asm.contains(OP_MUL64), "borrow accrues interest");
    assert!(
        asm.contains(OP_LESSTHANOREQUAL),
        "borrow bounded by idle liquidity"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "borrow re-creates the pool covenant"
    );
}

#[test]
fn test_all_functions_accrue_interest() {
    // Every spend rolls debt forward by rate * elapsed, so OP_MUL64 (the interest
    // multiply) must appear in all four functions.
    let output = compile(CODE).expect("compilation failed");
    for name in ["deposit", "withdraw", "borrow", "repay"] {
        assert!(
            asm_of(&output, name).contains(OP_MUL64),
            "{name} should accrue interest"
        );
    }
}

#[test]
fn test_yield_pool_cli() {
    use std::fs;
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let input = dir.path().join("yield_pool.ark");
    fs::write(&input, CODE).unwrap();
    let out = dir.path().join("yield_pool.json");

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
    assert!(json.contains("\"contractName\": \"YieldPool\""));
}
