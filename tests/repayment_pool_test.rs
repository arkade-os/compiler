use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CAT, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_DIV64,
    OP_FINDASSETGROUPBYASSETID, OP_INSPECTASSETGROUPCTRL, OP_INSPECTASSETGROUPSUM,
    OP_INSPECTINPUTSCRIPTPUBKEY, OP_INSPECTOUTASSETLOOKUP, OP_INSPECTOUTPUTSCRIPTPUBKEY,
    OP_INSPECTOUTPUTVALUE, OP_LESSTHAN, OP_LESSTHANOREQUAL, OP_MUL64, OP_SHA256,
};

const CODE: &str = include_str!("../examples/bonds/repayment_pool.ark");

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
fn test_repayment_pool_compiles() {
    let output = compile(CODE).expect("compilation failed");
    assert_eq!(output.name, "RepaymentPool");
    // 4 functions (issue, acceptRepayment, acceptAuction, redeem) x 2 = 8
    assert_eq!(output.functions.len(), 8, "expected 8 functions");

    let names: Vec<&str> = output.parameters.iter().map(|p| p.name.as_str()).collect();
    for id in [
        "usdtAssetId",
        "creditAssetId",
        "creditCtrlId",
        "debitAssetId",
        "debitCtrlId",
    ] {
        assert!(
            names.contains(&format!("{id}_txid").as_str())
                && names.contains(&format!("{id}_gidx").as_str()),
            "{id} not decomposed, got: {names:?}"
        );
    }
}

#[test]
fn test_issue_is_oracle_priced_and_dual_mints() {
    // issue verifies an oracle-signed price (OP_CHECKSIGFROMSTACK over
    // sha256(ticker||price||time) -> OP_SHA256 + OP_CAT), enforces the
    // origination collateral ratio (OP_MUL64/OP_DIV64 + OP_LESSTHANOREQUAL),
    // mints exactly `amount` of BOTH credit and debit (gated by their controls),
    // and pins the credit + BondMint outputs.
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "issue");
    assert!(
        asm.contains(OP_CHECKSIGFROMSTACK),
        "issue verifies oracle sig"
    );
    assert!(
        asm.contains(OP_SHA256) && asm.contains(OP_CAT),
        "issue rebuilds oracle msg"
    );
    assert!(
        asm.contains(OP_MUL64) && asm.contains(OP_DIV64),
        "issue computes collateral value"
    );
    assert!(
        asm.contains(OP_LESSTHANOREQUAL),
        "issue enforces origination ratio"
    );
    assert!(
        asm.contains(OP_FINDASSETGROUPBYASSETID) && asm.contains(OP_INSPECTASSETGROUPCTRL),
        "issue mints credit + debit gated by control assets"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "issue pins pool + credit + vault outputs"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTVALUE),
        "issue locks collateral in the vault"
    );
    assert!(asm.contains(OP_CHECKSIG), "issue needs borrower sig");
}

#[test]
fn test_accept_repayment_validates_vault_and_burns_debit() {
    // acceptRepayment reconstructs the BondMint at vaultIdx
    // (OP_INSPECTINPUTSCRIPTPUBKEY), burns the vault's debit
    // (OP_INSPECTASSETGROUPSUM), credits usdtBalance, and returns the collateral.
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "acceptRepayment");
    assert!(
        asm.contains(OP_INSPECTINPUTSCRIPTPUBKEY),
        "acceptRepayment validates the BondMint input"
    );
    assert!(
        asm.contains(OP_INSPECTASSETGROUPSUM),
        "acceptRepayment burns the debit"
    );
    assert!(
        asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "acceptRepayment routes USDT into the pool"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTVALUE),
        "acceptRepayment returns collateral"
    );
    assert!(
        asm.contains(OP_LESSTHAN),
        "acceptRepayment gated on tx.time < maturity"
    );
}

#[test]
fn test_accept_auction_is_oracle_priced_and_branches() {
    // acceptAuction verifies the oracle (OP_CHECKSIGFROMSTACK), validates the
    // BondMint input (OP_INSPECTINPUTSCRIPTPUBKEY), burns its debit, and pays
    // USDT in / collateral out via the oracle-priced split.
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "acceptAuction");
    assert!(
        asm.contains(OP_CHECKSIGFROMSTACK),
        "acceptAuction verifies oracle sig"
    );
    assert!(
        asm.contains(OP_SHA256) && asm.contains(OP_CAT),
        "acceptAuction rebuilds oracle msg"
    );
    assert!(
        asm.contains(OP_INSPECTINPUTSCRIPTPUBKEY),
        "acceptAuction validates the BondMint input"
    );
    assert!(
        asm.contains(OP_INSPECTASSETGROUPSUM),
        "acceptAuction burns the debit"
    );
    assert!(
        asm.contains(OP_MUL64) && asm.contains(OP_DIV64),
        "acceptAuction computes collateralValue and the sat split"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTVALUE),
        "acceptAuction pays collateral sats out"
    );
    assert!(asm.contains(OP_CHECKSIG), "acceptAuction needs keeper sig");
}

#[test]
fn test_redeem_is_pro_rata() {
    // redeem pays `amount * usdtBalance / totalCreditOutstanding` (OP_MUL64 +
    // OP_DIV64), burns the credit (OP_INSPECTASSETGROUPSUM), and re-creates the
    // pool with usdt and credit drained pro-rata.
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "redeem");
    assert!(
        asm.contains(OP_MUL64) && asm.contains(OP_DIV64),
        "redeem computes pro-rata payout"
    );
    assert!(
        asm.contains(OP_INSPECTASSETGROUPSUM),
        "redeem burns the credit"
    );
    assert!(
        asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "redeem pays USDT to the holder"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "redeem re-creates the pool covenant"
    );
    assert!(asm.contains(OP_CHECKSIG), "redeem needs holder sig");
}

#[test]
fn test_no_interest_rate_anywhere() {
    // The bond discount IS the yield (set by the order book), so no function
    // accrues a time-based rate. There must be no offchainTime *
    // ratePerSec-style multiplication wired through every function the way it
    // was in the old LendingPool. We sanity-check by ensuring there is no
    // function whose comment-level intent ("interest"/"accrual") appears, which
    // we approximate at the asm level by confirming none of the contracts
    // carries a single accrual constant: the contract intentionally has no
    // ratePerSec constructor input.
    let output = compile(CODE).expect("compilation failed");
    let names: Vec<&str> = output.parameters.iter().map(|p| p.name.as_str()).collect();
    assert!(
        !names.contains(&"ratePerSec") && !names.contains(&"lastAccrual"),
        "RepaymentPool must not carry interest-rate state, got: {names:?}"
    );
}

#[test]
fn test_exit_variant_is_unilateral_fallback() {
    let output = compile(CODE).expect("compilation failed");
    for name in ["issue", "acceptRepayment", "acceptAuction", "redeem"] {
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
            !asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY) && !asm.contains(OP_INSPECTASSETGROUPSUM),
            "{name} exit variant must not carry covenant introspection"
        );
    }
}

#[test]
fn test_repayment_pool_cli() {
    use std::fs;
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("bond_mint.ark"),
        include_str!("../examples/bonds/bond_mint.ark"),
    )
    .unwrap();
    let input = dir.path().join("repayment_pool.ark");
    fs::write(&input, CODE).unwrap();
    let out = dir.path().join("repayment_pool.json");

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
    assert!(json.contains("\"contractName\": \"RepaymentPool\""));
}
