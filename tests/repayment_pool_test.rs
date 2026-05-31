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

fn witness_names(output: &arkade_compiler::models::ContractJson, name: &str) -> Vec<String> {
    output
        .functions
        .iter()
        .find(|f| f.name == name && f.server_variant)
        .unwrap()
        .witness_schema
        .iter()
        .map(|w| w.name.clone())
        .collect()
}

/// The `require(...)` messages emitted by a function's server variant.
fn requirements(output: &arkade_compiler::models::ContractJson, name: &str) -> Vec<String> {
    output
        .functions
        .iter()
        .find(|f| f.name == name && f.server_variant)
        .unwrap()
        .require
        .clone()
}

#[test]
fn test_repayment_pool_compiles() {
    let output = compile(CODE).expect("compilation failed");
    assert_eq!(output.name, "RepaymentPool");
    // 5 functions (issue, acceptRepayment, liquidate, acceptAuction, redeem)
    // × 2 variants = 10
    assert_eq!(output.functions.len(), 10, "expected 10 functions");

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
    // Phased timeline + margin-call threshold + auction-incentive surface.
    assert!(
        names.contains(&"liqThresholdBps"),
        "liqThresholdBps (margin-call trigger) must be a constructor parameter"
    );
    assert!(
        names.contains(&"auctionWindow"),
        "auctionWindow must be a constructor parameter"
    );
    assert!(
        names.contains(&"auctionDiscountBps"),
        "auctionDiscountBps must be a constructor parameter"
    );
    assert!(
        names.contains(&"initRatioBps"),
        "initRatioBps must be a constructor parameter"
    );
}

#[test]
fn test_no_interest_rate_anywhere() {
    let output = compile(CODE).expect("compilation failed");
    let names: Vec<&str> = output.parameters.iter().map(|p| p.name.as_str()).collect();
    assert!(
        !names.contains(&"ratePerSec") && !names.contains(&"lastAccrual"),
        "RepaymentPool must not carry interest-rate state, got: {names:?}"
    );
}

#[test]
fn test_issue_is_oracle_priced_and_dual_mints() {
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
fn test_issue_enforces_liq_threshold_below_init_ratio() {
    // Deployment-safety invariant: issue must reject a pool where the
    // margin-call threshold is not strictly below the origination ratio,
    // otherwise a freshly-minted vault at minimum collateral would be
    // immediately liquidatable in the same block (guaranteed borrower loss).
    // Asserting on the require message is robust against how the compiler
    // lowers `initRatioBps > liqThresholdBps`.
    let output = compile(CODE).expect("compilation failed");
    let reqs = requirements(&output, "issue");
    assert!(
        reqs.iter()
            .any(|r| r.contains("liq threshold must be below init ratio")),
        "issue must enforce initRatioBps > liqThresholdBps, got requirements: {reqs:?}"
    );
}

#[test]
fn test_accept_repayment_validates_vault_and_burns_debit() {
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
fn test_accept_auction_is_permissionless_oracle_priced_phased() {
    // Oracle witness only. Auctioneer identity = witness pubkey.
    // Phased gate: tx.time >= maturity AND tx.time < maturity + auctionWindow.
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
        "acceptAuction computes collateralValue + discount math"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTVALUE),
        "acceptAuction pays collateral sats out"
    );
    assert!(
        asm.contains(OP_LESSTHAN),
        "acceptAuction enforces auction-window upper bound"
    );

    // Excluding serverSig (the Arkade cooperative-path sig auto-injected on
    // every server-variant function), exactly ONE signature witness remains:
    // the oracle. No auctioneer signature — auction is permissionless.
    let ws = witness_names(&output, "acceptAuction");
    let user_sigs: Vec<&String> = ws
        .iter()
        .filter(|w| w.to_lowercase().ends_with("sig") && w.as_str() != "serverSig")
        .collect();
    assert_eq!(
        user_sigs.len(),
        1,
        "acceptAuction must have exactly one user signature (the oracle), got: {ws:?}"
    );
    assert!(
        user_sigs[0].to_lowercase().contains("oracle"),
        "the sole user signature must be the oracle, got: {:?}",
        user_sigs[0]
    );
    assert!(
        ws.iter().any(|w| w == "auctioneerPk"),
        "auctioneerPk must be a witness parameter, got: {ws:?}"
    );
}

#[test]
fn test_liquidate_is_oracle_priced_health_gated_permissionless() {
    // Margin call (pre-maturity, permissionless): oracle-priced sale of the
    // collateral when collateralValue < liqThresholdBps × mintedAmount / 10000.
    // Same two-branch payout as acceptAuction, same auctioneer-discount
    // incentive — but pre-maturity and triggered by the health threshold.
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "liquidate");
    assert!(
        asm.contains(OP_CHECKSIGFROMSTACK),
        "liquidate verifies oracle sig"
    );
    assert!(
        asm.contains(OP_SHA256) && asm.contains(OP_CAT),
        "liquidate rebuilds oracle msg"
    );
    assert!(
        asm.contains(OP_INSPECTINPUTSCRIPTPUBKEY),
        "liquidate validates the BondMint input"
    );
    assert!(
        asm.contains(OP_INSPECTASSETGROUPSUM),
        "liquidate burns the debit"
    );
    assert!(
        asm.contains(OP_MUL64) && asm.contains(OP_DIV64),
        "liquidate computes collateralValue + health-threshold + payout"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTVALUE),
        "liquidate pays collateral sats out"
    );
    assert!(
        asm.contains(OP_LESSTHAN),
        "liquidate enforces tx.time < maturity (and collateralValue < healthFloor)"
    );

    // The health gate carries its own require message.
    let reqs = requirements(&output, "liquidate");
    assert!(
        reqs.iter().any(|r| r.contains("vault still healthy")),
        "liquidate must gate on the health threshold, got: {reqs:?}"
    );

    let ws = witness_names(&output, "liquidate");
    let user_sigs: Vec<&String> = ws
        .iter()
        .filter(|w| w.to_lowercase().ends_with("sig") && w.as_str() != "serverSig")
        .collect();
    assert_eq!(
        user_sigs.len(),
        1,
        "liquidate must have exactly one user signature (the oracle), got: {ws:?}"
    );
    assert!(
        user_sigs[0].to_lowercase().contains("oracle"),
        "the sole user signature must be the oracle, got: {:?}",
        user_sigs[0]
    );
    assert!(
        ws.iter().any(|w| w == "auctioneerPk"),
        "auctioneerPk must be a witness parameter, got: {ws:?}"
    );
}

#[test]
fn test_liquidate_and_accept_auction_are_phase_disjoint() {
    // Margin-call and post-maturity auction must NEVER both fire on the same
    // vault in the same block: liquidate is gated on tx.time < maturity (via
    // a "matured; use acceptAuction" require) and acceptAuction on tx.time >=
    // maturity (via a "not yet matured" require).
    let output = compile(CODE).expect("compilation failed");
    let liq = requirements(&output, "liquidate");
    let auc = requirements(&output, "acceptAuction");
    assert!(
        liq.iter().any(|r| r.contains("matured; use acceptAuction")),
        "liquidate must be gated pre-maturity, got: {liq:?}"
    );
    assert!(
        auc.iter().any(|r| r.contains("not yet matured")),
        "acceptAuction must be gated post-maturity, got: {auc:?}"
    );
    // Both also carry an explicit time-comparison opcode.
    assert!(asm_of(&output, "liquidate").contains(OP_LESSTHAN));
    assert!(asm_of(&output, "acceptAuction").contains(OP_LESSTHAN));
}

#[test]
fn test_redeem_is_pro_rata_post_window() {
    // redeem only opens AFTER the auction window closes, so the rate
    // (usdtBalance / totalCreditOutstanding) is locked and fair for all orderings.
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
        "redeem re-creates the pool covenant + pins payout destination"
    );
    assert!(asm.contains(OP_CHECKSIG), "redeem needs holder sig");
    // The post-window gate carries its own require message.
    let reqs = requirements(&output, "redeem");
    assert!(
        reqs.iter().any(|r| r.contains("auction window not closed")),
        "redeem must be gated on tx.time >= maturity + auctionWindow, got: {reqs:?}"
    );
}

#[test]
fn test_exit_variants_are_unilateral_fallback() {
    let output = compile(CODE).expect("compilation failed");
    for name in [
        "issue",
        "acceptRepayment",
        "liquidate",
        "acceptAuction",
        "redeem",
    ] {
        let asm = asm_variant(&output, name, false);
        assert!(
            asm.contains(OP_CHECKSEQUENCEVERIFY),
            "{name} exit must be CSV-timelocked"
        );
        assert!(asm.contains(OP_CHECKSIG), "{name} exit must check sigs");
        assert!(
            !asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY) && !asm.contains(OP_INSPECTASSETGROUPSUM),
            "{name} exit must not carry covenant introspection"
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
