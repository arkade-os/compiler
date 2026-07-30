use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_INSPECTASSETGROUPSUM, OP_INSPECTINASSETLOOKUP,
    OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_INSPECTOUTPUTVALUE, OP_LESSTHAN,
};

use crate::common::{arkade_asm, arkade_inputs, user_signatures};

const CODE: &str = include_str!("../../examples/bonds/bond_mint.ark");

#[test]
fn test_bond_mint_compiles() {
    let output = compile(CODE).expect("compilation failed");
    assert_eq!(output.name, "BondMint");
    // 4 covenant functions (repay, liquidate, auction, roll) + 1 tapscript (unilateral) = 5 groups
    assert_eq!(output.functions.len(), 5, "expected 5 function groups");

    let names: Vec<&str> = output.parameters.iter().map(|p| p.name.as_str()).collect();
    // Asset IDs are authored as explicit (Txid, Gidx) param pairs.
    for id in ["debitAssetId", "debitCtrlId"] {
        assert!(
            names.contains(&format!("{id}Txid").as_str())
                && names.contains(&format!("{id}Gidx").as_str()),
            "{id} not present as explicit Txid/Gidx params, got: {names:?}"
        );
    }
    assert!(
        names.contains(&"auctionWindow"),
        "auctionWindow must be a constructor parameter"
    );
}

#[test]
fn test_repay_is_atomic_with_pool() {
    let output = compile(CODE).expect("compilation failed");
    let asm = arkade_asm(&output, "repay");
    assert!(
        asm.contains(OP_INSPECTINASSETLOOKUP),
        "repay verifies pool co-spent"
    );
    assert!(asm.contains(OP_INSPECTASSETGROUPSUM), "repay burns debit");
    assert!(
        asm.contains(OP_INSPECTOUTPUTVALUE),
        "repay returns collateral"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "repay pins collateral dest"
    );
    assert!(
        asm.contains(OP_LESSTHAN),
        "repay gated on tx.time < maturity"
    );
    assert!(asm.contains(OP_CHECKSIG), "repay needs borrower sig");
}

#[test]
fn test_liquidate_is_permissionless_prematurity() {
    // Margin-call settlement path: permissionless (no user signature),
    // pre-maturity gated (tx.time < maturity), pool co-spent, debit-burned,
    // caller-selected collateral output. The oracle + threshold + payout
    // math lives on the pool side.
    let output = compile(CODE).expect("compilation failed");
    let asm = arkade_asm(&output, "liquidate");
    assert!(
        asm.contains(OP_INSPECTINASSETLOOKUP),
        "liquidate verifies pool co-spent"
    );
    assert!(
        asm.contains(OP_INSPECTASSETGROUPSUM),
        "liquidate burns the debit"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "liquidate pins collateral dest to auctioneer"
    );
    assert!(
        asm.contains(OP_LESSTHAN),
        "liquidate enforces tx.time < maturity"
    );

    let ws = arkade_inputs(&output, "liquidate");
    let user_sigs = user_signatures(&output, "liquidate");
    assert!(
        user_sigs.is_empty(),
        "liquidate must not require any user signature (was: {user_sigs:?})"
    );
    assert!(
        ws.iter().any(|w| w == "auctioneerScriptPubKey"),
        "auctioneerScriptPubKey must be a covenant input parameter (got: {ws:?})"
    );
    let destination = crate::common::group(&output, "liquidate")
        .arkade
        .as_ref()
        .expect("liquidate covenant")
        .inputs
        .iter()
        .find(|input| input.name == "auctioneerScriptPubKey")
        .expect("auctioneer destination input");
    assert_eq!(destination.param_type, "bytes");
}

#[test]
fn test_auction_is_permissionless_and_phased() {
    // The auction's only bindings are:
    //   - phased time gate (tx.time >= maturity AND tx.time < maturity + auctionWindow)
    //   - pool co-spent (debit control asset lookup)
    //   - debit burn
    //   - caller-selected collateral output
    // The destination is a witness scriptPubKey; no user signature.
    let output = compile(CODE).expect("compilation failed");
    let asm = arkade_asm(&output, "auction");
    assert!(
        asm.contains(OP_INSPECTINASSETLOOKUP),
        "auction verifies pool co-spent"
    );
    assert!(asm.contains(OP_INSPECTASSETGROUPSUM), "auction burns debit");
    assert!(
        asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "auction pins collateral dest to auctioneer"
    );
    assert!(
        asm.contains(OP_LESSTHAN),
        "auction enforces tx.time < maturity + auctionWindow"
    );

    let ws = arkade_inputs(&output, "auction");
    let user_sigs = user_signatures(&output, "auction");
    assert!(
        user_sigs.is_empty(),
        "auction must not require any user signature (was: {user_sigs:?})"
    );
    assert!(
        ws.iter().any(|w| w == "auctioneerScriptPubKey"),
        "auctioneerScriptPubKey must be a covenant input parameter (got: {ws:?})"
    );
    let destination = crate::common::group(&output, "auction")
        .arkade
        .as_ref()
        .expect("auction covenant")
        .inputs
        .iter()
        .find(|input| input.name == "auctioneerScriptPubKey")
        .expect("auctioneer destination input");
    assert_eq!(destination.param_type, "bytes");
}

#[test]
fn test_roll_is_borrower_authorized_prematurity_pool_cospent() {
    // ROLL — atomic with RepaymentPool.rollOut on the OLD pool and
    // RepaymentPool.rollIn on the NEW (next-maturity) pool. This script
    // authorises the spend (borrowerSig) + burns the old debit + verifies
    // the genuine old pool is co-spent (debitCtrlId lookup) + enforces
    // pre-maturity. It does NOT pin any output — outputs are claimed by
    // the paired rollOut/rollIn/swap covenants at their witness-supplied
    // indices.
    let output = compile(CODE).expect("compilation failed");
    let asm = arkade_asm(&output, "roll");
    assert!(
        asm.contains(OP_INSPECTINASSETLOOKUP),
        "roll verifies the genuine old pool is co-spent via debitCtrlId"
    );
    assert!(
        asm.contains(OP_INSPECTASSETGROUPSUM),
        "roll burns the old debit"
    );
    assert!(
        asm.contains(OP_LESSTHAN),
        "roll gated on tx.time < maturity"
    );
    assert!(asm.contains(OP_CHECKSIG), "roll needs borrower sig");

    // No output pin: this function intentionally leaves all outputs free for
    // the paired pool functions on either side of the roll.
    assert!(
        !asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "roll must NOT pin any output's scriptPubKey — that's rollOut/rollIn's job"
    );
    assert!(
        !asm.contains(OP_INSPECTOUTPUTVALUE),
        "roll must NOT pin any output's value — same reason"
    );

    let ws = arkade_inputs(&output, "roll");
    let user_sigs = user_signatures(&output, "roll");
    assert_eq!(
        user_sigs.len(),
        1,
        "roll must require exactly one user signature (borrower's), got: {ws:?}"
    );
    assert!(
        user_sigs[0].to_lowercase().contains("borrower"),
        "the sole user signature must be the borrower's, got: {:?}",
        user_sigs[0]
    );
}

#[test]
fn test_unilateral_exit_is_csv_timelocked() {
    // The shared unilateral exit leaf must be CSV-timelocked, avoid covenant
    // introspection, and require only the borrower's signature.
    use arkade_compiler::opcodes::OP_DROP;
    let output = compile(CODE).expect("compilation failed");
    let asm = crate::common::leaf_asm(&output, "unilateral", "unilateral");
    assert!(
        asm.contains(OP_CHECKSEQUENCEVERIFY),
        "unilateral exit must be CSV-timelocked"
    );
    assert!(asm.contains(OP_CHECKSIG), "unilateral exit must check sig");
    assert!(
        asm.contains(OP_DROP),
        "unilateral exit must drop the CSV value"
    );
    // No covenant introspection on the exit leaf.
    assert!(
        !asm.contains(OP_INSPECTOUTPUTVALUE),
        "exit leaf must carry no output-value introspection"
    );
    assert!(
        !asm.contains(OP_INSPECTASSETGROUPSUM),
        "exit leaf must carry no asset-group-sum introspection"
    );
    // The leaf witness is borrowerSig only — no serverSig/emulatorSig on a tapscript.
    let ws = crate::common::witness_names(&output, "unilateral", "unilateral");
    assert_eq!(
        ws,
        vec!["borrowerSig"],
        "unilateral witness must be [borrowerSig], got: {ws:?}"
    );
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
