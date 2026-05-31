use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_INSPECTASSETGROUPSUM, OP_INSPECTINASSETLOOKUP,
    OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_INSPECTOUTPUTVALUE, OP_LESSTHAN,
};

const CODE: &str = include_str!("../examples/bonds/bond_mint.ark");

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

#[test]
fn test_bond_mint_compiles() {
    let output = compile(CODE).expect("compilation failed");
    assert_eq!(output.name, "BondMint");
    assert_eq!(output.functions.len(), 4, "expected 4 functions");

    let names: Vec<&str> = output.parameters.iter().map(|p| p.name.as_str()).collect();
    for id in ["debitAssetId", "debitCtrlId"] {
        assert!(
            names.contains(&format!("{id}_txid").as_str())
                && names.contains(&format!("{id}_gidx").as_str()),
            "{id} not decomposed, got: {names:?}"
        );
    }
    assert!(
        !names.contains(&"keeperPk"),
        "keeperPk must not be a constructor parameter"
    );
    assert!(
        names.contains(&"auctionWindow"),
        "auctionWindow must be a constructor parameter"
    );
}

#[test]
fn test_repay_is_atomic_with_pool() {
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "repay");
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
fn test_auction_is_permissionless_and_phased() {
    // auction has NO keeper signature. The only binding is:
    //   - phased time gate (tx.time >= maturity AND tx.time < maturity + auctionWindow)
    //   - pool co-spent (debit control asset lookup)
    //   - debit burn
    //   - auctioneer-pinned collateral output
    // Auctioneer identity is a pure witness pubkey, no sig required.
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "auction");
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

    let ws = witness_names(&output, "auction");
    // serverSig is the Arkade cooperative-path signature, auto-injected on
    // every server-variant function — it's NOT a keeper or other trust sig.
    let user_sigs: Vec<&String> = ws
        .iter()
        .filter(|w| w.to_lowercase().ends_with("sig") && w.as_str() != "serverSig")
        .collect();
    assert!(
        user_sigs.is_empty(),
        "auction must not require any user signature (was: {user_sigs:?})"
    );
    assert!(
        ws.iter().any(|w| w == "auctioneerPk"),
        "auctioneerPk must be a witness parameter (got: {ws:?})"
    );
}

#[test]
fn test_exit_variant_drops_keeper() {
    let output = compile(CODE).expect("compilation failed");
    for name in ["repay", "auction"] {
        let asm = asm_variant(&output, name, false);
        assert!(
            asm.contains(OP_CHECKSEQUENCEVERIFY),
            "{name} exit must be CSV-timelocked"
        );
        assert!(asm.contains(OP_CHECKSIG), "{name} exit must check sigs");
        assert!(
            !asm.contains(OP_INSPECTOUTPUTVALUE) && !asm.contains(OP_INSPECTASSETGROUPSUM),
            "{name} exit must not carry covenant introspection"
        );
        assert!(
            !asm.contains("<keeperPk>"),
            "{name} exit must not reference keeperPk"
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
