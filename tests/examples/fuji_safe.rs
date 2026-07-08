use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKLOCKTIMEVERIFY, OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_CHECKSIGVERIFY, OP_LESSTHAN,
};

#[test]
fn test_fuji_safe_contract() {
    let fuji_code = include_str!("../../examples/fuji_safe.ark");

    let result = compile(fuji_code);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();

    // Verify contract name
    assert_eq!(output.name, "FujiSafe");

    // Verify parameters
    assert_eq!(output.parameters.len(), 10);
    assert_eq!(output.parameters[0].name, "assetCommitmentHash");
    assert_eq!(output.parameters[0].param_type, "bytes");
    assert_eq!(output.parameters[1].name, "borrowAmount");
    assert_eq!(output.parameters[1].param_type, "int");
    assert_eq!(output.parameters[2].name, "borrowerPk");
    assert_eq!(output.parameters[2].param_type, "pubkey");
    assert_eq!(output.parameters[3].name, "treasuryPk");
    assert_eq!(output.parameters[3].param_type, "pubkey");

    // 4 covenant functions + 1 standalone unilateral = 5 groups
    assert_eq!(
        output.functions.len(),
        5,
        "expected 5 groups (claim, liquidate, redeem, renew, unilateral)"
    );

    // All expected covenant function names should appear as group names
    let group_names: Vec<&str> = output.functions.iter().map(|g| g.name.as_str()).collect();
    assert!(group_names.contains(&"claim"), "missing claim group");
    assert!(
        group_names.contains(&"liquidate"),
        "missing liquidate group"
    );
    assert!(group_names.contains(&"redeem"), "missing redeem group");
    assert!(group_names.contains(&"renew"), "missing renew group");
    assert!(
        group_names.contains(&"unilateral"),
        "missing unilateral group"
    );

    // Verify claim function: checks expiration timeout (CLTV) in arkade covenant
    let claim_asm = crate::common::arkade_asm(&output, "claim");
    assert!(
        claim_asm.contains(OP_CHECKLOCKTIMEVERIFY),
        "claim covenant should enforce expiration timeout: {}",
        claim_asm
    );
    assert!(
        claim_asm.contains(OP_CHECKSIG),
        "claim covenant should verify treasury sig: {}",
        claim_asm
    );

    // claim leaf carries server + emulator cosig
    let claim_leaf = crate::common::leaf_asm(&output, "claim", "claim");
    assert!(
        claim_leaf.contains("<SERVER_KEY>"),
        "claim leaf should have SERVER_KEY: {}",
        claim_leaf
    );
    assert!(
        claim_leaf.contains(OP_CHECKSIGVERIFY),
        "claim leaf should have CHECKSIGVERIFY: {}",
        claim_leaf
    );

    // Verify liquidate function: price comparison + oracle sig + CLTV
    let liquidate_asm = crate::common::arkade_asm(&output, "liquidate");
    assert!(
        liquidate_asm.contains(OP_LESSTHAN),
        "liquidate covenant should compare price: {}",
        liquidate_asm
    );
    assert!(
        liquidate_asm.contains(OP_CHECKSIGFROMSTACK),
        "liquidate covenant should verify oracle sig: {}",
        liquidate_asm
    );
    assert!(
        liquidate_asm.contains(OP_CHECKSIG),
        "liquidate covenant should verify treasury sig: {}",
        liquidate_asm
    );

    // liquidate leaf carries server + emulator cosig
    let liquidate_leaf = crate::common::leaf_asm(&output, "liquidate", "liquidate");
    assert!(
        liquidate_leaf.contains("<SERVER_KEY>"),
        "liquidate leaf should have SERVER_KEY: {}",
        liquidate_leaf
    );

    // Verify redeem function: borrower signature
    let redeem_asm = crate::common::arkade_asm(&output, "redeem");
    assert!(
        redeem_asm.contains(OP_CHECKSIG),
        "redeem covenant should verify borrower sig: {}",
        redeem_asm
    );

    // redeem leaf carries server + emulator cosig
    let redeem_leaf = crate::common::leaf_asm(&output, "redeem", "redeem");
    assert!(
        redeem_leaf.contains("<SERVER_KEY>"),
        "redeem leaf should have SERVER_KEY: {}",
        redeem_leaf
    );

    // Verify renew function: treasury signature
    let renew_asm = crate::common::arkade_asm(&output, "renew");
    assert!(
        renew_asm.contains(OP_CHECKSIG),
        "renew covenant should verify treasury sig: {}",
        renew_asm
    );

    // renew leaf carries server + emulator cosig
    let renew_leaf = crate::common::leaf_asm(&output, "renew", "renew");
    assert!(
        renew_leaf.contains("<SERVER_KEY>"),
        "renew leaf should have SERVER_KEY: {}",
        renew_leaf
    );

    // Unilateral exit: CSV-based, borrower only (no server involvement)
    let unilateral_leaf = crate::common::leaf_asm(&output, "unilateral", "unilateral");
    assert!(
        unilateral_leaf.contains("OP_CHECKSEQUENCEVERIFY"),
        "unilateral leaf should have CSV: {}",
        unilateral_leaf
    );
    assert!(
        unilateral_leaf.contains(OP_CHECKSIG),
        "unilateral leaf should verify borrower sig: {}",
        unilateral_leaf
    );
}

#[test]
fn test_fuji_safe_cli() {
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let input_path = temp_dir.path().join("fuji_safe.ark");
    let output_path = temp_dir.path().join("fuji_safe.json");

    let fuji_code = include_str!("../../examples/fuji_safe.ark");
    fs::write(&input_path, fuji_code).unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_arkadec"))
        .arg(input_path.to_str().unwrap())
        .arg("-o")
        .arg(output_path.to_str().unwrap())
        .output()
        .expect("Failed to execute command");

    assert!(
        output.status.success(),
        "Command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(Path::new(&output_path).exists());

    let json_output = fs::read_to_string(&output_path).unwrap();

    assert!(json_output.contains("\"contractName\": \"FujiSafe\""));
    assert!(json_output.contains("\"assetCommitmentHash\""));
    assert!(json_output.contains("\"borrowAmount\""));
    assert!(json_output.contains("\"borrowerPk\""));
    assert!(json_output.contains("\"treasuryPk\""));
    // New model uses groups with leaves; no serverVariant field
    assert!(json_output.contains("\"arkade\""));
    assert!(json_output.contains("\"leaves\""));
}
