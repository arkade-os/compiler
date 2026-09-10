use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_CHECKSIGVERIFY, OP_INSPECTLOCKTIME, OP_LESSTHAN,
};

#[test]
fn test_fuji_safe_contract() {
    let fuji_code = include_str!("../../examples/fuji_safe/fuji_safe.ark");

    let result = compile(fuji_code);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();

    // Verify contract name
    assert_eq!(output.name, "FujiSafe");

    // Verify parameters
    assert_eq!(output.parameters.len(), 12);
    assert_eq!(output.parameters[10].name, "treasuryBurnScript");
    assert_eq!(output.parameters[10].param_type, "bytes32");
    assert_eq!(output.parameters[11].name, "borrowerBurnScript");
    assert_eq!(output.parameters[11].param_type, "bytes32");
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

    for (function, script, script_read, value_read, inputs) in [
        (
            "claim",
            "<treasuryBurnScript>",
            "OP_5 OP_PICK",
            "OP_2 OP_PICK",
            &[("treasurySig", "signature")][..],
        ),
        (
            "liquidate",
            "<treasuryBurnScript>",
            "OP_9 OP_PICK",
            "OP_3 OP_PICK",
            &[
                ("currentPrice", "int"),
                ("oracleSig", "signature"),
                ("treasurySig", "signature"),
            ][..],
        ),
        (
            "redeem",
            "<borrowerBurnScript>",
            "OP_3 OP_PICK",
            "OP_1 OP_PICK",
            &[("borrowerSig", "signature")][..],
        ),
        (
            "renew",
            "<borrowerBurnScript>",
            concat!(
                "<VTXO:FujiSafe(<assetCommitmentHash>,<borrowAmount>,<borrowerPk>,<treasuryPk>,",
                "<expirationTimeout>,<priceLevel>,<setupTimestamp>,<oraclePk>,<assetPair>,<exit>,",
                "<treasuryBurnScript>,<borrowerBurnScript>)>"
            ),
            "OP_1 OP_PICK",
            &[("treasurySig", "signature")][..],
        ),
    ] {
        let group = crate::common::group(&output, function);
        let covenant = group.arkade.as_ref().expect("covenant");
        assert_eq!(
            covenant
                .inputs
                .iter()
                .map(|input| (input.name.as_str(), input.param_type.as_str()))
                .collect::<Vec<_>>(),
            inputs
        );
        let asm = crate::common::arkade_asm_tokens(&output, function);
        assert_eq!(asm.first().map(String::as_str), Some(script));
        for (opcode, operand) in [
            ("OP_INSPECTOUTPUTSCRIPTPUBKEY OP_DROP", script_read),
            ("OP_INSPECTOUTPUTVALUE", value_read),
        ] {
            let comparison = format!("0 {opcode} {operand} OP_EQUAL OP_VERIFY");
            let expected = comparison.split_whitespace().collect::<Vec<_>>();
            assert!(
                asm.windows(expected.len()).any(|window| window
                    .iter()
                    .map(String::as_str)
                    .eq(expected.iter().copied())),
                "{function} must enforce {comparison}"
            );
        }
        assert_eq!(group.leaves.len(), 1);
        assert_eq!(group.leaves[0].name, function);
        assert_eq!(
            crate::common::leaf_asm(&output, function, function),
            format!("<SERVER_KEY> {OP_CHECKSIGVERIFY} <EMULATOR_KEY:{function}> {OP_CHECKSIG}")
        );
        assert_eq!(
            group.leaves[0]
                .witness
                .iter()
                .map(|input| (
                    input.name.as_str(),
                    input.elem_type.as_str(),
                    input.encoding.as_str(),
                    input.injected
                ))
                .collect::<Vec<_>>(),
            [
                ("serverSig", "signature", "schnorr-64", true),
                ("emulatorSig", "signature", "schnorr-64", true),
            ]
        );
    }

    // The claim covenant checks expiration through locktime inspection.
    let claim_asm = crate::common::arkade_asm(&output, "claim");
    assert!(
        claim_asm.contains(OP_INSPECTLOCKTIME),
        "claim covenant should enforce expiration timeout: {}",
        claim_asm
    );
    assert!(
        claim_asm.contains(OP_CHECKSIG),
        "claim covenant should verify treasury sig: {}",
        claim_asm
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

    // Verify redeem function: borrower signature
    let redeem_asm = crate::common::arkade_asm(&output, "redeem");
    assert!(
        redeem_asm.contains(OP_CHECKSIG),
        "redeem covenant should verify borrower sig: {}",
        redeem_asm
    );

    // Verify renew function: treasury signature
    let renew_asm = crate::common::arkade_asm(&output, "renew");
    assert!(
        renew_asm.contains(OP_CHECKSIG),
        "renew covenant should verify treasury sig: {}",
        renew_asm
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

    let fuji_code = include_str!("../../examples/fuji_safe/fuji_safe.ark");
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
