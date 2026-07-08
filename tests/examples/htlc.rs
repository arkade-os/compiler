use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_CHECKSIGVERIFY,
    OP_GREATERTHANOREQUAL64, OP_HASH160,
};
use serde_json::Value;
use std::fs;
use tempfile::tempdir;

// HTLC contract using the tapscript model.
// Covenant functions enforce output-value preservation; tapscript leaves handle
// the hash-preimage claim path, the timelock refund path, and a unilateral CSV exit.
const HTLC_CODE: &str = include_str!("../../examples/htlc/htlc.ark");

#[test]
fn test_htlc_contract() {
    let result = compile(HTLC_CODE);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();

    // Verify contract name
    assert_eq!(output.name, "HTLC");

    // Verify parameters: sender, receiver, preimageHash (bytes20), refundTime, exit
    assert_eq!(output.parameters.len(), 5);
    assert_eq!(output.parameters[0].name, "sender");
    assert_eq!(output.parameters[0].param_type, "pubkey");
    assert_eq!(output.parameters[1].name, "receiver");
    assert_eq!(output.parameters[1].param_type, "pubkey");
    assert_eq!(output.parameters[2].name, "preimageHash");
    assert_eq!(output.parameters[2].param_type, "bytes20");
    assert_eq!(output.parameters[3].name, "refundTime");
    assert_eq!(output.parameters[3].param_type, "int");
    assert_eq!(output.parameters[4].name, "exit");
    assert_eq!(output.parameters[4].param_type, "int");

    // 2 covenant groups (claim, refund) + 1 standalone unilateral = 3 groups
    assert_eq!(
        output.functions.len(),
        3,
        "expected 3 groups: claim, refund, unilateral"
    );

    // --- claim group -------------------------------------------------------
    // Covenant: checks output value >= input value
    let claim_cov = crate::common::arkade_asm(&output, "claim");
    assert!(
        claim_cov.contains(OP_GREATERTHANOREQUAL64),
        "claim covenant should enforce output >= input value: {}",
        claim_cov
    );

    // Leaf: hash-preimage check + server/emulator multisig
    let claim_leaf = crate::common::leaf_asm(&output, "claim", "claim");
    assert!(
        claim_leaf.contains(OP_HASH160),
        "claim leaf should hash the preimage: {}",
        claim_leaf
    );
    assert!(
        claim_leaf.contains("<SERVER_KEY>"),
        "claim leaf should require server cosig: {}",
        claim_leaf
    );
    assert!(
        claim_leaf.contains(OP_CHECKSIGVERIFY),
        "claim leaf should have CHECKSIGVERIFY: {}",
        claim_leaf
    );
    assert!(
        claim_leaf.contains(OP_CHECKSIG),
        "claim leaf should have final CHECKSIG: {}",
        claim_leaf
    );

    // Witness: preimage + serverSig + emulatorSig
    let claim_witnesses = crate::common::witness_names(&output, "claim", "claim");
    assert!(
        claim_witnesses.contains(&"preimage".to_string()),
        "claim leaf should require preimage: {:?}",
        claim_witnesses
    );
    assert!(
        claim_witnesses.contains(&"serverSig".to_string()),
        "claim leaf should require serverSig: {:?}",
        claim_witnesses
    );
    assert!(
        claim_witnesses.contains(&"emulatorSig".to_string()),
        "claim leaf should require emulatorSig: {:?}",
        claim_witnesses
    );

    // --- refund group ------------------------------------------------------
    // Covenant: checks output value >= input value
    let refund_cov = crate::common::arkade_asm(&output, "refund");
    assert!(
        refund_cov.contains(OP_GREATERTHANOREQUAL64),
        "refund covenant should enforce output >= input value: {}",
        refund_cov
    );

    // Leaf: absolute timelock (CLTV) + server/emulator multisig
    let refund_leaf = crate::common::leaf_asm(&output, "refund", "refund");
    assert!(
        refund_leaf.contains("<refundTime>"),
        "refund leaf should push refundTime: {}",
        refund_leaf
    );
    assert!(
        refund_leaf.contains(OP_CHECKLOCKTIMEVERIFY),
        "refund leaf should enforce timelock: {}",
        refund_leaf
    );
    assert!(
        refund_leaf.contains("<SERVER_KEY>"),
        "refund leaf should require server cosig: {}",
        refund_leaf
    );

    // Witness: serverSig + emulatorSig
    let refund_witnesses = crate::common::witness_names(&output, "refund", "refund");
    assert!(
        refund_witnesses.contains(&"serverSig".to_string()),
        "refund leaf should require serverSig: {:?}",
        refund_witnesses
    );
    assert!(
        refund_witnesses.contains(&"emulatorSig".to_string()),
        "refund leaf should require emulatorSig: {:?}",
        refund_witnesses
    );

    // --- unilateral group --------------------------------------------------
    // Standalone CSV exit leaf: no arkade covenant, pure Bitcoin.
    let unilateral_group = crate::common::group(&output, "unilateral");
    assert!(
        unilateral_group.arkade.is_none(),
        "unilateral should have no arkade covenant"
    );

    let unilateral_leaf = crate::common::leaf_asm(&output, "unilateral", "unilateral");
    assert!(
        unilateral_leaf.contains("<exit>"),
        "unilateral leaf should push exit timelock: {}",
        unilateral_leaf
    );
    assert!(
        unilateral_leaf.contains(OP_CHECKSEQUENCEVERIFY),
        "unilateral leaf should have CSV: {}",
        unilateral_leaf
    );
    assert!(
        unilateral_leaf.contains("<sender>"),
        "unilateral leaf should check sender key: {}",
        unilateral_leaf
    );
    assert!(
        unilateral_leaf.contains(OP_CHECKSIG),
        "unilateral leaf should have CHECKSIG: {}",
        unilateral_leaf
    );
}

#[test]
fn test_htlc_cli() {
    let temp_dir = tempdir().unwrap();
    let input_path = temp_dir.path().join("htlc.ark");
    let output_path = temp_dir.path().join("htlc.json");

    fs::write(&input_path, HTLC_CODE).unwrap();

    // Compile via library
    let result = compile(HTLC_CODE);
    assert!(result.is_ok());

    // Run the CLI command
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_arkadec"))
        .arg(input_path.to_str().unwrap())
        .arg("-o")
        .arg(output_path.to_str().unwrap())
        .status()
        .expect("Failed to execute command");

    assert!(status.success());

    let actual_json_str = fs::read_to_string(&output_path).unwrap();

    // Compare CLI output to library output, ignoring updatedAt timestamp
    let mut expected_output = result.unwrap();
    expected_output.updated_at = None;
    let expected_json_str = serde_json::to_string_pretty(&expected_output).unwrap();

    let mut actual_json: Value = serde_json::from_str(&actual_json_str).unwrap();
    if let Some(obj) = actual_json.as_object_mut() {
        obj.remove("updatedAt");
    }
    let actual_json_str = serde_json::to_string_pretty(&actual_json).unwrap();

    let mut expected_json: Value = serde_json::from_str(&expected_json_str).unwrap();
    if let Some(obj) = expected_json.as_object_mut() {
        obj.remove("updatedAt");
    }
    let expected_json_str = serde_json::to_string_pretty(&expected_json).unwrap();

    assert_eq!(actual_json_str, expected_json_str);
}
