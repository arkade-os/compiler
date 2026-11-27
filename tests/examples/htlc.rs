use crate::common;
use arkade_compiler::compile_file;
use arkade_compiler::opcodes::{
    OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_GREATERTHANOREQUAL, OP_HASH160,
    OP_INSPECTINPUTVALUE, OP_INSPECTOUTPUTVALUE,
};
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

// HTLC contract using the tapscript model.
// Covenant functions pin the payout to the receiver or sender; tapscript leaves handle
// the hash-preimage claim path, the timelock refund path, and a unilateral CSV exit.
const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/htlc/htlc.ark");

#[test]
fn test_htlc_contract() {
    let result = compile_file(PATH);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();

    // Verify contract name
    assert_eq!(output.name, "HTLC");

    // Verify parameters: sender, receiver, preimageHash (bytes20), refundTime
    assert_eq!(output.parameters.len(), 4);
    assert_eq!(output.parameters[0].name, "sender");
    assert_eq!(output.parameters[0].param_type.to_string(), "pubkey");
    assert_eq!(output.parameters[1].name, "receiver");
    assert_eq!(output.parameters[1].param_type.to_string(), "pubkey");
    assert_eq!(output.parameters[2].name, "preimageHash");
    assert_eq!(output.parameters[2].param_type.to_string(), "bytes20");
    assert_eq!(output.parameters[3].name, "refundTime");
    assert_eq!(output.parameters[3].param_type.to_string(), "int");

    // 2 Arkade Script function groups (claim, refund) + 1 standalone unilateral = 3 groups
    assert_eq!(
        output.functions.len(),
        3,
        "expected 3 groups: claim, refund, unilateral"
    );

    // --- claim group -------------------------------------------------------
    // Arkade Script: checks output value >= input value
    let claim_script = common::arkade_asm(&output, "claim");
    assert!(
        claim_script.contains(&format!(
            "OP_PUSHCURRENTINPUTINDEX {OP_INSPECTOUTPUTVALUE} OP_PUSHCURRENTINPUTINDEX {OP_INSPECTINPUTVALUE} {OP_GREATERTHANOREQUAL}"
        )),
        "claim Arkade Script should keep its own input value in its own output: {claim_script}"
    );
    assert!(
        claim_script.contains(
            "<CONTRACT:SingleSig(<receiver>)> OP_1 OP_SWAP OP_ROT OP_EQUALVERIFY OP_NUMEQUALVERIFY"
        ),
        "claim Arkade Script should pay the receiver: {claim_script}"
    );

    // Leaf: hash-preimage check + the operator key tweaked by claim
    let claim_leaf = common::leaf_asm(&output, "claim", "claim");
    assert!(
        claim_leaf.contains(OP_HASH160),
        "claim leaf should hash the preimage: {claim_leaf}"
    );
    assert!(
        claim_leaf.ends_with(&format!("<OPERATOR_KEY:claim> {OP_CHECKSIG}")),
        "claim leaf should require the operator cosig bound to claim: {claim_leaf}"
    );

    // Witness: preimage + operatorSig
    assert_eq!(
        common::witness_names(&output, "claim", "claim"),
        ["preimage", "operatorSig"]
    );

    // --- refund group ------------------------------------------------------
    // Arkade Script: checks output value >= input value
    let refund_script = common::arkade_asm(&output, "refund");
    assert!(
        refund_script.contains(&format!(
            "OP_PUSHCURRENTINPUTINDEX {OP_INSPECTOUTPUTVALUE} OP_PUSHCURRENTINPUTINDEX {OP_INSPECTINPUTVALUE} {OP_GREATERTHANOREQUAL}"
        )),
        "refund Arkade Script should keep its own input value in its own output: {refund_script}"
    );
    assert!(
        refund_script.contains(
            "<CONTRACT:SingleSig(<sender>)> OP_1 OP_SWAP OP_ROT OP_EQUALVERIFY OP_NUMEQUALVERIFY"
        ),
        "refund Arkade Script should pay the sender: {refund_script}"
    );

    // Leaf: absolute timelock (CLTV) + the operator key tweaked by refund
    let refund_leaf = common::leaf_asm(&output, "refund", "refund");
    assert!(
        refund_leaf.contains("<refundTime>"),
        "refund leaf should push refundTime: {refund_leaf}"
    );
    assert!(
        refund_leaf.contains(OP_CHECKLOCKTIMEVERIFY),
        "refund leaf should enforce timelock: {refund_leaf}"
    );
    assert!(
        refund_leaf.ends_with(&format!("<OPERATOR_KEY:refund> {OP_CHECKSIG}")),
        "refund leaf should require the operator cosig bound to refund: {refund_leaf}"
    );

    // Witness: operatorSig
    assert_eq!(
        common::witness_names(&output, "refund", "refund"),
        ["operatorSig"]
    );

    // --- unilateral group --------------------------------------------------
    // Standalone CSV exit leaf: no Arkade Script, pure Bitcoin.
    let unilateral_group = common::group(&output, "unilateral");
    assert!(
        unilateral_group.arkade.is_none(),
        "unilateral should have no Arkade Script"
    );

    let unilateral_leaf = common::leaf_asm(&output, "unilateral", "unilateral");
    assert!(
        unilateral_leaf.contains("<OPERATOR_EXIT_DELAY>"),
        "unilateral leaf should push the operator exit delay: {unilateral_leaf}"
    );
    assert!(
        unilateral_leaf.contains(OP_CHECKSEQUENCEVERIFY),
        "unilateral leaf should have CSV: {unilateral_leaf}"
    );
    assert!(
        unilateral_leaf.contains("<sender>"),
        "unilateral leaf should check sender key: {unilateral_leaf}"
    );
    assert!(
        unilateral_leaf.contains(OP_CHECKSIG),
        "unilateral leaf should have CHECKSIG: {unilateral_leaf}"
    );
}

#[test]
fn test_htlc_cli() {
    let temp_dir = tempdir().unwrap();
    let input_path = Path::new(PATH);
    let output_path = temp_dir.path().join("htlc.json");

    // Compile via library
    let result = compile_file(input_path);
    assert!(result.is_ok());

    // Run the CLI command
    let status = Command::new(env!("CARGO_BIN_EXE_arkadec"))
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
