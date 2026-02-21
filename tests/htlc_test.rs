use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_2, OP_CHECKLOCKTIMEVERIFY, OP_CHECKMULTISIG, OP_CHECKSIG, OP_DROP, OP_EQUAL, OP_SHA256,
};
use serde_json::Value;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_htlc_contract() {
    // HTLC contract source code
    let htlc_code = r#"// Contract configuration options
options {
  // Server key parameter from contract parameters
  server = server;
  
  // Exit timelock: 24 hours (144 blocks)
  exit = 144;
}

contract HTLC(
  pubkey sender,
  pubkey receiver,
  bytes32 hash,
  int refundTime,
  pubkey server
) {
  function together(signature senderSig, signature receiverSig) {
    require(checkMultisig([sender, receiver], [senderSig, receiverSig]));
  }
  
  function refund(signature senderSig) {
    require(checkSig(senderSig, sender));
    require(tx.time >= refundTime);
  }
  
  function claim(signature receiverSig, bytes32 preimage) {
    require(checkSig(receiverSig, receiver));
    require(sha256(preimage) == hash);
  }
}"#;

    // Compile the contract
    let result = compile(htlc_code);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();

    // Verify contract name
    assert_eq!(output.name, "HTLC");

    // Verify parameters
    assert_eq!(output.parameters.len(), 5);
    assert_eq!(output.parameters[0].name, "sender");
    assert_eq!(output.parameters[0].param_type, "pubkey");
    assert_eq!(output.parameters[1].name, "receiver");
    assert_eq!(output.parameters[1].param_type, "pubkey");
    assert_eq!(output.parameters[2].name, "hash");
    assert_eq!(output.parameters[2].param_type, "bytes32");
    assert_eq!(output.parameters[3].name, "refundTime");
    assert_eq!(output.parameters[3].param_type, "int");
    assert_eq!(output.parameters[4].name, "server");
    assert_eq!(output.parameters[4].param_type, "pubkey");

    // Verify functions - now we have 6 functions (3 functions x 2 variants)
    assert_eq!(output.functions.len(), 6);

    // Verify together function with server variant
    let together_function = output
        .functions
        .iter()
        .find(|f| f.name == "together" && f.server_variant)
        .unwrap();

    // Check function inputs
    assert_eq!(together_function.function_inputs.len(), 2);
    assert_eq!(together_function.function_inputs[0].name, "senderSig");
    assert_eq!(together_function.function_inputs[0].param_type, "signature");
    assert_eq!(together_function.function_inputs[1].name, "receiverSig");
    assert_eq!(together_function.function_inputs[1].param_type, "signature");

    // Check assembly instructions
    assert_eq!(together_function.asm.len(), 10);
    assert_eq!(together_function.asm[0], OP_2);
    assert_eq!(together_function.asm[1], "<sender>");
    assert_eq!(together_function.asm[2], "<receiver>");
    assert_eq!(together_function.asm[3], OP_2);
    assert_eq!(together_function.asm[4], "<senderSig>");
    assert_eq!(together_function.asm[5], "<receiverSig>");
    assert_eq!(together_function.asm[6], OP_CHECKMULTISIG);
    assert_eq!(together_function.asm[7], "<SERVER_KEY>");
    assert_eq!(together_function.asm[8], "<serverSig>");
    assert_eq!(together_function.asm[9], OP_CHECKSIG);
    // Verify refund function with server variant
    let refund_function = output
        .functions
        .iter()
        .find(|f| f.name == "refund" && f.server_variant)
        .unwrap();

    // Check assembly instructions
    assert_eq!(refund_function.asm.len(), 9);
    assert_eq!(refund_function.asm[0], "<sender>");
    assert_eq!(refund_function.asm[1], "<senderSig>");
    assert_eq!(refund_function.asm[2], OP_CHECKSIG);
    assert_eq!(refund_function.asm[3], "<refundTime>"); // Variable reference
    assert_eq!(refund_function.asm[4], OP_CHECKLOCKTIMEVERIFY);
    assert_eq!(refund_function.asm[5], OP_DROP);
    assert_eq!(refund_function.asm[6], "<SERVER_KEY>");
    assert_eq!(refund_function.asm[7], "<serverSig>");
    assert_eq!(refund_function.asm[8], OP_CHECKSIG);

    // Verify claim function with server variant
    let claim_function = output
        .functions
        .iter()
        .find(|f| f.name == "claim" && f.server_variant)
        .unwrap();

    // Check assembly instructions
    assert_eq!(claim_function.asm.len(), 10);
    assert_eq!(claim_function.asm[0], "<receiver>");
    assert_eq!(claim_function.asm[1], "<receiverSig>");
    assert_eq!(claim_function.asm[2], OP_CHECKSIG);
    assert_eq!(claim_function.asm[3], "<preimage>");
    assert_eq!(claim_function.asm[4], OP_SHA256);
    assert_eq!(claim_function.asm[5], "<hash>");
    assert_eq!(claim_function.asm[6], OP_EQUAL);
    assert_eq!(claim_function.asm[7], "<SERVER_KEY>");
    assert_eq!(claim_function.asm[8], "<serverSig>");
    assert_eq!(claim_function.asm[9], OP_CHECKSIG);
}

#[test]
fn test_htlc_cli() {
    // Create a temporary directory for our test files
    let temp_dir = tempdir().unwrap();
    let input_path = temp_dir.path().join("htlc.ark");
    let output_path = temp_dir.path().join("htlc.json");

    // HTLC contract source code
    let htlc_code = r#"// Contract configuration options
options {
  // Server key parameter from contract parameters
  server = server;
  
  // Exit timelock: 24 hours (144 blocks)
  exit = 144;
}

contract HTLC(
  pubkey sender,
  pubkey receiver,
  bytes32 hash,
  int refundTime,
  pubkey server
) {
  function together(signature senderSig, signature receiverSig) {
    require(checkMultisig([sender, receiver], [senderSig, receiverSig]));
  }
  
  function refund(signature senderSig) {
    require(checkSig(senderSig, sender));
    require(tx.time >= refundTime);
  }
  
  function claim(signature receiverSig, bytes32 preimage) {
    require(checkSig(receiverSig, receiver));
    require(sha256(preimage) == hash);
  }
}"#;

    // Write the contract to a file
    fs::write(&input_path, htlc_code).unwrap();

    // Compile the contract using the library
    let result = compile(htlc_code);
    assert!(result.is_ok());

    // Run the CLI command
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_arkadec"))
        .arg(input_path.to_str().unwrap())
        .arg("-o")
        .arg(output_path.to_str().unwrap())
        .status()
        .expect("Failed to execute command");

    assert!(status.success());

    // Read the output file
    let actual_json_str = fs::read_to_string(&output_path).unwrap();

    // Parse both JSONs to compare them ignoring the updatedAt field
    let mut expected_output = result.unwrap();
    expected_output.updated_at = None; // Remove the timestamp for comparison
    let expected_json_str = serde_json::to_string_pretty(&expected_output).unwrap();

    let mut actual_json: Value = serde_json::from_str(&actual_json_str).unwrap();
    if let Some(obj) = actual_json.as_object_mut() {
        obj.remove("updatedAt"); // Remove the timestamp for comparison
    }
    let actual_json_str = serde_json::to_string_pretty(&actual_json).unwrap();

    let mut expected_json: Value = serde_json::from_str(&expected_json_str).unwrap();
    if let Some(obj) = expected_json.as_object_mut() {
        obj.remove("updatedAt"); // Remove the timestamp for comparison
    }
    let expected_json_str = serde_json::to_string_pretty(&expected_json).unwrap();

    // Compare the outputs
    assert_eq!(actual_json_str, expected_json_str);
}
