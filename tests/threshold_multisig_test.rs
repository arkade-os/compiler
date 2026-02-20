use arkade_compiler::compile;
use serde_json::Value;
use std::fs;
use tempfile::tempdir;

// Threshold multisig example source code
const THRESHOLD_MULTISIG_CODE: &str = r#"// Contract configuration options
options {
  // Server key parameter from contract parameters
  server = server;

  // Exit timelock: 24 hours (144 blocks)
  exit = 144;
}

contract ThresholdMultisig(
  pubkey signer,
  pubkey signer1,
  pubkey signer2,
  pubkey signer3,
  pubkey signer4,
  pubkey server
) {
  // n-of-n using no literal threshold
  function twoOfTwo(signature signerSig, signature signer1Sig) {
    require(checkMultisig([signer, signer1]));
  }

  // n-of-n using literal threshold
  function fiveOfFive(signature signerSig, signature signer1Sig, signature signer2Sig, signature signer3Sig, signature signer4Sig) {
    require(checkMultisig([signer, signer1, signer2, signer3, signer4], 5));
  }

  // m-of-n using literal threshold
  function threeOfFive(signature signerSig, signature signer1Sig, signature signer2Sig, signature signer3Sig, signature signer4Sig) {
    require(checkMultisig([signer, signer1, signer2, signer3, signer4], 3));
  }
}"#;

#[test]
fn test_threshold_multisig() {
    // Compile the contract
    let result = compile(THRESHOLD_MULTISIG_CODE);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();

    // Verify contract name
    assert_eq!(output.name, "ThresholdMultisig");

    // Verify parameters
    assert_eq!(output.parameters.len(), 6);
    assert_eq!(output.parameters[0].name, "signer");
    assert_eq!(output.parameters[0].param_type, "pubkey");
    assert_eq!(output.parameters[1].name, "signer1");
    assert_eq!(output.parameters[1].param_type, "pubkey");
    assert_eq!(output.parameters[2].name, "signer2");
    assert_eq!(output.parameters[2].param_type, "pubkey");
    assert_eq!(output.parameters[3].name, "signer3");
    assert_eq!(output.parameters[3].param_type, "pubkey");
    assert_eq!(output.parameters[4].name, "signer4");
    assert_eq!(output.parameters[4].param_type, "pubkey");
    assert_eq!(output.parameters[5].name, "server");
    assert_eq!(output.parameters[5].param_type, "pubkey");

    // Verify functions - now we have 6 functions (3 functions x 2 variants)
    assert_eq!(output.functions.len(), 6);

    // Verify twoOfTwo function with server variant
    let two_of_two_function = output
        .functions
        .iter()
        .find(|f| f.name == "twoOfTwo" && f.server_variant)
        .unwrap();

    // Check function inputs
    assert_eq!(two_of_two_function.function_inputs.len(), 2);

    // Check require types
    assert_eq!(two_of_two_function.require[0].req_type, "multisig");

    // Check assembly instructions
    assert_eq!(two_of_two_function.asm.len(), 9);
    assert_eq!(two_of_two_function.asm[0], "<signer>");
    assert_eq!(two_of_two_function.asm[1], "OP_CHECKSIG");
    assert_eq!(two_of_two_function.asm[2], "<signer1>");
    assert_eq!(two_of_two_function.asm[3], "OP_CHECKSIGADD");
    assert_eq!(two_of_two_function.asm[4], "OP_2");
    assert_eq!(two_of_two_function.asm[5], "OP_NUMEQUAL");
    assert_eq!(two_of_two_function.asm[6], "<SERVER_KEY>");
    assert_eq!(two_of_two_function.asm[7], "<serverSig>");
    assert_eq!(two_of_two_function.asm[8], "OP_CHECKSIG");

    // Verify fiveOfFive function with server variant
    let five_of_five_function = output
        .functions
        .iter()
        .find(|f| f.name == "fiveOfFive" && f.server_variant)
        .unwrap();

    // Check function inputs
    assert_eq!(five_of_five_function.function_inputs.len(), 5);

    // Check require types
    assert_eq!(five_of_five_function.require[0].req_type, "multisig");

    // Check assembly instructions
    assert_eq!(five_of_five_function.asm.len(), 15);
    assert_eq!(five_of_five_function.asm[0], "<signer>");
    assert_eq!(five_of_five_function.asm[1], "OP_CHECKSIG");
    assert_eq!(five_of_five_function.asm[2], "<signer1>");
    assert_eq!(five_of_five_function.asm[3], "OP_CHECKSIGADD"); // Variable reference
    assert_eq!(five_of_five_function.asm[4], "<signer2>");
    assert_eq!(five_of_five_function.asm[5], "OP_CHECKSIGADD"); // Variable reference
    assert_eq!(five_of_five_function.asm[6], "<signer3>");
    assert_eq!(five_of_five_function.asm[7], "OP_CHECKSIGADD"); // Variable reference
    assert_eq!(five_of_five_function.asm[8], "<signer4>");
    assert_eq!(five_of_five_function.asm[9], "OP_CHECKSIGADD"); // Variable reference
    assert_eq!(five_of_five_function.asm[10], "OP_5");
    assert_eq!(five_of_five_function.asm[11], "OP_NUMEQUAL");
    assert_eq!(five_of_five_function.asm[12], "<SERVER_KEY>");
    assert_eq!(five_of_five_function.asm[13], "<serverSig>");
    assert_eq!(five_of_five_function.asm[14], "OP_CHECKSIG");

    // Verify threeOfFive function with server variant
    let three_of_five_function = output
        .functions
        .iter()
        .find(|f| f.name == "threeOfFive" && f.server_variant)
        .unwrap();

    // Check function inputs
    assert_eq!(three_of_five_function.function_inputs.len(), 5);

    // Check require types
    assert_eq!(three_of_five_function.require[0].req_type, "multisig");

    // Check assembly instructions
    assert_eq!(three_of_five_function.asm.len(), 15);
    assert_eq!(three_of_five_function.asm[0], "<signer>");
    assert_eq!(three_of_five_function.asm[1], "OP_CHECKSIG");
    assert_eq!(three_of_five_function.asm[2], "<signer1>");
    assert_eq!(three_of_five_function.asm[3], "OP_CHECKSIGADD");
    assert_eq!(three_of_five_function.asm[4], "<signer2>");
    assert_eq!(three_of_five_function.asm[5], "OP_CHECKSIGADD");
    assert_eq!(three_of_five_function.asm[6], "<signer3>");
    assert_eq!(three_of_five_function.asm[7], "OP_CHECKSIGADD");
    assert_eq!(three_of_five_function.asm[8], "<signer4>");
    assert_eq!(three_of_five_function.asm[9], "OP_CHECKSIGADD");
    assert_eq!(three_of_five_function.asm[10], "OP_3");
    assert_eq!(three_of_five_function.asm[11], "OP_NUMEQUAL");
    assert_eq!(three_of_five_function.asm[12], "<SERVER_KEY>");
    assert_eq!(three_of_five_function.asm[13], "<serverSig>");
    assert_eq!(three_of_five_function.asm[14], "OP_CHECKSIG");

    // Verify twoOfTwo function with exit path
    let two_of_two_function = output
        .functions
        .iter()
        .find(|f| f.name == "twoOfTwo" && !f.server_variant)
        .unwrap();

    // Check function inputs
    assert_eq!(two_of_two_function.function_inputs.len(), 2);

    // Check require types
    assert_eq!(two_of_two_function.require[0].req_type, "multisig");

    // Check function inputs
    assert_eq!(two_of_two_function.function_inputs.len(), 2);

    // Check assembly instructions
    assert_eq!(two_of_two_function.asm.len(), 9);
    assert_eq!(two_of_two_function.asm[0], "<signer>");
    assert_eq!(two_of_two_function.asm[1], "OP_CHECKSIG");
    assert_eq!(two_of_two_function.asm[2], "<signer1>");
    assert_eq!(two_of_two_function.asm[3], "OP_CHECKSIGADD");
    assert_eq!(two_of_two_function.asm[4], "OP_2");
    assert_eq!(two_of_two_function.asm[5], "OP_NUMEQUAL");
    assert_eq!(two_of_two_function.asm[6], "144");
    assert_eq!(two_of_two_function.asm[7], "OP_CHECKSEQUENCEVERIFY");
    assert_eq!(two_of_two_function.asm[8], "OP_DROP");

    // Verify fiveOfFive function with exit path
    let five_of_five_function = output
        .functions
        .iter()
        .find(|f| f.name == "fiveOfFive" && !f.server_variant)
        .unwrap();

    // Check function inputs
    assert_eq!(five_of_five_function.function_inputs.len(), 5);

    // Check require types
    assert_eq!(five_of_five_function.require[0].req_type, "multisig");

    // Check assembly instructions
    assert_eq!(five_of_five_function.asm.len(), 15);
    assert_eq!(five_of_five_function.asm[0], "<signer>");
    assert_eq!(five_of_five_function.asm[1], "OP_CHECKSIG");
    assert_eq!(five_of_five_function.asm[2], "<signer1>");
    assert_eq!(five_of_five_function.asm[3], "OP_CHECKSIGADD"); // Variable reference
    assert_eq!(five_of_five_function.asm[4], "<signer2>");
    assert_eq!(five_of_five_function.asm[5], "OP_CHECKSIGADD"); // Variable reference
    assert_eq!(five_of_five_function.asm[6], "<signer3>");
    assert_eq!(five_of_five_function.asm[7], "OP_CHECKSIGADD"); // Variable reference
    assert_eq!(five_of_five_function.asm[8], "<signer4>");
    assert_eq!(five_of_five_function.asm[9], "OP_CHECKSIGADD"); // Variable reference
    assert_eq!(five_of_five_function.asm[10], "OP_5");
    assert_eq!(five_of_five_function.asm[11], "OP_NUMEQUAL");
    assert_eq!(five_of_five_function.asm[12], "144");
    assert_eq!(five_of_five_function.asm[13], "OP_CHECKSEQUENCEVERIFY");
    assert_eq!(five_of_five_function.asm[14], "OP_DROP");

    // Verify threeOfFive function with exit path
    let three_of_five_function = output
        .functions
        .iter()
        .find(|f| f.name == "threeOfFive" && !f.server_variant)
        .unwrap();

    // Check function inputs
    assert_eq!(three_of_five_function.function_inputs.len(), 5);

    // Check require types
    assert_eq!(three_of_five_function.require[0].req_type, "multisig");

    // Check assembly instructions
    assert_eq!(three_of_five_function.asm.len(), 15);
    assert_eq!(three_of_five_function.asm[0], "<signer>");
    assert_eq!(three_of_five_function.asm[1], "OP_CHECKSIG");
    assert_eq!(three_of_five_function.asm[2], "<signer1>");
    assert_eq!(three_of_five_function.asm[3], "OP_CHECKSIGADD");
    assert_eq!(three_of_five_function.asm[4], "<signer2>");
    assert_eq!(three_of_five_function.asm[5], "OP_CHECKSIGADD");
    assert_eq!(three_of_five_function.asm[6], "<signer3>");
    assert_eq!(three_of_five_function.asm[7], "OP_CHECKSIGADD");
    assert_eq!(three_of_five_function.asm[8], "<signer4>");
    assert_eq!(three_of_five_function.asm[9], "OP_CHECKSIGADD");
    assert_eq!(three_of_five_function.asm[10], "OP_3");
    assert_eq!(three_of_five_function.asm[11], "OP_NUMEQUAL");
    assert_eq!(three_of_five_function.asm[12], "144");
    assert_eq!(three_of_five_function.asm[13], "OP_CHECKSEQUENCEVERIFY");
    assert_eq!(three_of_five_function.asm[14], "OP_DROP");
}

#[test]
fn test_threshold_multisig_should_fail_on_m_greater_than_n() {
    // Threshold multisig example source code
    let threshold_multisig_code = r#"// Contract configuration options
options {
  // Server key parameter from contract parameters
  server = server;

  // Exit timelock: 24 hours (144 blocks)
  exit = 144;
}

contract ThresholdMultisig(
  pubkey signer,
  pubkey signer1,
  pubkey signer2,
  pubkey server
) {
  // m-of-n using literal threshold greater than number of pubkeys
  // Should fail to compile
  function fourOfThree(signature signerSig, signature signer1Sig, signature signer2Sig) {
    require(checkMultisig([signer, signer1, signer2], 4));
  }
}"#;

    let result = compile(threshold_multisig_code);
    assert!(
        result.is_err(),
        "Expected compilation to fail for m > n threshold multisig"
    );
}

#[test]
fn test_threshold_multisig_cli() {
    // Create a temporary directory for our test files
    let temp_dir = tempdir().unwrap();
    let input_path = temp_dir.path().join("threshold_multisig.ark");
    let output_path = temp_dir.path().join("threshold_multisig.json");

    // Write the contract to a file
    fs::write(&input_path, THRESHOLD_MULTISIG_CODE).unwrap();

    // Compile the contract using the library
    let result = compile(THRESHOLD_MULTISIG_CODE);
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
