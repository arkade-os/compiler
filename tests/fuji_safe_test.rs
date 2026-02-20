use arkade_compiler::compile;

#[test]
fn test_fuji_safe_contract() {
    // Fuji Safe contract source code
    let fuji_code = include_str!("../examples/fuji_safe.ark");

    // Compile the contract
    let result = compile(fuji_code);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();

    // Verify contract name
    assert_eq!(output.name, "FujiSafe");

    // Verify parameters
    assert_eq!(output.parameters.len(), 9);
    assert_eq!(output.parameters[0].name, "assetCommitmentHash");
    assert_eq!(output.parameters[0].param_type, "bytes");
    assert_eq!(output.parameters[1].name, "borrowAmount");
    assert_eq!(output.parameters[1].param_type, "int");
    assert_eq!(output.parameters[2].name, "borrowerPk");
    assert_eq!(output.parameters[2].param_type, "pubkey");
    assert_eq!(output.parameters[3].name, "treasuryPk");
    assert_eq!(output.parameters[3].param_type, "pubkey");

    // Verify functions
    let functions = output
        .functions
        .iter()
        .map(|f| f.name.clone())
        .collect::<Vec<_>>();
    assert!(functions.contains(&"claim".to_string()));
    assert!(functions.contains(&"liquidate".to_string()));
    assert!(functions.contains(&"redeem".to_string()));
    assert!(functions.contains(&"renew".to_string()));

    // Verify server variants
    let server_variants = output
        .functions
        .iter()
        .filter(|f| f.server_variant)
        .map(|f| f.name.clone())
        .collect::<Vec<_>>();

    let non_server_variants = output
        .functions
        .iter()
        .filter(|f| !f.server_variant)
        .map(|f| f.name.clone())
        .collect::<Vec<_>>();

    // Each function should have both server and non-server variants
    for func_name in ["claim", "liquidate", "redeem", "renew"] {
        assert!(server_variants.contains(&func_name.to_string()));
        assert!(non_server_variants.contains(&func_name.to_string()));
    }

    // Verify claim function requirements
    let claim_func = output
        .functions
        .iter()
        .find(|f| f.name == "claim" && f.server_variant)
        .unwrap();
    assert!(claim_func.require.iter().any(|r| r.req_type == "older"));
    assert!(claim_func
        .require
        .iter()
        .any(|r| r.req_type == "serverSignature"));

    // Verify liquidate function requirements
    let liquidate_func = output
        .functions
        .iter()
        .find(|f| f.name == "liquidate" && f.server_variant)
        .unwrap();
    assert!(liquidate_func
        .require
        .iter()
        .any(|r| r.req_type == "comparison"));
    assert!(liquidate_func
        .require
        .iter()
        .any(|r| r.req_type == "serverSignature"));

    // Verify redeem function requirements
    let redeem_func = output
        .functions
        .iter()
        .find(|f| f.name == "redeem" && f.server_variant)
        .unwrap();
    assert!(redeem_func
        .require
        .iter()
        .any(|r| r.req_type == "signature"));
    assert!(redeem_func
        .require
        .iter()
        .any(|r| r.req_type == "serverSignature"));

    // Verify renew function requirements
    let renew_func = output
        .functions
        .iter()
        .find(|f| f.name == "renew" && f.server_variant)
        .unwrap();
    assert!(renew_func
        .require
        .iter()
        .any(|r| r.req_type == "serverSignature"));
}

#[test]
fn test_fuji_safe_cli() {
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

    // Create a temporary directory
    let temp_dir = tempdir().unwrap();
    let input_path = temp_dir.path().join("fuji_safe.ark");
    let output_path = temp_dir.path().join("fuji_safe.json");

    // Copy the example file to temp directory
    let fuji_code = include_str!("../examples/fuji_safe.ark");
    fs::write(&input_path, fuji_code).unwrap();

    // Run the compiler CLI using the built binary
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

    // Check that the output file exists
    assert!(Path::new(&output_path).exists());

    // Read the output file
    let json_output = fs::read_to_string(&output_path).unwrap();

    // Basic validation of the JSON output (note: pretty-printed JSON has spaces)
    assert!(json_output.contains("\"contractName\": \"FujiSafe\""));
    assert!(json_output.contains("\"assetCommitmentHash\""));
    assert!(json_output.contains("\"borrowAmount\""));
    assert!(json_output.contains("\"borrowerPk\""));
    assert!(json_output.contains("\"treasuryPk\""));
    assert!(json_output.contains("\"serverVariant\": true"));
    assert!(json_output.contains("\"serverVariant\": false"));
}
