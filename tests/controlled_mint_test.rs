use arkade_compiler::compile;

#[test]
fn test_controlled_mint_contract() {
    let code = include_str!("../examples/controlled_mint.ark");

    let result = compile(code);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();

    // Verify contract name
    assert_eq!(output.name, "ControlledMint");

    // Verify parameters
    let param_names: Vec<&str> = output.parameters.iter().map(|p| p.name.as_str()).collect();
    assert!(param_names.contains(&"authorityPk"), "missing authorityPk");
    assert!(param_names.contains(&"serverPk"), "missing serverPk");

    // ctrlAssetId (bytes32 used in lookups) should be decomposed into _txid + _gidx
    assert!(
        param_names.contains(&"ctrlAssetId_txid"),
        "missing ctrlAssetId_txid decomposition, got: {:?}",
        param_names
    );
    assert!(
        param_names.contains(&"ctrlAssetId_gidx"),
        "missing ctrlAssetId_gidx decomposition"
    );

    // tokenAssetId is bytes32 but NOT used in assets.lookup(), so not decomposed
    assert!(
        param_names.contains(&"tokenAssetId"),
        "tokenAssetId should remain as-is (not used in lookup)"
    );

    // maxMintAmount is int, should not be decomposed
    assert!(
        param_names.contains(&"maxMintAmount"),
        "missing maxMintAmount"
    );

    // Verify functions: 2 functions x 2 variants = 4
    assert_eq!(output.functions.len(), 4, "expected 4 functions");

    // Verify mint function
    let mint = output
        .functions
        .iter()
        .find(|f| f.name == "mint" && f.server_variant)
        .expect("mint server variant not found");

    let mint_asm = mint.asm.join(" ");

    // Should have asset lookup opcodes for both input and output
    assert!(
        mint_asm.contains("OP_INSPECTINASSETLOOKUP"),
        "missing OP_INSPECTINASSETLOOKUP in mint: {}",
        mint_asm
    );
    assert!(
        mint_asm.contains("OP_INSPECTOUTASSETLOOKUP"),
        "missing OP_INSPECTOUTASSETLOOKUP in mint: {}",
        mint_asm
    );

    // Should have sentinel guard pattern
    assert!(
        mint_asm.contains("OP_DUP OP_1NEGATE OP_EQUAL OP_NOT OP_VERIFY"),
        "missing sentinel guard in mint: {}",
        mint_asm
    );

    // Should have comparison operators for mint amount limit
    assert!(
        mint.require
            .iter()
            .any(|r| r.req_type == "comparison" || r.req_type == "assetCheck"),
        "missing comparison requirement in mint"
    );

    // Verify burn function
    let burn = output
        .functions
        .iter()
        .find(|f| f.name == "burn" && f.server_variant)
        .expect("burn server variant not found");

    let burn_asm = burn.asm.join(" ");
    assert!(
        burn_asm.contains("OP_INSPECTINASSETLOOKUP"),
        "missing input lookup in burn: {}",
        burn_asm
    );
    assert!(
        burn_asm.contains("OP_INSPECTOUTASSETLOOKUP"),
        "missing output lookup in burn: {}",
        burn_asm
    );
    assert!(
        burn_asm.contains("OP_CHECKSIG"),
        "missing checksig in burn: {}",
        burn_asm
    );
}

#[test]
fn test_controlled_mint_cli() {
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let input_path = temp_dir.path().join("controlled_mint.ark");
    let output_path = temp_dir.path().join("controlled_mint.json");

    let code = include_str!("../examples/controlled_mint.ark");
    fs::write(&input_path, code).unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_arkadec"))
        .arg(input_path.to_str().unwrap())
        .arg("-o")
        .arg(output_path.to_str().unwrap())
        .output()
        .expect("Failed to execute command");

    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(Path::new(&output_path).exists());

    let json = fs::read_to_string(&output_path).unwrap();
    assert!(json.contains("\"contractName\": \"ControlledMint\""));
    assert!(json.contains("OP_INSPECTINASSETLOOKUP"));
    assert!(json.contains("OP_INSPECTOUTASSETLOOKUP"));
}
