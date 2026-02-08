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
    assert!(param_names.contains(&"issuerPk"), "missing issuerPk");
    assert!(param_names.contains(&"serverPk"), "missing serverPk");

    // tokenAssetId (bytes32 used in lookups) should be decomposed into _txid + _gidx
    assert!(
        param_names.contains(&"tokenAssetId_txid"),
        "missing tokenAssetId_txid decomposition, got: {:?}",
        param_names
    );
    assert!(
        param_names.contains(&"tokenAssetId_gidx"),
        "missing tokenAssetId_gidx decomposition"
    );

    // ctrlAssetId should also be decomposed (used in find and lookup)
    assert!(
        param_names.contains(&"ctrlAssetId_txid"),
        "missing ctrlAssetId_txid decomposition, got: {:?}",
        param_names
    );
    assert!(
        param_names.contains(&"ctrlAssetId_gidx"),
        "missing ctrlAssetId_gidx decomposition"
    );

    // Verify functions: 3 functions x 2 variants = 6
    assert_eq!(output.functions.len(), 6, "expected 6 functions");

    // Verify mint function
    let mint = output
        .functions
        .iter()
        .find(|f| f.name == "mint" && f.server_variant)
        .expect("mint server variant not found");

    let mint_asm = mint.asm.join(" ");

    // Should have asset group find opcode
    assert!(
        mint_asm.contains("OP_FINDASSETGROUPBYASSETID"),
        "missing OP_FINDASSETGROUPBYASSETID in mint: {}",
        mint_asm
    );

    // Should have group property opcodes for delta and control
    assert!(
        mint_asm.contains("OP_INSPECTASSETGROUPSUM") || mint_asm.contains("OP_SUB64"),
        "missing group sum or delta in mint: {}",
        mint_asm
    );

    assert!(
        mint_asm.contains("OP_INSPECTASSETGROUPCTRL"),
        "missing OP_INSPECTASSETGROUPCTRL in mint: {}",
        mint_asm
    );

    // Should have asset lookup for output check
    assert!(
        mint_asm.contains("OP_INSPECTOUTASSETLOOKUP"),
        "missing OP_INSPECTOUTASSETLOOKUP in mint: {}",
        mint_asm
    );

    // Should have checksig
    assert!(
        mint_asm.contains("OP_CHECKSIG"),
        "missing checksig in mint: {}",
        mint_asm
    );

    // Verify burn function
    let burn = output
        .functions
        .iter()
        .find(|f| f.name == "burn" && f.server_variant)
        .expect("burn server variant not found");

    let burn_asm = burn.asm.join(" ");

    // Burn uses group sumInputs >= sumOutputs + amount
    assert!(
        burn_asm.contains("OP_FINDASSETGROUPBYASSETID"),
        "missing group find in burn: {}",
        burn_asm
    );
    assert!(
        burn_asm.contains("OP_INSPECTASSETGROUPSUM"),
        "missing group sum in burn: {}",
        burn_asm
    );
    assert!(
        burn_asm.contains("OP_CHECKSIG"),
        "missing checksig in burn: {}",
        burn_asm
    );

    // Verify lockSupply function
    let lock = output
        .functions
        .iter()
        .find(|f| f.name == "lockSupply" && f.server_variant)
        .expect("lockSupply server variant not found");

    let lock_asm = lock.asm.join(" ");

    // lockSupply checks sumOutputs == 0
    assert!(
        lock_asm.contains("OP_FINDASSETGROUPBYASSETID"),
        "missing group find in lockSupply: {}",
        lock_asm
    );
    assert!(
        lock_asm.contains("OP_INSPECTASSETGROUPSUM"),
        "missing group sum in lockSupply: {}",
        lock_asm
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

    // Should have group-related opcodes
    assert!(json.contains("OP_FINDASSETGROUPBYASSETID"), "missing OP_FINDASSETGROUPBYASSETID");
    assert!(json.contains("OP_INSPECTASSETGROUPSUM"), "missing OP_INSPECTASSETGROUPSUM");
    assert!(json.contains("OP_INSPECTASSETGROUPCTRL"), "missing OP_INSPECTASSETGROUPCTRL");
}
