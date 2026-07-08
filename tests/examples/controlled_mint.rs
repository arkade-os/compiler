use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKSIG, OP_FINDASSETGROUPBYASSETID, OP_INSPECTASSETGROUPCTRL, OP_INSPECTASSETGROUPSUM,
    OP_INSPECTOUTASSETLOOKUP, OP_SUB64,
};

#[test]
fn test_controlled_mint_contract() {
    let code = include_str!("../../examples/controlled_mint.ark");

    let result = compile(code);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();

    // Verify contract name
    assert_eq!(output.name, "ControlledMint");

    // Verify parameters
    let param_names: Vec<&str> = output.parameters.iter().map(|p| p.name.as_str()).collect();
    assert!(param_names.contains(&"issuerPk"), "missing issuerPk");

    // Asset IDs are authored as explicit (Txid, Gidx) param pairs.
    assert!(
        param_names.contains(&"tokenAssetIdTxid"),
        "missing explicit tokenAssetIdTxid, got: {:?}",
        param_names
    );
    assert!(
        param_names.contains(&"tokenAssetIdGidx"),
        "missing explicit tokenAssetIdGidx"
    );
    assert!(
        param_names.contains(&"ctrlAssetIdTxid"),
        "missing explicit ctrlAssetIdTxid, got: {:?}",
        param_names
    );
    assert!(
        param_names.contains(&"ctrlAssetIdGidx"),
        "missing explicit ctrlAssetIdGidx"
    );

    // 3 covenant functions + 1 standalone unilateral tapscript = 4 groups
    assert_eq!(output.functions.len(), 4, "expected 4 groups");

    // Verify mint function
    let mint_asm = crate::common::arkade_asm(&output, "mint");

    // Should have asset group find opcode
    assert!(
        mint_asm.contains(OP_FINDASSETGROUPBYASSETID),
        "missing {OP_FINDASSETGROUPBYASSETID} in mint: {}",
        mint_asm
    );

    // Should have group property opcodes for delta and control
    assert!(
        mint_asm.contains(OP_INSPECTASSETGROUPSUM) || mint_asm.contains(OP_SUB64),
        "missing group sum or delta in mint: {}",
        mint_asm
    );

    assert!(
        mint_asm.contains(OP_INSPECTASSETGROUPCTRL),
        "missing {OP_INSPECTASSETGROUPCTRL} in mint: {}",
        mint_asm
    );

    // Should have asset lookup for output check
    assert!(
        mint_asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "missing {OP_INSPECTOUTASSETLOOKUP} in mint: {}",
        mint_asm
    );

    // Should have checksig
    assert!(
        mint_asm.contains(OP_CHECKSIG),
        "missing checksig in mint: {}",
        mint_asm
    );

    // Verify burn function
    let burn_asm = crate::common::arkade_asm(&output, "burn");

    // Burn uses group sumInputs >= sumOutputs + amount
    assert!(
        burn_asm.contains(OP_FINDASSETGROUPBYASSETID),
        "missing group find in burn: {}",
        burn_asm
    );
    assert!(
        burn_asm.contains(OP_INSPECTASSETGROUPSUM),
        "missing group sum in burn: {}",
        burn_asm
    );
    assert!(
        burn_asm.contains(OP_CHECKSIG),
        "missing checksig in burn: {}",
        burn_asm
    );

    // Verify lockSupply function
    let lock_asm = crate::common::arkade_asm(&output, "lockSupply");

    // lockSupply checks sumOutputs == 0
    assert!(
        lock_asm.contains(OP_FINDASSETGROUPBYASSETID),
        "missing group find in lockSupply: {}",
        lock_asm
    );
    assert!(
        lock_asm.contains(OP_INSPECTASSETGROUPSUM),
        "missing group sum in lockSupply: {}",
        lock_asm
    );

    // Unilateral exit leaf (CSV-based, pure L1)
    let unilateral_asm = crate::common::leaf_asm(&output, "unilateral", "unilateral");
    assert!(
        unilateral_asm.contains("OP_CHECKSEQUENCEVERIFY"),
        "unilateral leaf should have CSV: {}",
        unilateral_asm
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

    let code = include_str!("../../examples/controlled_mint.ark");
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
    assert!(
        json.contains(OP_FINDASSETGROUPBYASSETID),
        "missing {OP_FINDASSETGROUPBYASSETID}"
    );
    assert!(
        json.contains(OP_INSPECTASSETGROUPSUM),
        "missing {OP_INSPECTASSETGROUPSUM}"
    );
    assert!(
        json.contains(OP_INSPECTASSETGROUPCTRL),
        "missing {OP_INSPECTASSETGROUPCTRL}"
    );
}
