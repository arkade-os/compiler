use arkade_compiler::compile;

#[test]
fn test_fee_adapter_contract() {
    let code = include_str!("../examples/fee_adapter.ark");

    let result = compile(code);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();

    // Verify contract name
    assert_eq!(output.name, "FeeAdapter");

    // Verify parameters
    let param_names: Vec<&str> = output.parameters.iter().map(|p| p.name.as_str()).collect();
    assert!(param_names.contains(&"senderPk"));
    assert!(param_names.contains(&"operatorPk"));
    assert!(param_names.contains(&"recipientPk"));
    assert!(param_names.contains(&"minFee"));

    // paymentAssetId (bytes32 used in lookup) should be decomposed
    assert!(
        param_names.contains(&"paymentAssetId_txid"),
        "missing paymentAssetId_txid decomposition, got: {:?}",
        param_names
    );
    assert!(
        param_names.contains(&"paymentAssetId_gidx"),
        "missing paymentAssetId_gidx decomposition"
    );

    // Verify functions: 2 functions x 2 variants = 4
    assert_eq!(output.functions.len(), 4, "expected 4 functions");

    // Verify execute function with server variant
    let execute = output
        .functions
        .iter()
        .find(|f| f.name == "execute" && f.server_variant)
        .expect("execute server variant not found");

    // Should have comparison requirement (fee >= minFee)
    assert!(
        execute.require.iter().any(|r| r.req_type == "comparison"),
        "missing comparison requirement in execute"
    );

    // Should have asset check requirements (tx.inputs/outputs lookups)
    assert!(
        execute.require.iter().any(|r| r.req_type == "assetCheck"),
        "missing assetCheck requirement in execute"
    );

    // Should have signature requirement
    assert!(
        execute.require.iter().any(|r| r.req_type == "signature"),
        "missing signature requirement in execute"
    );

    // Should have server signature requirement
    assert!(
        execute
            .require
            .iter()
            .any(|r| r.req_type == "serverSignature"),
        "missing serverSignature requirement"
    );

    // Check assembly for asset lookup opcodes
    let execute_asm = execute.asm.join(" ");
    assert!(
        execute_asm.contains("OP_INSPECTINASSETLOOKUP"),
        "missing OP_INSPECTINASSETLOOKUP in execute: {}",
        execute_asm
    );
    assert!(
        execute_asm.contains("OP_INSPECTOUTASSETLOOKUP"),
        "missing OP_INSPECTOUTASSETLOOKUP in execute: {}",
        execute_asm
    );

    // Should have sentinel guard pattern
    assert!(
        execute_asm.contains("OP_DUP OP_1NEGATE OP_EQUAL OP_NOT OP_VERIFY"),
        "missing sentinel guard in execute: {}",
        execute_asm
    );

    // Should have 64-bit comparison opcodes for asset comparisons
    assert!(
        execute_asm.contains("OP_GREATERTHAN64"),
        "missing 64-bit comparison in execute: {}",
        execute_asm
    );

    // Should also have standard comparison opcodes (fee >= minFee)
    assert!(
        execute_asm.contains("OP_GREATERTHANOREQUAL"),
        "missing comparison opcode in execute: {}",
        execute_asm
    );

    assert!(
        execute_asm.contains("OP_CHECKSIG"),
        "missing OP_CHECKSIG in execute: {}",
        execute_asm
    );

    // Verify execute function inputs
    assert_eq!(execute.function_inputs.len(), 2);
    assert_eq!(execute.function_inputs[0].name, "senderSig");
    assert_eq!(execute.function_inputs[0].param_type, "signature");
    assert_eq!(execute.function_inputs[1].name, "fee");
    assert_eq!(execute.function_inputs[1].param_type, "int");

    // Verify adjust function
    let adjust = output
        .functions
        .iter()
        .find(|f| f.name == "adjust" && f.server_variant)
        .expect("adjust server variant not found");

    assert_eq!(adjust.function_inputs.len(), 1);
    assert_eq!(adjust.function_inputs[0].name, "operatorSig");

    // Verify exit variants exist
    let execute_exit = output
        .functions
        .iter()
        .find(|f| f.name == "execute" && !f.server_variant)
        .expect("execute exit variant not found");

    let exit_asm = execute_exit.asm.join(" ");

    // Exit path with introspection should have:
    // 1. N-of-N CHECKSIG chain (pure Bitcoin, no introspection)
    // 2. CSV timelock (relative, not absolute CLTV)
    assert!(
        exit_asm.contains("OP_CHECKSIG"),
        "missing CHECKSIG in exit path: {}",
        exit_asm
    );
    assert!(
        exit_asm.contains("OP_CHECKSEQUENCEVERIFY"),
        "missing CSV exit timelock: {}",
        exit_asm
    );

    // Exit path should NOT have introspection opcodes (pure Bitcoin fallback)
    assert!(
        !exit_asm.contains("OP_INSPECTINASSETLOOKUP"),
        "exit path should not have introspection: {}",
        exit_asm
    );
    assert!(
        !exit_asm.contains("OP_INSPECTOUTASSETLOOKUP"),
        "exit path should not have introspection: {}",
        exit_asm
    );

    // Should have N-of-N multisig requirement
    assert!(
        execute_exit
            .require
            .iter()
            .any(|r| r.req_type == "nOfNMultisig"),
        "missing nOfNMultisig requirement in exit path"
    );
}

#[test]
fn test_fee_adapter_cli() {
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let input_path = temp_dir.path().join("fee_adapter.ark");
    let output_path = temp_dir.path().join("fee_adapter.json");

    let code = include_str!("../examples/fee_adapter.ark");
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
    assert!(json.contains("\"contractName\": \"FeeAdapter\""));
    assert!(json.contains("\"serverVariant\": true"));
    assert!(json.contains("\"serverVariant\": false"));
    assert!(json.contains("OP_INSPECTINASSETLOOKUP"));
    assert!(json.contains("OP_INSPECTOUTASSETLOOKUP"));
}
