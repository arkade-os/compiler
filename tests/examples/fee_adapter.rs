use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_GREATERTHAN, OP_GREATERTHANOREQUAL,
    OP_INSPECTINASSETLOOKUP, OP_INSPECTOUTASSETLOOKUP, OP_VERIFY,
};

#[test]
fn test_fee_adapter_contract() {
    let code = include_str!("../../examples/fee_adapter/fee_adapter.ark");

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

    assert!(
        param_names.contains(&"paymentAssetIdTxid"),
        "missing explicit paymentAssetIdTxid, got: {:?}",
        param_names
    );
    assert!(
        param_names.contains(&"paymentAssetIdGidx"),
        "missing explicit paymentAssetIdGidx"
    );

    // 2 covenant functions (execute, adjust) + 1 standalone unilateral = 3 groups
    assert_eq!(output.functions.len(), 3, "expected 3 groups");

    // Verify execute function arkade covenant
    let execute_group = crate::common::group(&output, "execute");
    let execute_inputs = &execute_group.arkade.as_ref().unwrap().inputs;
    assert_eq!(execute_inputs.len(), 2);
    assert_eq!(execute_inputs[0].name, "senderSig");
    assert_eq!(execute_inputs[0].param_type, "signature");
    assert_eq!(execute_inputs[1].name, "fee");
    assert_eq!(execute_inputs[1].param_type, "int");

    let execute_asm = crate::common::arkade_asm(&output, "execute");

    // fee >= minFee comparison
    assert!(
        execute_asm.contains(OP_GREATERTHANOREQUAL),
        "missing {OP_GREATERTHANOREQUAL} (fee >= minFee) in execute: {}",
        execute_asm
    );

    // Asset lookup opcodes for payment asset verification
    assert!(
        execute_asm.contains(OP_INSPECTINASSETLOOKUP),
        "missing {OP_INSPECTINASSETLOOKUP} in execute: {}",
        execute_asm
    );
    assert!(
        execute_asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "missing {OP_INSPECTOUTASSETLOOKUP} in execute: {}",
        execute_asm
    );

    // Lookups assert presence by consuming the opcode success flag with OP_VERIFY
    assert!(
        execute_asm.contains(&format!("{OP_INSPECTINASSETLOOKUP} {OP_VERIFY}")),
        "input lookup must be followed by OP_VERIFY flag-consume: {}",
        execute_asm
    );
    assert!(
        execute_asm.contains(&format!("{OP_INSPECTOUTASSETLOOKUP} {OP_VERIFY}")),
        "output lookup must be followed by OP_VERIFY flag-consume: {}",
        execute_asm
    );

    // Both lookup amounts must be positive.
    assert!(
        execute_asm.contains(&format!(
            "{OP_INSPECTINASSETLOOKUP} {OP_VERIFY} 0 {OP_GREATERTHAN}"
        )),
        "input amount must be compared with zero: {}",
        execute_asm
    );
    assert!(
        execute_asm.contains(&format!(
            "{OP_INSPECTOUTASSETLOOKUP} {OP_VERIFY} 0 {OP_GREATERTHAN}"
        )),
        "output amount must be compared with zero: {}",
        execute_asm
    );

    // Sender signature check
    assert!(
        execute_asm.contains(OP_CHECKSIG),
        "missing {OP_CHECKSIG} in execute: {}",
        execute_asm
    );

    // execute leaf carries server + emulator cosig
    let execute_leaf = crate::common::leaf_asm(&output, "execute", "execute");
    assert!(
        execute_leaf.contains("<SERVER_KEY>"),
        "execute leaf should have SERVER_KEY: {}",
        execute_leaf
    );

    // Verify adjust function
    let adjust_group = crate::common::group(&output, "adjust");
    let adjust_inputs = &adjust_group.arkade.as_ref().unwrap().inputs;
    assert_eq!(adjust_inputs.len(), 1);
    assert_eq!(adjust_inputs[0].name, "operatorSig");

    // Unilateral exit: standalone CSV leaf with no introspection.
    let unilateral_asm = crate::common::leaf_asm(&output, "unilateral", "unilateral");

    assert!(
        unilateral_asm.contains(OP_CHECKSIG),
        "missing {OP_CHECKSIG} in unilateral exit: {}",
        unilateral_asm
    );
    assert!(
        unilateral_asm.contains(OP_CHECKSEQUENCEVERIFY),
        "missing CSV exit timelock in unilateral leaf: {}",
        unilateral_asm
    );
    assert!(
        !unilateral_asm.contains(OP_INSPECTINASSETLOOKUP),
        "exit leaf should not have introspection: {}",
        unilateral_asm
    );
    assert!(
        !unilateral_asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "exit leaf should not have introspection: {}",
        unilateral_asm
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

    let code = include_str!("../../examples/fee_adapter/fee_adapter.ark");
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
    // New model uses arkade groups and leaves; no serverVariant field
    assert!(json.contains("\"arkade\""));
    assert!(json.contains("\"leaves\""));
    assert!(json.contains(OP_INSPECTINASSETLOOKUP));
    assert!(json.contains(OP_INSPECTOUTASSETLOOKUP));
}
