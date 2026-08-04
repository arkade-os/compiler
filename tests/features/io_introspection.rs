use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_INSPECTINPUTOUTPOINT, OP_INSPECTINPUTSCRIPTPUBKEY, OP_INSPECTINPUTSEQUENCE,
    OP_INSPECTINPUTVALUE, OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_INSPECTOUTPUTVALUE, OP_SWAP,
};

/// Test input introspection opcodes
#[test]
fn test_input_value() {
    let code = r#"
        contract InputValueChecker(pubkey owner) {
            function checkInputValue(signature ownerSig, int minValue) {
                require(checkSig(ownerSig, owner));
                require(tx.inputs[0].value >= minValue);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse tx.inputs[0].value: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let asm_str = crate::common::arkade_asm(&output, "checkInputValue");
    assert!(
        asm_str.contains(OP_INSPECTINPUTVALUE),
        "Expected {OP_INSPECTINPUTVALUE} in ASM: {}",
        asm_str
    );
}

#[test]
fn test_input_script_pubkey() {
    let code = r#"
        contract InputScriptChecker(pubkey owner, bytes32 expectedScript) {
            function checkInputScript(signature ownerSig) {
                require(checkSig(ownerSig, owner));
                require(tx.inputs[0].scriptPubKey == expectedScript);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse tx.inputs[0].scriptPubKey: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let asm_str = crate::common::arkade_asm(&output, "checkInputScript");
    assert!(
        asm_str.contains(OP_INSPECTINPUTSCRIPTPUBKEY),
        "Expected {OP_INSPECTINPUTSCRIPTPUBKEY} in ASM: {}",
        asm_str
    );
}

#[test]
fn test_input_sequence() {
    let code = r#"
        contract SequenceChecker(pubkey owner) {
            function checkSequence(signature ownerSig, int expectedSeq) {
                require(checkSig(ownerSig, owner));
                require(tx.inputs[0].sequence == expectedSeq);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse tx.inputs[0].sequence: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let asm_str = crate::common::arkade_asm(&output, "checkSequence");
    assert!(
        asm_str.contains(OP_INSPECTINPUTSEQUENCE),
        "Expected {OP_INSPECTINPUTSEQUENCE} in ASM: {}",
        asm_str
    );
}

#[test]
fn test_input_outpoint_returns_struct() {
    let code = r#"
        contract OutpointChecker(pubkey owner, bytes32 expectedTxid, int expectedVout) {
            function checkOutpoint(signature ownerSig, int inputIndex) {
                require(checkSig(ownerSig, owner));
                let outpoint = tx.inputs[inputIndex].outpoint;
                Outpoint current = tx.input.current.outpoint;
                require(outpoint.txid == expectedTxid);
                require(outpoint.vout == expectedVout);
                require(current.vout >= 0);
            }
        }
    "#;

    let output = compile(code).expect("outpoint returns an Outpoint struct");
    let asm = crate::common::arkade_asm_tokens(&output, "checkOutpoint");
    assert!(asm.iter().any(|token| token == OP_INSPECTINPUTOUTPOINT));
    assert!(asm.iter().any(|token| token == OP_SWAP));
}

/// Test output introspection opcodes
#[test]
fn test_output_value() {
    let code = r#"
        contract OutputValueChecker(pubkey owner) {
            function checkOutputValue(signature ownerSig, int minValue) {
                require(checkSig(ownerSig, owner));
                require(tx.outputs[0].value >= minValue);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse tx.outputs[0].value: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let asm_str = crate::common::arkade_asm(&output, "checkOutputValue");
    assert!(
        asm_str.contains(OP_INSPECTOUTPUTVALUE),
        "Expected {OP_INSPECTOUTPUTVALUE} in ASM: {}",
        asm_str
    );
}

#[test]
fn test_output_script_pubkey() {
    let code = r#"
        contract OutputScriptChecker(pubkey owner, bytes32 expectedScript) {
            function checkOutputScript(signature ownerSig) {
                require(checkSig(ownerSig, owner));
                require(tx.outputs[0].scriptPubKey == expectedScript);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse tx.outputs[0].scriptPubKey: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let asm_str = crate::common::arkade_asm(&output, "checkOutputScript");
    assert!(
        asm_str.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "Expected {OP_INSPECTOUTPUTSCRIPTPUBKEY} in ASM: {}",
        asm_str
    );
}

/// Test variable index for input/output introspection
#[test]
fn test_variable_index_input() {
    let code = r#"
        contract DynamicInputChecker(pubkey owner) {
            function checkInput(signature ownerSig, int inputIdx, int minValue) {
                require(checkSig(ownerSig, owner));
                require(tx.inputs[inputIdx].value >= minValue);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse tx.inputs[inputIdx].value: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let asm_str = crate::common::arkade_asm(&output, "checkInput");
    assert!(
        asm_str.contains("OP_PICK OP_INSPECTINPUTVALUE"),
        "{asm_str}"
    );
    assert!(
        !asm_str.contains("<inputIdx>"),
        "Function inputs must be read from the symbolic stack: {asm_str}"
    );
    assert!(
        asm_str.contains(OP_INSPECTINPUTVALUE),
        "Expected {OP_INSPECTINPUTVALUE} in ASM: {}",
        asm_str
    );
}

#[test]
fn test_variable_index_output() {
    let code = r#"
        contract DynamicOutputChecker(pubkey owner) {
            function checkOutput(signature ownerSig, int outputIdx, int minValue) {
                require(checkSig(ownerSig, owner));
                require(tx.outputs[outputIdx].value >= minValue);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse tx.outputs[outputIdx].value: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let asm_str = crate::common::arkade_asm(&output, "checkOutput");
    assert!(
        asm_str.contains("OP_PICK OP_INSPECTOUTPUTVALUE"),
        "{asm_str}"
    );
    assert!(
        !asm_str.contains("<outputIdx>"),
        "Function inputs must be read from the symbolic stack: {asm_str}"
    );
    assert!(
        asm_str.contains(OP_INSPECTOUTPUTVALUE),
        "Expected {OP_INSPECTOUTPUTVALUE} in ASM: {}",
        asm_str
    );
}

/// Test cross-comparison between input and output values
#[test]
fn test_input_output_value_comparison() {
    let code = r#"
        contract ValueComparison(pubkey owner) {
            function checkValues(signature ownerSig) {
                require(checkSig(ownerSig, owner));
                require(tx.outputs[0].value >= tx.inputs[0].value);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse input/output value comparison: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let asm_str = crate::common::arkade_asm(&output, "checkValues");
    assert!(
        asm_str.contains(OP_INSPECTOUTPUTVALUE),
        "Expected {OP_INSPECTOUTPUTVALUE} in ASM: {}",
        asm_str
    );
    assert!(
        asm_str.contains(OP_INSPECTINPUTVALUE),
        "Expected {OP_INSPECTINPUTVALUE} in ASM: {}",
        asm_str
    );
}
