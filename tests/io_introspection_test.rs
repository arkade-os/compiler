use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_INSPECTINPUTISSUANCE, OP_INSPECTINPUTOUTPOINT, OP_INSPECTINPUTSCRIPTPUBKEY,
    OP_INSPECTINPUTSEQUENCE, OP_INSPECTINPUTVALUE, OP_INSPECTOUTPUTNONCE,
    OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_INSPECTOUTPUTVALUE,
};

/// Test input introspection opcodes
#[test]
fn test_input_value() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract InputValueChecker(pubkey serverKey, pubkey owner) {
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
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "checkInputValue" && f.server_variant)
        .expect("Should have checkInputValue server variant");

    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains(OP_INSPECTINPUTVALUE),
        "Expected {OP_INSPECTINPUTVALUE} in ASM: {}",
        asm_str
    );
}

#[test]
fn test_input_script_pubkey() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract InputScriptChecker(pubkey serverKey, pubkey owner, bytes32 expectedScript) {
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
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "checkInputScript" && f.server_variant)
        .expect("Should have checkInputScript server variant");

    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains(OP_INSPECTINPUTSCRIPTPUBKEY),
        "Expected {OP_INSPECTINPUTSCRIPTPUBKEY} in ASM: {}",
        asm_str
    );
}

#[test]
fn test_input_sequence() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract SequenceChecker(pubkey serverKey, pubkey owner) {
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
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "checkSequence" && f.server_variant)
        .expect("Should have checkSequence server variant");

    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains(OP_INSPECTINPUTSEQUENCE),
        "Expected {OP_INSPECTINPUTSEQUENCE} in ASM: {}",
        asm_str
    );
}

#[test]
fn test_input_outpoint() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract OutpointChecker(pubkey serverKey, pubkey owner, bytes32 expectedOutpoint) {
            function checkOutpoint(signature ownerSig) {
                require(checkSig(ownerSig, owner));
                require(tx.inputs[0].outpoint == expectedOutpoint);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse tx.inputs[0].outpoint: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "checkOutpoint" && f.server_variant)
        .expect("Should have checkOutpoint server variant");

    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains(OP_INSPECTINPUTOUTPOINT),
        "Expected {OP_INSPECTINPUTOUTPOINT} in ASM: {}",
        asm_str
    );
}

#[test]
fn test_input_issuance() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract IssuanceChecker(pubkey serverKey, pubkey owner, bytes32 expectedIssuance) {
            function checkIssuance(signature ownerSig) {
                require(checkSig(ownerSig, owner));
                require(tx.inputs[0].issuance == expectedIssuance);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse tx.inputs[0].issuance: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "checkIssuance" && f.server_variant)
        .expect("Should have checkIssuance server variant");

    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains(OP_INSPECTINPUTISSUANCE),
        "Expected {OP_INSPECTINPUTISSUANCE} in ASM: {}",
        asm_str
    );
}

/// Test output introspection opcodes
#[test]
fn test_output_value() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract OutputValueChecker(pubkey serverKey, pubkey owner) {
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
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "checkOutputValue" && f.server_variant)
        .expect("Should have checkOutputValue server variant");

    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains(OP_INSPECTOUTPUTVALUE),
        "Expected {OP_INSPECTOUTPUTVALUE} in ASM: {}",
        asm_str
    );
}

#[test]
fn test_output_script_pubkey() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract OutputScriptChecker(pubkey serverKey, pubkey owner, bytes32 expectedScript) {
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
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "checkOutputScript" && f.server_variant)
        .expect("Should have checkOutputScript server variant");

    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "Expected {OP_INSPECTOUTPUTSCRIPTPUBKEY} in ASM: {}",
        asm_str
    );
}

#[test]
fn test_output_nonce() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract NonceChecker(pubkey serverKey, pubkey owner, bytes32 expectedNonce) {
            function checkNonce(signature ownerSig) {
                require(checkSig(ownerSig, owner));
                require(tx.outputs[0].nonce == expectedNonce);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse tx.outputs[0].nonce: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "checkNonce" && f.server_variant)
        .expect("Should have checkNonce server variant");

    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains(OP_INSPECTOUTPUTNONCE),
        "Expected {OP_INSPECTOUTPUTNONCE} in ASM: {}",
        asm_str
    );
}

/// Test variable index for input/output introspection
#[test]
fn test_variable_index_input() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract DynamicInputChecker(pubkey serverKey, pubkey owner) {
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
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "checkInput" && f.server_variant)
        .expect("Should have checkInput server variant");

    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains("<inputIdx>"),
        "Expected <inputIdx> placeholder in ASM: {}",
        asm_str
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
        options {
            server = serverKey;
            exit = 144;
        }

        contract DynamicOutputChecker(pubkey serverKey, pubkey owner) {
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
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "checkOutput" && f.server_variant)
        .expect("Should have checkOutput server variant");

    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains("<outputIdx>"),
        "Expected <outputIdx> placeholder in ASM: {}",
        asm_str
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
        options {
            server = serverKey;
            exit = 144;
        }

        contract ValueComparison(pubkey serverKey, pubkey owner) {
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
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "checkValues" && f.server_variant)
        .expect("Should have checkValues server variant");

    let asm_str = func.asm.join(" ");
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
