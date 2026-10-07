use crate::common::compile_unoptimized as compile;
use arkade_compiler::opcodes::{
    OP_EQUALVERIFY, OP_INSPECTINPUTARKADESCRIPTHASH, OP_INSPECTINPUTARKADEWITNESSHASH,
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

#[test]
fn test_input_outpoint_is_compared_field_by_field() {
    let output = compile(
        r#"
        contract OutpointChecker() {
            function checkOutpoint() {
                let expected = tx.input.current.outpoint;
                require(tx.inputs[0].outpoint == expected);
            }
        }
    "#,
    )
    .expect("outpoint equality compares txid and vout");

    let asm = crate::common::arkade_asm_tokens(&output, "checkOutpoint");
    assert_eq!(
        asm.iter()
            .filter(|token| *token == OP_INSPECTINPUTOUTPOINT)
            .count(),
        2,
        "both outpoints are inspected: {asm:?}"
    );
    assert_eq!(
        asm.iter().filter(|token| *token == OP_EQUALVERIFY).count(),
        2,
        "txid and vout are both verified: {asm:?}"
    );
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
        asm_str.contains("OP_ROLL OP_INSPECTINPUTVALUE"),
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
        asm_str.contains("OP_ROLL OP_INSPECTOUTPUTVALUE"),
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

/// tx.input.current.arkadeScriptHash/.arkadeWitnessHash used to silently
/// compile to a scriptPubKey inspection instead of the named field.
#[test]
fn test_current_input_arkade_hashes() {
    let code = r#"
        contract V(pubkey owner) {
            function spend(signature sig) {
                require(checkSig(sig, owner));
                require(tx.input.current.arkadeScriptHash != tx.input.current.arkadeWitnessHash);
            }
        }
    "#;

    let output = compile(code).expect("current-input arkade hashes compile");
    let asm_str = crate::common::arkade_asm(&output, "spend");
    assert!(
        asm_str.contains(OP_INSPECTINPUTARKADESCRIPTHASH),
        "Expected {OP_INSPECTINPUTARKADESCRIPTHASH} in ASM: {asm_str}"
    );
    assert!(
        asm_str.contains(OP_INSPECTINPUTARKADEWITNESSHASH),
        "Expected {OP_INSPECTINPUTARKADEWITNESSHASH} in ASM: {asm_str}"
    );
}

/// An unrecognized tx.input.current property must be a clear parse error,
/// not a silent fall-through to scriptPubKey inspection.
#[test]
fn test_current_input_rejects_unknown_property() {
    let code = r#"
        contract V(pubkey owner) {
            function spend(signature sig) {
                require(checkSig(sig, owner));
                let x = tx.input.current.weight;
                require(x >= 0);
            }
        }
    "#;

    let error = compile(code)
        .expect_err("unknown current-input property must be rejected")
        .to_string();
    assert!(
        error.contains("tx.input.current requires one of"),
        "{error}"
    );
}

/// tx.input.current with no property is not a value on its own.
#[test]
fn test_current_input_requires_a_property() {
    let code = r#"
        contract V(pubkey owner) {
            function spend(signature sig) {
                require(checkSig(sig, owner));
                let x = tx.input.current;
                require(x == x);
            }
        }
    "#;

    let error = compile(code)
        .expect_err("bare tx.input.current must be rejected")
        .to_string();
    assert!(
        error.contains("tx.input.current requires one of"),
        "{error}"
    );
}

#[test]
fn witness_version_keeps_the_second_script_pubkey_result() {
    for (expression, expected) in [
        (
            "tx.inputs[1].witnessVersion",
            format!("1 {OP_INSPECTINPUTSCRIPTPUBKEY} OP_NIP"),
        ),
        (
            "tx.outputs[2].witnessVersion",
            format!("2 {OP_INSPECTOUTPUTSCRIPTPUBKEY} OP_NIP"),
        ),
        (
            "tx.input.current.witnessVersion",
            format!("OP_PUSHCURRENTINPUTINDEX {OP_INSPECTINPUTSCRIPTPUBKEY} OP_NIP"),
        ),
    ] {
        let code = format!("contract V() {{ function spend() {{ require({expression} == 1); }} }}");
        let output = compile(&code).unwrap_or_else(|error| panic!("{expression}: {error}"));
        let asm = crate::common::arkade_asm_tokens(&output, "spend").join(" ");
        assert!(asm.contains(&expected), "{expression}: {asm}");
    }
}

#[test]
fn witness_version_is_an_int() {
    let code = "contract V(bytes program) { function spend() { require(tx.outputs[0].witnessVersion == program); } }";
    let error = compile(code)
        .expect_err("a witness version is not bytes")
        .to_string();
    assert!(
        error.contains("comparison '==' is not defined between 'int' and 'bytes'"),
        "{error}"
    );
}

#[test]
fn witness_version_is_rejected_in_tapscripts() {
    for expression in [
        "tx.input.current.witnessVersion",
        "tx.inputs[0].witnessVersion",
        "tx.outputs[0].witnessVersion",
    ] {
        let code = format!("contract V(pubkey owner) {{ function exit(signature sig) tapscript {{ require({expression} == 1); require(checkSig(sig, owner)); }} }}");
        let error = compile(&code)
            .expect_err("introspection must not compile into an L1 leaf")
            .to_string();
        assert!(
            error.contains("unsupported compound expression in tapscript"),
            "{expression}: {error}"
        );
    }
}
