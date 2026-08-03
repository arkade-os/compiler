use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKSIGFROMSTACK, OP_GREATERTHANOREQUAL, OP_INSPECTINASSETLOOKUP,
};

use crate::common::{arkade_asm, arkade_inputs};

/// Exercises array flattening and threshold verification over unrolled oracle signatures.
const THRESHOLD_ORACLE_CODE: &str =
    include_str!("../../examples/threshold_oracle/threshold_oracle.ark");

#[test]
fn test_threshold_oracle_parses() {
    let result = compile(THRESHOLD_ORACLE_CODE);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

#[test]
fn test_threshold_oracle_structure() {
    let output = compile(THRESHOLD_ORACLE_CODE).unwrap();

    assert_eq!(output.name, "ThresholdOracle");
    assert_eq!(output.functions.len(), 1);
    assert_eq!(output.functions[0].name, "attest");
}

#[test]
fn test_threshold_oracle_has_asset_lookup() {
    let output = compile(THRESHOLD_ORACLE_CODE).unwrap();
    let asm = arkade_asm(&output, "attest");

    // Should have asset lookup for control asset check
    assert!(
        asm.contains(OP_INSPECTINASSETLOOKUP),
        "Missing {OP_INSPECTINASSETLOOKUP} in attest function"
    );
}

#[test]
fn test_threshold_oracle_has_control_flow() {
    let output = compile(THRESHOLD_ORACLE_CODE).unwrap();
    let tokens = crate::common::arkade_asm_tokens(&output, "attest");

    // Should have assembly (for loop unrolled etc.)
    assert!(!tokens.is_empty(), "Assembly should not be empty");
}

// ─── Array ABI Grouping ────────────────────────────────────────────────────────

#[test]
fn test_threshold_oracle_constructor_array_is_one_grouped_input() {
    let output = compile(THRESHOLD_ORACLE_CODE).unwrap();

    let oracles = output
        .parameters
        .iter()
        .find(|p| p.name == "oracles")
        .expect("constructorInputs keeps one entry per source parameter");
    assert_eq!(oracles.param_type, "pubkey[3]");

    let param_names: Vec<&str> = output.parameters.iter().map(|p| p.name.as_str()).collect();
    assert!(
        !param_names.iter().any(|name| name.starts_with("oracles_")),
        "array elements must not appear as separate inputs. Got: {param_names:?}"
    );

    // The asm prologue still pushes one placeholder per element.
    let asm = crate::common::arkade_asm(&output, "attest");
    for placeholder in ["<oracles_0>", "<oracles_1>", "<oracles_2>"] {
        assert!(asm.contains(placeholder), "missing {placeholder} in: {asm}");
    }
}

#[test]
fn test_threshold_oracle_covenant_array_input_is_one_grouped_input() {
    let output = compile(THRESHOLD_ORACLE_CODE).unwrap();

    let input_names = arkade_inputs(&output, "attest");
    assert!(
        input_names.contains(&"recipientScriptPubKey".to_string()),
        "Missing recipientScriptPubKey in covenant inputs. Got: {input_names:?}"
    );
    assert!(
        input_names.contains(&"oracleSigs".to_string()),
        "covenant inputs keep one entry per source parameter. Got: {input_names:?}"
    );
    assert!(
        !input_names
            .iter()
            .any(|name| name.starts_with("oracleSigs_")),
        "array elements must not appear as separate inputs. Got: {input_names:?}"
    );
}

#[test]
fn test_threshold_oracle_checksig_from_stack_unrolled() {
    let output = compile(THRESHOLD_ORACLE_CODE).unwrap();

    let tokens = crate::common::arkade_asm_tokens(&output, "attest");

    // The for loop should unroll to 3 OP_CHECKSIGFROMSTACK calls
    let checksig_count = tokens.iter().filter(|s| *s == OP_CHECKSIGFROMSTACK).count();

    assert_eq!(
        checksig_count, 3,
        "Expected 3 {OP_CHECKSIGFROMSTACK} calls (one per oracle). Got: {}. ASM: {:?}",
        checksig_count, tokens
    );
}

#[test]
fn test_threshold_oracle_array_indexing_in_loop() {
    let output = compile(THRESHOLD_ORACLE_CODE).unwrap();

    let asm_str = arkade_asm(&output, "attest");

    // When loop unrolls, oracles[i] should become <oracles_0>, <oracles_1>, <oracles_2>
    assert!(
        asm_str.contains("<oracles_0>"),
        "Missing <oracles_0> in assembly (from oracles[0]). ASM: {}",
        asm_str
    );
    assert!(
        asm_str.contains("<oracles_1>"),
        "Missing <oracles_1> in assembly (from oracles[1]). ASM: {}",
        asm_str
    );
    assert!(
        asm_str.contains("<oracles_2>"),
        "Missing <oracles_2> in assembly (from oracles[2]). ASM: {}",
        asm_str
    );

    // Function inputs are read from their witness stack positions.
    assert!(!asm_str.contains("<oracleSigs_"), "ASM: {}", asm_str);
    assert!(asm_str.contains("OP_PICK"), "ASM: {}", asm_str);
}

#[test]
fn test_threshold_oracle_quorum_uses_csn_comparison() {
    let output = compile(THRESHOLD_ORACLE_CODE).unwrap();

    let asm_str = arkade_asm(&output, "attest");

    // The quorum check (valid >= threshold) should use OP_GREATERTHANOREQUAL
    assert!(
        asm_str.contains(OP_GREATERTHANOREQUAL),
        "Missing {OP_GREATERTHANOREQUAL} for quorum check. ASM: {}",
        asm_str
    );
}
