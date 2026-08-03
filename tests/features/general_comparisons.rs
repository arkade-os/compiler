use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_0, OP_1, OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_EQUAL, OP_GREATERTHAN, OP_GREATERTHANOREQUAL,
    OP_LESSTHAN, OP_LESSTHANOREQUAL, OP_NOT, OP_PICK, OP_PUSHCURRENTINPUTINDEX, OP_VERIFY,
};

fn compile_asm(source: &str) -> Vec<String> {
    let output = compile(source).unwrap_or_else(|error| panic!("compile failed: {error}"));
    crate::common::arkade_asm_tokens(&output, "compare")
}

fn contains_tokens(asm: &[String], expected: &[&str]) -> bool {
    asm.windows(expected.len()).any(|window| {
        window
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied())
    })
}

#[test]
fn integer_comparisons_emit_all_boolean_operators() {
    let cases: [(&str, &[&str]); 6] = [
        ("==", &[OP_0, OP_PICK, "OP_2", OP_PICK, OP_EQUAL]),
        ("!=", &[OP_0, OP_PICK, "OP_2", OP_PICK, OP_EQUAL, OP_NOT]),
        (
            ">=",
            &[OP_0, OP_PICK, "OP_2", OP_PICK, OP_GREATERTHANOREQUAL],
        ),
        (">", &[OP_0, OP_PICK, "OP_2", OP_PICK, OP_GREATERTHAN]),
        ("<=", &[OP_0, OP_PICK, "OP_2", OP_PICK, OP_LESSTHANOREQUAL]),
        ("<", &[OP_0, OP_PICK, "OP_2", OP_PICK, OP_LESSTHAN]),
    ];

    for (operator, expected) in cases {
        let source = format!(
            "contract Compare(int left, int right) {{
                function compare() {{
                    require(left {operator} right);
                }}
            }}"
        );
        let asm = compile_asm(&source);
        assert!(
            contains_tokens(&asm, expected),
            "{operator} must emit {expected:?}; got {asm:?}"
        );
    }
}

#[test]
fn declared_scalar_types_compare_directly() {
    for scalar_type in [
        "pubkey",
        "signature",
        "bytes",
        "bytes20",
        "bytes32",
        "int",
        "bool",
        "asset",
    ] {
        let source = format!(
            "contract Compare() {{
                function compare({scalar_type} left, {scalar_type} right) {{
                    require(left == right);
                    require(left != right);
                }}
            }}"
        );
        let output = compile(&source)
            .unwrap_or_else(|error| panic!("{scalar_type} compile failed: {error}"));
        let asm = crate::common::arkade_asm_tokens(&output, "compare");
        assert!(
            contains_tokens(&asm, &[OP_0, OP_PICK, "OP_2", OP_PICK, OP_EQUAL]),
            "{scalar_type} equality must emit OP_EQUAL: {asm:?}"
        );
        assert!(
            contains_tokens(&asm, &[OP_0, OP_PICK, "OP_2", OP_PICK, OP_EQUAL, OP_NOT]),
            "{scalar_type} inequality must emit OP_EQUAL OP_NOT: {asm:?}"
        );
        assert!(
            output
                .warnings
                .iter()
                .all(|warning| !warning.contains("warning[type]")),
            "same-type {scalar_type} comparison must not warn: {:?}",
            output.warnings
        );
    }
}

#[test]
fn active_input_index_comparison_preserves_operand_order() {
    let asm = compile_asm(
        "contract Compare(int index) {
            function compare() {
                require(index == this.activeInputIndex);
                require(this.activeInputIndex == index);
            }
        }",
    );

    assert!(
        contains_tokens(&asm, &[OP_0, OP_PICK, OP_PUSHCURRENTINPUTINDEX, OP_EQUAL]),
        "reversed comparison must emit the variable first: {asm:?}"
    );
    assert!(
        contains_tokens(&asm, &[OP_PUSHCURRENTINPUTINDEX, OP_1, OP_PICK, OP_EQUAL]),
        "property-first comparison must emit the property first: {asm:?}"
    );
    assert!(
        !asm.iter().any(|token| token == "<this.activeInputIndex>"),
        "the active input index must not leak as a placeholder: {asm:?}"
    );
}

#[test]
fn require_accepts_direct_boolean_expressions() {
    let asm = compile_asm(
        "contract Compare(pubkey owner, bool enabled) {
            function compare(signature signature) {
                require(enabled);
                require(checkSig(signature, owner));
            }
        }",
    );

    assert!(
        contains_tokens(&asm, &[OP_1, OP_PICK, OP_VERIFY]),
        "a bool variable must be read from its symbolic stack slot: {asm:?}"
    );
    assert!(
        contains_tokens(
            &asm,
            &["OP_2", OP_PICK, OP_1, OP_PICK, OP_CHECKSIG, OP_VERIFY]
        ),
        "checkSig must be accepted as a direct boolean requirement: {asm:?}"
    );
    assert!(
        !asm.iter().any(|token| token.contains("true")),
        "boolean requirements must not emit a dummy true value: {asm:?}"
    );
}

#[test]
fn boolean_literals_emit_canonical_script_values() {
    let asm = compile_asm(
        "contract Compare() {
            function compare() {
                require(true);
                require(false);
            }
        }",
    );

    // Each require() fails fast via OP_VERIFY; the covenant terminates with OP_1.
    assert_eq!(
        asm,
        [OP_1, OP_VERIFY, OP_0, OP_VERIFY, OP_1],
        "boolean literals must be canonical: {asm:?}"
    );
    assert!(
        !asm.iter()
            .any(|token| matches!(token.as_str(), "<true>" | "<false>")),
        "boolean literals must not leak as placeholders: {asm:?}"
    );
}

#[test]
fn true_on_comparison_rhs_is_not_treated_as_a_bare_requirement() {
    let asm = compile_asm(
        "contract Compare() {
            function compare() {
                require(2 == true);
            }
        }",
    );

    assert!(
        contains_tokens(&asm, &["2", OP_1, OP_EQUAL]),
        "explicit comparison must emit both operands and OP_EQUAL: {asm:?}"
    );
}

#[test]
fn boolean_calls_can_be_compared_or_required_directly() {
    let asm = compile_asm(
        "contract Compare(pubkey owner, bytes32 message, bool expected) {
            function compare(signature signature) {
                require(checkSig(signature, owner) == expected);
                require(checkSigFromStack(signature, owner, message) != expected);
                require(checkSig(signature, owner));
                require(checkSigFromStack(signature, owner, message));
            }
        }",
    );

    assert!(
        asm.iter().filter(|token| *token == OP_CHECKSIG).count() == 2
            && asm.iter().filter(|token| *token == OP_EQUAL).count() == 2,
        "checkSig result must be comparable: {asm:?}"
    );
    assert!(
        contains_tokens(
            &asm,
            &[OP_CHECKSIGFROMSTACK, "OP_3", OP_PICK, OP_EQUAL, OP_NOT]
        ),
        "checkSigFromStack result must support inequality: {asm:?}"
    );
    assert_eq!(
        asm.iter().filter(|token| *token == OP_CHECKSIG).count(),
        2,
        "direct and compared checkSig calls must both remain: {asm:?}"
    );
    assert_eq!(
        asm.iter()
            .filter(|token| *token == OP_CHECKSIGFROMSTACK)
            .count(),
        2,
        "direct and compared checkSigFromStack calls must both remain: {asm:?}"
    );
}

#[test]
fn compared_boolean_calls_reject_invalid_signature_types() {
    let error = compile(
        "contract Compare(bool expected) {
            function compare(pubkey wrongSignature, signature wrongPubkey) {
                require(checkSig(wrongSignature, wrongPubkey) == expected);
            }
        }",
    )
    .expect_err("signature type errors must be fatal")
    .to_string();

    assert!(
        error.contains("expected 'signature'") && error.contains("expected 'pubkey'"),
        "comparison-context checkSig must retain argument validation: {error}"
    );
}

#[test]
fn comparison_results_can_be_compared_as_boolean_operands() {
    let asm = compile_asm(
        "contract Compare(int left, int right, bool expected) {
            function compare() {
                require((left < right) == expected);
            }
        }",
    );

    assert!(
        contains_tokens(
            &asm,
            &[
                OP_0,
                OP_PICK,
                "OP_2",
                OP_PICK,
                OP_LESSTHAN,
                "OP_3",
                OP_PICK,
                OP_EQUAL
            ]
        ),
        "nested comparison must leave a boolean for the outer comparison: {asm:?}"
    );
}

#[test]
fn constructor_and_introspection_results_use_general_comparisons() {
    let asm = compile_asm(
        r#"
import "single_sig.ark";

contract Compare(pubkey owner, bytes expectedScript, bytes32 expectedTxid) {
    function compare() {
        require(expectedScript == new SingleSig(owner));
        require(expectedTxid == tx.id);
    }
}
"#,
    );

    assert!(
        asm.windows(4).any(|window| {
            window[0] == OP_1
                && window[1] == OP_PICK
                && window[2].contains("VTXO:SingleSig(")
                && window[3] == OP_EQUAL
        }),
        "constructor comparison must preserve the reversed operand order: {asm:?}"
    );
    assert!(
        contains_tokens(&asm, &["OP_2", OP_PICK, "OP_TXID", OP_EQUAL]),
        "introspection comparison must emit its native opcode: {asm:?}"
    );
}

#[test]
fn non_boolean_requirements_warn() {
    let non_boolean = compile(
        "contract Invalid() {
            function compare() {
                require(1);
            }
        }",
    )
    .expect("type errors remain non-fatal");
    assert!(
        non_boolean
            .warnings
            .iter()
            .any(|warning| warning.contains("warning[type]") && warning.contains("bool")),
        "require must warn for a known non-boolean expression: {:?}",
        non_boolean.warnings
    );
}

#[test]
fn mismatched_comparisons_warn() {
    let mismatch = compile(
        "contract Invalid(int count, bytes payload) {
            function compare() {
                require(count == payload);
            }
        }",
    )
    .expect("type errors remain non-fatal");
    assert!(
        mismatch.warnings.iter().any(|warning| {
            warning.contains("warning[type]")
                && (warning.contains("comparison") || warning.contains("compatible"))
        }),
        "comparison must warn for known incompatible operand types: {:?}",
        mismatch.warnings
    );
}

#[test]
fn direct_array_equality_is_rejected() {
    let error = compile(
        "contract Invalid() {
            function compare(int[] left, int[] right) {
                require(left == right);
            }
        }",
    )
    .expect_err("array bindings cannot be read as one stack item")
    .to_string();
    assert!(
        error.contains("array expressions are composite values"),
        "direct array equality must be rejected: {error}"
    );
}
