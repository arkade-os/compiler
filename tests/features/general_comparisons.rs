use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_0, OP_1, OP_BOOLAND, OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_EQUAL, OP_EQUALVERIFY,
    OP_GREATERTHAN, OP_GREATERTHANOREQUAL, OP_LESSTHAN, OP_LESSTHANOREQUAL, OP_NOT, OP_PICK,
    OP_PUSHCURRENTINPUTINDEX, OP_ROLL, OP_VERIFY,
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
    let source = r#"
import "single_sig.ark";

contract Compare(pubkey owner, bytes expectedScript, bytes32 expectedTxid) {
    function compare() {
        require(expectedScript == new SingleSig(owner));
        require(expectedTxid == tx.id);
    }
}
"#;
    let output = arkade_compiler::compile_sources(
        "main.ark",
        &[
            ("main.ark".into(), source.into()),
            (
                "single_sig.ark".into(),
                "contract SingleSig(pubkey owner) {}".into(),
            ),
        ]
        .into_iter()
        .collect(),
    )
    .unwrap();
    let asm = crate::common::arkade_asm_tokens(&output, "compare");

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
fn array_equality_compares_every_element() {
    let asm = compile_asm(
        "contract Compare() {
            function compare(int[3] left, int[3] right) {
                require(left == right);
            }
        }",
    );
    assert_eq!(
        asm.iter().filter(|token| *token == OP_EQUALVERIFY).count(),
        3,
        "every element pair must be verified: {asm:?}"
    );
    assert!(
        asm.iter().any(|token| token == OP_ROLL),
        "element pairs are rolled together: {asm:?}"
    );

    let error = compile(
        "contract Invalid() {
            function compare(int[3] left, int[2] right) {
                require(left == right);
            }
        }",
    )
    .expect_err("arrays of different length have no common layout")
    .to_string();
    assert!(
        error.contains("comparison '==' is not defined between 'int[3]' and 'int[2]'"),
        "{error}"
    );
}

#[test]
fn array_inequality_negates_the_folded_comparison() {
    let asm = compile_asm(
        "contract Compare() {
            function compare(int[2] left, int[2] right) {
                require(left != right);
            }
        }",
    );
    assert_eq!(
        asm.iter().filter(|token| *token == OP_EQUAL).count(),
        2,
        "both element pairs are compared: {asm:?}"
    );
    assert!(
        contains_tokens(&asm, &[OP_BOOLAND, OP_NOT, OP_VERIFY]),
        "the folded result must be negated: {asm:?}"
    );
}

#[test]
fn composite_comparison_literals_are_validated() {
    for (ty, literal, diagnostic) in [
        ("int[2]", "[1, true]", "expected 'int', got 'bool'"),
        ("Point", "{x: 1, y: 2, y: 3}", "duplicate field 'y'"),
        ("Point", "{x: 1, y: 2, z: 3}", "unknown field 'z'"),
        ("Point", "{x: 1}", "missing field 'y'"),
        ("Point", "{x: true, y: 2}", "expected 'int', got 'bool'"),
        (
            "Nested",
            "{point: {x: 1, y: 2}, values: [1, true]}",
            "expected 'int', got 'bool'",
        ),
    ] {
        for op in ["==", "!="] {
            for (left, right) in [("value", literal), (literal, "value")] {
                let source = format!(
                    "struct Point {{ int x; int y; }}
                     struct Nested {{ Point point; int[2] values; }}
                     contract C() {{
                         function spend({ty} value) {{ require({left} {op} {right}); }}
                     }}"
                );
                let error = compile(&source).expect_err(&source).to_string();
                assert!(error.contains(diagnostic), "{source}: {error}");
            }
        }
    }
    let error = compile("contract C() { function spend() { require([1, true] == [1, 2]); } }")
        .expect_err("both operands are literals")
        .to_string();
    assert!(error.contains("expected 'int', got 'bool'"), "{error}");
}

#[test]
fn composite_comparisons_resolve_inferred_locals() {
    let source = "struct Point { int x; int y; }
        contract C() {
            private function helper() { let q = 5; require(q == 5); }
            function compare(Point q, int[2] a) {
                helper();
                let n = 1;
                require([n, 2] == a);
                require(a == [n, 2]);
                require([n, 3] != a);
                require(a != [n, 3]);
                require(q == {x: 1, y: 2});
            }
        }";
    let asm = compile_asm(source);
    assert_eq!(
        asm.iter().filter(|token| *token == OP_EQUALVERIFY).count(),
        6
    );
    assert_eq!(asm.iter().filter(|token| *token == OP_BOOLAND).count(), 2);
}

#[test]
fn logical_expressions_short_circuit_and_match_truth_tables() {
    // Only the opcodes used by these literal expressions need execution here.
    fn execute(asm: &[String]) -> Vec<i64> {
        let mut stack = Vec::new();
        let mut branches = Vec::new();
        let mut active = true;
        for token in asm {
            match token.as_str() {
                "OP_IF" => {
                    let condition = active && stack.pop().unwrap() != 0;
                    branches.push((active, condition));
                    active = condition;
                }
                "OP_ELSE" => {
                    let (parent, condition) = branches.last().unwrap();
                    active = *parent && !condition;
                }
                "OP_ENDIF" => active = branches.pop().unwrap().0,
                _ if !active => {}
                "OP_0" => stack.push(0),
                "OP_1" => stack.push(1),
                "OP_NOT" => {
                    let value = stack.pop().unwrap();
                    stack.push(i64::from(value == 0));
                }
                "OP_VERIFY" => assert_ne!(stack.pop().unwrap(), 0, "{asm:?}"),
                "OP_NIP" => {
                    stack.remove(stack.len() - 2);
                }
                "OP_EQUAL" | "OP_GREATERTHAN" | "OP_LESSTHAN" | "OP_DIV" => {
                    let right = stack.pop().unwrap();
                    let left = stack.pop().unwrap();
                    stack.push(match token.as_str() {
                        "OP_EQUAL" => i64::from(left == right),
                        "OP_GREATERTHAN" => i64::from(left > right),
                        "OP_LESSTHAN" => i64::from(left < right),
                        _ => left / right,
                    });
                }
                _ => stack.push(
                    token
                        .parse()
                        .unwrap_or_else(|_| panic!("unexpected token: {token}")),
                ),
            }
        }
        assert!(branches.is_empty());
        stack
    }
    for a in [false, true] {
        for b in [false, true] {
            for c in [false, true] {
                for (expression, expected) in [
                    (format!("{a} && {b}"), a && b),
                    (format!("{a} || {b}"), a || b),
                    (format!("{a} || {b} && !{c}"), a || b && !c),
                    (format!("({a} || {b}) && !{c}"), (a || b) && !c),
                    (format!("!({a} && {b}) || {c}"), !(a && b) || c),
                ] {
                    let asm = compile_asm(&format!("contract C() {{ function compare() {{ require(({expression}) == {expected}); }} }}"));
                    assert_eq!(execute(&asm), [1], "{expression}: {asm:?}");
                }
            }
        }
    }
    for expression in [
        "!(false && 1 / 0 > 0)",
        "true || 1 / 0 > 0",
        "!(false && (true || 1 / 0 > 0))",
        "true || (false && 1 / 0 > 0)",
        "(1 < 2 && 3 > 2) || false",
        "true || guarded()",
        "!(false && guarded())",
    ] {
        let asm = compile_asm(&format!(
            "contract C() {{ function compare() {{ require({expression}); }} private function guarded() bool {{ require(false); return true; }} }}"
        ));
        assert_eq!(execute(&asm), [1], "{expression}: {asm:?}");
    }
}

#[test]
fn logical_expressions_preserve_calls_bindings_and_spend_abi() {
    let output = compile(
        r#"
contract C(pubkey owner, bytes32 hash) {
    function compare(signature sig, bytes preimage, bool enabled, int amount) {
        bool valid = checkSig(sig, owner) || !enabled && amount > 0;
        valid = valid && (sha256(preimage) == hash || sufficient(amount));
        if (valid && sufficient(amount)) { require(valid); } else { require(!valid); }
        require(checkSigFromStack(sig, owner, hash) || !enabled);
        require(tx.time >= 0 && (amount > 0 || enabled));
        require(sha256(preimage) == hash || checkSig(sig, owner));
        require(sufficient(amount) == (enabled || amount > 0));
    }
    private function sufficient(int amount) bool { return amount > 0 && (amount < 100 || !false); }
}
"#,
    )
    .expect("logical calls and bindings");
    assert!(output.warnings.is_empty(), "{:?}", output.warnings);
    assert_eq!(output.functions.len(), 1);
    assert_eq!(
        crate::common::arkade_inputs(&output, "compare"),
        ["sig", "preimage", "enabled", "amount"]
    );
    assert_eq!(crate::common::group(&output, "compare").leaves.len(), 1);
    assert_eq!(
        crate::common::witness_names(&output, "compare", "compare"),
        ["serverSig", "emulatorSig"]
    );
    assert_eq!(
        crate::common::leaf_asm(&output, "compare", "compare"),
        "<SERVER_KEY> OP_CHECKSIGVERIFY <EMULATOR_KEY:compare> OP_CHECKSIG"
    );
    let asm = crate::common::arkade_asm_tokens(&output, "compare");
    assert!(asm.iter().any(|token| token == "OP_IF"));
    assert!(asm.iter().any(|token| token == "OP_INSPECTLOCKTIME"));
    assert!(asm.iter().any(|token| token == OP_CHECKSIGFROMSTACK));
    assert!(asm.iter().all(|token| !token.contains('$')));
    assert!(!asm
        .iter()
        .any(|token| token == "OP_BOOLAND" || token == "OP_BOOLOR"));
}

#[test]
fn logical_operands_require_booleans_even_when_skipped() {
    for expression in [
        "true && 1",
        "0 || false",
        "false && 0x00",
        "true || \"\"",
        "false && number()",
    ] {
        let error = compile(&format!("contract C() {{ function compare() {{ require({expression}); }} private function number() int {{ return 1; }} }}")).expect_err("invalid logical operand").to_string();
        assert!(
            error.contains("logical") && error.contains("expected 'bool'"),
            "{expression}: {error}"
        );
    }
    for expression in [
        "false && missing",
        "true || absent()",
        "false && checkSigFromStackVerify(sig, key, message)",
    ] {
        let error = compile(&format!("contract C(pubkey key, bytes32 message) {{ function compare(signature sig) {{ require({expression}); }} }}")).expect_err("invalid skipped expression").to_string();
        assert!(
            error.contains("undefined")
                || error.contains("unknown private")
                || error.contains("does not produce one stack item"),
            "{expression}: {error}"
        );
    }
    let error = compile("contract C(pubkey owner) { function exit(signature sig) tapscript { require(checkSig(sig, owner) || true); } }").expect_err("compound tapscript expression").to_string();
    assert!(
        error.contains("unsupported compound expression in tapscript"),
        "{error}"
    );
}

#[test]
fn logical_skipped_helpers_do_not_guarantee_spend_enforcement() {
    for expression in [
        "skip && guarded()",
        "skip || guarded()",
        "skip || (skip && guarded())",
    ] {
        let error = compile(&format!("contract C() {{ function compare(bool skip) {{ let value = {expression}; }} private function guarded() bool {{ require(true); return true; }} }}")).expect_err("skippable requirement").to_string();
        assert!(
            error.contains("spend path with no require"),
            "{expression}: {error}"
        );
    }
    for expression in ["guarded() && skip", "guarded() || skip"] {
        compile(&format!("contract C() {{ function compare(bool skip) {{ let value = {expression}; }} private function guarded() bool {{ require(true); return true; }} }}")).unwrap_or_else(|error| panic!("{expression}: {error}"));
    }
}
