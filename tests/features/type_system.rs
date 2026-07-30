//! CashScript-style type-system error detection tests.
//!
//! CashScript pioneered compile-time type checking for smart contract languages
//! that compile to Bitcoin Script.  These tests verify that the Arkade type
//! checker surfaces the same class of errors:
//!
//! - **Swapped arguments** — `checkSig(pubkey, sig)` instead of `checkSig(sig, pubkey)`.
//! - **Undeclared variable** — assigning to a name never declared.
//! - **Numeric types** — comparing BigNum introspection values with plain `int` values.
//! - **Wrong hash type** — passing an `int` where `bytes32` is expected.
//! - **Non-boolean if condition** — using an integer expression as a branch condition.
//!
//! Type errors that make stack behavior ambiguous are fatal. Other compatibility
//! issues remain warnings in `ContractJson.warnings`.

use arkade_compiler::compile;

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn compile_ok(source: &str) -> arkade_compiler::models::ContractJson {
    compile(source).unwrap_or_else(|e| panic!("unexpected compile error: {}", e))
}

fn has_type_warning(output: &arkade_compiler::models::ContractJson, pattern: &str) -> bool {
    output
        .warnings
        .iter()
        .any(|w| w.contains("warning[type]") && w.to_lowercase().contains(&pattern.to_lowercase()))
}

fn compile_error(source: &str) -> String {
    compile(source)
        .expect_err("contract must fail validation")
        .to_string()
}

// ─── Swapped sig / pubkey ─────────────────────────────────────────────────────

#[test]
fn swapped_checksig_args_are_rejected() {
    // The contract declares `pubkey sig, signature owner` — the *names* clearly
    // describe the types but are passed in the wrong order to checkSig.
    let source = r#"
contract Swapped(pubkey owner) {
    function spend(pubkey sig, signature ownerSig) {
        require(checkSig(sig, ownerSig));
    }
}"#;
    // sig is pubkey, ownerSig is signature → arguments are swapped
    let error = compile_error(source);
    assert!(
        error.contains("expected 'signature'") && error.contains("expected 'pubkey'"),
        "swapped checkSig arguments must be rejected: {error}"
    );
}

#[test]
fn correct_checksig_order_produces_no_type_warning() {
    let source = r#"
contract Correct(pubkey owner) {
    function spend(signature ownerSig) {
        require(checkSig(ownerSig, owner));
    }
}"#;
    let output = compile_ok(source);
    let has_warning = has_type_warning(&output, "swapped") || has_type_warning(&output, "checkSig");
    assert!(
        !has_warning,
        "correct checkSig argument order must produce no type warnings; got: {:?}",
        output.warnings
    );
}

// ─── Undeclared variable assignment ──────────────────────────────────────────

#[test]
fn assignment_to_undeclared_variable_is_rejected() {
    let source = r#"
contract UndeclaredAssign(pubkey owner) {
    function spend(signature ownerSig) {
        undeclaredVar = 42;
        require(checkSig(ownerSig, owner));
    }
}"#;
    let error = compile_error(source);
    assert!(
        error.contains("assignment to undeclared variable 'undeclaredVar'"),
        "assignment to an undeclared variable must be rejected: {error}"
    );
}

#[test]
fn assignment_to_declared_let_binding_produces_no_warning() {
    let source = r#"
contract DeclaredAssign(pubkey owner) {
    function spend(signature ownerSig) {
        let x = 1;
        x = 2;
        require(checkSig(ownerSig, owner));
    }
}"#;
    let output = compile_ok(source);
    let has_warning = has_type_warning(&output, "undeclared");
    assert!(
        !has_warning,
        "assigning to a declared variable must not warn; got: {:?}",
        output.warnings
    );
}

// ─── Introspection / int comparison ──────────────────────────────────────────

#[test]
fn introspected_value_vs_int_comparison_produces_no_type_warning() {
    let source = r#"
contract MixedTypes(pubkey owner, int minValue) {
    function spend(signature ownerSig) {
        require(tx.inputs[0].value >= minValue);
        require(checkSig(ownerSig, owner));
    }
}"#;
    let output = compile_ok(source);
    let has_comparison_warning =
        has_type_warning(&output, "comparison") || has_type_warning(&output, "compatible");
    assert!(
        !has_comparison_warning,
        "BigNum comparison must not warn about operand widths; got: {:?}",
        output.warnings
    );
}

#[test]
fn integer_equality_across_widths_produces_no_type_warning() {
    // Equality between int params/literals and numeric introspection values is
    // well-defined, exactly like ordered comparisons.
    let source = r#"
contract IntEquality(pubkey owner, int expectedValue, int expectedVersion) {
    function spend(signature ownerSig) {
        require(tx.inputs[0].value == expectedValue);
        require(tx.version == expectedVersion);
        require(tx.version == 2);
        require(checkSig(ownerSig, owner));
    }
}"#;
    let output = compile_ok(source);
    let has_comparison_warning =
        has_type_warning(&output, "comparison") || has_type_warning(&output, "compatible");
    assert!(
        !has_comparison_warning,
        "numeric equality across int/uint widths must not warn; got: {:?}",
        output.warnings
    );
}

#[test]
fn introspected_value_comparison_produces_no_type_warning() {
    // Introspected values are emitted as BigNums.
    let source = r#"
contract SameTypes(pubkey owner) {
    function spend(signature ownerSig) {
        require(tx.inputs[0].value >= tx.outputs[0].value);
        require(checkSig(ownerSig, owner));
    }
}"#;
    let output = compile_ok(source);
    let has_implicit_warn = has_type_warning(&output, "implicit");
    assert!(
        !has_implicit_warn,
        "BigNum values must not warn about implicit conversion; got: {:?}",
        output.warnings
    );
}

// ─── Wrong hash type ─────────────────────────────────────────────────────────

#[test]
fn non_bytes32_hash_param_produces_warning() {
    // sha256(preimage) == hashVal where hashVal is declared as `int`
    // The typechecker should flag that the hash comparison target is not bytes32.
    let source = r#"
contract BadHashType(pubkey owner, int hashVal) {
    function claim(bytes32 preimage) {
        require(sha256(preimage) == hashVal);
    }
}"#;
    let output = compile_ok(source);
    assert!(
        has_type_warning(&output, "bytes32") || has_type_warning(&output, "hash"),
        "wrong hash type must produce a type warning; got: {:?}",
        output.warnings
    );
}

#[test]
fn bytes32_hash_param_produces_no_type_warning() {
    let source = r#"
contract CorrectHashType(pubkey owner, bytes32 hashVal) {
    function claim(bytes32 preimage) {
        require(sha256(preimage) == hashVal);
    }
}"#;
    let output = compile_ok(source);
    let has_warning = has_type_warning(&output, "bytes32") || has_type_warning(&output, "hash");
    assert!(
        !has_warning,
        "correct bytes32 hash type must produce no type warning; got: {:?}",
        output.warnings
    );
}

// ─── Non-boolean if condition ─────────────────────────────────────────────────

#[test]
fn non_boolean_if_condition_is_rejected() {
    // `tx.inputs[0].value` is an int, not bool — using it as an if condition.
    let source = r#"
contract NonBoolCond(pubkey owner) {
    function spend(signature ownerSig) {
        if (tx.inputs[0].value) {
            require(checkSig(ownerSig, owner));
        } else {
            require(checkSig(ownerSig, owner));
        }
    }
}"#;
    let error = compile_error(source);
    assert!(
        error.contains("if condition has type 'int', expected bool"),
        "non-boolean if condition must be rejected: {error}"
    );
}

#[test]
fn checksig_expr_if_condition_is_valid() {
    // checkSig(...) as a condition returns bool — no warning expected.
    let source = r#"
contract BoolCond(pubkey owner) {
    function spend(signature ownerSig, signature altSig) {
        if (checkSig(ownerSig, owner)) {
            require(checkSig(ownerSig, owner));
        } else {
            require(checkSig(altSig, owner));
        }
    }
}"#;
    let output = compile_ok(source);
    let has_cond_warn = has_type_warning(&output, "bool") || has_type_warning(&output, "condition");
    assert!(
        !has_cond_warn,
        "checkSig() if condition must produce no bool warning; got: {:?}",
        output.warnings
    );
}

// ─── Stack-unsafe type errors are fatal ───────────────────────────────────────

#[test]
fn stack_unsafe_type_errors_are_fatal() {
    let source = r#"
contract MultiTypeError(pubkey owner, int badHash) {
    function spend(pubkey sigSwapped, signature ownerSwapped) {
        require(checkSig(sigSwapped, ownerSwapped));
        require(sha256(sigSwapped) == badHash);
    }
}"#;
    let error = compile_error(source);
    assert!(
        error.contains("expected 'signature'") && error.contains("expected 'pubkey'"),
        "signature argument errors must stop compilation: {error}"
    );
}

// ─── checkSigFromStack argument order ────────────────────────────────────────

#[test]
fn swapped_checksigfromstack_args_are_rejected() {
    // checkSigFromStack(pubkey, sig, msg) — first two are swapped
    let source = r#"
contract SwappedCsfs(pubkey owner) {
    function spend(pubkey sigSwapped, signature pkSwapped, bytes32 msg) {
        require(checkSigFromStack(sigSwapped, pkSwapped, msg));
    }
}"#;
    let error = compile_error(source);
    assert!(
        error.contains("expected 'signature'") && error.contains("expected 'pubkey'"),
        "swapped checkSigFromStack arguments must be rejected: {error}"
    );
}

// ─── Warnings are surfaced in the ContractJson output ────────────────────────

#[test]
fn type_warnings_appear_in_contract_json_warnings_field() {
    let source = r#"
contract HasWarnings(pubkey owner, int minVal) {
    function spend(signature ownerSig) {
        require(minVal);
        require(checkSig(ownerSig, owner));
    }
}"#;
    let output = compile_ok(source);
    // Warnings should be in the JSON output, not silently dropped
    assert!(
        output.warnings.iter().any(|w| w.starts_with("warning[")),
        "warnings must be tagged with warning[...] prefix; got: {:?}",
        output.warnings
    );
    // Compile to JSON and back to verify warnings are serialized
    let json = serde_json::to_string(&output).expect("serialize to JSON");
    assert!(
        json.contains("warning"),
        "warnings must appear in serialized JSON"
    );
}
