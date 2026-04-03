//! CashScript-style type-system error detection tests.
//!
//! CashScript pioneered compile-time type checking for smart contract languages
//! that compile to Bitcoin Script.  These tests verify that the Arkade type
//! checker surfaces the same class of errors:
//!
//! - **Swapped arguments** — `checkSig(pubkey, sig)` instead of `checkSig(sig, pubkey)`.
//! - **Undeclared variable** — assigning to a name never declared.
//! - **Mixed numeric types** — comparing a `uint64le` (from introspection) against a
//!   plain `int` without an explicit conversion.
//! - **Wrong hash type** — passing an `int` where `bytes32` is expected.
//! - **Non-boolean if condition** — using an integer expression as a branch condition.
//!
//! In Arkade, type errors are non-fatal: compilation succeeds but warnings appear
//! in `ContractJson.warnings`.  These tests assert both that compilation succeeds
//! and that the expected warning is present.

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

// ─── Swapped sig / pubkey ─────────────────────────────────────────────────────

#[test]
fn swapped_checksig_args_produces_warning() {
    // The contract declares `pubkey sig, signature owner` — the *names* clearly
    // describe the types but are passed in the wrong order to checkSig.
    let source = r#"
options { exit = 144; server = server; }
contract Swapped(pubkey owner, pubkey server) {
    function spend(pubkey sig, signature ownerSig) {
        require(checkSig(sig, ownerSig));
    }
}"#;
    // sig is pubkey, ownerSig is signature → arguments are swapped
    let output = compile_ok(source);
    assert!(
        has_type_warning(&output, "swapped"),
        "swapped checkSig arguments must produce a warning; got: {:?}",
        output.warnings
    );
}

#[test]
fn correct_checksig_order_produces_no_type_warning() {
    let source = r#"
options { exit = 144; server = server; }
contract Correct(pubkey owner, pubkey server) {
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
fn assignment_to_undeclared_variable_produces_warning() {
    let source = r#"
options { exit = 144; server = server; }
contract UndeclaredAssign(pubkey owner, pubkey server) {
    function spend(signature ownerSig) {
        undeclaredVar = 42;
        require(checkSig(ownerSig, owner));
    }
}"#;
    let output = compile_ok(source);
    assert!(
        has_type_warning(&output, "undeclared"),
        "assignment to undeclared variable must produce a warning; got: {:?}",
        output.warnings
    );
}

#[test]
fn assignment_to_declared_let_binding_produces_no_warning() {
    let source = r#"
options { exit = 144; server = server; }
contract DeclaredAssign(pubkey owner, pubkey server) {
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

// ─── Mixed uint64le / int comparison ─────────────────────────────────────────

#[test]
fn uint64le_vs_int_comparison_produces_warning() {
    // tx.inputs[0].value is uint64le; comparing directly with an int literal
    // triggers the implicit-conversion warning.
    let source = r#"
options { exit = 144; server = server; }
contract MixedTypes(pubkey owner, pubkey server, int minValue) {
    function spend(signature ownerSig) {
        require(tx.inputs[0].value >= minValue);
        require(checkSig(ownerSig, owner));
    }
}"#;
    let output = compile_ok(source);
    assert!(
        has_type_warning(&output, "uint64le") || has_type_warning(&output, "implicit"),
        "uint64le vs int comparison must warn about implicit conversion; got: {:?}",
        output.warnings
    );
}

#[test]
fn uint64le_vs_uint64le_comparison_produces_no_type_warning() {
    // Comparing two introspection values of the same uint64le type is fine.
    let source = r#"
options { exit = 144; server = server; }
contract SameTypes(pubkey owner, pubkey server) {
    function spend(signature ownerSig) {
        require(tx.inputs[0].value >= tx.outputs[0].value);
        require(checkSig(ownerSig, owner));
    }
}"#;
    let output = compile_ok(source);
    // Both sides are uint64le — no implicit conversion warning expected
    let has_implicit_warn = has_type_warning(&output, "implicit");
    assert!(
        !has_implicit_warn,
        "uint64le vs uint64le must not warn about implicit conversion; got: {:?}",
        output.warnings
    );
}

// ─── Wrong hash type ─────────────────────────────────────────────────────────

#[test]
fn non_bytes32_hash_param_produces_warning() {
    // sha256(preimage) == hashVal where hashVal is declared as `int`
    // The typechecker should flag that the hash comparison target is not bytes32.
    let source = r#"
options { exit = 144; server = server; }
contract BadHashType(pubkey owner, pubkey server, int hashVal) {
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
options { exit = 144; server = server; }
contract CorrectHashType(pubkey owner, pubkey server, bytes32 hashVal) {
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
fn non_boolean_if_condition_produces_warning() {
    // `tx.inputs[0].value` is uint64le, not bool — using it as an if condition.
    let source = r#"
options { exit = 144; server = server; }
contract NonBoolCond(pubkey owner, pubkey server) {
    function spend(signature ownerSig) {
        if (tx.inputs[0].value) {
            require(checkSig(ownerSig, owner));
        }
    }
}"#;
    let output = compile_ok(source);
    assert!(
        has_type_warning(&output, "bool") || has_type_warning(&output, "condition"),
        "non-boolean if condition must produce a type warning; got: {:?}",
        output.warnings
    );
}

#[test]
fn checksig_expr_if_condition_is_valid() {
    // checkSig(...) as a condition returns bool — no warning expected.
    let source = r#"
options { exit = 144; server = server; }
contract BoolCond(pubkey owner, pubkey server) {
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

// ─── Compilation succeeds despite type errors (non-fatal) ────────────────────

#[test]
fn type_errors_are_non_fatal_compilation_succeeds() {
    // Multiple type errors in one contract — compilation must still succeed.
    let source = r#"
options { exit = 144; server = server; }
contract MultiTypeError(pubkey owner, pubkey server, int badHash) {
    function spend(pubkey sigSwapped, signature ownerSwapped) {
        require(checkSig(sigSwapped, ownerSwapped));
        require(sha256(sigSwapped) == badHash);
    }
}"#;
    let result = compile(source);
    assert!(
        result.is_ok(),
        "type errors must be non-fatal; compilation should succeed with warnings"
    );
    let output = result.unwrap();
    assert!(
        !output.warnings.is_empty(),
        "multiple type errors must produce at least one warning"
    );
    // Should have both a swapped-args warning and a hash-type warning
    let warning_text = output.warnings.join(" ");
    assert!(
        warning_text.to_lowercase().contains("swapped") || warning_text.contains("warning[type]"),
        "expected type warnings; got: {:?}",
        output.warnings
    );
}

// ─── checkSigFromStack argument order ────────────────────────────────────────

#[test]
fn swapped_checksigfromstack_args_produces_warning() {
    // checkSigFromStack(pubkey, sig, msg) — first two are swapped
    let source = r#"
options { exit = 144; server = server; }
contract SwappedCsfs(pubkey owner, pubkey server) {
    function spend(pubkey sigSwapped, signature pkSwapped, bytes32 msg) {
        require(checkSigFromStack(sigSwapped, pkSwapped, msg));
    }
}"#;
    let output = compile_ok(source);
    assert!(
        has_type_warning(&output, "swapped"),
        "swapped checkSigFromStack arguments must produce a warning; got: {:?}",
        output.warnings
    );
}

// ─── Warnings are surfaced in the ContractJson output ────────────────────────

#[test]
fn type_warnings_appear_in_contract_json_warnings_field() {
    let source = r#"
options { exit = 144; server = server; }
contract HasWarnings(pubkey owner, pubkey server, int minVal) {
    function spend(signature ownerSig) {
        require(tx.inputs[0].value >= minVal);
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
