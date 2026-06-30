//! Error-path and validation tests.
//!
//! These tests verify that malformed or semantically invalid source code is
//! rejected with a meaningful error message rather than producing silent broken
//! output.  They exercise the semantic validator, parser error handling, and the
//! contract → compiler pipeline boundary.
//!
//! Note: the `options { … }` block was removed from the language; exit-timelock
//! validation (zero/positive exit) no longer exists, so those cases are gone.

use arkade_compiler::compile;

// ─── Parse-level errors ───────────────────────────────────────────────────────

#[test]
fn empty_source_is_rejected() {
    let result = compile("");
    assert!(result.is_err(), "empty source must fail");
    let msg = result.unwrap_err().to_string();
    assert!(!msg.is_empty(), "error message must not be empty");
}

#[test]
fn whitespace_only_source_is_rejected() {
    let result = compile("   \n\t  ");
    assert!(result.is_err(), "whitespace-only source must fail");
}

#[test]
fn syntax_error_produces_parse_error_message() {
    let source = r#"
contract Broken(pubkey owner) {
    function spend(signature sig) {
        require(INVALID!!!);
    }
}"#;
    let result = compile(source);
    assert!(result.is_err(), "syntax error must fail");
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.to_lowercase().contains("parse") || msg.to_lowercase().contains("error"),
        "error message should describe a parse failure; got: {}",
        msg
    );
}

#[test]
fn unclosed_brace_is_rejected() {
    let source = r#"
contract Unclosed(pubkey owner) {
    function spend(signature sig) {
        require(checkSig(sig, owner));
    }
"#; // missing closing `}`
    let result = compile(source);
    assert!(result.is_err(), "unclosed contract brace must fail");
}

// ─── Semantic validation errors ───────────────────────────────────────────────

#[test]
fn duplicate_function_names_are_rejected() {
    let source = r#"
contract DupFuncs(pubkey owner) {
    function spend(signature sig) {
        require(checkSig(sig, owner));
    }
    function spend(signature sig) {
        require(checkSig(sig, owner));
    }
}"#;
    let result = compile(source);
    assert!(result.is_err(), "duplicate function names must be rejected");
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("spend") || msg.to_lowercase().contains("duplicate"),
        "error must reference the duplicate function name; got: {}",
        msg
    );
}

#[test]
fn duplicate_constructor_params_are_rejected() {
    let source = r#"
contract DupParam(pubkey owner, pubkey owner) {
    function spend(signature sig) {
        require(checkSig(sig, owner));
    }
}"#;
    // This may be caught by the parser (pest won't reject it) or the validator.
    // Either way the result must be an error.
    let result = compile(source);
    assert!(
        result.is_err(),
        "duplicate constructor parameter must be rejected"
    );
}

#[test]
fn no_functions_is_rejected() {
    // contract with zero functions and zero tapscripts should fail validation
    let source = r#"
contract Empty(pubkey owner) {
}"#;
    let result = compile(source);
    assert!(
        result.is_err(),
        "contract with no functions must be rejected"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("function") || msg.contains("Function") || msg.contains("tapscript"),
        "error must mention the missing function; got: {}",
        msg
    );
}

#[test]
fn only_internal_functions_is_rejected() {
    let source = r#"
contract AllInternal(pubkey owner) {
    function helper(signature sig) internal {
        require(checkSig(sig, owner));
    }
}"#;
    let result = compile(source);
    assert!(
        result.is_err(),
        "contract with only internal functions must be rejected; no callable entry points"
    );
}

// ─── Valid edge cases (must compile successfully) ─────────────────────────────

#[test]
fn minimal_contract_succeeds() {
    // A single covenant function gets a synthesized default collaborative leaf.
    let source = r#"
contract Minimal(pubkey owner) {
    function spend(signature sig) {
        require(checkSig(sig, owner));
    }
}"#;
    let result = compile(source);
    assert!(
        result.is_ok(),
        "minimal contract must succeed; got: {:?}",
        result.err()
    );
}

// ─── Post-removal: options block must be rejected ────────────────────────────

#[test]
fn options_block_is_rejected_after_removal() {
    let src = r#"
options { exit = 144; server = server; }
contract Broken(pubkey owner) {
    function spend(signature ownerSig) tapscript {
        require(checkSig(ownerSig, owner));
    }
}
"#;
    assert!(compile(src).is_err(), "options block must no longer parse");
}

// ─── Error message quality ────────────────────────────────────────────────────

#[test]
fn all_validation_errors_have_non_empty_messages() {
    let bad_inputs = vec![
        // no functions
        r#"contract A(pubkey o) { }"#,
        // duplicate function
        r#"contract A(pubkey o) {
  function f(signature s) { require(checkSig(s, o)); }
  function f(signature s) { require(checkSig(s, o)); }
}"#,
        // duplicate constructor param
        r#"contract A(pubkey o, pubkey o) {
  function f(signature s) { require(checkSig(s, o)); }
}"#,
    ];

    for source in bad_inputs {
        let preview: String = source.chars().take(60).collect();
        let result = compile(source);
        assert!(result.is_err(), "expected error for source: {}", preview);
        let msg = result.unwrap_err().to_string();
        assert!(
            !msg.is_empty(),
            "error message must be non-empty for source: {}",
            preview
        );
        assert!(
            msg.len() > 5,
            "error message is suspiciously short ('{}'); should describe the problem",
            msg
        );
    }
}
