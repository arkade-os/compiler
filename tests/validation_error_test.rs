//! Error-path and validation tests.
//!
//! These tests verify that malformed or semantically invalid source code is
//! rejected with a meaningful error message rather than producing silent broken
//! output.  They exercise the semantic validator, parser error handling, and the
//! contract → compiler pipeline boundary.

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
options { exit = 144; server = server; }
contract Broken(pubkey owner, pubkey server) {
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
options { exit = 144; server = server; }
contract Unclosed(pubkey owner, pubkey server) {
    function spend(signature sig) {
        require(checkSig(sig, owner));
    }
"#; // missing closing `}`
    let result = compile(source);
    assert!(result.is_err(), "unclosed contract brace must fail");
}

// ─── Semantic validation errors ───────────────────────────────────────────────

#[test]
fn zero_exit_timelock_is_rejected() {
    let source = r#"
options { exit = 0; server = server; }
contract ZeroExit(pubkey owner, pubkey server) {
    function spend(signature sig) {
        require(checkSig(sig, owner));
    }
}"#;
    let result = compile(source);
    assert!(
        result.is_err(),
        "exit timelock of 0 must be rejected; compiler would produce an unusable exit path"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("greater than 0") || msg.contains("timelock"),
        "error must mention the timelock issue; got: {}",
        msg
    );
}

#[test]
fn duplicate_function_names_are_rejected() {
    let source = r#"
options { exit = 144; server = server; }
contract DupFuncs(pubkey owner, pubkey server) {
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
options { exit = 144; server = server; }
contract DupParam(pubkey owner, pubkey owner, pubkey server) {
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
    // options is optional; contract with zero functions should fail validation
    let source = r#"
options { exit = 144; server = server; }
contract Empty(pubkey owner, pubkey server) {
}"#;
    let result = compile(source);
    assert!(
        result.is_err(),
        "contract with no functions must be rejected"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("function") || msg.contains("Function"),
        "error must mention the missing function; got: {}",
        msg
    );
}

#[test]
fn only_internal_functions_is_rejected() {
    let source = r#"
options { exit = 144; server = server; }
contract AllInternal(pubkey owner, pubkey server) {
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
fn contract_without_options_block_succeeds() {
    // options block is optional per the grammar
    let source = r#"
contract NoOptions(pubkey owner) {
    function spend(signature sig) {
        require(checkSig(sig, owner));
    }
}"#;
    // Without server key, no exit timelock is required; should compile fine
    let result = compile(source);
    assert!(
        result.is_ok(),
        "contract without options block must succeed; got: {:?}",
        result.err()
    );
}

#[test]
fn contract_without_server_key_needs_no_exit_timelock() {
    let source = r#"
options { exit = 144; }
contract NoServer(pubkey owner) {
    function spend(signature sig) {
        require(checkSig(sig, owner));
    }
}"#;
    let result = compile(source);
    assert!(
        result.is_ok(),
        "contract without server key must compile; got: {:?}",
        result.err()
    );
}

#[test]
fn positive_exit_timelock_succeeds() {
    let source = r#"
options { exit = 1; server = server; }
contract MinTimelock(pubkey owner, pubkey server) {
    function spend(signature sig) {
        require(checkSig(sig, owner));
    }
}"#;
    let result = compile(source);
    assert!(
        result.is_ok(),
        "minimum positive timelock (1 block) must succeed; got: {:?}",
        result.err()
    );
}

// ─── Error message quality ────────────────────────────────────────────────────

#[test]
fn all_validation_errors_have_non_empty_messages() {
    let bad_inputs = vec![
        // zero timelock
        r#"options { exit = 0; server = server; }
contract A(pubkey o, pubkey server) { function f(signature s) { require(checkSig(s, o)); } }"#,
        // no functions
        r#"options { exit = 144; server = server; }
contract A(pubkey o, pubkey server) { }"#,
        // duplicate function
        r#"options { exit = 144; server = server; }
contract A(pubkey o, pubkey server) {
  function f(signature s) { require(checkSig(s, o)); }
  function f(signature s) { require(checkSig(s, o)); }
}"#,
    ];

    for source in bad_inputs {
        let result = compile(source);
        assert!(
            result.is_err(),
            "expected error for source: {}",
            &source[..60]
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            !msg.is_empty(),
            "error message must be non-empty for source: {}",
            &source[..60]
        );
        assert!(
            msg.len() > 5,
            "error message is suspiciously short ('{}'); should describe the problem",
            msg
        );
    }
}
