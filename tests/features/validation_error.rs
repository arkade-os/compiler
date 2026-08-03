//! Error-path and validation tests.
//!
//! These tests verify that malformed or semantically invalid source code is
//! rejected with a meaningful error message rather than producing silent broken
//! output.  They exercise the semantic validator, parser error handling, and the
//! contract → compiler pipeline boundary.
//!
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

#[test]
fn malformed_reserved_require_calls_are_rejected_before_generic_fallback() {
    let cases = [
        (
            "checkSig extra argument",
            r#"
contract BadCheckSig(pubkey owner) {
    function spend(signature sig) {
        require(checkSig(sig, owner, extra));
    }
}"#,
            "checkSig(signature, pubkey)",
        ),
        (
            "checkMultisig extra argument",
            r#"
contract BadCheckMultisig(pubkey owner) {
    function spend(signature sig) {
        require(checkMultisig([owner], [sig], 1, extra));
    }
}"#,
            "checkMultisig([pubkeys], [sigs], threshold?)",
        ),
    ];

    for (label, source, expected) in cases {
        let result = compile(source);
        assert!(result.is_err(), "{label} must be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("malformed reserved function call") && msg.contains(expected),
            "unexpected error for {label}: {msg}"
        );
    }
}

#[test]
fn malformed_reserved_expression_calls_are_rejected_before_generic_fallback() {
    let source = r#"
contract BadShaInit(pubkey owner) {
    function spend(signature sig) {
        require(checkSig(sig, owner));
        let ctx = sha256Initialize(owner, extra);
    }
}"#;

    let result = compile(source);
    assert!(result.is_err(), "sha256Initialize extra argument must fail");
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("malformed reserved function call") && msg.contains("sha256Initialize(data)"),
        "unexpected error: {msg}"
    );
}

#[test]
fn unsupported_generic_function_calls_are_rejected() {
    let source = r#"
contract GenericCall(pubkey owner) {
    function spend(signature sig) {
        require(foo(sig, owner, extra));
        let ctx = bar(owner, extra);
    }
}"#;

    let error = compile(source)
        .expect_err("unsupported calls cannot be represented as symbolic stack reads")
        .to_string();
    assert!(
        error.contains("undefined binding 'foo(sig, owner, extra)'"),
        "unexpected generic-call error: {error}"
    );
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
fn reserved_role_as_constructor_param_is_rejected() {
    for role in ["server", "emulator"] {
        let source = format!(
            r#"
contract Reserved(pubkey {role}) {{
    function spend() {{
        require(tx.outputs[0].value >= 1);
    }}
}}"#
        );
        let result = compile(&source);
        assert!(
            result.is_err(),
            "reserved role '{role}' as constructor param must be rejected"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains(role) && msg.to_lowercase().contains("reserved"),
            "error must flag reserved role '{role}'; got: {msg}"
        );
    }
}

#[test]
fn internal_server_key_placeholder_name_is_rejected() {
    let source = r#"
contract Reserved(pubkey SERVER_KEY) {
    function spend() {
        require(tx.outputs[0].value >= 1);
    }
}"#;
    let error = compile(source)
        .expect_err("SERVER_KEY must remain compiler-owned")
        .to_string();
    assert!(
        error.contains("SERVER_KEY") && error.contains("compiler-reserved placeholder"),
        "unexpected error: {error}"
    );
}

#[test]
fn duplicate_tapscript_names_are_rejected() {
    let source = r#"
contract DupLeaves(pubkey owner) {
    function spend() {
        require(tx.outputs[0].value >= 1);
    }
    function spend(signature serverSig, signature emulatorSig) tapscript {
        require(checkMultisig([server, emulator], [serverSig, emulatorSig], 2));
    }
    function spend(signature serverSig, signature emulatorSig) tapscript {
        require(checkMultisig([server, emulator], [serverSig, emulatorSig], 2));
    }
}"#;
    let result = compile(source);
    assert!(
        result.is_err(),
        "duplicate tapscript names must be rejected"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("spend") || msg.to_lowercase().contains("duplicate"),
        "error must reference the duplicate tapscript name; got: {}",
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
