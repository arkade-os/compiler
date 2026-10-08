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
fn parse_errors_use_source_terms() {
    let cases = [
        ("require(checkSig(s, pk), \"x\") }", "1:81", "expected ';'"),
        (
            "require(checkSig(s, pk), \"x\"; }",
            "1:79",
            "expected ')', ',' or an operator",
        ),
        (
            "require(tx.); }",
            "1:62",
            "expected a transaction property or a name",
        ),
        (
            "require(checkSig(s, pk), \"x\"); ",
            "1:84",
            "expected '}', a constant or a function",
        ),
    ];
    for (body, at, expected) in cases {
        let source = format!("contract C(pubkey pk) {{ function f(signature s) {{ {body} }}");
        let msg = compile(&source).unwrap_err().to_string();
        assert!(msg.contains(&format!("--> {at}")), "{body}: {msg}");
        assert!(msg.ends_with(&format!("= {expected}")), "{body}: {msg}");
    }

    let msg = compile("contract C(pubkey pk { }").unwrap_err().to_string();
    assert!(msg.contains("--> 1:22"), "{msg}");
    assert!(msg.ends_with("= expected ')' or ','"), "{msg}");
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
        error.contains("unknown private function 'foo'"),
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
    for role in ["server", "emulator", "serverExitDelay"] {
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
fn server_exit_delay_as_tapscript_input_is_rejected() {
    let source = r#"
contract Reserved(pubkey owner) {
    function exit(int serverExitDelay, signature ownerSig) tapscript {
        require(older(serverExitDelay));
        require(checkSig(ownerSig, owner));
    }
}"#;
    let error = compile(source).unwrap_err().to_string();
    assert!(
        error.contains("input 'serverExitDelay' collides with a reserved arkd name"),
        "got: {error}"
    );
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
fn only_private_functions_is_rejected() {
    let source = r#"
contract AllInternal(pubkey owner) {
    private function helper(signature sig) {
        require(checkSig(sig, owner));
    }
}"#;
    let result = compile(source);
    assert!(
        result.is_err(),
        "contract with only private functions must be rejected; no callable entry points"
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

#[test]
fn undefined_byte_operands_are_caught_by_validation() {
    let error = compile(
        r#"
contract Demo(bytes32 expected) {
    function spend() {
        require(reverseBytes(missing) == expected);
    }
}"#,
    )
    .expect_err("an undefined byte operand must be rejected")
    .to_string();
    assert!(
        error.contains("function 'spend': binding 'missing' is undefined"),
        "expected a validation diagnostic, got: {error}"
    );
}

#[test]
fn semantic_diagnostics_carry_source_positions() {
    let error = compile(
        "contract Positions(pubkey owner) {
    private function helper(int x) {
        require(x > 0);
    }
    function spend(signature sig, bool flag) {
        if (flag) {
            helper(sig);
        }
        require(checkSig(sig, owner));
    }
}",
    )
    .expect_err("mistyped helper argument must fail")
    .to_string();
    assert!(
        error.contains("validation error: line 7, column 20: argument 'x' to 'helper'"),
        "error must point at the faulty argument: {error}"
    );
    assert!(
        error.starts_with("main.ark: "),
        "error must still be prefixed with the entry file path: {error}"
    );

    let error = compile(
        "contract Positions() {
    function spend() {
        require(1);
    }
}",
    )
    .expect_err("non-boolean require must fail")
    .to_string();
    assert!(
        error.contains("type error: line 3, column 9: "),
        "type error must point at its statement: {error}"
    );
}

#[test]
fn builtin_calls_take_arity_and_reserved_names_from_the_registry() {
    for (body, expected) in [
        (
            "function spend(bytes a) { require(cat(a) == a); }",
            "malformed reserved function call `cat(...)`; expected cat(a, b)",
        ),
        (
            "function spend(bytes a) { require(size(a, a) == 1); }",
            "malformed reserved function call `size(...)`; expected size(data)",
        ),
        (
            "private function size(bytes a) int { return 1; } function spend() { require(true); }",
            "function name 'size' is reserved",
        ),
        (
            "function spend(bytes32 k, bytes q) { tweakVerify(k, k, q); require(true); }",
            "`tweakVerify(...)` cannot be a statement; use it inside require()",
        ),
        (
            "function spend(bytes a) { require(hash160(a, a) == substr(a, 0, 20)); }",
            "malformed reserved function call `hash160(...)`; expected hash160(data)",
        ),
    ] {
        let source = format!("contract C() {{ {body} }}");
        let error = compile(&source).expect_err(body).to_string();
        assert!(error.contains(expected), "{body}: {error}");
    }

    let error = compile(
        "contract C(ECPoint p) { function spend() { let r = ecMul(p, p, 1); require(r.x == 1); } }",
    )
    .expect_err("struct scalar")
    .to_string();
    assert!(
        error.contains("ecMul operand has type 'ECPoint', expected 'int'")
            && !error.contains("composite values"),
        "{error}"
    );
}

#[test]
fn expression_diagnostics_point_at_the_expression() {
    for (body, expected) in [
        ("let x = n / 0; require(x == n);", "0"),
        ("require(!n);", "n"),
        ("require(xs[a] == n);", "a"),
        ("require(missing == n);", "missing"),
        ("let y = cat(a, n); require(y == a);", "n"),
        ("require(a == n);", "a == n"),
        ("require((n & a) == a);", "n"),
        ("require(n << -1 == n);", "-1"),
        ("require((a) == (n));", "(a) == (n)"),
        ("require(((a)) == ((n)));", "((a)) == ((n))"),
        ("require(bytes32(h) == n);", "bytes32(h) == n"),
        ("require(n == bytes32(h));", "n == bytes32(h)"),
        (
            "require(bytes32(bytes32(h)) == n);",
            "bytes32(bytes32(h)) == n",
        ),
        ("require((bytes32(h) == n) || true);", "(bytes32(h) == n)"),
        ("require(rows[0].missing == n);", "rows[0].missing"),
        ("require(rows[0].values[4] == n);", "4"),
        ("require(rows[4].values[0] == n);", "4"),
        ("require(xs[4] == n);", "4"),
        ("require(unknown(n) == n);", "unknown(n)"),
        ("require(id(a) == n);", "a"),
        ("require(first([1, a]) == n);", "a"),
        ("require(checkSig(missing, owner));", "missing"),
        ("require(checkSig(missing, owner) && true);", "missing"),
        ("require(checkSig(n, owner));", "n"),
        ("require(checkSigFromStack(sig, owner, n));", "n"),
        ("require(checkSigFromStackVerify(sig, owner, n));", "n"),
        ("require(checkMultisig([owner], [n]));", "n"),
    ] {
        let source = format!(
            "struct S {{ int[2] values; }}
            contract C(bytes a, bytes32 h, int[2] xs, S[2] rows, pubkey owner) {{
                private function id(int value) int {{ return value; }}
                private function first(int[2] values) int {{ return values[0]; }}
                function spend(int n, signature sig) {{
                    {body}
                    require(n == n);
                    require(checkSig(sig, owner));
                }}
            }}"
        );
        let files = std::collections::BTreeMap::from([("main.ark".to_string(), source.clone())]);
        let diagnostics = arkade_compiler::check("main.ark", &files);
        let error = diagnostics
            .iter()
            .find(|d| d.severity == arkade_compiler::Severity::Error)
            .unwrap_or_else(|| panic!("{body}: no error in {diagnostics:?}"));
        let span = error.span.unwrap_or_else(|| panic!("{body}: unlocated"));
        assert_eq!(
            &source[span.start..span.end],
            expected,
            "{body}: {}",
            error.message
        );
    }
}
