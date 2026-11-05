use arkade_compiler::analyze;
use std::collections::BTreeMap;

/// The file and source text of the first diagnostic of `main.ark`, given `files`.
fn located(main: &str, others: &[(&str, &str)]) -> (String, String, String) {
    let mut files = BTreeMap::from([("main.ark".to_string(), main.to_string())]);
    files.extend(
        others
            .iter()
            .map(|(path, source)| (path.to_string(), source.to_string())),
    );
    let diagnostics = analyze("main.ark", &files).diagnostics();
    let error = diagnostics.first().expect("an error");
    let span = error.span.unwrap_or_else(|| panic!("unlocated: {error:?}"));
    let text = files[&error.file][span.start..span.end].to_string();
    (error.file.clone(), text, error.message.clone())
}

#[test]
fn errors_outside_the_validator_are_located() {
    for (main, others, expected_text, expected_message) in [
        (
            "contract C() { private function require() { require(true); } function f() { require(true); } }",
            &[][..],
            "require",
            "function name 'require' is reserved",
        ),
        (
            "contract C() { function f(bytes d) { sha256(d); } }",
            &[],
            "sha256(d);",
            "cannot be a statement",
        ),
        (
            "contract C() { function f(bytes d) { if (true) { sha256(d); } } }",
            &[],
            "sha256(d);",
            "cannot be a statement",
        ),
        (
            "contract C() { const int N = 1; const int N = 2; function f() { require(N == 1); } }",
            &[],
            "N",
            "duplicate constant 'N'",
        ),
        (
            "contract C() { const int N = M; function f() { require(N == 1); } }",
            &[],
            "N",
            "unknown constant 'M'",
        ),
        (
            "contract C() { function f(int[Z] xs) { require(xs[0] == 1); } }",
            &[],
            "xs",
            "array size 'Z'",
        ),
        (
            "contract C(Missing m) { function f() { require(true); } }",
            &[],
            "m",
            "unknown type 'Missing'",
        ),
        (
            "contract C() { function f() { require(tx.outputs[0].script == new Other()); } }",
            &[],
            "new Other()",
            "unknown contract 'Other'",
        ),
        (
            "import \"missing.ark\"; contract C() { function f() { require(true); } }",
            &[],
            "import \"missing.ark\";",
            "source file 'missing.ark' not found",
        ),
        (
            "import \"a.ark\"; contract C() { function f() { require(true); } }",
            &[("a.ark", "import \"main.ark\"; struct A { int x; }")],
            "import \"main.ark\";",
            "circular import",
        ),
        (
            "import \"../a.ark\"; contract C() { function f() { require(true); } }",
            &[],
            "import \"../a.ark\";",
            "escapes the source root",
        ),
        (
            "import \"a.ark\"; struct A { int y; } contract C() { function f() { require(true); } }",
            &[("a.ark", "struct A { int x; }")],
            "A",
            "duplicate declaration 'A'",
        ),
        (
            "contract tx() { function f() { require(true); } }",
            &[],
            "tx",
            "contract name 'tx' is reserved",
        ),
        (
            "contract C(pubkey owner) { function weird(signature serverSig, signature emulatorSig) tapscript { require(checkMultisig([server, emulator], [serverSig, emulatorSig], 2)); } }",
            &[],
            "weird",
            "standalone",
        ),
    ] {
        let (_, text, message) = located(main, others);
        assert!(message.contains(expected_message), "{main}: {message}");
        assert_eq!(text, expected_text, "{main}: {message}");
    }
}

#[test]
fn an_error_in_an_import_is_located_in_that_file() {
    let (file, text, message) = located(
        "import \"a.ark\"; contract C() { function f() { require(true); } }",
        &[(
            "a.ark",
            "library A { function g(Missing m) { require(true); } }",
        )],
    );
    assert_eq!(file, "a.ark");
    assert_eq!(text, "m");
    assert!(message.contains("unknown type 'Missing'"), "{message}");
}

/// The line (from 1) and text of the first diagnostic's span in `main`, and its message.
fn at_line(main: &str) -> (usize, String, String) {
    let files = BTreeMap::from([("main.ark".to_string(), main.to_string())]);
    let diagnostics = analyze("main.ark", &files).diagnostics();
    let error = diagnostics.first().expect("an error");
    let span = error.span.expect("located");
    let line = main[..span.start].matches('\n').count() + 1;
    (
        line,
        main[span.start..span.end].to_string(),
        error.message.clone(),
    )
}

#[test]
fn a_missing_token_is_reported_at_the_end_of_its_line() {
    let body = |statements: &str| {
        format!("contract C(pubkey o) {{\n  function f(signature s) {{\n{statements}\n  }}\n}}\n")
    };
    for (statements, line, text) in [
        ("    require(checkSig(s, o))\n    require(true);", 3, ")"),
        (
            "    int x = 5\n    require(checkSig(s, o) && x > 1);",
            3,
            "5",
        ),
        (
            "    require(checkSig(s, o)) // see \"docs\"\n    // more\n    require(true);",
            3,
            ")",
        ),
        (
            "    require(checkSig(s, o), \"https://x\")\n    require(true);",
            3,
            ")",
        ),
        ("    require(checkSig(s, o);", 3, ";"),
    ] {
        let (found, spanned, message) = at_line(&body(statements));
        assert_eq!(
            (found, spanned.as_str()),
            (line, text),
            "{statements}: {message}"
        );
    }
    let typo =
        "contract C(pubkey o) {\n  fucntion f(signature s) { require(checkSig(s, o)); }\n}\n";
    assert_eq!(at_line(typo).0, 2);
}

#[test]
fn call_errors_name_the_problem() {
    let body = |statement: &str| {
        format!("contract C(pubkey o) {{\n  function f(signature s) {{\n    {statement}\n    require(checkSig(s, o));\n  }}\n}}\n")
    };
    for (statement, message) in [
        ("require(chekSig(s, o));", "unknown function 'chekSig'"),
        (
            "require(true, 5);",
            "the message of require must be a string",
        ),
        (
            "require(checkSig(s));",
            "wrong number of arguments to `checkSig`: expected checkSig(signature, pubkey), got 1",
        ),
    ] {
        assert_eq!(at_line(&body(statement)).2, message, "{statement}");
    }
}

#[test]
fn an_unused_parameter_is_located_at_its_name() {
    let source = "contract C(pubkey o) {\n  function f(signature s, int extra) {\n    require(checkSig(s, o));\n  }\n}\n";
    let (line, text, message) = at_line(source);
    assert_eq!((line, text.as_str()), (2, "extra"));
    assert_eq!(message, "parameter 'extra' of function 'f' is never used");
    let tapscript = source.replace(
        "{\n    require(checkSig(s, o));",
        "tapscript {\n    require(checkSig(s, o));",
    );
    assert_eq!(at_line(&tapscript).1, "extra");
}

#[test]
fn a_tapscript_require_is_located_at_its_condition() {
    let source = "contract C(pubkey o) {\n  function f(signature s) tapscript {\n    require(\"dupa\");\n    require(checkSig(s, o));\n  }\n}\n";
    let (line, text, message) = at_line(source);
    assert_eq!((line, text.as_str()), (3, "\"dupa\""));
    assert_eq!(
        message,
        "a tapscript require can check only signatures, hashes and timelocks, not a string"
    );
}

#[test]
fn a_require_condition_of_the_wrong_type_is_located_at_the_condition() {
    let source = "contract C(pubkey o) {\n  function f(signature s) {\n    require(\"dupa\");\n    require(checkSig(s, o));\n  }\n}\n";
    let (line, text, message) = at_line(source);
    assert_eq!((line, text.as_str()), (3, "\"dupa\""));
    assert_eq!(message, "require condition has type 'bytes', expected bool");
}
