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
            "contract C() { function f() { require(tx.outputs[0].scriptPubKey == new Other()); } }",
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

#[test]
fn an_unknown_tapscript_operand_is_located_at_the_operand() {
    let leaf = |body: &str| {
        format!("contract C(pubkey owner) {{ function f(signature s) {{ require(checkSig(s, owner)); }} function exit(signature s) tapscript {{ {body} }} }}")
    };
    for (body, expected_text, expected_message) in [
        (
            "require(older(144)); require(checkSig(s, ownr));",
            "ownr",
            "unknown key `ownr` in tapscript `exit`",
        ),
        (
            "require(older(delay)); require(checkSig(s, owner));",
            "delay",
            "'delay' is undefined in tapscript 'exit'",
        ),
    ] {
        let (file, text, message) = located(&leaf(body), &[]);
        assert_eq!(
            (file.as_str(), text.as_str(), message.as_str()),
            ("main.ark", expected_text, expected_message)
        );
    }
}
