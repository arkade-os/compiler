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
            "contract C(pubkey owner) { function weird() { require(true); } function weird(signature operatorSig) tapscript { require(checkSig(operatorSig, operator)); } }",
            &[],
            "weird",
            "must tweak a key to `weird`",
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
        ("    let x = o\n    require(checkSig(s, x));", 3, "o"),
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
        (
            "require(chekSig(s, o));",
            "unknown function 'chekSig'; did you mean 'checkSig'?",
        ),
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
    for statement in [
        "require();",
        "require(require(true));",
        "require(true, \"m\", 1);",
    ] {
        let message = at_line(&body(statement)).2;
        assert_ne!(
            message, "the message of require must be a string",
            "{statement}"
        );
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

#[test]
fn an_unknown_transaction_property_is_reported_by_validation() {
    let source = "contract C(pubkey o) {\n  function f(signature s) {\n    require(tx.outputs[0].valu >= 1000);\n    require(checkSig(s, o));\n  }\n}\n";
    let (line, text, message) = at_line(source);
    assert_eq!((line, text.as_str()), (3, "tx.outputs[0].valu"));
    assert_eq!(
        message,
        "unknown member 'valu' of 'tx.outputs[0]'; expected one of assets, script, value, witnessVersion"
    );
    for access in ["tx.assetGroups", "tx.outputs[0]", "tx.outputs[0].assets"] {
        let message = at_line(&source.replace("tx.outputs[0].valu", access)).2;
        assert_eq!(message, format!("'{access}' is not a value on its own"));
    }
}

#[test]
fn a_word_left_on_its_own_is_reported_at_the_word() {
    let body = |statements: &str, tapscript: &str| {
        format!("contract C(pubkey o) {{\n  function f(signature s){tapscript} {{\n{statements}\n  }}\n}}\n")
    };
    for (source, line) in [
        (body("    require(checkSig(s, o));\n    dasd", ""), 4),
        (body("    require(checkSig(s, o)); dasd", ""), 3),
        (
            body("    require(checkSig(s, o));\n    dasd", " tapscript"),
            4,
        ),
        (
            body(
                "    if (true) {\n      dasd\n    }\n    require(checkSig(s, o));",
                "",
            ),
            4,
        ),
    ] {
        let (found, text, message) = at_line(&source);
        assert_eq!(
            (found, text.as_str(), message.as_str()),
            (line, "dasd", "`dasd` on its own is not a statement"),
            "{source}"
        );
    }
    let message = at_line(&body("    require(checkSig(s, o));\n    héllo", "")).2;
    assert!(!message.contains("on its own"), "{message}");
}

#[test]
fn declaration_errors_are_located_at_the_declared_name() {
    // Each span must end the `context` occurrence and cover only `name`.
    for (source, expected_message, context, name) in [
        (
            "contract C(pubkey o) { function f(signature operator) tapscript { require(checkSig(operator, o)); } }",
            "tapscript 'f' input 'operator' collides with a reserved arkd name",
            "f(signature operator",
            "operator",
        ),
        (
            "contract C(pubkey o) { function f(signature s, signature s) tapscript { require(checkSig(s, o)); } }",
            "duplicate input 's' in tapscript 'f'",
            "signature s, signature s",
            "s",
        ),
        (
            "contract C(pubkey o) { function f(signature s, int[2] xs) tapscript { require(checkSig(s, o)); } }",
            "tapscript 'f' input 'xs' has array type 'int[2]'; array witnesses are not supported in tapscript functions",
            "int[2] xs",
            "xs",
        ),
        (
            "contract C(pubkey o) { function f(signature o) tapscript { require(checkSig(o, o)); } }",
            "input 'o' in tapscript 'f' shadows constructor parameter 'o'",
            "f(signature o",
            "o",
        ),
        (
            "contract C(pubkey o) { function f(signature s) tapscript { require(checkSig(s, o)); } function f(signature t) tapscript { require(checkSig(t, o)); } }",
            "duplicate tapscript name 'f'; each tapscript must have a unique name",
            "} function f",
            "f",
        ),
        (
            "contract C(pubkey operator) { function f(signature s) { require(checkSig(s, operator)); } }",
            "constructor parameter 'operator' collides with a reserved arkd name",
            "C(pubkey operator",
            "operator",
        ),
        (
            "contract C(pubkey o, pubkey o) { function f(signature s) { require(checkSig(s, o)); } }",
            "duplicate constructor parameter 'o'",
            "pubkey o, pubkey o",
            "o",
        ),
        (
            "contract C(pubkey OPERATOR_KEY) { function f(signature s) { require(checkSig(s, OPERATOR_KEY)); } }",
            "constructor parameter 'OPERATOR_KEY' uses a compiler-reserved placeholder name",
            "C(pubkey OPERATOR_KEY",
            "OPERATOR_KEY",
        ),
        (
            "struct AssetId { int x; } contract C() { function f() { require(true); } }",
            "struct 'AssetId' collides with a built-in type",
            "struct AssetId",
            "AssetId",
        ),
        (
            "struct S { int x; bool x; } contract C() { function f() { require(true); } }",
            "duplicate field 'x' in struct 'S'",
            "bool x",
            "x",
        ),
        (
            "struct A { B b; } struct B { A a; } contract C() { function f() { require(true); } }",
            "recursive struct layout: A -> B -> A",
            "struct A",
            "A",
        ),
        (
            "contract C() {}",
            "contract must declare at least one Arkade Script or tapscript function",
            "contract C",
            "C",
        ),
    ] {
        let files = BTreeMap::from([("main.ark".to_string(), source.to_string())]);
        let diagnostics = arkade_compiler::check("main.ark", &files);
        let error = diagnostics
            .iter()
            .find(|d| d.message == expected_message)
            .unwrap_or_else(|| panic!("{source}: {diagnostics:?}"));
        let span = error.span.unwrap_or_else(|| panic!("{source}: unlocated"));
        assert_eq!(&source[span.start..span.end], name, "{source}");
        assert!(source[..span.end].ends_with(context), "{source}: {span:?}");
    }
}

#[test]
fn struct_errors_never_take_a_span_from_an_imported_file() {
    // `AssetId` in lib.ark is the built-in struct, so no cycle runs through main.ark's `AssetId`.
    let main = "import \"lib.ark\";\nstruct Z { P p; }\nstruct AssetId { P p; }\ncontract C(pubkey o) { function f(signature s) { require(checkSig(s, o)); } }";
    let files = BTreeMap::from([
        ("main.ark".to_string(), main.to_string()),
        (
            "lib.ark".to_string(),
            "// pad\nstruct P { AssetId a; }".to_string(),
        ),
    ]);
    let diagnostics = arkade_compiler::check("main.ark", &files);
    let [error] = diagnostics.as_slice() else {
        panic!("{diagnostics:?}");
    };
    assert_eq!(
        error.message,
        "struct 'AssetId' collides with a built-in type"
    );
    let span = error.span.expect("located");
    assert!(main[..span.end].ends_with("struct AssetId"), "{span:?}");
}

#[test]
fn a_file_without_a_contract_reports_it_unlocated() {
    let files = BTreeMap::from([("main.ark".to_string(), "struct S { int x; }".to_string())]);
    let diagnostics = arkade_compiler::check("main.ark", &files);
    let error = diagnostics
        .iter()
        .find(|d| {
            d.message == "contract must declare at least one Arkade Script or tapscript function"
        })
        .unwrap_or_else(|| panic!("{diagnostics:?}"));
    assert_eq!(error.span, None);
}
