use arkade_compiler::lint::{Level, Levels, Lint};
use arkade_compiler::{analyze, Diagnostic, Severity};
use std::collections::BTreeMap;

fn diagnostics_with(source: &str, levels: &Levels) -> Vec<Diagnostic> {
    let files = BTreeMap::from([("main.ark".to_string(), source.to_string())]);
    analyze("main.ark", &files).diagnostics_with(levels)
}

/// The lint ids `function` reports, in order.
fn lints(function: &str) -> Vec<String> {
    let source = format!("contract C(pubkey owner, pubkey oracle, bytes32 hash) {{ {function} }}");
    let mut levels = Levels::default();
    levels.set_named("all", Level::Warn).unwrap();
    diagnostics_with(&source, &levels)
        .into_iter()
        .filter_map(|d| d.lint)
        .filter(|&lint| lint != Lint::UnusedParameter)
        .map(|lint| lint.id().to_string())
        .collect()
}

#[test]
fn covenant_lints_report_unauthorized_and_half_constrained_spends() {
    for (function, expected) in [
        (
            "function f(bytes p) { require(sha256(p) == hash); }",
            &["anyone-can-spend", "reveal-without-timeout"][..],
        ),
        ("function f(signature s) { require(checkSig(s, owner)); }", &[]),
        (
            "function f() { require(tx.outputs[0].value >= tx.input.current.value); }",
            &["output-script-unchecked", "outputs-shared-across-inputs"],
        ),
        (
            "function f(signature s) { require(checkSig(s, owner)); require(tx.outputs[0].value >= 1); }",
            &[],
        ),
        (
            "function f() { require(tx.numInputs == 1); require(tx.outputs[0].scriptPubKey == new C(owner, oracle, hash)); }",
            &["output-value-unchecked"],
        ),
        (
            "function f() { require(this.activeInputIndex == 0); require(tx.outputs[0].scriptPubKey == new C(owner, oracle, hash)); require(tx.outputs[0].value >= tx.input.current.value); }",
            &[],
        ),
        (
            "function f(signature s, bytes32 m) { require(checkSigFromStack(s, oracle, m)); require(tx.outputs[this.activeInputIndex].scriptPubKey == hash); require(tx.outputs[this.activeInputIndex].value >= 1); }",
            &["oracle-message-unbound"],
        ),
        (
            "function f(signature s, bytes32 m) { require(sha256(m) == hash); require(checkSigFromStack(s, oracle, m)); require(tx.outputs[this.activeInputIndex].scriptPubKey == hash); require(tx.outputs[this.activeInputIndex].value >= 1); }",
            &["reveal-without-timeout"],
        ),
        (
            "function f(signature s) { require(checkSig(s, owner)); require(tx.locktime >= 100); }",
            &["offchain-locktime"],
        ),
        ("function f() { require(1 == 2); }", &[]),
        (
            "function f(bytes p) { require(sha256(p) == hash); } function g() { require(1 == 2); }",
            &["anyone-can-spend", "reveal-without-timeout"],
        ),
        ("function f() { require(tx.inputs[0].scriptPubKey == hash); }", &[]),
        (
            "function f(pubkey k, signature s) { require(checkSig(s, k)); }",
            &["signer-from-witness"],
        ),
        (
            "function f(pubkey k, signature s) { require(sha256(k) == hash); require(checkSig(s, k)); }",
            &["reveal-without-timeout"],
        ),
        (
            "function f(signature s, signature t, int n) { require(checkMultisig([owner, oracle], [s, t], n)); }",
            &["signer-from-witness"],
        ),
        (
            "function f(signature s, signature t) { require(checkMultisig([owner, owner], [s, t])); }",
            &["duplicate-multisig-key"],
        ),
        (
            "function f(signature s, signature t, signature u) tapscript { require(checkMultisig([server, owner, owner], [s, t, u])); }",
            &["duplicate-multisig-key"],
        ),
        (
            "function f(signature s, bytes a, bytes b) { require(checkSig(s, owner)); require(sha256(a + b) == hash); }",
            &["ambiguous-hash-concat"],
        ),
        (
            "function f(signature s, bytes a, bytes b) { require(checkSig(s, owner)); require(sha256(a + sha256(b)) == hash); }",
            &[],
        ),
        (
            "function f(signature s, bytes p) { require(checkSig(s, owner)); require(sha256(p) == hash); } function g(signature s) { require(checkSig(s, owner)); require(checkTime(100)); }",
            &[],
        ),
        (
            "function f(signature s, int a) { require(checkSig(s, owner)); require(a / 2 * 3 > 1); require(a * 3 / 2 > 1); }",
            &["divide-before-multiply"],
        ),
        (
            "function f(signature s, int a) { require(checkSig(s, owner)); require(a == a); if (a < 1 || a < 1) { require(a >= a); } }",
            &["self-comparison", "self-comparison", "self-comparison"],
        ),
        (
            "function f(signature s) { require(helper(s)); } private function helper(signature s) bool { return checkSig(s, owner); }",
            &[],
        ),
    ] {
        assert_eq!(lints(function), expected, "{function}");
    }
}

#[test]
fn levels_allow_warn_or_deny_each_lint() {
    let source = "contract C(int n, int unused) { function f(int x) { require(x == n); } }";
    let codes = |levels: &Levels| {
        diagnostics_with(source, levels)
            .into_iter()
            .map(|d| (d.code.unwrap(), d.severity))
            .collect::<Vec<_>>()
    };
    let defaults = codes(&Levels::default());
    assert!(
        defaults.contains(&("anyone-can-spend".into(), Severity::Warning)),
        "{defaults:?}"
    );
    assert!(defaults.contains(&("unused-parameter".into(), Severity::Warning)));

    let mut levels = Levels::default();
    levels.set(Lint::AnyoneCanSpend, Level::Deny);
    levels.set(Lint::UnusedParameter, Level::Allow);
    assert_eq!(
        codes(&levels),
        [("anyone-can-spend".into(), Severity::Error)]
    );

    let mut levels = Levels::default();
    levels.set_named("warnings", Level::Deny).unwrap();
    assert!(codes(&levels)
        .iter()
        .all(|(_, severity)| *severity == Severity::Error));
    assert!(Levels::default()
        .set_named("no-such-lint", Level::Deny)
        .is_err());
}

#[test]
fn lint_attributes_set_levels_on_the_node_they_precede() {
    let codes = |source: &str, levels: &Levels| {
        diagnostics_with(source, levels)
            .into_iter()
            .map(|d| (d.code.unwrap(), d.severity))
            .collect::<Vec<_>>()
    };
    let unsigned = |attribute: &str| {
        format!(
            "contract C(int n) {{\n  {attribute}\n  function f(int x) {{ require(x == n); }}\n}}"
        )
    };
    let warning = |code: &str| (code.to_string(), Severity::Warning);
    let error = |code: &str| (code.to_string(), Severity::Error);
    let defaults = Levels::default();
    assert_eq!(
        codes(&unsigned(""), &defaults),
        [warning("anyone-can-spend")]
    );
    assert!(codes(
        &unsigned(r#"@allow(anyone-can-spend, "a demo")"#),
        &defaults
    )
    .is_empty());
    assert!(codes(
        &unsigned(r#"@expect(anyone-can-spend, "a demo")"#),
        &defaults
    )
    .is_empty());
    assert_eq!(
        codes(&unsigned("@deny(anyone-can-spend)"), &defaults),
        [error("anyone-can-spend")]
    );
    let mut denied = Levels::default();
    denied.set(Lint::AnyoneCanSpend, Level::Deny);
    assert!(codes(
        &unsigned(r#"@allow(anyone-can-spend, "reviewed")"#),
        &denied
    )
    .is_empty());
    let mut allowed = Levels::default();
    allowed.set(Lint::AnyoneCanSpend, Level::Allow);
    assert_eq!(
        codes(&unsigned("@warn(anyone-can-spend)"), &allowed),
        [warning("anyone-can-spend")]
    );
    assert_eq!(
        codes(&unsigned(r#"@allow(anyone-can-spnd, "typo")"#), &defaults),
        [warning("anyone-can-spend"), warning("unknown-lint")]
    );
    assert_eq!(
        codes(
            &unsigned(r#"@expect(anyone-can-spend, self-comparison, "one does not fire")"#),
            &defaults
        ),
        [warning("unfulfilled-expectation")]
    );

    let nested = r#"@deny(self-comparison)
    contract C(pubkey k) {
        @allow(self-comparison, "kept on purpose")
        function f(signature s, int x) {
            require(checkSig(s, k));
            require(x == x);
            @deny(self-comparison) require(x != x);
        }
        function g(signature s, int x) { require(checkSig(s, k)); require(x < x); }
    }"#;
    assert_eq!(
        codes(nested, &defaults),
        [error("self-comparison"), error("self-comparison")]
    );
}

#[test]
fn malformed_lint_attributes_are_errors() {
    for (attribute, expected) in [
        ("@allow(anyone-can-spend)", "@allow needs a reason"),
        (
            r#"@expect(anyone-can-spend, " ")"#,
            "@expect needs a reason",
        ),
        ("@inline(anyone-can-spend)", "unknown attribute '@inline'"),
        (r#"@deny("why")"#, "@deny needs a lint"),
        (
            r#"@deny("why", anyone-can-spend)"#,
            "takes lint names, then one reason",
        ),
    ] {
        let source =
            format!("contract C(int n) {{ {attribute} function f(int x) {{ require(x == n); }} }}");
        let errors: Vec<_> = diagnostics_with(&source, &Levels::default())
            .into_iter()
            .filter(|d| d.severity == Severity::Error)
            .collect();
        assert!(
            errors.len() == 1 && errors[0].message.contains(expected) && errors[0].span.is_some(),
            "{attribute}: {errors:?}"
        );
    }
    let dangling =
        "contract C(int n) { function f(int x) { require(x == n); @deny(anyone-can-spend) } }";
    assert!(diagnostics_with(dangling, &Levels::default())
        .iter()
        .any(|d| d.severity == Severity::Error));
}

#[test]
fn the_cli_applies_lint_levels() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("c.ark");
    std::fs::write(
        &source,
        "contract C(int n) { function f(int x) { require(x == n); } }",
    )
    .unwrap();
    let run = |args: &[&str]| {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_arkadec"))
            .arg(&source)
            .arg("-o")
            .arg(dir.path().join("c.json"))
            .args(args)
            .output()
            .unwrap();
        (
            output.status.success(),
            String::from_utf8(output.stderr).unwrap(),
        )
    };
    let (passed, stderr) = run(&[]);
    assert!(
        passed && stderr.contains("warning[anyone-can-spend]"),
        "{stderr}"
    );
    let (passed, stderr) = run(&["--deny", "anyone-can-spend"]);
    assert!(
        !passed && stderr.contains("error[anyone-can-spend]"),
        "{stderr}"
    );
    let (passed, stderr) = run(&["--allow", "anyone-can-spend"]);
    assert!(passed && !stderr.contains("anyone-can-spend"), "{stderr}");
    let (passed, stderr) = run(&["--deny", "security"]);
    assert!(
        !passed && stderr.contains("error[anyone-can-spend]"),
        "{stderr}"
    );
    let (passed, _) = run(&["--deny", "style"]);
    assert!(passed);
    let (passed, _) = run(&["--allow", "anyone-can-spend", "--deny", "security"]);
    assert!(passed);
}

#[test]
fn denied_lints_stop_compilation_only_in_the_file_being_compiled() {
    let main = |annotation: &str| {
        format!("import \"fees.ark\";\ncontract C(pubkey k) {{ function f(signature s, int n) {{ {annotation} let x = Fees.fee(n); require(checkSig(s, k)); }} }}")
    };
    let library = "library Fees { function fee(int n) int { let unused = n; return n + 1; } }";
    let files = |main: String| {
        BTreeMap::from([
            ("main.ark".to_string(), main),
            ("fees.ark".to_string(), library.to_string()),
        ])
    };
    let error = arkade_compiler::compile_sources("main.ark", &files(main("")))
        .unwrap_err()
        .to_string();
    assert!(error.contains("variable 'x'"), "{error}");
    let allowed = files(main(r#"@allow(unused-variable, "kept for the demo")"#));
    let output = arkade_compiler::compile_sources("main.ark", &allowed).unwrap();
    assert!(
        output
            .warnings
            .iter()
            .any(|w| w.contains("unused-variable") && w.ends_with("(fees.ark)")),
        "{:?}",
        output.warnings
    );
    let severity = |entry: &str| {
        analyze(entry, &allowed)
            .diagnostics()
            .into_iter()
            .find(|d| d.code.as_deref() == Some("unused-variable"))
            .map(|d| d.severity)
    };
    assert_eq!(severity("main.ark"), Some(Severity::Warning));
    assert_eq!(severity("fees.ark"), Some(Severity::Error));
}

#[test]
fn every_lint_is_documented_and_explained() {
    let readme = include_str!("../../README.md");
    for &lint in Lint::ALL {
        assert!(
            readme.contains(&format!("| `{}` |", lint.id())),
            "README's table of lints is missing {}",
            lint.id()
        );
        assert!(!lint.explanation().trim().is_empty(), "{}", lint.id());
    }
    let explain = |id: &str| {
        std::process::Command::new(env!("CARGO_BIN_EXE_arkadec"))
            .args(["--explain", id])
            .output()
            .unwrap()
    };
    let output = explain("reveal-without-timeout");
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(output.status.success());
    assert!(text.starts_with("reveal-without-timeout: security, warn by default"));
    assert!(text.contains("checkTime"), "{text}");
    assert!(!explain("no-such-lint").status.success());
}
