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
            &["unsigned-spend-path"][..],
        ),
        ("function f(signature s) { require(checkSig(s, owner)); }", &[]),
        (
            "function f() { require(tx.outputs[0].value >= tx.input.current.value); }",
            &["output-script-unchecked", "outputs-shared-across-inputs", "unsigned-spend-path"],
        ),
        (
            "function f(signature s) { require(checkSig(s, owner)); require(tx.outputs[0].value >= 1); }",
            &[],
        ),
        (
            "function f() { require(tx.numInputs == 1); require(tx.outputs[0].script == new C(owner, oracle, hash)); }",
            &["output-value-unchecked", "unsigned-spend-path"],
        ),
        (
            "function f() { require(this.activeInputIndex == 0); require(tx.outputs[0].script == new C(owner, oracle, hash)); require(tx.outputs[0].value >= tx.input.current.value); }",
            &["unsigned-spend-path"],
        ),
        (
            "function f(signature s, bytes32 m) { require(checkSigFromStack(s, oracle, m)); require(tx.outputs[this.activeInputIndex].script == new C(owner, oracle, hash)); require(tx.outputs[this.activeInputIndex].value >= 1); }",
            &["oracle-message-unbound", "unsigned-spend-path"],
        ),
        (
            "function f(signature s, bytes32 m) { require(sha256(m) == hash); require(checkSigFromStack(s, oracle, m)); require(tx.outputs[this.activeInputIndex].script == new C(owner, oracle, hash)); require(tx.outputs[this.activeInputIndex].value >= 1); }",
            &["unsigned-spend-path"],
        ),
        (
            "function f(signature s) { require(checkSig(s, owner)); require(tx.locktime >= 100); }",
            &["offchain-locktime"],
        ),
        ("function f() { require(1 == 2); }", &[]),
        (
            "function f(bytes p) { require(sha256(p) == hash); } function g() { require(1 == 2); }",
            &["unsigned-spend-path"],
        ),
        ("function f() { require(tx.inputs[0].script == new C(owner, oracle, hash)); }", &["unsigned-spend-path"]),
        (
            "function f(pubkey k, signature s) { require(checkSig(s, k)); }",
            &["signer-from-witness"],
        ),
        (
            "function f(pubkey k, signature s) { require(sha256(k) == hash); require(checkSig(s, k)); }",
            &[],
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
            "function f(signature s, int a, int b) { require(checkSig(s, owner)); require(a / 2 * 2 > 1); require(b * (a / b) > 1); }",
            &[],
        ),
        (
            "function f(signature s, int a) { require(checkSig(s, owner)); require(a == a); if (a < 1 || a < 1) { require(a >= a); } }",
            &["self-comparison", "self-comparison", "self-comparison"],
        ),
        (
            "function f(signature s, int a, int b, int c) { require(checkSig(s, owner)); require((a + b) * c == a + b * c); }",
            &[],
        ),
        (
            "function f(signature s, int a, int b, int c) { require(checkSig(s, owner)); require(a - b - c != a - (b - c)); }",
            &[],
        ),
        (
            "function f(signature s, int a, int b, int c) { require(checkSig(s, owner)); require(a + b * c == a + b * c); }",
            &["self-comparison"],
        ),
        (
            "function f(signature s) { require(helper(s)); } private function helper(signature s) bool { return checkSig(s, owner); }",
            &[],
        ),
        (
            "function f(signature s, int b) { if (b == 1) { require(helper(s)); } else { require(b == 2); } require(helper(s)); } private function helper(signature s) bool { return checkSig(s, owner); }",
            &[],
        ),
        (
            "function f(signature s, int b) { if (b == 1) { require(checkSig(s, owner)); } else { require(b == 2); } }",
            &["unsigned-spend-path"],
        ),
        (
            "function f(int b) { if (b == 1) { require(tx.outputs[0].script == new C(owner, oracle, hash)); require(tx.outputs[0].value >= tx.input.current.value); require(tx.numInputs == 1); } else { require(b == 2); } }",
            &["unsigned-spend-path"],
        ),
        (
            "function f(signature s, int b) { if (b == 1) { require(checkSig(s, owner)); } else { require(checkSig(s, oracle)); } }",
            &[],
        ),
        (
            "function f(signature s, int b) { require(b > 0); if (b == 1) { require(checkSig(s, owner)); } }",
            &["unsigned-spend-path"],
        ),
        (
            "function f(signature s, int b) { if (b == 1) { require(checkSig(s, owner)); } else if (b == 2) { require(checkSig(s, oracle)); } else { require(1 == 2); } }",
            &[],
        ),
        (
            "function f(signature s, int b) { if (b == 1) { require(checkSig(s, owner)); } else if (b == 2) { require(b == 2); } else { require(checkSig(s, oracle)); } }",
            &["unsigned-spend-path"],
        ),
        (
            "function f(signature s, bytes p, int b) { if (b == 1) { require(sha256(p) == hash); } else { require(checkSig(s, owner)); } }",
            &["unsigned-spend-path"],
        ),
        (
            "function f(bytes p, int b) { if (b == 1) { require(sha256(p) == hash); } else { require(1 == 2); } }",
            &["unsigned-spend-path"],
        ),
        (
            "function f(int b) { require(b > 0); if (b == 1) { require(1 == 2); } }",
            &["unsigned-spend-path"],
        ),
        (
            "function f(signature s, bytes p, int b) { require(checkSig(s, owner)); if (b == 1) { require(sha256(p) == hash); } }",
            &[],
        ),
        (
            "function claim() { require(tx.outputs[this.activeInputIndex].value >= tx.input.current.value); require(tx.outputs[this.activeInputIndex].script == new C(owner, oracle, hash)); } function claim(bytes p, signature a, signature b) tapscript { require(sha256(p) == hash); require(checkMultisig([server, emulator], [a, b], 2)); }",
            &["unsigned-spend-path"],
        ),
        (
            "function claim(bytes p) { require(sha256(p) == hash); require(tx.outputs[this.activeInputIndex].value >= tx.input.current.value); require(tx.outputs[this.activeInputIndex].script == new C(owner, oracle, hash)); } function claim(signature a, signature b) tapscript { require(checkMultisig([server, emulator], [a, b], 2)); }",
            &["unsigned-spend-path"],
        ),
        (
            "function f(bytes p) { require(sha256(p) == hash); } function g() { require(1 == 2); } function g(signature a, signature b) tapscript { require(checkMultisig([server, emulator], [a, b])); }",
            &["unsigned-spend-path"],
        ),
        (
            "function f(signature s) { require(checkSig(s, owner)); require(tx.outputs[0].script == new C(owner, oracle, hash)); }",
            &[],
        ),
        (
            "function w(int x) { require(x > 0); } function w(signature a, signature b, signature c) tapscript { require(checkMultisig([owner, server, emulator], [a, b, c], 3)); }",
            &[],
        ),
        (
            "function w(int x) { require(x > 0); } function w(signature a, signature b) tapscript { require(checkMultisig([server, emulator], [a, b], 2)); }",
            &["unsigned-spend-path"],
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
        defaults.contains(&("unsigned-spend-path".into(), Severity::Warning)),
        "{defaults:?}"
    );
    assert!(defaults.contains(&("unused-parameter".into(), Severity::Warning)));

    let mut levels = Levels::default();
    levels.set(Lint::UnsignedSpendPath, Level::Deny);
    levels.set(Lint::UnusedParameter, Level::Allow);
    assert_eq!(
        codes(&levels),
        [("unsigned-spend-path".into(), Severity::Error)]
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
        [warning("unsigned-spend-path")]
    );
    assert!(codes(
        &unsigned(r#"@allow(unsigned-spend-path, "a demo")"#),
        &defaults
    )
    .is_empty());
    assert!(codes(
        &unsigned(r#"@expect(unsigned-spend-path, "a demo")"#),
        &defaults
    )
    .is_empty());
    assert_eq!(
        codes(&unsigned("@deny(unsigned-spend-path)"), &defaults),
        [error("unsigned-spend-path")]
    );
    let mut denied = Levels::default();
    denied.set(Lint::UnsignedSpendPath, Level::Deny);
    assert!(codes(
        &unsigned(r#"@allow(unsigned-spend-path, "reviewed")"#),
        &denied
    )
    .is_empty());
    let mut allowed = Levels::default();
    allowed.set(Lint::UnsignedSpendPath, Level::Allow);
    assert_eq!(
        codes(&unsigned("@warn(unsigned-spend-path)"), &allowed),
        [warning("unsigned-spend-path")]
    );
    let mut deny_warnings = Levels::default();
    deny_warnings.set_named("warnings", Level::Deny).unwrap();
    assert_eq!(
        codes(&unsigned("@warn(unsigned-spend-path)"), &deny_warnings),
        [error("unsigned-spend-path")]
    );
    assert!(codes(
        &unsigned(r#"@allow(unsigned-spend-path, "reviewed")"#),
        &deny_warnings
    )
    .is_empty());
    assert_eq!(
        codes(&unsigned(r#"@allow(anyone-can-spnd, "typo")"#), &defaults),
        [warning("unsigned-spend-path"), warning("unknown-lint")]
    );
    assert_eq!(
        codes(
            &unsigned(r#"@expect(unsigned-spend-path, self-comparison, "one does not fire")"#),
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
        ("@allow(unsigned-spend-path)", "@allow needs a reason"),
        (
            r#"@expect(unsigned-spend-path, " ")"#,
            "@expect needs a reason",
        ),
        (
            "@inline(unsigned-spend-path)",
            "unknown attribute '@inline'",
        ),
        (r#"@deny("why")"#, "@deny needs a lint"),
        (
            r#"@deny("why", unsigned-spend-path)"#,
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
        "contract C(int n) { function f(int x) { require(x == n); @deny(unsigned-spend-path) } }";
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
        passed && stderr.contains("warning[unsigned-spend-path]"),
        "{stderr}"
    );
    let (passed, stderr) = run(&["--deny", "unsigned-spend-path"]);
    assert!(
        !passed && stderr.contains("error[unsigned-spend-path]"),
        "{stderr}"
    );
    let (passed, stderr) = run(&["--allow", "unsigned-spend-path"]);
    assert!(
        passed && !stderr.contains("unsigned-spend-path"),
        "{stderr}"
    );
    let (passed, stderr) = run(&["--deny", "security"]);
    assert!(
        !passed && stderr.contains("error[unsigned-spend-path]"),
        "{stderr}"
    );
    let (passed, _) = run(&["--deny", "style"]);
    assert!(passed);
    let (passed, _) = run(&["--allow", "unsigned-spend-path", "--deny", "security"]);
    assert!(passed);
    let (passed, _) = run(&["--deny", "all", "--allow", "security"]);
    assert!(passed);
    let (passed, _) = run(&["--allow", "security", "--deny", "all"]);
    assert!(!passed);
    let (passed, _) = run(&["--warn", "unsigned-spend-path", "--deny", "warnings"]);
    assert!(!passed);
    let (passed, _) = run(&["--deny", "warnings", "--allow", "warnings"]);
    assert!(passed);
}

#[test]
fn denied_lints_stop_compilation_only_in_the_file_being_compiled() {
    let main = |annotation: &str| {
        format!("import \"fees.ark\";\ncontract C(pubkey k) {{ function f(signature s, int n) {{ {annotation} let x = Fees.fee(n); require(n > 0); require(checkSig(s, k)); }} }}")
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
    let mut deny_warnings = Levels::default();
    deny_warnings.set_named("warnings", Level::Deny).unwrap();
    let imported = analyze("main.ark", &allowed).diagnostics_with(&deny_warnings);
    assert!(
        imported.iter().any(
            |d| d.code.as_deref() == Some("unused-variable") && d.severity == Severity::Warning
        ),
        "{imported:?}"
    );
}

#[test]
fn a_read_by_a_dead_local_does_not_count_as_a_use() {
    let source = r#"contract C(pubkey k, int p) { function f(signature s) {
        let a = p;
        @allow(unused-variable, "r") let b = a;
        require(checkSig(s, k));
    } }"#;
    let messages: Vec<String> = diagnostics_with(source, &Levels::default())
        .into_iter()
        .map(|d| d.message)
        .collect();
    assert_eq!(
        messages,
        [
            "variable 'a' in function 'f' is never used",
            "constructor parameter 'p' is never used"
        ],
    );
}

#[test]
fn a_tapscript_reading_an_element_or_field_uses_its_parameter() {
    let source = r#"struct Policy { pubkey owner; bytes32 lockHash; }
    contract Vault(pubkey[2] guardians, Policy policy, Policy[2] backups, int exitDelay, int unused) {
        function exit(signature g0Sig, signature g1Sig) tapscript {
            require(older(exitDelay));
            require(checkMultisig([guardians[0], guardians[1]], [g0Sig, g1Sig], 2));
        }
        function claim(bytes32 preimage, signature serverSig, signature ownerSig) tapscript {
            require(sha256(preimage) == policy.lockHash);
            require(checkMultisig([server, policy.owner], [serverSig, ownerSig], 2));
        }
        function recover(signature serverSig, signature backupSig) tapscript {
            require(checkMultisig([server, backups[1].owner], [serverSig, backupSig], 2));
        }
    }"#;
    let messages: Vec<String> = diagnostics_with(source, &Levels::default())
        .into_iter()
        .map(|d| d.message)
        .collect();
    assert_eq!(messages, ["constructor parameter 'unused' is never used"]);
}

#[test]
fn a_leaf_keyed_by_an_element_or_field_is_signed() {
    let source = r#"struct Policy { pubkey owner; int weight; }
    contract Vault(pubkey[2] guardians, Policy policy) {
        function claim() { require(tx.input.current.value >= 1); }
        function claim(signature serverSig, signature emulatorSig, signature gSig) tapscript {
            require(checkMultisig([server, emulator, guardians[0]], [serverSig, emulatorSig, gSig], 3));
        }
        function release() { require(tx.input.current.value >= 1); }
        function release(signature serverSig, signature emulatorSig, signature oSig) tapscript {
            require(checkMultisig([server, emulator, policy.owner], [serverSig, emulatorSig, oSig], 3));
        }
        function refund() { require(tx.input.current.value >= 1); }
    }"#;
    let messages: Vec<String> = diagnostics_with(source, &Levels::default())
        .into_iter()
        .map(|d| d.message)
        .collect();
    assert_eq!(
        messages,
        ["function 'refund' has a spending path with no transaction signature, so its other conditions alone authorize the spend"]
    );
}

#[test]
fn a_helper_call_counts_as_a_use_and_an_empty_branch_does_not() {
    let helper =
        "private function checked(signature s) bool { require(checkSig(s, owner)); return true; }";
    let checked = |attribute: &str| {
        format!(
            "contract C(pubkey owner) {{ function spend(signature sig) {{ {attribute} bool ok = checked(sig); ok = !ok; }} {helper} }}"
        )
    };
    let error = arkade_compiler::compile(&checked(""))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("variable 'ok' in function 'spend' is never used")
            && !error.contains("'sig'"),
        "{error}"
    );
    let output = arkade_compiler::compile(&checked(r#"@allow(unused-variable, "r")"#)).unwrap();
    assert!(crate::common::arkade_asm(&output, "spend").contains("<owner> OP_CHECKSIGVERIFY"));

    for (parameter, body, unread) in [
        (
            "int amount",
            r#"if (amount > 0) { @allow(unused-variable, "r") let t = 1; }"#,
            "amount",
        ),
        (
            "int[2] xs",
            r#"for (i, x) in xs { @allow(unused-variable, "r") let t = 1; }"#,
            "xs",
        ),
    ] {
        let source = format!(
            "contract C(pubkey owner) {{ function spend(signature sig, {parameter}) {{ require(checkSig(sig, owner)); {body} }} }}"
        );
        let error = arkade_compiler::compile(&source).unwrap_err().to_string();
        assert!(
            error.contains(&format!(
                "parameter '{unread}' of function 'spend' is never used"
            )),
            "{error}"
        );
    }

    let error = arkade_compiler::compile(
        "contract C(pubkey owner) { function spend(signature sig) { let t = 1; require(checkSig(sig, owner)); } }",
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("error[unused-variable]: "), "{error}");
}

#[test]
fn an_allowed_unused_local_is_dropped_from_the_covenant_stack() {
    let source = r#"contract P(pubkey owner) { function spend(signature ownerSig, int amount) {
        @allow(unused-variable, "probe") int doubled = amount * 2;
        require(amount > 0);
        require(checkSig(ownerSig, owner));
    } }"#;
    let output = arkade_compiler::compile(source).unwrap();
    assert_eq!(
        crate::common::arkade_asm(&output, "spend"),
        "OP_OVER 2 OP_MUL OP_ROT 0 OP_GREATERTHAN OP_VERIFY OP_SWAP <owner> OP_CHECKSIG OP_NIP"
    );
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
    let output = explain("unsigned-spend-path");
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(output.status.success());
    assert!(text.starts_with("unsigned-spend-path: security, warn by default"));
    assert!(text.contains("checkSig"), "{text}");
    assert!(!explain("no-such-lint").status.success());
}

#[test]
fn findings_from_an_imported_helper_sit_at_the_call() {
    let main = |annotation: &str| {
        format!("import \"fees.ark\";\ncontract C(int n) {{\n  function f(int amount) {{\n    {annotation}Fees.check(amount);\n    require(amount == n);\n  }}\n}}")
    };
    let library = "library Fees {\n  function check(int value) {\n    require(tx.outputs[0].value >= value);\n  }\n}";
    let analyze_main = |main: String| {
        let files = BTreeMap::from([
            ("main.ark".to_string(), main.clone()),
            ("fees.ark".to_string(), library.to_string()),
        ]);
        let diagnostics = analyze("main.ark", &files).diagnostics();
        (main, diagnostics)
    };
    let (source, diagnostics) = analyze_main(main(""));
    let finding = diagnostics
        .iter()
        .find(|d| d.lint == Some(Lint::OutputScriptUnchecked))
        .expect("the helper's unpinned output is reported");
    let span = finding.span.unwrap();
    assert_eq!(finding.file, "main.ark");
    assert_eq!(&source[span.start..span.end], "Fees.check(amount)");
    let (_, allowed) = analyze_main(main(
        r#"@allow(output-script-unchecked, "pinned by the caller") "#,
    ));
    assert!(!allowed
        .iter()
        .any(|d| d.lint == Some(Lint::OutputScriptUnchecked)));
}

#[test]
fn a_requirement_that_folds_to_false_disables_the_function() {
    for dead in ["1 > 2", "0xAB != 0xab", "!true", "1 + 1 == 3"] {
        let source = format!(
            "contract C(int n) {{ function f(int x) {{ require({dead}); require(x == n); }} }}"
        );
        assert!(
            !diagnostics_with(&source, &Levels::default())
                .iter()
                .any(|d| d.lint == Some(Lint::UnsignedSpendPath)),
            "{dead}"
        );
    }
}

#[test]
fn a_disabled_branch_keeps_the_rest_of_the_function_linted() {
    let source = "contract C(int n) { function f(bool b, int x) { if (b) { require(false); } else { require(x == n); } } }";
    assert!(diagnostics_with(source, &Levels::default())
        .iter()
        .any(|d| d.lint == Some(Lint::UnsignedSpendPath)));
}

#[test]
fn a_finding_fulfills_only_the_innermost_expectation() {
    let source = r#"contract C(pubkey k) {
        @expect(self-comparison, "outer")
        function f(signature s, int x) {
            require(checkSig(s, k));
            @expect(self-comparison, "inner") require(x == x);
        }
    }"#;
    let unfulfilled: Vec<_> = diagnostics_with(source, &Levels::default())
        .into_iter()
        .filter(|d| d.lint == Some(Lint::UnfulfilledExpectation))
        .map(|d| d.span.unwrap().start)
        .collect();
    assert_eq!(unfulfilled, [source.find("self-comparison").unwrap()]);
}

#[test]
fn an_attribute_applies_to_findings_on_its_own_node_but_not_a_sibling() {
    let lints = |functions: &str| {
        let source = format!("contract C(pubkey k) {{ {functions} }}");
        diagnostics_with(&source, &Levels::default())
            .into_iter()
            .filter_map(|d| d.lint)
            .collect::<Vec<_>>()
    };
    let body = "(signature s) { require(checkSig(s, k)); }";
    assert!(lints(&format!(
        r#"@allow(unknown-lint, "x") @allow(no-such-lint, "y") function f{body}"#
    ))
    .is_empty());
    assert!(lints(&format!(
        r#"@allow(unfulfilled-expectation, "x") @expect(self-comparison, "y") function f{body}"#
    ))
    .is_empty());
    assert_eq!(
        lints(&format!(
            r#"@allow(unknown-lint, "x") function f{body} @allow(no-such-lint, "y") function g{body}"#
        )),
        [Lint::UnknownLint]
    );
}
