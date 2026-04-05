//! BSST-style ASM structural analysis tests.
//!
//! Inspired by Dmitry Petukhov's Bitcoin Script Symbolic Tracer (BSST), these
//! tests verify structural properties of every compiled ASM output:
//!
//! - OP_IF / OP_ELSE / OP_ENDIF are balanced (no dangling branches).
//! - No empty instruction strings (would silently produce malformed scripts).
//! - Every `<placeholder>` token is syntactically well-formed.
//! - Every `<placeholder>` is resolvable (appears in witnessSchema or
//!   constructorInputs).
//! - Stack depth never goes negative at known opcode sites.
//!
//! These checks run over all 16 canonical example contracts to give us broad
//! coverage, and over targeted synthetic contracts to verify each check fires
//! correctly when the invariant is violated.

use arkade_compiler::compile;
use arkade_compiler::validator::{
    validate_asm_structure, validate_placeholder_consistency, ValidationIssue,
};
use std::fs;
use std::path::PathBuf;

fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples")
}

fn count_errors(issues: &[ValidationIssue]) -> usize {
    issues
        .iter()
        .filter(|i| matches!(i.severity, arkade_compiler::validator::Severity::Error))
        .count()
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Count IF-depth changes across the ASM to verify balance.
fn if_else_endif_balance(asm: &[String]) -> i32 {
    let mut depth: i32 = 0;
    for instr in asm {
        match instr.as_str() {
            "OP_IF" | "OP_NOTIF" => depth += 1,
            "OP_ENDIF" => depth -= 1,
            _ => {}
        }
    }
    depth
}

// ─── All-examples sweep ───────────────────────────────────────────────────────

/// Compile every example and assert no structural errors in any function's ASM.
#[test]
fn all_examples_have_balanced_if_else_endif() {
    let dir = examples_dir();
    let mut entries: Vec<_> = fs::read_dir(&dir)
        .expect("failed to read examples dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "ark").unwrap_or(false))
        .collect();
    entries.sort_by_key(|e| e.path());

    for entry in entries {
        let path = entry.path();
        let filename = path.file_name().unwrap().to_string_lossy().into_owned();
        let source = fs::read_to_string(&path).unwrap();
        let output = compile(&source).unwrap_or_else(|e| panic!("compile {}: {}", filename, e));

        for func in &output.functions {
            let balance = if_else_endif_balance(&func.asm);
            assert_eq!(
                balance, 0,
                "{}: fn '{}' (serverVariant={}) has unbalanced OP_IF/OP_ENDIF (net depth={})",
                filename, func.name, func.server_variant, balance
            );
        }
    }
}

#[test]
fn all_examples_have_no_empty_asm_instructions() {
    let dir = examples_dir();
    let mut entries: Vec<_> = fs::read_dir(&dir)
        .expect("failed to read examples dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "ark").unwrap_or(false))
        .collect();
    entries.sort_by_key(|e| e.path());

    for entry in entries {
        let path = entry.path();
        let filename = path.file_name().unwrap().to_string_lossy().into_owned();
        let source = fs::read_to_string(&path).unwrap();
        let output = compile(&source).unwrap_or_else(|e| panic!("compile {}: {}", filename, e));

        for func in &output.functions {
            for (i, instr) in func.asm.iter().enumerate() {
                assert!(
                    !instr.is_empty(),
                    "{}: fn '{}' (serverVariant={}) has empty instruction at index {}",
                    filename,
                    func.name,
                    func.server_variant,
                    i
                );
            }
        }
    }
}

#[test]
fn all_examples_have_well_formed_placeholders() {
    // Every <placeholder> token must be syntactically valid: starts with '<',
    // ends with '>', and is non-empty.  The validate_asm_structure check covers
    // this.  Compound-expression placeholders like
    // <checkMultisig([a,b],[c,d])> are legitimately emitted by the compiler
    // and are checked here only for delimiter correctness.
    let dir = examples_dir();
    let mut entries: Vec<_> = fs::read_dir(&dir)
        .expect("failed to read examples dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "ark").unwrap_or(false))
        .collect();
    entries.sort_by_key(|e| e.path());

    for entry in entries {
        let path = entry.path();
        let filename = path.file_name().unwrap().to_string_lossy().into_owned();
        let source = fs::read_to_string(&path).unwrap();
        let output = compile(&source).unwrap_or_else(|e| panic!("compile {}: {}", filename, e));

        for func in &output.functions {
            // Run the validator and check no structural errors
            let issues = validate_asm_structure(&func.name, func.server_variant, &func.asm);
            let errors = count_errors(&issues);
            assert_eq!(
                errors,
                0,
                "{}: fn '{}' (serverVariant={}) has ASM structure errors: {:?}",
                filename,
                func.name,
                func.server_variant,
                issues
                    .iter()
                    .filter(|i| matches!(i.severity, arkade_compiler::validator::Severity::Error))
                    .map(|i| &i.message)
                    .collect::<Vec<_>>()
            );
        }
    }
}

/// Verify placeholder resolution for simple contracts that have no let-binding
/// placeholders or compound expression placeholders.  Complex contracts like
/// arkade_kitties use `let sireGroup = tx.assetGroups.find(...)` which emits
/// `<sireGroup>` — an unresolved local-variable placeholder (a known current
/// compiler limitation tracked by the variable-binding TODO).  Those are
/// correctly surfaced as warnings by `validate_placeholder_consistency` and
/// tested separately below.
#[test]
fn simple_contracts_have_fully_resolvable_placeholders() {
    let simple = ["single_sig.ark", "htlc.ark", "bare_vtxo.ark"];
    // Note: htlc.ark uses checkMultisig with explicit sig arrays; those are
    // emitted as compound-expression placeholders and are also tested.
    for filename in &simple {
        let path = examples_dir().join(filename);
        if !path.exists() {
            continue;
        }
        let source = fs::read_to_string(&path).unwrap();
        let output = compile(&source).unwrap_or_else(|e| panic!("compile {}: {}", filename, e));

        for func in &output.functions {
            let issues = validate_placeholder_consistency(
                &func.name,
                func.server_variant,
                &func.asm,
                &func.witness_schema,
                &output.parameters,
            );
            let unresolvable: Vec<_> = issues
                .iter()
                .filter(|i| i.message.contains("cannot be constructed"))
                .collect();
            assert!(
                unresolvable.is_empty(),
                "{}: fn '{}' (serverVariant={}) has unresolvable placeholders: {:?}",
                filename,
                func.name,
                func.server_variant,
                unresolvable.iter().map(|i| &i.message).collect::<Vec<_>>()
            );
        }
    }
}

/// Contracts that use `let` bindings for intermediate values (e.g.
/// `let sireGroup = tx.assetGroups.find(sireId)`) currently emit those
/// names as `<sireGroup>` placeholders that are not in the witnessSchema or
/// constructorInputs.  The validator correctly surfaces these as warnings —
/// this test verifies that the warning mechanism works and the placeholder is
/// named in the message.
#[test]
fn local_variable_placeholders_are_surfaced_as_warnings() {
    let path = examples_dir().join("arkade_kitties.ark");
    if !path.exists() {
        return;
    }
    let source = fs::read_to_string(&path).unwrap();
    let output = compile(&source).expect("arkade_kitties.ark must compile");

    // Find a function that uses let-binding placeholders
    let breed = output
        .functions
        .iter()
        .find(|f| f.name == "breed" && f.server_variant);

    if let Some(func) = breed {
        let issues = validate_placeholder_consistency(
            &func.name,
            func.server_variant,
            &func.asm,
            &func.witness_schema,
            &output.parameters,
        );
        // There should be warnings about unresolved local variables
        let unresolved_warnings: Vec<_> = issues
            .iter()
            .filter(|i| {
                matches!(i.severity, arkade_compiler::validator::Severity::Warning)
                    && i.message.contains("cannot be constructed")
            })
            .collect();
        assert!(
            !unresolved_warnings.is_empty(),
            "arkade_kitties breed should have unresolvable placeholder warnings \
             (known compiler limitation: let-binding variables not tracked)"
        );
        // Each warning must name the problematic placeholder
        for w in &unresolved_warnings {
            assert!(
                w.message.contains('<') && w.message.contains('>'),
                "warning must name the unresolvable placeholder: {}",
                w.message
            );
        }
    }
}

// ─── validate_asm_structure — unit tests ─────────────────────────────────────

#[test]
fn balanced_if_endif_is_clean() {
    let asm = vec![
        "<cond>".to_string(),
        "OP_IF".to_string(),
        "<a>".to_string(),
        "OP_CHECKSIG".to_string(),
        "OP_ELSE".to_string(),
        "<b>".to_string(),
        "OP_CHECKSIG".to_string(),
        "OP_ENDIF".to_string(),
    ];
    let issues = validate_asm_structure("f", false, &asm);
    assert_eq!(
        count_errors(&issues),
        0,
        "balanced IF/ELSE/ENDIF: {:?}",
        issues
    );
}

#[test]
fn unbalanced_if_without_endif_is_error() {
    let asm = vec![
        "<cond>".to_string(),
        "OP_IF".to_string(),
        "<sig>".to_string(),
        "OP_CHECKSIG".to_string(),
        // Missing OP_ENDIF
    ];
    let issues = validate_asm_structure("f", false, &asm);
    assert!(count_errors(&issues) > 0, "unclosed OP_IF must be detected");
    assert!(
        issues
            .iter()
            .any(|i| i.message.contains("unclosed") || i.message.contains("missing")),
        "error message must mention unclosed branch; got: {:?}",
        issues.iter().map(|i| &i.message).collect::<Vec<_>>()
    );
}

#[test]
fn stray_endif_without_if_is_error() {
    let asm = vec![
        "<sig>".to_string(),
        "OP_CHECKSIG".to_string(),
        "OP_ENDIF".to_string(), // no matching OP_IF
    ];
    let issues = validate_asm_structure("f", false, &asm);
    assert!(count_errors(&issues) > 0, "stray OP_ENDIF must be detected");
}

#[test]
fn stray_else_without_if_is_error() {
    let asm = vec![
        "<sig>".to_string(),
        "OP_CHECKSIG".to_string(),
        "OP_ELSE".to_string(), // no matching OP_IF
        "<sig2>".to_string(),
        "OP_CHECKSIG".to_string(),
        "OP_ENDIF".to_string(),
    ];
    let issues = validate_asm_structure("f", false, &asm);
    assert!(count_errors(&issues) > 0, "stray OP_ELSE must be detected");
}

#[test]
fn empty_asm_instruction_is_error() {
    let asm = vec![
        "<sig>".to_string(),
        "".to_string(),
        "OP_CHECKSIG".to_string(),
    ];
    let issues = validate_asm_structure("f", false, &asm);
    assert!(
        count_errors(&issues) > 0,
        "empty instruction string must be an error"
    );
    assert!(
        issues.iter().any(|i| i.message.contains("empty")),
        "error must mention 'empty'"
    );
}

#[test]
fn malformed_placeholder_missing_close_is_error() {
    let asm = vec!["<sig".to_string(), "OP_CHECKSIG".to_string()];
    let issues = validate_asm_structure("f", false, &asm);
    assert!(
        count_errors(&issues) > 0,
        "placeholder without closing '>' must be an error"
    );
}

#[test]
fn empty_placeholder_is_error() {
    // "<>" is invalid
    let asm = vec!["<>".to_string(), "OP_CHECKSIG".to_string()];
    let issues = validate_asm_structure("f", false, &asm);
    assert!(
        count_errors(&issues) > 0,
        "empty placeholder '<>' must be an error"
    );
}

// ─── validate_placeholder_consistency — unit tests ───────────────────────────

#[test]
fn placeholder_in_witness_schema_is_clean() {
    use arkade_compiler::models::WitnessElement;
    let asm = vec!["<sig>".to_string(), "OP_CHECKSIG".to_string()];
    let witness = vec![WitnessElement {
        name: "sig".to_string(),
        elem_type: "signature".to_string(),
        encoding: "schnorr-64".to_string(),
    }];
    let issues = validate_placeholder_consistency("f", false, &asm, &witness, &[]);
    assert!(
        issues.is_empty(),
        "known witness placeholder must produce no issues: {:?}",
        issues
    );
}

#[test]
fn placeholder_in_constructor_inputs_is_clean() {
    use arkade_compiler::models::{Parameter, WitnessElement};
    let asm = vec![
        "<owner>".to_string(),
        "<sig>".to_string(),
        "OP_CHECKSIG".to_string(),
    ];
    let witness = vec![WitnessElement {
        name: "sig".to_string(),
        elem_type: "signature".to_string(),
        encoding: "schnorr-64".to_string(),
    }];
    let ctor = vec![Parameter {
        name: "owner".to_string(),
        param_type: "pubkey".to_string(),
    }];
    let issues = validate_placeholder_consistency("f", false, &asm, &witness, &ctor);
    assert!(
        issues.is_empty(),
        "constructor-bound placeholder must produce no issues: {:?}",
        issues
    );
}

#[test]
fn orphaned_placeholder_is_warned() {
    let asm = vec!["<mystery>".to_string(), "OP_CHECKSIG".to_string()];
    let issues = validate_placeholder_consistency("f", false, &asm, &[], &[]);
    assert!(
        !issues.is_empty(),
        "unresolvable placeholder must produce a warning"
    );
    assert!(
        issues.iter().any(|i| i.message.contains("mystery")),
        "warning must name the unresolvable placeholder"
    );
}

#[test]
fn server_key_placeholder_is_always_resolved() {
    // <SERVER_KEY> is injected at runtime by the Ark operator — it must not be
    // flagged as unresolvable even though it is not in the schema.
    let asm = vec![
        "<SERVER_KEY>".to_string(),
        "<serverSig>".to_string(),
        "OP_CHECKSIG".to_string(),
    ];
    let issues = validate_placeholder_consistency("f", true, &asm, &[], &[]);
    // serverSig is special-cased; SERVER_KEY must not be flagged
    let orphan: Vec<_> = issues
        .iter()
        .filter(|i| i.message.contains("SERVER_KEY"))
        .collect();
    assert!(
        orphan.is_empty(),
        "<SERVER_KEY> must never be flagged as unresolvable"
    );
}

#[test]
fn vtxo_placeholder_is_always_resolved() {
    let asm = vec![
        "<VTXO:SomeContract(x,y)>".to_string(),
        "OP_EQUAL".to_string(),
    ];
    let issues = validate_placeholder_consistency("f", false, &asm, &[], &[]);
    let orphan: Vec<_> = issues
        .iter()
        .filter(|i| i.message.contains("VTXO:"))
        .collect();
    assert!(
        orphan.is_empty(),
        "<VTXO:...> placeholders must never be flagged as unresolvable"
    );
}

// ─── Require-guard warning via full pipeline ─────────────────────────────────

#[test]
fn function_with_no_require_produces_warning() {
    // A function that has only variable assignments but no require() is a security hole.
    // The compiler should surface a warning[validation] for it.
    let source = r#"
options { exit = 144; server = server; }
contract AlwaysPass(pubkey owner, pubkey server) {
    function spend(signature sig) {
        let x = 1;
    }
}"#;
    let result = compile(source);
    assert!(
        result.is_ok(),
        "should compile (warning, not error): {:?}",
        result.err()
    );
    let output = result.unwrap();
    let has_require_warning = output
        .warnings
        .iter()
        .any(|w| w.contains("always succeed") || w.contains("no require"));
    assert!(
        has_require_warning,
        "missing-require warning must appear in warnings; got: {:?}",
        output.warnings
    );
}

#[test]
fn function_with_require_in_if_branch_suppresses_warning() {
    // require() inside an if branch counts as having a guard.
    let source = r#"
options { exit = 144; server = server; }
contract Guarded(pubkey owner, pubkey server) {
    function spend(signature sig) {
        if (checkSig(sig, owner)) {
            require(checkSig(sig, owner));
        }
    }
}"#;
    let result = compile(source);
    assert!(result.is_ok(), "compile failed: {:?}", result.err());
    let output = result.unwrap();
    let has_no_require_warning = output.warnings.iter().any(|w| w.contains("always succeed"));
    assert!(
        !has_no_require_warning,
        "should NOT warn about missing requires when require is inside a branch"
    );
}
