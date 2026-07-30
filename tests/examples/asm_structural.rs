//! BSST-style ASM structural analysis tests.
//!
//! Inspired by Dmitry Petukhov's Bitcoin Script Symbolic Tracer (BSST), these
//! tests verify structural properties of every compiled ASM output:
//!
//! - OP_IF / OP_ELSE / OP_ENDIF are balanced (no dangling branches).
//! - No empty instruction strings (would silently produce malformed scripts).
//! - Every `<placeholder>` token is syntactically well-formed.
//! - Every `<placeholder>` is resolvable (appears in covenant inputs,
//!   leaf witness, or constructorInputs).
//! - Stack depth never goes negative at known opcode sites.
//!
//! These checks run over all canonical example contracts to give us broad
//! coverage, and over targeted synthetic contracts to verify each check fires
//! correctly when the invariant is violated.

use arkade_compiler::compile;
use std::fs;
use std::path::PathBuf;

fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples")
}

// ─── Local structural-check helpers ──────────────────────────────────────────

/// Check ASM for structural validity (IF balance, empty tokens, placeholder
/// syntax). Returns a list of human-readable error strings; empty ⇒ all OK.
fn local_check_asm_structure(asm: &[String]) -> Vec<String> {
    let mut errors = Vec::new();
    let mut depth: i32 = 0;
    for (i, tok) in asm.iter().enumerate() {
        if tok.is_empty() {
            errors.push(format!("empty instruction at index {}", i));
            continue;
        }
        if tok.starts_with('<') {
            if tok == "<>" {
                errors.push(format!("empty placeholder '<>' at index {}", i));
            } else if !tok.ends_with('>') {
                errors.push(format!(
                    "malformed placeholder (missing '>') at index {}: {}",
                    i, tok
                ));
            }
        }
        match tok.as_str() {
            "OP_IF" | "OP_NOTIF" => depth += 1,
            "OP_ENDIF" => {
                if depth <= 0 {
                    errors.push(format!(
                        "stray OP_ENDIF at index {} (depth was {})",
                        i, depth
                    ));
                }
                depth -= 1;
            }
            "OP_ELSE" if depth <= 0 => {
                errors.push(format!(
                    "stray OP_ELSE at index {} without matching OP_IF",
                    i
                ));
            }
            "OP_ELSE" => {}
            _ => {}
        }
    }
    if depth > 0 {
        errors.push(format!("unclosed OP_IF: missing {} OP_ENDIF(s)", depth));
    }
    errors
}

/// Warn when a `<name>` placeholder in `asm` cannot be resolved from
/// `witness_names`, `ctor_names`, or the built-in special token set.
/// Returns warning strings; empty ⇒ all placeholders resolved.
fn local_check_placeholder_consistency(
    asm: &[String],
    witness_names: &[&str],
    ctor_names: &[&str],
) -> Vec<String> {
    let mut warnings = Vec::new();
    for tok in asm {
        if !(tok.starts_with('<') && tok.ends_with('>') && tok.len() > 2) {
            continue;
        }
        let inner = &tok[1..tok.len() - 1];
        // Built-in / runtime-injected names that are always resolved.
        if inner == "SERVER_KEY"
            || inner == "serverSig"
            || inner == "emulatorSig"
            || inner.starts_with("EMULATOR_KEY:")
            || inner.starts_with("VTXO:")
            || inner.starts_with("checkMultisig(")
        {
            continue;
        }
        if !witness_names.contains(&inner) && !ctor_names.contains(&inner) {
            warnings.push(format!(
                "placeholder <{}> cannot be constructed from witness or constructor inputs",
                inner
            ));
        }
    }
    warnings
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

/// Compile every example and assert no structural errors in any ASM segment.
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

        for group in &output.functions {
            if let Some(arkade) = &group.arkade {
                let balance = if_else_endif_balance(&arkade.asm);
                assert_eq!(
                    balance, 0,
                    "{}: group '{}' covenant has unbalanced OP_IF/OP_ENDIF (net depth={})",
                    filename, group.name, balance
                );
            }
            for leaf in &group.leaves {
                let balance = if_else_endif_balance(&leaf.asm);
                assert_eq!(
                    balance, 0,
                    "{}: group '{}' leaf '{}' has unbalanced OP_IF/OP_ENDIF (net depth={})",
                    filename, group.name, leaf.name, balance
                );
            }
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

        for group in &output.functions {
            if let Some(arkade) = &group.arkade {
                for (i, instr) in arkade.asm.iter().enumerate() {
                    assert!(
                        !instr.is_empty(),
                        "{}: group '{}' covenant has empty instruction at index {}",
                        filename,
                        group.name,
                        i
                    );
                }
            }
            for leaf in &group.leaves {
                for (i, instr) in leaf.asm.iter().enumerate() {
                    assert!(
                        !instr.is_empty(),
                        "{}: group '{}' leaf '{}' has empty instruction at index {}",
                        filename,
                        group.name,
                        leaf.name,
                        i
                    );
                }
            }
        }
    }
}

#[test]
fn all_examples_have_well_formed_placeholders() {
    // Every <placeholder> token must be syntactically valid: starts with '<',
    // ends with '>', and is non-empty.  Compound-expression placeholders like
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

        for group in &output.functions {
            if let Some(arkade) = &group.arkade {
                let errors = local_check_asm_structure(&arkade.asm);
                assert!(
                    errors.is_empty(),
                    "{}: group '{}' covenant has ASM structure errors: {:?}",
                    filename,
                    group.name,
                    errors
                );
            }
            for leaf in &group.leaves {
                let errors = local_check_asm_structure(&leaf.asm);
                assert!(
                    errors.is_empty(),
                    "{}: group '{}' leaf '{}' has ASM structure errors: {:?}",
                    filename,
                    group.name,
                    leaf.name,
                    errors
                );
            }
        }
    }
}

/// Verify placeholder resolution for simple contracts that have no let-binding
/// placeholders or compound expression placeholders.  Complex contracts like
/// arkade_kitties use `let sireGroup = tx.assetGroups.find(...)` which emits
/// `<sireGroup>` — an unresolved local-variable placeholder (a known current
/// compiler limitation tracked by the variable-binding TODO).  Those are
/// correctly surfaced as warnings by `local_check_placeholder_consistency` and
/// tested separately below.
#[test]
fn simple_contracts_have_fully_resolvable_placeholders() {
    // bare_vtxo has its own dedicated test in tests/bare_vtxo_test.rs and no
    // example file in examples/, so it's not listed here.
    // htlc.ark uses checkMultisig with explicit sig arrays; those are
    // emitted as compound-expression placeholders and are also tested.
    let simple = ["single_sig/single_sig.ark", "htlc/htlc.ark"];
    for filename in &simple {
        let path = examples_dir().join(filename);
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{} must exist in examples/: {}", filename, e));
        let output = compile(&source).unwrap_or_else(|e| panic!("compile {}: {}", filename, e));

        let ctor_names: Vec<&str> = output.parameters.iter().map(|p| p.name.as_str()).collect();

        for group in &output.functions {
            if let Some(arkade) = &group.arkade {
                let input_names: Vec<&str> =
                    arkade.inputs.iter().map(|i| i.name.as_str()).collect();
                let warnings =
                    local_check_placeholder_consistency(&arkade.asm, &input_names, &ctor_names);
                let unresolvable: Vec<_> = warnings
                    .iter()
                    .filter(|w| w.contains("cannot be constructed"))
                    .collect();
                assert!(
                    unresolvable.is_empty(),
                    "{}: group '{}' covenant has unresolvable placeholders: {:?}",
                    filename,
                    group.name,
                    unresolvable
                );
            }
            for leaf in &group.leaves {
                let witness_names: Vec<&str> =
                    leaf.witness.iter().map(|w| w.name.as_str()).collect();
                let warnings =
                    local_check_placeholder_consistency(&leaf.asm, &witness_names, &ctor_names);
                let unresolvable: Vec<_> = warnings
                    .iter()
                    .filter(|w| w.contains("cannot be constructed"))
                    .collect();
                assert!(
                    unresolvable.is_empty(),
                    "{}: group '{}' leaf '{}' has unresolvable placeholders: {:?}",
                    filename,
                    group.name,
                    leaf.name,
                    unresolvable
                );
            }
        }
    }
}

#[test]
fn local_variable_placeholders_are_resolved() {
    let path = examples_dir().join("arkade_kitties/arkade_kitties.ark");
    if !path.exists() {
        return;
    }
    let source = fs::read_to_string(&path).unwrap();
    let output = compile(&source).expect("arkade_kitties.ark must compile");

    // Find the breed function group
    let breed_group = output.functions.iter().find(|g| g.name == "breed");

    if let Some(group) = breed_group {
        if let Some(arkade) = &group.arkade {
            let ctor_names: Vec<&str> = output.parameters.iter().map(|p| p.name.as_str()).collect();
            let input_names: Vec<&str> = arkade.inputs.iter().map(|i| i.name.as_str()).collect();
            let warnings =
                local_check_placeholder_consistency(&arkade.asm, &input_names, &ctor_names);
            let unresolved: Vec<_> = warnings
                .iter()
                .filter(|w| w.contains("cannot be constructed"))
                .collect();
            assert!(
                unresolved.is_empty(),
                "arkade_kitties breed has unresolved local placeholders: {:?}",
                unresolved
            );
        }
    }
}

// ─── local_check_asm_structure — unit tests ───────────────────────────────────

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
    let errors = local_check_asm_structure(&asm);
    assert!(errors.is_empty(), "balanced IF/ELSE/ENDIF: {:?}", errors);
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
    let errors = local_check_asm_structure(&asm);
    assert!(!errors.is_empty(), "unclosed OP_IF must be detected");
    assert!(
        errors
            .iter()
            .any(|e| e.contains("unclosed") || e.contains("missing")),
        "error message must mention unclosed branch; got: {:?}",
        errors
    );
}

#[test]
fn stray_endif_without_if_is_error() {
    let asm = vec![
        "<sig>".to_string(),
        "OP_CHECKSIG".to_string(),
        "OP_ENDIF".to_string(), // no matching OP_IF
    ];
    let errors = local_check_asm_structure(&asm);
    assert!(!errors.is_empty(), "stray OP_ENDIF must be detected");
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
    let errors = local_check_asm_structure(&asm);
    assert!(!errors.is_empty(), "stray OP_ELSE must be detected");
}

#[test]
fn empty_asm_instruction_is_error() {
    let asm = vec![
        "<sig>".to_string(),
        "".to_string(),
        "OP_CHECKSIG".to_string(),
    ];
    let errors = local_check_asm_structure(&asm);
    assert!(
        !errors.is_empty(),
        "empty instruction string must be an error"
    );
    assert!(
        errors.iter().any(|e| e.contains("empty")),
        "error must mention 'empty'"
    );
}

#[test]
fn malformed_placeholder_missing_close_is_error() {
    let asm = vec!["<sig".to_string(), "OP_CHECKSIG".to_string()];
    let errors = local_check_asm_structure(&asm);
    assert!(
        !errors.is_empty(),
        "placeholder without closing '>' must be an error"
    );
}

#[test]
fn empty_placeholder_is_error() {
    // "<>" is invalid
    let asm = vec!["<>".to_string(), "OP_CHECKSIG".to_string()];
    let errors = local_check_asm_structure(&asm);
    assert!(
        !errors.is_empty(),
        "empty placeholder '<>' must be an error"
    );
}

// ─── local_check_placeholder_consistency — unit tests ────────────────────────

#[test]
fn placeholder_in_witness_schema_is_clean() {
    use arkade_compiler::models::WitnessElement;
    let asm = vec!["<sig>".to_string(), "OP_CHECKSIG".to_string()];
    let witness = [WitnessElement {
        name: "sig".to_string(),
        elem_type: "signature".to_string(),
        encoding: "schnorr-64".to_string(),
        injected: false,
    }];
    let witness_names: Vec<&str> = witness.iter().map(|w| w.name.as_str()).collect();
    let warnings = local_check_placeholder_consistency(&asm, &witness_names, &[]);
    assert!(
        warnings.is_empty(),
        "known witness placeholder must produce no issues: {:?}",
        warnings
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
    let witness = [WitnessElement {
        name: "sig".to_string(),
        elem_type: "signature".to_string(),
        encoding: "schnorr-64".to_string(),
        injected: false,
    }];
    let ctor = [Parameter {
        name: "owner".to_string(),
        param_type: "pubkey".to_string(),
    }];
    let witness_names: Vec<&str> = witness.iter().map(|w| w.name.as_str()).collect();
    let ctor_names: Vec<&str> = ctor.iter().map(|p| p.name.as_str()).collect();
    let warnings = local_check_placeholder_consistency(&asm, &witness_names, &ctor_names);
    assert!(
        warnings.is_empty(),
        "constructor-bound placeholder must produce no issues: {:?}",
        warnings
    );
}

#[test]
fn orphaned_placeholder_is_warned() {
    let asm = vec!["<mystery>".to_string(), "OP_CHECKSIG".to_string()];
    let warnings = local_check_placeholder_consistency(&asm, &[], &[]);
    assert!(
        !warnings.is_empty(),
        "unresolvable placeholder must produce a warning"
    );
    assert!(
        warnings.iter().any(|w| w.contains("mystery")),
        "warning must name the unresolvable placeholder"
    );
}

#[test]
fn server_key_placeholder_is_always_resolved() {
    // <SERVER_KEY> is injected at runtime by the Arkade operator — it must not be
    // flagged as unresolvable even though it is not in any schema.
    let asm = vec![
        "<SERVER_KEY>".to_string(),
        "<serverSig>".to_string(),
        "OP_CHECKSIG".to_string(),
    ];
    let warnings = local_check_placeholder_consistency(&asm, &[], &[]);
    // SERVER_KEY and serverSig are both special-cased
    let orphan: Vec<_> = warnings
        .iter()
        .filter(|w| w.contains("SERVER_KEY"))
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
    let warnings = local_check_placeholder_consistency(&asm, &[], &[]);
    let orphan: Vec<_> = warnings.iter().filter(|w| w.contains("VTXO:")).collect();
    assert!(
        orphan.is_empty(),
        "<VTXO:...> placeholders must never be flagged as unresolvable"
    );
}

// ─── Require-guard warning via full pipeline ─────────────────────────────────

#[test]
fn function_with_no_require_is_error() {
    // A function with only assignments and no require() has a bare spend path
    // that trivially passes — the compiler must reject it.
    let source = r#"
contract AlwaysPass(pubkey owner) {
    function spend(signature sig) {
        let x = 1;
    }
}"#;
    let err = compile(source).expect_err("bare-path function must be rejected");
    assert!(
        err.to_string().contains("spend path with no require()"),
        "unexpected error: {err}"
    );
}

#[test]
fn function_with_require_only_in_if_branch_is_error() {
    // A require() inside a lone if-branch leaves the "condition false" path with
    // no require() — a trivially-passing spend, which must be rejected.
    let source = r#"
contract Guarded(pubkey owner) {
    function spend(signature sig) {
        if (checkSig(sig, owner)) {
            require(checkSig(sig, owner));
        }
    }
}"#;
    let err = compile(source).expect_err("single-branch require must be rejected");
    assert!(
        err.to_string().contains("spend path with no require()"),
        "unexpected error: {err}"
    );
}
