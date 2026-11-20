//! ASM placeholder resolution tests.
//!
//! Every `<placeholder>` in compiled ASM must resolve to an Arkade Script input,
//! a leaf witness element, a constructor parameter, or a runtime-injected name.

use arkade_compiler::{compile, compile_file};
use std::path::PathBuf;

fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples")
}

// ─── Placeholder helper ──────────────────────────────────────────────────────

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
        if inner == "OPERATOR_KEY"
            || inner == "OPERATOR_EXIT_DELAY"
            || inner == "operatorSig"
            || inner.starts_with("OPERATOR_KEY:")
            || inner.starts_with("CONTRACT:")
            || inner.starts_with("checkMultisig(")
        {
            continue;
        }
        // Struct and array parameters read their fields, as in `<id.txid>`.
        let root = inner.split('.').next().unwrap_or(inner);
        if !witness_names.contains(&inner) && !ctor_names.contains(&root) {
            warnings.push(format!(
                "placeholder <{inner}> cannot be constructed from witness or constructor inputs"
            ));
        }
    }
    warnings
}

/// Verify placeholder resolution for simple contracts that have no let-binding
/// placeholders or compound expression placeholders.  Complex contracts like
/// arkade_kitties use `let sireGroup = tx.assetGroups.lookup(...)` which emits
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
        let output = compile_file(&path).unwrap_or_else(|e| panic!("compile {filename}: {e}"));

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
                    "{}: group '{}' Arkade Script has unresolvable placeholders: {:?}",
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
    let output = compile_file(&path).expect("arkade_kitties.ark must compile");

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
                "arkade_kitties breed has unresolved local placeholders: {unresolved:?}"
            );
        }
    }
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
        "known witness placeholder must produce no issues: {warnings:?}"
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
        span: Default::default(),
        name: "owner".to_string(),
        param_type: "pubkey".into(),
    }];
    let witness_names: Vec<&str> = witness.iter().map(|w| w.name.as_str()).collect();
    let ctor_names: Vec<&str> = ctor.iter().map(|p| p.name.as_str()).collect();
    let warnings = local_check_placeholder_consistency(&asm, &witness_names, &ctor_names);
    assert!(
        warnings.is_empty(),
        "constructor-bound placeholder must produce no issues: {warnings:?}"
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
fn operator_key_placeholder_is_always_resolved() {
    // <OPERATOR_KEY> is injected at runtime by the Arkade operator — it must not be
    // flagged as unresolvable even though it is not in any schema.
    let asm = vec![
        "<OPERATOR_KEY>".to_string(),
        "<operatorSig>".to_string(),
        "OP_CHECKSIG".to_string(),
    ];
    let warnings = local_check_placeholder_consistency(&asm, &[], &[]);
    // OPERATOR_KEY and operatorSig are both special-cased
    let orphan: Vec<_> = warnings
        .iter()
        .filter(|w| w.contains("OPERATOR_KEY"))
        .collect();
    assert!(
        orphan.is_empty(),
        "<OPERATOR_KEY> must never be flagged as unresolvable"
    );
}

#[test]
fn vtxo_placeholder_is_always_resolved() {
    let asm = vec![
        "<CONTRACT:SomeContract(x,y)>".to_string(),
        "OP_EQUAL".to_string(),
    ];
    let warnings = local_check_placeholder_consistency(&asm, &[], &[]);
    let orphan: Vec<_> = warnings
        .iter()
        .filter(|w| w.contains("CONTRACT:"))
        .collect();
    assert!(
        orphan.is_empty(),
        "<CONTRACT:...> placeholders must never be flagged as unresolvable"
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
