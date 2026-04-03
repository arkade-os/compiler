//! Generalized compilation roundtrip tests.
//!
//! Each test in this file compiles one of the canonical `.ark` example files and
//! asserts output invariants that must hold for every well-formed contract:
//!
//! - `contractName` is non-empty.
//! - `functions` array is non-empty.
//! - Every function variant (server and exit) has non-empty `asm`.
//! - Every function variant has non-empty `witnessSchema`.
//! - For every unique function name, both `serverVariant=true` and
//!   `serverVariant=false` entries are present.
//!
//! These tests catch regressions where the compiler silently emits structurally
//! broken output without failing.

use arkade_compiler::compile;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples")
}

fn compile_example(filename: &str) -> arkade_compiler::models::ContractJson {
    let path = examples_dir().join(filename);
    let source = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
    compile(&source).unwrap_or_else(|e| panic!("failed to compile {}: {}", filename, e))
}

/// Assert every structural invariant on a compiled `ContractJson`.
fn assert_output_invariants(output: &arkade_compiler::models::ContractJson, filename: &str) {
    assert!(
        !output.name.is_empty(),
        "{}: contractName must not be empty",
        filename
    );

    assert!(
        !output.functions.is_empty(),
        "{}: functions array must not be empty",
        filename
    );

    for func in &output.functions {
        assert!(
            !func.asm.is_empty(),
            "{}: function '{}' (serverVariant={}) must have non-empty ASM",
            filename,
            func.name,
            func.server_variant
        );
        assert!(
            !func.witness_schema.is_empty(),
            "{}: function '{}' (serverVariant={}) must have non-empty witnessSchema",
            filename,
            func.name,
            func.server_variant
        );
    }

    // Both variants (server + exit) should be present for every function name
    let mut by_name: HashMap<&str, (bool, bool)> = HashMap::new();
    for func in &output.functions {
        let entry = by_name.entry(func.name.as_str()).or_insert((false, false));
        if func.server_variant {
            entry.0 = true;
        } else {
            entry.1 = true;
        }
    }
    for (name, (has_server, has_exit)) in &by_name {
        assert!(
            has_server,
            "{}: function '{}' is missing serverVariant=true",
            filename, name
        );
        assert!(
            has_exit,
            "{}: function '{}' is missing serverVariant=false (exit variant)",
            filename, name
        );
    }

    // Output must contain no output-invariant-error warnings (would indicate compiler bug)
    let invariant_errors: Vec<&str> = output
        .warnings
        .iter()
        .filter(|w| w.contains("output-invariant-error"))
        .map(|w| w.as_str())
        .collect();
    assert!(
        invariant_errors.is_empty(),
        "{}: compiler self-check found output invariant errors: {:?}",
        filename,
        invariant_errors
    );
}

// ─── One test per example contract ───────────────────────────────────────────

#[test]
fn roundtrip_single_sig() {
    let output = compile_example("single_sig.ark");
    assert_output_invariants(&output, "single_sig.ark");
}

#[test]
fn roundtrip_htlc() {
    let output = compile_example("htlc.ark");
    assert_output_invariants(&output, "htlc.ark");
    assert_eq!(output.name, "HTLC");
    // 3 functions × 2 variants = 6
    assert_eq!(output.functions.len(), 6);
}

#[test]
fn roundtrip_beacon() {
    let output = compile_example("beacon.ark");
    assert_output_invariants(&output, "beacon.ark");
}

#[test]
fn roundtrip_token_vault() {
    let output = compile_example("token_vault.ark");
    assert_output_invariants(&output, "token_vault.ark");
}

#[test]
fn roundtrip_controlled_mint() {
    let output = compile_example("controlled_mint.ark");
    assert_output_invariants(&output, "controlled_mint.ark");
}

#[test]
fn roundtrip_nft_mint() {
    let output = compile_example("nft_mint.ark");
    assert_output_invariants(&output, "nft_mint.ark");
}

#[test]
fn roundtrip_fuji_safe() {
    let output = compile_example("fuji_safe.ark");
    assert_output_invariants(&output, "fuji_safe.ark");
}

#[test]
fn roundtrip_price_beacon() {
    let output = compile_example("price_beacon.ark");
    assert_output_invariants(&output, "price_beacon.ark");
}

#[test]
fn roundtrip_threshold_oracle() {
    let output = compile_example("threshold_oracle.ark");
    assert_output_invariants(&output, "threshold_oracle.ark");
}

#[test]
fn roundtrip_threshold_multisig_htlc() {
    let output = compile_example("threshold_multisig_htlc.ark");
    assert_output_invariants(&output, "threshold_multisig_htlc.ark");
}

#[test]
fn roundtrip_non_interactive_swap() {
    let output = compile_example("non_interactive_swap.ark");
    assert_output_invariants(&output, "non_interactive_swap.ark");
}

#[test]
fn roundtrip_stable_position() {
    let output = compile_example("stable_position.ark");
    assert_output_invariants(&output, "stable_position.ark");
}

#[test]
fn roundtrip_fee_adapter() {
    let output = compile_example("fee_adapter.ark");
    assert_output_invariants(&output, "fee_adapter.ark");
}

#[test]
fn roundtrip_stability_offer() {
    let output = compile_example("stability_offer.ark");
    assert_output_invariants(&output, "stability_offer.ark");
}

#[test]
fn roundtrip_arkade_kitties() {
    let output = compile_example("arkade_kitties.ark");
    assert_output_invariants(&output, "arkade_kitties.ark");
}

#[test]
fn roundtrip_payment_auth() {
    let output = compile_example("payment_auth.ark");
    assert_output_invariants(&output, "payment_auth.ark");
}

// ─── Cross-cutting invariant: scan ALL examples ───────────────────────────────

/// Compile every .ark file in the examples/ directory and assert invariants.
/// This catches any new example added without a dedicated test.
#[test]
fn all_examples_compile_and_satisfy_invariants() {
    let dir = examples_dir();
    let mut count = 0;
    let mut entries: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("failed to read examples dir: {}", e))
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "ark").unwrap_or(false))
        .collect();
    // Sort for deterministic test output
    entries.sort_by_key(|e| e.path());

    for entry in entries {
        let path = entry.path();
        let filename = path.file_name().unwrap().to_string_lossy().into_owned();
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
        let output =
            compile(&source).unwrap_or_else(|e| panic!("failed to compile {}: {}", filename, e));
        assert_output_invariants(&output, &filename);
        count += 1;
    }

    assert!(
        count >= 16,
        "expected at least 16 example contracts, found {}",
        count
    );
}
