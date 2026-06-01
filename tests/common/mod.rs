//! Shared helpers for the bond-market integration tests
//! (`bond_mint_test.rs`, `repayment_pool_test.rs`).
//!
//! Cargo compiles `tests/common/mod.rs` as an ordinary module included by each
//! test binary via `mod common;`, NOT as its own test target — so these helpers
//! live in one place and every test file pulls them in with `use common::*;`.
//!
//! `dead_code` is allowed module-wide: each test binary compiles its own copy
//! of this module and uses only the subset of helpers it needs, so a helper
//! unused by one binary (but used by another) would otherwise warn.
#![allow(dead_code)]

use arkade_compiler::models::{AbiFunction, ContractJson};

/// Locate a (name, server_variant) function or panic with a descriptive
/// message. Centralised so every helper produces the same diagnostic when a
/// test references a missing/renamed function.
fn find_fn<'a>(output: &'a ContractJson, name: &str, server: bool) -> &'a AbiFunction {
    output
        .functions
        .iter()
        .find(|f| f.name == name && f.server_variant == server)
        .unwrap_or_else(|| {
            let known: Vec<String> = output
                .functions
                .iter()
                .map(|f| format!("{}(server={})", f.name, f.server_variant))
                .collect();
            panic!("function {name} (server_variant={server}) not found; known variants: {known:?}")
        })
}

/// The server-variant ASM of a function, joined into one searchable string.
pub fn asm_of(output: &ContractJson, name: &str) -> String {
    asm_variant(output, name, true)
}

/// The ASM of a specific (function, variant) pair, joined into one string.
/// `server = true` selects the cooperative variant; `false` the exit variant.
pub fn asm_variant(output: &ContractJson, name: &str, server: bool) -> String {
    find_fn(output, name, server).asm.join(" ")
}

/// The ASM of a function's server variant as a token vector — for structural
/// checks (e.g. "the operand immediately before OP_CHECKLOCKTIMEVERIFY must be
/// <redeemStart>") that can't be done via substring search.
pub fn asm_tokens(output: &ContractJson, name: &str) -> Vec<String> {
    find_fn(output, name, true).asm.clone()
}

/// The witness-schema parameter names of a function's server variant.
pub fn witness_names(output: &ContractJson, name: &str) -> Vec<String> {
    find_fn(output, name, true)
        .witness_schema
        .iter()
        .map(|w| w.name.clone())
        .collect()
}

/// Count exact-token occurrences of an opcode in a function's server-variant
/// ASM. Exact match, so "OP_GREATERTHAN" does NOT match "OP_GREATERTHANOREQUAL"
/// or "OP_GREATERTHANOREQUAL64".
pub fn opcode_count(output: &ContractJson, name: &str, op: &str) -> usize {
    find_fn(output, name, true)
        .asm
        .iter()
        .filter(|tok| tok.as_str() == op)
        .count()
}

/// Signature-witness names of a function's server variant, excluding
/// `serverSig` (the Arkade cooperative-path signature auto-injected on every
/// server variant — not a user/trust signature).
pub fn user_signatures(output: &ContractJson, name: &str) -> Vec<String> {
    witness_names(output, name)
        .into_iter()
        .filter(|w| w.to_lowercase().ends_with("sig") && w != "serverSig")
        .collect()
}
