//! Shared assertion helpers for the integration test binaries.
//!
//! The two grouped test binaries (`tests/examples.rs`, `tests/features.rs`)
//! include this module via `#[path = "common/mod.rs"] mod common;`, so it is a
//! plain module — never its own test target — and each grouped test file reaches
//! the helpers through `crate::common::*`.
//!
//! `dead_code` is allowed module-wide: each binary compiles its own copy of this
//! module and uses only the subset of helpers it needs, so a helper unused by
//! one binary (but used by the other) would otherwise warn.
#![allow(dead_code)]

use arkade_compiler::models::{AbiFunctionGroup, AbiLeaf, ContractJson};

/// Settings with `optimize` set, built as a crate outside the compiler must build them.
pub fn options(optimize: bool) -> arkade_compiler::CompileOptions {
    let mut options = arkade_compiler::CompileOptions::default();
    options.optimize = optimize;
    options
}

pub fn compile_unoptimized(source: &str) -> Result<ContractJson, arkade_compiler::Error> {
    arkade_compiler::compile_sources_with_options(
        "main.ark",
        &[("main.ark".to_string(), source.to_string())].into(),
        options(false),
    )
}

/// Compile `entry` from in-memory `(path, source)` pairs.
pub fn project(
    entry: &str,
    sources: &[(&str, &str)],
) -> Result<ContractJson, arkade_compiler::Error> {
    arkade_compiler::compile_sources(
        entry,
        &sources
            .iter()
            .map(|(path, source)| (path.to_string(), source.to_string()))
            .collect(),
    )
}

/// Locate a spend group by name or panic with a descriptive message.
pub fn group<'a>(out: &'a ContractJson, name: &str) -> &'a AbiFunctionGroup {
    out.functions
        .iter()
        .find(|g| g.name == name)
        .unwrap_or_else(|| {
            let known: Vec<_> = out.functions.iter().map(|g| g.name.clone()).collect();
            panic!("group {name} not found; known: {known:?}")
        })
}

fn leaf<'a>(out: &'a ContractJson, group_name: &str, leaf_name: &str) -> &'a AbiLeaf {
    group(out, group_name)
        .leaves
        .iter()
        .find(|l| l.name == leaf_name)
        .unwrap_or_else(|| panic!("leaf {leaf_name} not found in group {group_name}"))
}

/// The Arkade Script ASM of a group, joined into one searchable string.
/// Panics if the group has no Arkade Script.
pub fn arkade_asm(out: &ContractJson, group_name: &str) -> String {
    group(out, group_name)
        .arkade
        .as_ref()
        .unwrap_or_else(|| panic!("group {group_name} has no Arkade Script"))
        .asm
        .join(" ")
}

/// The Arkade Script ASM as a token vector — for structural checks
/// (e.g. "the operand immediately before OP_CHECKLOCKTIMEVERIFY must be
/// <redeemStart>") that can't be done via substring search.
/// Panics if the group has no Arkade Script.
pub fn arkade_asm_tokens(out: &ContractJson, group_name: &str) -> Vec<String> {
    group(out, group_name)
        .arkade
        .as_ref()
        .unwrap_or_else(|| panic!("group {group_name} has no Arkade Script"))
        .asm
        .clone()
}

/// The Arkade Script input parameter names (function parameters that go into
/// the Arkade Script, NOT the leaf's cosig witnesses). Returns empty if no arkade.
pub fn arkade_inputs(out: &ContractJson, group_name: &str) -> Vec<String> {
    group(out, group_name)
        .arkade
        .as_ref()
        .map(|a| a.inputs.iter().map(|i| i.name.clone()).collect())
        .unwrap_or_default()
}

/// The ASM of a named leaf within a named group, joined into one string.
pub fn leaf_asm(out: &ContractJson, group_name: &str, leaf_name: &str) -> String {
    leaf(out, group_name, leaf_name).asm.join(" ")
}

/// The ASM of a named leaf as a token vector.
pub fn leaf_asm_tokens(out: &ContractJson, group_name: &str, leaf_name: &str) -> Vec<String> {
    leaf(out, group_name, leaf_name).asm.clone()
}

/// Witness element names of a leaf (the on-chain witness stack items).
pub fn witness_names(out: &ContractJson, group_name: &str, leaf_name: &str) -> Vec<String> {
    leaf(out, group_name, leaf_name)
        .witness
        .iter()
        .map(|w| w.name.clone())
        .collect()
}

/// Count exact-token occurrences of an opcode in a group's Arkade Script ASM.
/// Exact match, so "OP_GREATERTHAN" does NOT match "OP_GREATERTHANOREQUAL".
/// Returns 0 if the group has no arkade.
pub fn opcode_count_in_arkade(out: &ContractJson, group_name: &str, op: &str) -> usize {
    group(out, group_name)
        .arkade
        .as_ref()
        .map(|a| a.asm.iter().filter(|tok| tok.as_str() == op).count())
        .unwrap_or(0)
}

/// Signature-input names from the Arkade Script inputs, identified by name
/// ending with "sig" (case-insensitive). These are the user-supplied signatures
/// — excludes operatorSig, which lives in the leaf witness, not in
/// arkade.inputs.
pub fn user_signatures(out: &ContractJson, group_name: &str) -> Vec<String> {
    arkade_inputs(out, group_name)
        .into_iter()
        .filter(|w| w.to_lowercase().ends_with("sig"))
        .collect()
}

/// Whether `lint` judges a function's authorization or outputs; the toy contracts of tests for
/// other features have neither, so those tests leave such lints out.
pub fn is_security_lint(lint: arkade_compiler::lint::Lint) -> bool {
    lint.category() == arkade_compiler::lint::Category::Security
}

/// `out`'s warnings except security lints.
pub fn feature_warnings(out: &ContractJson) -> Vec<&String> {
    out.warnings
        .iter()
        .filter(|warning| {
            let id = warning
                .strip_prefix("warning[")
                .and_then(|rest| rest.split_once(']'));
            !id.and_then(|(id, _)| id.parse().ok())
                .is_some_and(is_security_lint)
        })
        .collect()
}
