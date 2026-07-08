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

/// The arkade covenant ASM of a group, joined into one searchable string.
/// Panics if the group has no arkade covenant.
pub fn arkade_asm(out: &ContractJson, group_name: &str) -> String {
    group(out, group_name)
        .arkade
        .as_ref()
        .unwrap_or_else(|| panic!("group {group_name} has no arkade covenant"))
        .asm
        .join(" ")
}

/// The arkade covenant ASM as a token vector — for structural checks
/// (e.g. "the operand immediately before OP_CHECKLOCKTIMEVERIFY must be
/// <redeemStart>") that can't be done via substring search.
/// Panics if the group has no arkade covenant.
pub fn arkade_asm_tokens(out: &ContractJson, group_name: &str) -> Vec<String> {
    group(out, group_name)
        .arkade
        .as_ref()
        .unwrap_or_else(|| panic!("group {group_name} has no arkade covenant"))
        .asm
        .clone()
}

/// The arkade covenant input parameter names (function parameters that go into
/// the covenant, NOT the leaf's cosig witnesses). Returns empty if no arkade.
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

/// Count exact-token occurrences of an opcode in a group's arkade covenant ASM.
/// Exact match, so "OP_GREATERTHAN" does NOT match "OP_GREATERTHANOREQUAL"
/// or "OP_GREATERTHANOREQUAL64". Returns 0 if the group has no arkade.
pub fn opcode_count_in_arkade(out: &ContractJson, group_name: &str, op: &str) -> usize {
    group(out, group_name)
        .arkade
        .as_ref()
        .map(|a| a.asm.iter().filter(|tok| tok.as_str() == op).count())
        .unwrap_or(0)
}

/// Signature-input names from the arkade covenant inputs, identified by name
/// ending with "sig" (case-insensitive). These are the user-supplied signatures
/// — excludes serverSig/emulatorSig which live in the leaf witness, not in
/// arkade.inputs.
pub fn user_signatures(out: &ContractJson, group_name: &str) -> Vec<String> {
    arkade_inputs(out, group_name)
        .into_iter()
        .filter(|w| w.to_lowercase().ends_with("sig"))
        .collect()
}
