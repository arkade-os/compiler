//! Self-check of compiled [`ContractJson`]: structural invariants every valid source satisfies,
//! so an error here is a compiler bug, not a user error.

use std::collections::HashSet;

use super::ValidationIssue;
use crate::compiler;
use crate::models::ContractJson;

pub(crate) fn validate_output(output: &ContractJson) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();

    if output.functions.is_empty() {
        issues.push(ValidationIssue::error("contract produced no spend groups"));
    }

    for group in &output.functions {
        if group.leaves.is_empty() {
            issues.push(ValidationIssue::error(format!(
                "spend group '{}' has no leaves (compiler bug)",
                group.name
            )));
        }
        if let Some(arkade) = &group.arkade {
            if arkade.asm.is_empty() {
                issues.push(ValidationIssue::error(format!(
                    "group '{}' Arkade Script has empty asm",
                    group.name
                )));
            }
            // A constructor placeholder is pushed at most once: in the prologue, or inline
            // at its single read.
            let placeholders =
                match compiler::expanded_placeholder_params(&output.parameters, &output.structs) {
                    Ok(parameters) => parameters
                        .into_iter()
                        .map(|parameter| format!("<{}>", parameter.name))
                        .collect::<HashSet<_>>(),
                    Err(error) => {
                        issues.push(ValidationIssue::error(format!(
                            "group '{}' has an invalid type layout: {error}",
                            group.name
                        )));
                        continue;
                    }
                };
            let mut pushed = HashSet::new();
            if arkade
                .asm
                .iter()
                .filter(|token| {
                    token.starts_with('<')
                        && token.ends_with('>')
                        && !token.starts_with("<CONTRACT:")
                })
                .any(|token| !placeholders.contains(token) || !pushed.insert(token))
            {
                issues.push(ValidationIssue::error(format!(
                    "group '{}' Arkade Script has an invalid constructor placeholder",
                    group.name
                )));
            }
        }
        for leaf in &group.leaves {
            if leaf.asm.is_empty() {
                issues.push(ValidationIssue::error(format!(
                    "leaf '{}' in group '{}' has empty asm",
                    leaf.name, group.name
                )));
            }
            // Signatures are witness data. Matched case-insensitively, as a leaked placeholder
            // may be `<ownersig>` or `<operatorSig>`.
            if leaf
                .asm
                .iter()
                .filter_map(|token| token.strip_prefix('<')?.strip_suffix('>'))
                .any(|name| {
                    name.chars()
                        .all(|character| character.is_ascii_alphanumeric() || character == '_')
                        && name.to_ascii_lowercase().ends_with("sig")
                })
            {
                issues.push(ValidationIssue::error(format!(
                    "leaf '{}' in group '{}' has a signature in asm (must be witness-only)",
                    leaf.name, group.name
                )));
            }
        }
    }

    issues
}
