//! Self-check of compiled [`ContractJson`]: structural invariants every valid source satisfies,
//! so an error here is a compiler bug, not a user error.

use std::collections::HashSet;

use super::ValidationError;
use crate::compiler;
use crate::models::ContractJson;

pub(crate) fn validate_output(output: &ContractJson) -> Vec<ValidationError> {
    let mut issues = Vec::new();

    if output.functions.is_empty() {
        issues.push(ValidationError::NoSpendGroups);
    }

    for group in &output.functions {
        let name = || group.name.clone();
        if group.leaves.is_empty() {
            issues.push(ValidationError::GroupWithoutLeaves { group: name() });
        }
        if let Some(arkade) = &group.arkade {
            if arkade.asm.is_empty() {
                issues.push(ValidationError::EmptyArkadeAsm { group: name() });
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
                        issues.push(ValidationError::InvalidTypeLayout {
                            group: name(),
                            error,
                        });
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
                issues.push(ValidationError::InvalidPlaceholder { group: name() });
            }
        }
        for leaf in &group.leaves {
            let leaf_name = leaf.name.clone();
            if leaf.asm.is_empty() {
                let leaf = leaf_name.clone();
                issues.push(ValidationError::EmptyLeafAsm {
                    leaf,
                    group: name(),
                });
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
                let leaf = leaf_name;
                issues.push(ValidationError::SignatureInLeafAsm {
                    leaf,
                    group: name(),
                });
            }
        }
    }

    issues
}
