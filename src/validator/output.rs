use super::*;

/// Validate the compiled [`ContractJson`] output for structural invariants.
///
/// This pass acts as a compiler self-check: a valid source contract should always
/// produce output that satisfies these invariants. Any error here indicates a
/// compiler bug rather than a user error.
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
                    "group '{}' arkade covenant has empty asm",
                    group.name
                )));
            }
            // Constructor leaves are pushed once: in the prologue, or inline at a single read.
            let leaves = match crate::compiler::expanded_placeholder_params(
                &output.parameters,
                &output.structs,
            ) {
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
                .any(|token| !leaves.contains(token) || !pushed.insert(token))
            {
                issues.push(ValidationIssue::error(format!(
                    "group '{}' arkade covenant has an invalid constructor placeholder",
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
            // Leaf ASM must not carry signature placeholders (sigs are witness).
            // Case-insensitive: a leaked placeholder may be named `<sig>`,
            // `<ownersig>`, or `<serverSig>` depending on the source naming —
            // all must trip this compiler-bug self-check.
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
