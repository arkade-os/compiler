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
            let prologue = arkade
                .asm
                .iter()
                .take_while(|token| {
                    token.starts_with('<')
                        && token.ends_with('>')
                        && !token.starts_with("<CONTRACT:")
                })
                .collect::<Vec<_>>();
            let retained_names = prologue
                .iter()
                .map(|token| token[1..token.len() - 1].split('.').next().unwrap())
                .collect::<HashSet<_>>();
            let retained_parameters = output
                .parameters
                .iter()
                .filter(|parameter| retained_names.contains(parameter.name.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            // Retained parameters push every scalar leaf in reverse declaration order.
            let expected_prologue = match crate::compiler::expanded_placeholder_params(
                &retained_parameters,
                &output.structs,
            ) {
                Ok(parameters) => parameters
                    .iter()
                    .rev()
                    .map(|parameter| format!("<{}>", parameter.name))
                    .collect::<Vec<_>>(),
                Err(error) => {
                    issues.push(ValidationIssue::error(format!(
                        "group '{}' has an invalid type layout: {error}",
                        group.name
                    )));
                    continue;
                }
            };
            if !prologue.iter().copied().eq(expected_prologue.iter()) {
                issues.push(ValidationIssue::error(format!(
                    "group '{}' arkade covenant has an invalid constructor prologue",
                    group.name
                )));
            }
            if arkade.asm[prologue.len()..].iter().any(|token| {
                token.starts_with('<') && token.ends_with('>') && !token.starts_with("<CONTRACT:")
            }) {
                issues.push(ValidationIssue::error(format!(
                    "group '{}' arkade covenant has a placeholder outside its constructor prologue",
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
