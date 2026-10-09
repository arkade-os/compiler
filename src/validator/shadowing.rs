use super::*;

/// Check 1: reject any binding that shadows a name still live in an enclosing scope.
pub(super) fn check_shadowing(contract: &Contract, issues: &mut Vec<ValidationIssue>) {
    let ctor_names: HashSet<&str> = contract
        .parameters
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    let const_names: HashSet<&str> = contract.constants.iter().map(|c| c.name.as_str()).collect();

    for tapscript in &contract.tapscripts {
        for input in &tapscript.inputs {
            if ctor_names.contains(input.name.as_str()) {
                issues.push(ValidationIssue::error(format!(
                    "input '{}' in tapscript '{}' shadows constructor parameter '{}'",
                    input.name, tapscript.name, input.name
                )));
            }
            if const_names.contains(input.name.as_str()) {
                issues.push(ValidationIssue::error(format!(
                    "input '{}' in tapscript '{}' shadows constant '{}'",
                    input.name, tapscript.name, input.name
                )));
            }
        }
    }

    for func in contract.functions.iter().filter(|f| !f.is_imported()) {
        let first = issues.len();
        // Seed frame: constructor params + this function's params.
        let mut seed: HashSet<String> = ctor_names
            .iter()
            .chain(&const_names)
            .map(|s| s.to_string())
            .collect();
        for param in &func.parameters {
            if ctor_names.contains(param.name.as_str()) {
                issues.push(ValidationIssue::error(format!(
                    "parameter '{}' in function '{}' shadows constructor parameter '{}'",
                    param.name, func.name, param.name
                )));
            }
            if const_names.contains(param.name.as_str()) {
                issues.push(ValidationIssue::error(format!(
                    "parameter '{}' in function '{}' shadows constant '{}'",
                    param.name, func.name, param.name
                )));
            }
            seed.insert(param.name.clone());
        }

        let mut stack: Vec<HashSet<String>> = vec![seed];
        walk_scope(&func.statements, &func.name, &mut stack, issues);

        check_ctor_assignment(
            &func.statements,
            &func.name,
            &ctor_names,
            &const_names,
            issues,
        );
        locate(&mut issues[first..], func.span);
    }
}

/// Reject assignments to constructor parameters or their flattened children.
/// Recurses into branch and loop bodies.
fn check_ctor_assignment(
    stmts: &[LocatedStatement],
    fname: &str,
    ctor_names: &HashSet<&str>,
    const_names: &HashSet<&str>,
    issues: &mut Vec<ValidationIssue>,
) {
    for stmt in stmts {
        let first = issues.len();
        match &stmt.statement {
            Statement::VarAssign { target, .. } => {
                let access_name;
                let name = match target {
                    AssignmentTarget::Access(value) => {
                        access_name = value.binding_path().unwrap_or_default();
                        &access_name
                    }
                    AssignmentTarget::Binding(name) => name,
                    AssignmentTarget::ArrayIndex { array, .. } => array,
                };
                let root = name.split(['.', '[']).next().unwrap_or(name);
                if ctor_names.contains(root) {
                    issues.push(ValidationIssue::error(format!(
                        "cannot assign to constructor parameter '{name}' in function '{fname}'; \
                         constructor parameters are immutable"
                    )));
                }
                if const_names.contains(root) {
                    issues.push(ValidationIssue::error(format!(
                        "cannot assign to constant '{name}' in function '{fname}'"
                    )));
                }
            }
            Statement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                check_ctor_assignment(then_body, fname, ctor_names, const_names, issues);
                if let Some(eb) = else_body {
                    check_ctor_assignment(eb, fname, ctor_names, const_names, issues);
                }
            }
            Statement::ForIn { body, .. } | Statement::ForCount { body, .. } => {
                check_ctor_assignment(body, fname, ctor_names, const_names, issues);
            }
            Statement::LetBinding { .. }
            | Statement::Require(_)
            | Statement::Call(_)
            | Statement::Return(_) => {}
        }
        locate(&mut issues[first..], stmt.span);
    }
}

/// Returns true if `name` is bound in any frame currently on the stack.
fn in_scope(stack: &[HashSet<String>], name: &str) -> bool {
    stack.iter().any(|frame| frame.contains(name))
}

/// Walk statements maintaining a lexical scope stack. Each block (`for` body,
/// `if`/`else` branch) is a pushed frame, so sibling blocks do not conflict.
fn walk_scope(
    stmts: &[LocatedStatement],
    fname: &str,
    stack: &mut Vec<HashSet<String>>,
    issues: &mut Vec<ValidationIssue>,
) {
    for stmt in stmts {
        let first = issues.len();
        match &stmt.statement {
            Statement::LetBinding { name, .. } => {
                validate_source_identifier(name, &format!("binding in function '{fname}'"), issues);
                if in_scope(stack, name) {
                    issues.push(ValidationIssue::error(format!(
                        "binding '{name}' in function '{fname}' shadows an in-scope binding"
                    )));
                } else {
                    stack
                        .last_mut()
                        .expect("non-empty scope stack")
                        .insert(name.clone());
                }
            }
            Statement::ForIn {
                index_var,
                value_var,
                body,
                ..
            } => {
                validate_source_identifier(
                    index_var,
                    &format!("loop variable in function '{fname}'"),
                    issues,
                );
                validate_source_identifier(
                    value_var,
                    &format!("loop variable in function '{fname}'"),
                    issues,
                );
                if index_var == value_var {
                    issues.push(ValidationIssue::error(format!(
                        "loop variables in function '{fname}' must differ; both are named '{index_var}'"
                    )));
                }
                for v in [index_var, value_var] {
                    if in_scope(stack, v) {
                        issues.push(ValidationIssue::error(format!(
                            "loop variable '{v}' in function '{fname}' shadows an in-scope binding"
                        )));
                    }
                }
                let mut frame = HashSet::new();
                frame.insert(index_var.clone());
                frame.insert(value_var.clone());
                stack.push(frame);
                walk_scope(body, fname, stack, issues);
                stack.pop();
            }
            Statement::ForCount { body, .. } => {
                stack.push(HashSet::new());
                walk_scope(body, fname, stack, issues);
                stack.pop();
            }
            Statement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                stack.push(HashSet::new());
                walk_scope(then_body, fname, stack, issues);
                stack.pop();
                if let Some(eb) = else_body {
                    stack.push(HashSet::new());
                    walk_scope(eb, fname, stack, issues);
                    stack.pop();
                }
            }
            // Reassignment is handled separately; requires introduce no bindings.
            Statement::VarAssign { .. }
            | Statement::Require(_)
            | Statement::Call(_)
            | Statement::Return(_) => {}
        }
        locate(&mut issues[first..], stmt.span);
    }
}
