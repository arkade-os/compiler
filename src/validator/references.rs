use std::collections::HashSet;

use crate::models::child_exprs;
use crate::models::{
    AssignmentTarget, ExprKind, Expression, Function, LocatedStatement, Requirement, Statement,
};

// Parameters are retained whole; pruning individual composite fields needs a sparse stack layout.
pub(crate) fn referenced_parameters<'a>(
    statements: &'a [LocatedStatement],
    functions: &'a [Function],
) -> HashSet<&'a str> {
    let mut names = HashSet::new();
    collect_statements(statements, &mut names, functions, &mut HashSet::new());
    names
}

/// The names `statements` read, leaving out the reads of a local or assignment nothing later
/// reads, since the script drops the value they compute.
pub(crate) fn live_reads(statements: &[LocatedStatement]) -> HashSet<&str> {
    let mut live = HashSet::new();
    collect_live(statements, &mut live);
    live
}

/// Add the names `statements` read to `live`, which holds the names read after them.
fn collect_live<'a>(statements: &'a [LocatedStatement], live: &mut HashSet<&'a str>) {
    for statement in statements.iter().rev() {
        match &statement.statement {
            Statement::Declaration { name, .. } | Statement::LetBinding { name, .. } => {
                if !live.remove(name.as_str()) {
                    continue;
                }
            }
            Statement::VarAssign { target, .. } => {
                let path = match target {
                    AssignmentTarget::Binding(path)
                    | AssignmentTarget::ArrayIndex { array: path, .. } => Some(path.clone()),
                    AssignmentTarget::Access(value) => value.binding_path(),
                };
                if path.is_some_and(|path| !live.contains(path.root.as_str())) {
                    continue;
                }
            }
            Statement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                let mut other = live.clone();
                collect_live(then_body, live);
                collect_live(else_body.as_deref().unwrap_or_default(), &mut other);
                live.extend(other);
            }
            // An iteration reads what the one before it assigned.
            // ponytail: re-walks the body until no new name turns up, which multiplies with loop
            // nesting depth; summarize each body once if loops ever nest deeply.
            Statement::ForIn { body, .. } | Statement::ForCount { body, .. } => {
                loop {
                    let mut next = live.clone();
                    collect_live(body, &mut next);
                    if next.is_subset(live) {
                        break;
                    }
                    live.extend(next);
                }
                if let Statement::ForIn {
                    index_var,
                    value_var,
                    ..
                } = &statement.statement
                {
                    live.remove(index_var.as_str());
                    live.remove(value_var.as_str());
                }
            }
            _ => {}
        }
        for expression in statement.statement.expressions() {
            collect_expression(expression, live, &[], &mut HashSet::new());
        }
    }
}

fn collect_expression<'a>(
    expression: &'a Expression,
    names: &mut HashSet<&'a str>,
    functions: &'a [Function],
    visited: &mut HashSet<&'a str>,
) {
    match &expression.kind {
        ExprKind::Call { name, .. } if visited.insert(name) => {
            // Static helpers cannot capture constructor state and are validated independently.
            if let Some(function) = functions
                .iter()
                .find(|f| f.is_private && !f.is_static && f.name == *name)
            {
                collect_statements(&function.statements, names, functions, visited);
            }
        }
        ExprKind::Name(path) | ExprKind::ArrayIndex { array: path, .. } => {
            names.insert(&path.root);
        }
        _ => {}
    }
    for child in child_exprs(expression) {
        collect_expression(child, names, functions, visited);
    }
}

fn collect_requirement<'a>(
    requirement: &'a Requirement,
    names: &mut HashSet<&'a str>,
    functions: &'a [Function],
    visited: &mut HashSet<&'a str>,
) {
    match requirement {
        Requirement::Expression(expression) => {
            collect_expression(expression, names, functions, visited)
        }
        Requirement::Comparison { left, right, .. } => {
            collect_expression(left, names, functions, visited);
            collect_expression(right, names, functions, visited);
        }
    }
}

fn collect_statements<'a>(
    statements: &'a [LocatedStatement],
    names: &mut HashSet<&'a str>,
    functions: &'a [Function],
    visited: &mut HashSet<&'a str>,
) {
    for statement in statements {
        match &statement.statement {
            Statement::Call(expression) | Statement::Return(Some(expression)) => {
                collect_expression(expression, names, functions, visited);
            }
            Statement::Return(None) | Statement::Declaration { .. } => {}
            Statement::Require(requirement) => {
                collect_requirement(requirement, names, functions, visited)
            }
            Statement::LetBinding { value, .. } => {
                collect_expression(value, names, functions, visited)
            }
            Statement::VarAssign { target, value } => {
                if let AssignmentTarget::ArrayIndex { index, .. }
                | AssignmentTarget::Access(index) = target
                {
                    collect_expression(index, names, functions, visited);
                }
                collect_expression(value, names, functions, visited);
            }
            Statement::IfElse {
                condition,
                then_body,
                else_body,
            } => {
                collect_expression(condition, names, functions, visited);
                collect_statements(then_body, names, functions, visited);
                if let Some(body) = else_body {
                    collect_statements(body, names, functions, visited);
                }
            }
            Statement::ForIn { iterable, body, .. } => {
                collect_expression(iterable, names, functions, visited);
                collect_statements(body, names, functions, visited);
            }
            Statement::ForCount { count, body } => {
                collect_expression(count, names, functions, visited);
                collect_statements(body, names, functions, visited);
            }
        }
    }
}
