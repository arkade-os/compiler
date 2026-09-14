use std::collections::HashSet;

use super::child_exprs;
use crate::models::{AssignmentTarget, Expression, Function, Requirement, Statement};

// Parameters are retained whole; pruning individual composite fields needs a sparse stack layout.
pub(crate) fn referenced_parameters<'a>(
    statements: &'a [Statement],
    functions: &'a [Function],
) -> HashSet<&'a str> {
    let mut names = HashSet::new();
    collect_statements(statements, &mut names, functions, &mut HashSet::new());
    names
}

fn collect_name<'a>(name: &'a str, names: &mut HashSet<&'a str>) {
    names.insert(name.split(['.', '[']).next().unwrap_or(name));
    // Named crypto operands can carry runtime indices, e.g. keys[index].
    if let Some((_, index)) = name.strip_suffix(']').and_then(|name| name.split_once('[')) {
        collect_name(index, names);
    }
}

fn collect_expression<'a>(
    expression: &'a Expression,
    names: &mut HashSet<&'a str>,
    functions: &'a [Function],
    visited: &mut HashSet<&'a str>,
) {
    match expression {
        Expression::Call { name, .. } if visited.insert(name) => {
            if let Some(function) = functions
                .iter()
                .find(|f| f.is_private && !f.is_static && f.name == *name)
            {
                collect_statements(&function.statements, names, functions, visited);
            }
        }
        Expression::Variable(name)
        | Expression::Property(name)
        | Expression::ArrayIndex { array: name, .. }
        | Expression::GroupProperty { group: name, .. }
        | Expression::GroupControlIs { group: name, .. } => collect_name(name, names),
        Expression::CheckSigExpr { signature, pubkey } => {
            collect_name(signature, names);
            collect_name(pubkey, names);
        }
        Expression::CheckSigFromStackExpr {
            signature,
            pubkey,
            message,
        }
        | Expression::CheckSigFromStackVerify {
            signature,
            pubkey,
            message,
        } => {
            collect_name(signature, names);
            collect_name(pubkey, names);
            collect_name(message, names);
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
        Requirement::CheckSig { signature, pubkey } => {
            collect_name(signature, names);
            collect_name(pubkey, names);
        }
        Requirement::CheckSigFromStack {
            signature,
            pubkey,
            message,
        } => {
            collect_name(signature, names);
            collect_name(pubkey, names);
            collect_name(message, names);
        }
        Requirement::CheckMultisig {
            pubkeys,
            signatures,
            ..
        } => {
            for name in pubkeys.iter().chain(signatures) {
                collect_name(name, names);
            }
        }
        Requirement::HashEqual { preimage, hash, .. } => {
            collect_name(preimage, names);
            collect_name(hash, names);
        }
    }
}

fn collect_statements<'a>(
    statements: &'a [Statement],
    names: &mut HashSet<&'a str>,
    functions: &'a [Function],
    visited: &mut HashSet<&'a str>,
) {
    for statement in statements {
        match statement {
            Statement::Call(expression) | Statement::Return(Some(expression)) => {
                collect_expression(expression, names, functions, visited);
            }
            Statement::Return(None) => {}
            Statement::Require(requirement) => {
                collect_requirement(requirement, names, functions, visited)
            }
            Statement::LetBinding { value, .. } => {
                collect_expression(value, names, functions, visited)
            }
            Statement::VarAssign { target, value } => {
                if let AssignmentTarget::ArrayIndex { index, .. } = target {
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
        }
    }
}
