use std::collections::HashSet;

use crate::models::{AssignmentTarget, Expression, Requirement, Statement};
use crate::validator::child_exprs;

// Parameters are retained whole; pruning individual composite fields needs a sparse stack layout.
pub(super) fn referenced_parameters(statements: &[Statement]) -> HashSet<&str> {
    let mut names = HashSet::new();
    collect_statements(statements, &mut names);
    names
}

fn collect_name<'a>(name: &'a str, names: &mut HashSet<&'a str>) {
    names.insert(name.split(['.', '[']).next().unwrap_or(name));
    // Named crypto operands can carry runtime indices, e.g. keys[index].
    if let Some((_, index)) = name.strip_suffix(']').and_then(|name| name.split_once('[')) {
        collect_name(index, names);
    }
}

fn collect_expression<'a>(expression: &'a Expression, names: &mut HashSet<&'a str>) {
    match expression {
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
        collect_expression(child, names);
    }
}

fn collect_requirement<'a>(requirement: &'a Requirement, names: &mut HashSet<&'a str>) {
    match requirement {
        Requirement::Expression(expression) => collect_expression(expression, names),
        Requirement::Comparison { left, right, .. } => {
            collect_expression(left, names);
            collect_expression(right, names);
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
        Requirement::After { timelock_var, .. } => {
            if let Some(name) = timelock_var {
                collect_name(name, names);
            }
        }
        Requirement::HashEqual { preimage, hash, .. } => {
            collect_name(preimage, names);
            collect_name(hash, names);
        }
    }
}

fn collect_statements<'a>(statements: &'a [Statement], names: &mut HashSet<&'a str>) {
    for statement in statements {
        match statement {
            Statement::Require(requirement) => collect_requirement(requirement, names),
            Statement::LetBinding { value, .. } => collect_expression(value, names),
            Statement::VarAssign { target, value } => {
                if let AssignmentTarget::ArrayIndex { index, .. } = target {
                    collect_expression(index, names);
                }
                collect_expression(value, names);
            }
            Statement::IfElse {
                condition,
                then_body,
                else_body,
            } => {
                collect_expression(condition, names);
                collect_statements(then_body, names);
                if let Some(body) = else_body {
                    collect_statements(body, names);
                }
            }
            Statement::ForIn { iterable, body, .. } => {
                collect_expression(iterable, names);
                collect_statements(body, names);
            }
        }
    }
}
