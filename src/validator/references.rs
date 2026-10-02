use std::collections::HashSet;

use super::child_exprs;
use crate::models::{
    AssignmentTarget, Expression, Function, LocatedStatement, Requirement, Statement,
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

fn collect_name<'a>(name: &'a str, names: &mut HashSet<&'a str>) {
    names.insert(name.split('.').next().unwrap_or(name));
}

fn collect_expression<'a>(
    expression: &'a Expression,
    names: &mut HashSet<&'a str>,
    functions: &'a [Function],
    visited: &mut HashSet<&'a str>,
) {
    match expression {
        Expression::Call { name, .. } if visited.insert(name) => {
            // Static helpers cannot capture constructor state and are validated independently.
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
            for operand in [signature, pubkey] {
                collect_expression(operand, names, functions, visited);
            }
        }
        Requirement::CheckSigFromStack {
            signature,
            pubkey,
            message,
        } => {
            for operand in [signature, pubkey, message] {
                collect_expression(operand, names, functions, visited);
            }
        }
        Requirement::CheckMultisig {
            pubkeys,
            signatures,
            ..
        } => {
            for operand in pubkeys.iter().chain(signatures) {
                collect_expression(operand, names, functions, visited);
            }
        }
        Requirement::HashEqual { preimage, hash, .. } => {
            for operand in [preimage, hash] {
                collect_expression(operand, names, functions, visited);
            }
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
            Statement::Return(None) => {}
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
