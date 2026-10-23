//! Warns where a signature check's result is used as a value that can be false: the VM fails
//! the spend on a non-empty invalid signature, so such a check is false only for an empty one.

use super::{Finding, Lint};
use crate::models::{
    child_exprs, Contract, ExprKind, Expression, LocatedStatement, Requirement, Statement,
};
use crate::operators::{BinaryOperator, UnaryOperator};

pub(super) fn check(contract: &Contract, issues: &mut Vec<Finding>) {
    for function in contract.functions.iter().filter(|f| !f.is_imported()) {
        statements(&function.statements, &function.name, issues);
    }
}

fn statements(statements: &[LocatedStatement], function: &str, issues: &mut Vec<Finding>) {
    for statement in statements {
        let branches = matches!(
            statement.statement,
            Statement::IfElse { .. } | Statement::Require(Requirement::Comparison { .. })
        );
        for value in statement.statement.expressions() {
            expression(value, branches, function, issues);
        }
        match &statement.statement {
            Statement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                self::statements(then_body, function, issues);
                self::statements(else_body.as_deref().unwrap_or_default(), function, issues);
            }
            Statement::ForIn { body, .. } | Statement::ForCount { body, .. } => {
                self::statements(body, function, issues)
            }
            _ => {}
        }
    }
}

/// `branches` when the value decides something, as an `if` condition, a `||` operand, a
/// negation or a comparison does, rather than having to hold.
fn expression(expression: &Expression, branches: bool, function: &str, issues: &mut Vec<Finding>) {
    let child_branches = match &expression.kind {
        ExprKind::Builtin { builtin, .. }
            if branches
                && matches!(
                    builtin.name,
                    "checkSig" | "checkSigFromStack" | "checkMultisig"
                ) =>
        {
            issues.push(Finding::new(
                Lint::SignatureMayFail,
                expression.span,
                format!(
                    "function '{function}': {} fails the spend on an invalid non-empty signature \
                     instead of returning false; pass an empty signature where the check may fail",
                    builtin.name
                ),
            ));
            false
        }
        ExprKind::BinaryOp {
            op: BinaryOperator::And,
            ..
        } => branches,
        ExprKind::BinaryOp { op, .. } => *op == BinaryOperator::Or || op.compares(),
        ExprKind::Unary {
            op: UnaryOperator::Not,
            ..
        } => true,
        _ => false,
    };
    for child in child_exprs(expression) {
        self::expression(child, child_branches, function, issues);
    }
}
