//! Warns where a signature check's result is used as a value that can be false: the VM fails
//! the spend on a non-empty invalid signature, so such a check is false only for an empty one.

use super::walk::{Visitor, Walk};
use super::{Finding, Lint};
use crate::models::{Contract, ExprKind, Expression, LocatedStatement, Requirement, Statement};
use crate::operators::{BinaryOperator, UnaryOperator};

pub(super) fn check(contract: &Contract, findings: &mut Vec<Finding>) {
    for function in contract.functions.iter().filter(|f| !f.is_imported()) {
        let mut results = Results {
            root: false,
            branches: Vec::new(),
            findings: Vec::new(),
        };
        Walk::default().statements(&function.statements, &mut results);
        findings.append(&mut results.findings);
    }
}

/// `branches` holds, per open expression, whether its children decide something, as an `if`
/// condition, a `||` operand, a negation or a comparison does, rather than having to hold.
struct Results {
    root: bool,
    branches: Vec<bool>,
    findings: Vec<Finding>,
}

impl<'a> Visitor<'a> for Results {
    fn statement(&mut self, statement: &'a LocatedStatement) {
        self.root = matches!(
            statement.statement,
            Statement::IfElse { .. } | Statement::Require(Requirement::Comparison { .. })
        );
    }

    fn expression(&mut self, expression: &'a Expression) {
        let branches = self.branches.last().copied().unwrap_or(self.root);
        let children = match &expression.kind {
            ExprKind::Builtin { builtin, .. }
                if branches
                    && matches!(
                        builtin.name,
                        "checkSig" | "checkSigFromStack" | "checkMultisig"
                    ) =>
            {
                self.findings.push(Finding::new(
                    Lint::SignatureMayFail,
                    expression.span,
                    format!(
                        "{} fails the spend on an invalid non-empty signature instead of \
                         returning false; pass an empty signature where the check may fail",
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
        self.branches.push(children);
    }

    fn leave_expression(&mut self, _expression: &'a Expression) {
        self.branches.pop();
    }
}
