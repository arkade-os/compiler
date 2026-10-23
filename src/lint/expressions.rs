//! Lints on single expressions, in every function and helper, and on tapscript multisig keys.

use super::walk::{Visitor, Walk};
use super::{Finding, Lint};
use crate::diagnostics::Span;
use crate::models::{
    Contract, ExprKind, Expression, Function, KeyExpr, LocatedStatement, Requirement, Statement,
    TapItem, TypeName,
};
use crate::operators::BinaryOperator;

pub(super) fn check(contract: &Contract, findings: &mut Vec<Finding>) {
    for function in contract.functions.iter().filter(|f| !f.is_imported()) {
        let mut lints = Expressions {
            contract,
            function,
            findings: &mut *findings,
        };
        Walk::default().statements(&function.statements, &mut lints);
    }
    for tapscript in &contract.tapscripts {
        for item in &tapscript.items {
            let TapItem::Sig { keys, .. } = item else {
                continue;
            };
            let repeated = keys
                .iter()
                .enumerate()
                .find_map(|(at, key)| keys[..at].contains(key).then_some(key));
            if let Some(key) = repeated {
                let key = match key {
                    KeyExpr::Ident(name) => format!("'{name}'"),
                    KeyExpr::Tweak { base, func } => format!("tweak({base}, {func})"),
                };
                findings.push(duplicate_key(&key, tapscript.span));
            }
        }
    }
}

struct Expressions<'f, 'c> {
    contract: &'c Contract,
    function: &'c Function,
    findings: &'f mut Vec<Finding>,
}

impl<'a> Visitor<'a> for Expressions<'_, '_> {
    fn statement(&mut self, statement: &'a LocatedStatement) {
        if let Statement::Require(Requirement::Comparison { left, right, .. }) =
            &statement.statement
        {
            if same(left, right) {
                self.findings.push(self_comparison(statement.span));
            }
        }
    }

    fn expression(&mut self, expression: &'a Expression) {
        match &expression.kind {
            ExprKind::BinaryOp { left, op, right } => {
                if (op.compares() || matches!(op, BinaryOperator::And | BinaryOperator::Or))
                    && same(left, right)
                {
                    self.findings.push(self_comparison(expression.span));
                }
                let divides = |side: &Expression| {
                    matches!(
                        side.kind,
                        ExprKind::BinaryOp {
                            op: BinaryOperator::Div,
                            ..
                        }
                    )
                };
                if *op == BinaryOperator::Mul && (divides(left) || divides(right)) {
                    self.findings.push(Finding::new(
                        Lint::DivideBeforeMultiply,
                        expression.span,
                        "this divides before it multiplies, so the remainder is lost before it \
                         is scaled; multiply first",
                    ));
                }
            }
            ExprKind::Builtin { builtin, args }
                if builtin.name.starts_with("sha256")
                    || crate::models::HashFn::parse(builtin.name).is_some() =>
            {
                for data in args {
                    let mut parts = Vec::new();
                    concatenated(data, &mut parts);
                    let variable: Vec<String> = parts
                        .into_iter()
                        .filter(|part| self.variable_length(part))
                        .map(Expression::source_text)
                        .collect();
                    if variable.len() >= 2 {
                        self.findings.push(Finding::new(
                            Lint::AmbiguousHashConcat,
                            data.span,
                            format!(
                                "{} hashes {} joined together, which vary in length, so other \
                                 values joined the same way can give the same bytes; give them a \
                                 fixed length, such as bytes32",
                                builtin.name,
                                variable.join(" + "),
                            ),
                        ));
                    }
                }
            }
            ExprKind::Builtin { builtin, args } if builtin.name == "checkMultisig" => {
                if let Some(ExprKind::ArrayLiteral(keys)) = args.first().map(|keys| &keys.kind) {
                    let repeated = keys.iter().enumerate().find_map(|(at, key)| {
                        keys[..at].iter().any(|k| same(k, key)).then_some(key)
                    });
                    if let Some(key) = repeated {
                        let key = format!("'{}'", key.source_text());
                        self.findings.push(duplicate_key(&key, expression.span));
                    }
                }
            }
            _ => {}
        }
    }
}

impl Expressions<'_, '_> {
    /// A `bytes` parameter of the contract or the function, whose length the witness chooses.
    fn variable_length(&self, expression: &Expression) -> bool {
        match &expression.kind {
            ExprKind::Name(path) if path.segments.is_empty() => self
                .contract
                .parameters
                .iter()
                .chain(&self.function.parameters)
                .any(|p| p.name == path.root && p.param_type == TypeName::Named("bytes".into())),
            _ => false,
        }
    }
}

/// Two operands that are the same name or access, so the result never depends on them.
fn same(left: &Expression, right: &Expression) -> bool {
    let text = left.source_text();
    !matches!(left.kind, ExprKind::Literal(_))
        && !text.contains("<expr>")
        && text == right.source_text()
}

fn self_comparison(span: Span) -> Finding {
    Finding::new(
        Lint::SelfComparison,
        span,
        "both sides of this comparison are the same, so its result never depends on them",
    )
}

fn duplicate_key(key: &str, span: Span) -> Finding {
    Finding::new(
        Lint::DuplicateMultisigKey,
        span,
        format!("checkMultisig lists {key} more than once, so its one signature counts for each"),
    )
}

/// The operands of a chain of `+` on bytes, in order.
fn concatenated<'a>(expression: &'a Expression, parts: &mut Vec<&'a Expression>) {
    match &expression.kind {
        ExprKind::BinaryOp {
            left,
            op: BinaryOperator::Add,
            right,
        } if expression.ty != crate::types::ArkType::Int => {
            concatenated(left, parts);
            concatenated(right, parts);
        }
        _ => parts.push(expression),
    }
}
