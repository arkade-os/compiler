use crate::models::{AssignmentTarget, ExprKind, Expression, Requirement, Statement};
use crate::opcodes::{
    OP_0, OP_1, OP_1ADD, OP_2, OP_2DROP, OP_ADD, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_DROP, OP_DUP,
    OP_EQUAL, OP_EQUALVERIFY, OP_NIP, OP_OVER, OP_PICK, OP_PUT, OP_ROLL, OP_ROT, OP_SWAP,
    OP_VERIFY,
};

use crate::operators::{BinaryOperator, UnaryOperator};
use crate::types::{ArkType, Scope};

const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

pub(super) fn fold_statement(statement: &mut Statement, scope: &Scope) -> Result<(), String> {
    match statement {
        Statement::Call(value)
        | Statement::Return(Some(value))
        | Statement::LetBinding { value, .. } => fold_expression(value, scope)?,
        Statement::Require(requirement) => {
            if let Requirement::Comparison { left, op, right } = requirement {
                let mut expression = left.with_kind(ExprKind::BinaryOp {
                    left: Box::new(left.clone()),
                    op: *op,
                    right: Box::new(right.clone()),
                });
                expression.ty = ArkType::Bool;
                fold_expression(&mut expression, scope)?;
                if matches!(expression.kind, ExprKind::Literal(_)) {
                    *requirement = Requirement::Expression(expression);
                } else if let ExprKind::BinaryOp {
                    left: folded_left,
                    right: folded_right,
                    ..
                } = expression.kind
                {
                    *left = *folded_left;
                    *right = *folded_right;
                }
            } else {
                for expression in requirement.expressions_mut() {
                    fold_expression(expression, scope)?;
                }
            }
        }
        Statement::VarAssign { target, value } => {
            match target {
                AssignmentTarget::Access(access) => fold_expression(access, scope)?,
                AssignmentTarget::ArrayIndex { array, index } => {
                    let mut access = index.with_kind(ExprKind::ArrayIndex {
                        array: array.clone(),
                        index: index.clone(),
                    });
                    fold_expression(&mut access, scope)?;
                    let ExprKind::ArrayIndex { index: folded, .. } = access.kind else {
                        unreachable!()
                    };
                    *index = folded;
                }
                AssignmentTarget::Binding(_) => {}
            }
            fold_expression(value, scope)?;
        }
        Statement::IfElse { condition, .. } => fold_expression(condition, scope)?,
        Statement::ForIn { iterable, .. } => fold_expression(iterable, scope)?,
        Statement::ForCount { count, .. } => fold_expression(count, scope)?,
        Statement::Return(None) | Statement::Declaration { .. } => {}
    }
    Ok(())
}

fn fold_expression(expression: &mut Expression, scope: &Scope) -> Result<(), String> {
    if let ExprKind::BinaryOp { left, op, right } = &mut expression.kind {
        if matches!(op, BinaryOperator::And | BinaryOperator::Or) {
            fold_expression(left, scope)?;
            if let ExprKind::Literal(value) = &left.kind {
                if (*op == BinaryOperator::And && value == "false")
                    || (*op == BinaryOperator::Or && value == "true")
                {
                    expression.kind = left.kind.clone();
                    return Ok(());
                }
            }
            fold_expression(right, scope)?;
            if matches!(&left.kind, ExprKind::Literal(value) if value == "true" || value == "false")
            {
                expression.kind = right.kind.clone();
            }
            return Ok(());
        }
    }
    for child in crate::models::child_exprs_mut(expression) {
        fold_expression(child, scope)?;
    }
    let access = match &expression.kind {
        ExprKind::ArrayIndex { array, index } => Some((array.clone(), index)),
        ExprKind::IndexAccess { value, index } => value.binding_path().map(|array| (array, index)),
        _ => None,
    };
    if let Some((array, index)) = access {
        if let (Some(ArkType::Array(_, length)), ExprKind::Literal(index)) =
            (scope.get(&array), &index.kind)
        {
            if !index.parse::<usize>().is_ok_and(|index| index < *length) {
                return Err(format!(
                    "array index '{index}' is out of range for '{array}[{length}]'"
                ));
            }
        }
    }
    let literal = match &expression.kind {
        ExprKind::Literal(value) if expression.ty == ArkType::Int => {
            value.parse::<i128>().ok().map(|value| value.to_string())
        }
        ExprKind::Property(name) if !scope.contains_key(name) => name
            .strip_suffix(".length")
            .and_then(|array| match scope.get(array) {
                Some(ArkType::Array(_, length)) => Some(length.to_string()),
                _ => None,
            }),
        ExprKind::Builtin { builtin, args } if builtin.name == "num2bin" => match args.as_slice() {
            [Expression {
                kind: ExprKind::Literal(value),
                ..
            }, Expression {
                kind: ExprKind::Literal(width),
                ..
            }] => value
                .parse::<i128>()
                .ok()
                .zip(width.parse::<usize>().ok())
                .and_then(|(value, width)| fixed_bytes(value, width)),
            _ => None,
        },
        ExprKind::Unary {
            op: UnaryOperator::Neg,
            value,
        } if matches!(value.kind, ExprKind::Literal(_)) => {
            super::constants::evaluate(expression, &mut |_| Err("runtime value".into()))
                .ok()
                .and_then(|value| value.parse::<i128>().ok())
                .map(|value| value.to_string())
        }
        ExprKind::Unary { .. } | ExprKind::BinaryOp { .. }
            if crate::models::child_exprs(expression)
                .iter()
                .all(|child| match &child.kind {
                    ExprKind::Literal(value) => {
                        matches!(value.as_str(), "true" | "false")
                            || value.parse::<i128>().is_ok()
                            || (value.starts_with("0x")
                                && value.len() <= 2 + 2 * MAX_SCRIPT_ELEMENT_SIZE)
                    }
                    _ => false,
                }) =>
        {
            // ponytail: the evaluator uses i128; larger or failing computations stay at runtime.
            super::constants::evaluate(expression, &mut |_| Err("runtime value".into())).ok()
        }
        _ => None,
    };
    if let Some(literal) = literal {
        expression.kind = ExprKind::Literal(literal);
    }
    Ok(())
}

fn fixed_bytes(value: i128, width: usize) -> Option<String> {
    if width > MAX_SCRIPT_ELEMENT_SIZE {
        return None;
    }
    let mut bytes = value.unsigned_abs().to_le_bytes().to_vec();
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    if bytes.last().is_some_and(|byte| byte & 0x80 != 0) {
        bytes.push(0);
    }
    if bytes.len() > width {
        return None;
    }
    bytes.resize(width, 0);
    if value < 0 {
        *bytes.last_mut()? |= 0x80;
    }
    Some(format!(
        "0x{}",
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}

pub(super) fn optimize(mut asm: Vec<String>) -> Vec<String> {
    // The final clean-stack truth check already enforces a trailing `OP_VERIFY OP_1`, so a
    // failing last requirement reports a false stack entry instead. The NIPs clear items below it.
    let tail = asm.iter().rposition(|token| token != OP_NIP).unwrap_or(0);
    if tail > 0 && asm[tail - 1] == OP_VERIFY && asm[tail] == OP_1 {
        asm.drain(tail - 1..=tail);
    }

    let mut optimized = Vec::with_capacity(asm.len());
    for token in asm {
        optimized.push(token);
        while optimized.len() >= 2 {
            let len = optimized.len();
            let replacement = match (optimized[len - 2].as_str(), optimized[len - 1].as_str()) {
                (OP_0, OP_PICK) => Some(Some(OP_DUP)),
                (OP_DUP, OP_SWAP) => Some(Some(OP_DUP)),
                (OP_0, OP_PUT) => Some(Some(OP_NIP)),
                (OP_1, OP_PICK) => Some(Some(OP_OVER)),
                (OP_0, OP_ROLL) | (OP_SWAP, OP_SWAP) => Some(None),
                (OP_1, OP_ROLL) => Some(Some(OP_SWAP)),
                (OP_2, OP_ROLL) => Some(Some(OP_ROT)),
                (OP_SWAP, OP_DROP) => Some(Some(OP_NIP)),
                (OP_DROP, OP_DROP) => Some(Some(OP_2DROP)),
                (OP_1 | "1", OP_ADD) => Some(Some(OP_1ADD)),
                (OP_1 | "1", OP_1ADD) => Some(Some(OP_2)),
                (OP_EQUAL, OP_VERIFY) => Some(Some(OP_EQUALVERIFY)),
                (OP_DUP, OP_EQUALVERIFY) => Some(Some(OP_DROP)),
                (OP_CHECKSIG, OP_VERIFY) => Some(Some(OP_CHECKSIGVERIFY)),
                _ => None,
            };
            let Some(replacement) = replacement else {
                break;
            };
            optimized.truncate(len - 2);
            if let Some(replacement) = replacement {
                optimized.push(replacement.to_string());
            }
        }
    }
    optimized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shallow_stack_operations_and_final_requirement() {
        assert_eq!(
            optimize(
                ["<owner>", OP_0, OP_PICK, "9", OP_0, OP_PUT, OP_VERIFY, OP_1, OP_NIP]
                    .into_iter()
                    .map(String::from)
                    .collect()
            ),
            ["<owner>", OP_DUP, "9", OP_NIP, OP_NIP]
        );
        assert_eq!(
            optimize([OP_VERIFY, OP_1, OP_NIP, OP_1].map(String::from).to_vec()),
            [OP_VERIFY, OP_1, OP_NIP, OP_1]
        );
        assert_eq!(
            optimize(["<x>", OP_0, OP_PICK, OP_SWAP].map(String::from).to_vec()),
            ["<x>", OP_DUP]
        );
    }

    #[test]
    fn adjacent_rewrites_revisit_newly_exposed_tokens() {
        let asm = [
            OP_0,
            OP_ROLL,
            OP_1,
            OP_PICK,
            OP_2,
            OP_ROLL,
            OP_1,
            OP_ROLL,
            OP_1,
            OP_ROLL,
            OP_EQUAL,
            OP_0,
            OP_ROLL,
            OP_VERIFY,
            OP_CHECKSIG,
            OP_VERIFY,
            OP_1,
            OP_ROLL,
            OP_1,
            OP_ROLL,
        ];
        assert_eq!(
            optimize(asm.map(String::from).to_vec()),
            [OP_OVER, OP_ROT, OP_EQUALVERIFY, OP_CHECKSIGVERIFY]
        );
        assert_eq!(
            optimize(
                [OP_EQUAL, OP_VERIFY, OP_1, OP_NIP]
                    .map(String::from)
                    .to_vec()
            ),
            [OP_EQUAL, OP_NIP]
        );
        assert_eq!(
            optimize(
                [OP_DUP, OP_EQUAL, OP_VERIFY, "<next>"]
                    .map(String::from)
                    .to_vec()
            ),
            [OP_DROP, "<next>"]
        );
        assert_eq!(
            optimize([OP_DUP, OP_EQUAL].map(String::from).to_vec()),
            [OP_DUP, OP_EQUAL]
        );
    }

    #[test]
    fn stack_and_arithmetic_rewrites() {
        let asm = [
            "<a>", "<b>", OP_1, OP_ROLL, OP_DROP, "<c>", "<d>", OP_DROP, OP_DROP, "<x>", OP_1,
            OP_ADD, OP_1, OP_1, OP_ADD,
        ];
        assert_eq!(
            optimize(asm.map(String::from).to_vec()),
            ["<a>", "<b>", OP_NIP, "<c>", "<d>", OP_2DROP, "<x>", OP_1ADD, OP_2]
        );
        assert_eq!(
            optimize(["1", "1", OP_ADD].map(String::from).to_vec()),
            [OP_2]
        );
    }
}
