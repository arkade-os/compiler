use crate::models::{AssignmentTarget, ExprKind, Expression, Requirement, Statement};
use crate::opcodes::{
    OP_0, OP_0NOTEQUAL, OP_1, OP_1ADD, OP_2, OP_2DROP, OP_2DUP, OP_2OVER, OP_2ROT, OP_2SWAP, OP_3,
    OP_3DUP, OP_4, OP_5, OP_ADD, OP_BOOLAND, OP_BOOLOR, OP_CHECKSIG, OP_CHECKSIGFROMSTACK,
    OP_CHECKSIGVERIFY, OP_DROP, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_GREATERTHAN,
    OP_GREATERTHANOREQUAL, OP_INSPECTINPUTPACKET, OP_INSPECTPACKET, OP_LESSTHAN,
    OP_LESSTHANOREQUAL, OP_NIP, OP_NOT, OP_NUMEQUAL, OP_NUMEQUALVERIFY, OP_OVER, OP_PICK, OP_PUT,
    OP_ROLL, OP_ROT, OP_SWAP, OP_VERIFY,
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

/// Opcodes that leave a minimal 0 or 1, which `OP_0NOTEQUAL` returns unchanged.
const BOOLEAN_RESULTS: [&str; 12] = [
    OP_EQUAL,
    OP_NUMEQUAL,
    OP_LESSTHAN,
    OP_LESSTHANOREQUAL,
    OP_GREATERTHAN,
    OP_GREATERTHANOREQUAL,
    OP_NOT,
    OP_0NOTEQUAL,
    OP_BOOLAND,
    OP_BOOLOR,
    OP_CHECKSIG,
    OP_CHECKSIGFROMSTACK,
];

pub(super) fn optimize(mut asm: Vec<String>) -> Vec<String> {
    // The NIPs clear every item below the final truthy value. The final clean-stack truth check
    // already enforces a trailing `OP_VERIFY OP_1`, so a failing last requirement reports a false
    // stack entry instead when the NIPs are kept.
    let nips = asm
        .iter()
        .rev()
        .take_while(|token| *token == OP_NIP)
        .count();
    let body = asm.len() - nips;
    let mut kept = asm.clone();
    if body >= 2 && kept[body - 2] == OP_VERIFY && kept[body - 1] == OP_1 {
        kept.drain(body - 2..body);
    }
    // Verifying the final value first lets the cleared items go in pairs with OP_2DROP; a failing
    // last requirement then reports `OP_VERIFY failed`.
    asm.truncate(body);
    asm.push(OP_VERIFY.to_string());
    asm.extend(std::iter::repeat_n(OP_DROP.to_string(), nips));
    asm.push(OP_1.to_string());

    let (kept, dropped) = (rewrite(kept), rewrite(asm));
    if dropped.len() < kept.len() {
        dropped
    } else {
        kept
    }
}

fn rewrite(asm: Vec<String>) -> Vec<String> {
    let mut optimized: Vec<String> = Vec::with_capacity(asm.len());
    for token in asm {
        optimized.push(token);
        // Every rewrite shortens the window, so this terminates.
        loop {
            let len = optimized.len();
            let window: Vec<&str> = optimized[len.saturating_sub(4)..]
                .iter()
                .map(String::as_str)
                .collect();
            let (matched, replacement): (usize, &[&str]) = match window.as_slice() {
                [.., flag, OP_0NOTEQUAL] if BOOLEAN_RESULTS.contains(flag) => (1, &[]),
                [.., OP_0, OP_PICK] => (2, &[OP_DUP]),
                [.., OP_DUP, OP_SWAP] => (2, &[OP_DUP]),
                [.., OP_0, OP_PUT] => (2, &[OP_NIP]),
                [.., OP_1, OP_PICK] => (2, &[OP_OVER]),
                [.., OP_0, OP_ROLL] | [.., OP_SWAP, OP_SWAP] => (2, &[]),
                [.., OP_1, OP_ROLL] => (2, &[OP_SWAP]),
                [.., OP_2, OP_ROLL] => (2, &[OP_ROT]),
                [.., OP_SWAP, OP_DROP] => (2, &[OP_NIP]),
                [.., OP_DROP, OP_DROP] => (2, &[OP_2DROP]),
                [.., OP_OVER, OP_OVER] => (2, &[OP_2DUP]),
                [.., OP_DUP, OP_2, OP_PICK] => (3, &[OP_2DUP, OP_SWAP]),
                [.., OP_2, OP_PICK, OP_OVER] => (3, &[OP_3DUP, OP_NIP]),
                [.., OP_2, OP_PICK, OP_4, OP_PICK] => (4, &[OP_2OVER, OP_SWAP]),
                [.., OP_ROT, OP_SWAP, OP_ROT] => (3, &[OP_SWAP]),
                [.., OP_ROT, OP_3, OP_ROLL] => (3, &[OP_2SWAP, OP_SWAP]),
                [.., OP_3, OP_ROLL, OP_3, OP_ROLL] => (4, &[OP_2SWAP]),
                [.., OP_4, OP_ROLL, OP_5, OP_ROLL] => (4, &[OP_2ROT, OP_SWAP]),
                [.., OP_1 | "1", OP_ADD] => (2, &[OP_1ADD]),
                [.., OP_1 | "1", OP_1ADD] => (2, &[OP_2]),
                [.., OP_1 | "1", OP_VERIFY] => (2, &[]),
                [.., OP_EQUAL, OP_VERIFY] => (2, &[OP_EQUALVERIFY]),
                [.., OP_NUMEQUAL, OP_VERIFY] => (2, &[OP_NUMEQUALVERIFY]),
                [.., OP_DUP, OP_EQUALVERIFY] => (2, &[OP_DROP]),
                // Packet lookups push a 0 or 1 presence flag.
                [.., OP_INSPECTPACKET | OP_INSPECTINPUTPACKET, OP_1, OP_EQUALVERIFY] => {
                    (2, &[OP_VERIFY])
                }
                [.., OP_CHECKSIG, OP_VERIFY] => (2, &[OP_CHECKSIGVERIFY]),
                [.., OP_NOT, OP_NOT] => (2, &[OP_0NOTEQUAL]),
                [.., OP_0NOTEQUAL, OP_NOT] => (2, &[OP_NOT]),
                _ => break,
            };
            optimized.truncate(len - matched);
            optimized.extend(replacement.iter().map(|token| token.to_string()));
        }
    }
    optimized
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcodes::OP_ENDIF;

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
    fn boolean_presence_and_trailing_cleanup_rewrites() {
        let optimize = |asm: &[&str]| optimize(asm.iter().map(|token| token.to_string()).collect());
        assert_eq!(
            optimize(&[
                "<a>",
                "<b>",
                OP_LESSTHAN,
                OP_0NOTEQUAL,
                OP_NOT,
                OP_NOT,
                "<c>"
            ]),
            ["<a>", "<b>", OP_LESSTHAN, "<c>"]
        );
        assert_eq!(
            optimize(&["<x>", OP_0NOTEQUAL, OP_NOT, "<y>", OP_0NOTEQUAL]),
            ["<x>", OP_NOT, "<y>", OP_0NOTEQUAL]
        );
        assert_eq!(
            optimize(&[
                OP_CHECKSIGFROMSTACK,
                OP_0NOTEQUAL,
                OP_NUMEQUAL,
                OP_VERIFY,
                "<z>"
            ]),
            [OP_CHECKSIGFROMSTACK, OP_NUMEQUALVERIFY, "<z>"]
        );
        assert_eq!(
            optimize(&[
                "5",
                OP_INSPECTPACKET,
                OP_1,
                OP_EQUALVERIFY,
                OP_1,
                OP_EQUALVERIFY,
                "<z>"
            ]),
            [
                "5",
                OP_INSPECTPACKET,
                OP_VERIFY,
                OP_1,
                OP_EQUALVERIFY,
                "<z>"
            ]
        );
        // Paired drops win only once they cover the added `OP_VERIFY OP_1`; ties keep the NIPs.
        assert_eq!(
            optimize(&[OP_ENDIF, OP_1, OP_NIP, OP_NIP, OP_NIP, OP_NIP, OP_NIP]),
            [OP_ENDIF, OP_2DROP, OP_2DROP, OP_DROP, OP_1]
        );
        assert_eq!(
            optimize(&[OP_EQUAL, OP_NIP, OP_NIP, OP_NIP, OP_NIP]),
            [OP_EQUALVERIFY, OP_2DROP, OP_2DROP, OP_1]
        );
        assert_eq!(
            optimize(&[OP_EQUAL, OP_NIP, OP_NIP, OP_NIP]),
            [OP_EQUAL, OP_NIP, OP_NIP, OP_NIP]
        );
    }

    /// Runs stack shuffles over distinct items; small numbers are depth operands.
    fn shuffle(asm: &[String]) -> Vec<usize> {
        let mut stack: Vec<usize> = (100..108).collect();
        for token in asm {
            let len = stack.len();
            match token.as_str() {
                OP_PICK | OP_ROLL => {
                    let depth = stack.pop().unwrap();
                    let item = stack.len() - 1 - depth;
                    let value = if token == OP_PICK {
                        stack[item]
                    } else {
                        stack.remove(item)
                    };
                    stack.push(value);
                }
                OP_DUP => stack.push(stack[len - 1]),
                OP_OVER => stack.push(stack[len - 2]),
                OP_2DUP => stack.extend(stack[len - 2..].to_vec()),
                OP_3DUP => stack.extend(stack[len - 3..].to_vec()),
                OP_2OVER => stack.extend(stack[len - 4..len - 2].to_vec()),
                OP_NIP => drop(stack.remove(len - 2)),
                OP_SWAP => stack.swap(len - 1, len - 2),
                OP_ROT => stack[len - 3..].rotate_left(1),
                OP_2SWAP => stack[len - 4..].rotate_left(2),
                OP_2ROT => stack[len - 6..].rotate_left(2),
                depth => stack.push(depth.trim_start_matches("OP_").parse().unwrap()),
            }
        }
        stack
    }

    #[test]
    fn shuffle_rewrites_keep_the_stack_order() {
        let cases: [&[&str]; 8] = [
            &[OP_OVER, OP_OVER],
            &[OP_DUP, OP_2, OP_PICK],
            &[OP_2, OP_PICK, OP_1, OP_PICK],
            &[OP_2, OP_PICK, OP_4, OP_PICK],
            &[OP_ROT, OP_SWAP, OP_ROT],
            &[OP_ROT, OP_3, OP_ROLL],
            &[OP_3, OP_ROLL, OP_3, OP_ROLL],
            &[OP_4, OP_ROLL, OP_5, OP_ROLL],
        ];
        for case in cases {
            let asm: Vec<String> = case.iter().map(|token| token.to_string()).collect();
            let rewritten = rewrite(asm.clone());
            assert!(rewritten.len() < asm.len(), "{asm:?} -> {rewritten:?}");
            assert_eq!(
                shuffle(&rewritten),
                shuffle(&asm),
                "{asm:?} -> {rewritten:?}"
            );
        }
    }

    #[test]
    fn wide_clean_stack_tails_drop_in_pairs() {
        let nips = |count| std::iter::repeat_n(OP_NIP, count);
        let tail = |prefix: &[&'static str], count| {
            prefix
                .iter()
                .copied()
                .chain([OP_1])
                .chain(nips(count))
                .map(String::from)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            optimize(tail(&[OP_EQUAL, OP_VERIFY], 4)),
            [OP_EQUALVERIFY, OP_2DROP, OP_2DROP, OP_1]
        );
        assert_eq!(
            optimize(tail(&["<x>"], 3)),
            ["<x>", OP_2DROP, OP_DROP, OP_1]
        );
        // A tie keeps the NIPs and the removed final `OP_VERIFY OP_1`.
        assert_eq!(
            optimize(tail(&["<x>", OP_VERIFY], 5)),
            ["<x>", OP_NIP, OP_NIP, OP_NIP, OP_NIP, OP_NIP]
        );
        assert_eq!(optimize(tail(&["<x>"], 1)), ["<x>", OP_1, OP_NIP]);
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
