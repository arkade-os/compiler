use crate::models::{AssignmentTarget, ExprKind, Expression, Requirement, Statement};
use crate::opcodes::Opcode::{self, *};

use crate::operators::{BinaryOperator, UnaryOperator};
use crate::types::{ArkType, Scope};

use super::Op;

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
    // Unoptimized builds fold only to check, so a threshold that folds out of range fails here.
    if let ExprKind::Builtin { builtin, args } = &expression.kind {
        if let (crate::builtins::Lowering::Multisig, Some(ArkType::Array(_, count))) =
            (&builtin.lowering, args.first().map(|keys| &keys.ty))
        {
            super::access::multisig_threshold(args.get(2), *count)?;
        }
    }
    let access = match &expression.kind {
        ExprKind::ArrayIndex { array, index } => Some((array.clone(), index)),
        ExprKind::IndexAccess { value, index } => value.binding_path().map(|array| (array, index)),
        _ => None,
    };
    if let Some((array, index)) = access {
        if let (Some(ArkType::Array(_, length)), ExprKind::Literal(index)) =
            (scope.get(&array.key()), &index.kind)
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
        ExprKind::Name(path) if !scope.contains_key(&path.key()) => path
            .split_last()
            .filter(|&(_, field)| field == "length")
            .and_then(|(array, _)| match scope.get(&array.key()) {
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

/// Opcodes that leave a minimal 0 or 1, which `NotEqual0` returns unchanged.
const BOOLEAN_RESULTS: [Opcode; 12] = [
    Equal,
    NumEqual,
    LessThan,
    LessThanOrEqual,
    GreaterThan,
    GreaterThanOrEqual,
    Not,
    NotEqual0,
    BoolAnd,
    BoolOr,
    CheckSig,
    CheckSigFromStack,
];

/// Rewrites of the output's last tokens, tried in order. A leading token that only guards a
/// rewrite reappears in its replacement.
const REWRITES: &[(&[Opcode], &[Opcode])] = &[
    (&[Int0, Pick], &[Dup]),
    (&[Dup, Swap], &[Dup]),
    (&[Int0, Put], &[Nip]),
    (&[Int1, Pick], &[Over]),
    (&[Int0, Roll], &[]),
    (&[Swap, Swap], &[]),
    (&[Int1, Roll], &[Swap]),
    (&[Int2, Roll], &[Rot]),
    (&[Swap, Drop], &[Nip]),
    (&[Drop, Drop], &[Drop2]),
    (&[Over, Over], &[Dup2]),
    (&[Dup, Int2, Pick], &[Dup2, Swap]),
    (&[Int2, Pick, Over], &[Dup3, Nip]),
    (&[Int2, Pick, Int4, Pick], &[Over2, Swap]),
    (&[Rot, Swap, Rot], &[Swap]),
    (&[Rot, Int3, Roll], &[Swap2, Swap]),
    (&[Int3, Roll, Int3, Roll], &[Swap2]),
    (&[Int4, Roll, Int5, Roll], &[Rot2, Swap]),
    (&[Int1, Add], &[Add1]),
    (&[Int1, Add1], &[Int2]),
    (&[Int1, Verify], &[]),
    (&[Equal, Verify], &[EqualVerify]),
    (&[NumEqual, Verify], &[NumEqualVerify]),
    (&[Dup, EqualVerify], &[Drop]),
    // Packet lookups push a 0 or 1 presence flag.
    (
        &[InspectPacket, Int1, EqualVerify],
        &[InspectPacket, Verify],
    ),
    (
        &[InspectInputPacket, Int1, EqualVerify],
        &[InspectInputPacket, Verify],
    ),
    (&[CheckSig, Verify], &[CheckSigVerify]),
    (&[Not, Not], &[NotEqual0]),
    (&[NotEqual0, Not], &[Not]),
];

/// Whether `op` is `opcode`; a literal `1` assembles to `OP_1`, so it counts as one.
fn matches(op: &Op, opcode: Opcode) -> bool {
    match op {
        Op::Opcode(op) => *op == opcode,
        Op::Push(value) => value == "1" && opcode == Int1,
        _ => false,
    }
}

/// The optimized instructions, and how many items the rewrites can add to the unoptimized
/// stack peak.
pub(super) fn optimize(mut asm: Vec<Op>) -> (Vec<Op>, usize) {
    // The NIPs clear every item below the final truthy value. The final clean-stack truth check
    // already enforces a trailing `Verify Int1`, so a failing last requirement reports a false
    // stack entry instead when the NIPs are kept.
    let nips = asm.iter().rev().take_while(|op| matches(op, Nip)).count();
    let body = asm.len() - nips;
    let mut kept = asm.clone();
    if body >= 2 && matches(&kept[body - 2], Verify) && matches(&kept[body - 1], Int1) {
        kept.drain(body - 2..body);
    }
    // Verifying the final value first lets the cleared items go in pairs with Drop2; a failing
    // last requirement then reports `Verify failed`.
    asm.truncate(body);
    asm.push(Verify.into());
    asm.extend(std::iter::repeat_n(Drop.into(), nips));
    asm.push(Int1.into());

    let (kept, dropped) = (rewrite(kept), rewrite(asm));
    if dropped.0.len() < kept.0.len() {
        dropped
    } else {
        kept
    }
}

fn rewrite(asm: Vec<Op>) -> (Vec<Op>, usize) {
    let mut optimized: Vec<Op> = Vec::with_capacity(asm.len());
    let mut raise = 0;
    for op in asm {
        optimized.push(op);
        // Every rewrite shortens the window, so this terminates.
        loop {
            let len = optimized.len();
            if len >= 2
                && matches(&optimized[len - 1], NotEqual0)
                && BOOLEAN_RESULTS
                    .iter()
                    .any(|&opcode| matches(&optimized[len - 2], opcode))
            {
                optimized.pop();
                continue;
            }
            let Some((from, to)) = REWRITES.iter().find(|(from, _)| {
                len >= from.len()
                    && optimized[len - from.len()..]
                        .iter()
                        .zip(*from)
                        .all(|(op, &opcode)| matches(op, opcode))
            }) else {
                break;
            };
            optimized.truncate(len - from.len());
            optimized.extend(to.iter().copied().map(Op::from));
            raise = raise.max(peak(to).saturating_sub(peak(from)));
        }
    }
    (optimized, raise)
}

/// The most items `ops` holds above where they start.
// ponytail: adding the largest rewrite raise to the unoptimized peak is conservative; simulate
// the final script for an exact peak if contracts sit at the VM limit.
fn peak(ops: &[Opcode]) -> usize {
    let mut height = 0isize;
    let mut peak = 0;
    for op in ops {
        let (pops, pushes) = match op {
            // Their depth is the operand pushed before them.
            Pick => (1, 1),
            Roll => (1, 0),
            Put => (2, 0),
            op => op
                .stack_effect()
                .expect("rewrite opcodes have a stack effect"),
        };
        height += pushes as isize - pops as isize;
        peak = peak.max(height);
    }
    peak as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcodes::*;

    /// Instructions for assembly tokens: opcodes, `<binding>` reads and constants.
    fn ops(tokens: Vec<String>) -> Vec<Op> {
        tokens
            .into_iter()
            .map(
                |token| match Opcode::ALL.iter().find(|opcode| opcode.name() == token) {
                    Some(&opcode) => opcode.into(),
                    None if token.starts_with('<') => {
                        Op::Read(crate::models::Path::from_key(&token[1..token.len() - 1]))
                    }
                    None => Op::Push(token),
                },
            )
            .collect()
    }

    fn optimize(tokens: Vec<String>) -> Vec<String> {
        super::optimize(ops(tokens))
            .0
            .iter()
            .map(Op::spell)
            .collect()
    }

    fn rewrite(tokens: Vec<String>) -> Vec<String> {
        super::rewrite(ops(tokens))
            .0
            .iter()
            .map(Op::spell)
            .collect()
    }

    #[test]
    fn only_three_dup_raises_the_stack_peak() {
        let raising: Vec<_> = REWRITES
            .iter()
            .filter(|(from, to)| peak(to) > peak(from))
            .collect();
        assert_eq!(raising, [&(&[Int2, Pick, Over][..], &[Dup3, Nip][..])]);
        let asm = ["<a>", "<b>", "<c>", OP_2, OP_PICK, OP_OVER].map(String::from);
        assert_eq!(super::rewrite(ops(asm.to_vec())).1, 1);
    }

    #[test]
    fn rewrites_shorten_and_keep_the_stack_height() {
        let height = |ops: &[Opcode]| -> isize {
            ops.iter()
                .map(|op| {
                    let (pops, pushes) = op
                        .stack_effect()
                        .unwrap_or_else(|| panic!("{op} has no effect"));
                    pushes as isize - pops as isize
                })
                .sum()
        };
        for &(from, to) in REWRITES {
            assert!(to.len() < from.len(), "{from:?}");
            // These take their depth from an operand; the shuffle test covers them.
            if from.iter().any(|op| [Pick, Roll, Put].contains(op)) {
                continue;
            }
            assert_eq!(height(from), height(to), "{from:?}");
        }
    }

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
