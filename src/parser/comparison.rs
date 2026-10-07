use super::Rule;
#[allow(unused_imports)]
use super::*;
use crate::models::*;
use pest::iterators::Pair;

pub(crate) fn parse_time_comparison(pair: Pair<Rule>) -> Result<Requirement, String> {
    let start = pair.as_span().start();
    let span = crate::diagnostics::Span {
        start,
        end: start + "tx.time".len(),
    };
    let mut inner = pair.into_inner();
    Ok(Requirement::Comparison {
        left: Expression::new(ExprKind::Property("tx.time".to_string()), span),
        op: crate::operators::BinaryOperator::Ge,
        right: parse_general_expression(inner.next().ok_or("Missing timelock")?)?,
    })
}

/// Parse sha256(preimage) == hash → HashEqual requirement
pub(crate) fn parse_hash_comparison(pair: Pair<Rule>) -> Result<Requirement, String> {
    let mut inner = pair.into_inner();
    let hash_func = inner.next().ok_or("Missing hash function")?;
    let span: crate::diagnostics::Span = hash_func.as_span().into();
    let mut hash_func_inner = hash_func.into_inner();
    let fn_name = hash_func_inner
        .next()
        .ok_or("Missing hash function name")?
        .as_str();
    let hash_fn = crate::models::HashFn::parse(fn_name)
        .ok_or_else(|| format!("unknown hash function {fn_name}"))?;
    let preimage_pair = hash_func_inner.next().ok_or("Missing preimage")?;
    let rhs_pair = inner.next().ok_or("Missing the hash")?;

    // The grammar keeps the RHS simple, so only the preimage decides between
    // structured HashEqual emission and an inline sha256 comparison.
    let preimage_expr = parse_general_expression(preimage_pair)?;
    if matches!(
        &preimage_expr.kind,
        ExprKind::Variable(_)
            | ExprKind::Literal(_)
            | ExprKind::Property(_)
            | ExprKind::ArrayIndex { .. }
            | ExprKind::FieldAccess { .. }
            | ExprKind::IndexAccess { .. }
    ) {
        return Ok(Requirement::HashEqual {
            hash_fn,
            preimage: preimage_expr,
            hash: parse_operand(rhs_pair)?,
        });
    }

    // A computed preimage expands inline; only sha256 is a value builtin.
    if !matches!(hash_fn, crate::models::HashFn::Sha256) {
        return Err(format!(
            "{fn_name} with byte-expression operands is not supported; \
             only sha256 allows substr/cat operands"
        ));
    }
    let rhs_expr = parse_operand(rhs_pair)?;

    Ok(Requirement::Comparison {
        left: Expression::new(
            ExprKind::Builtin {
                builtin: crate::builtins::find("sha256").expect("sha256 is a builtin"),
                args: vec![preimage_expr],
            },
            span,
        ),
        op: crate::operators::BinaryOperator::Eq,
        right: rhs_expr,
    })
}
