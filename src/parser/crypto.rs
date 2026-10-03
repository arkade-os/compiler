use super::Rule;
#[allow(unused_imports)]
use super::*;
use crate::models::*;
use pest::iterators::Pair;

/// Parse checkSigFromStackVerify(sig, pubkey, msg) → Requirement::CheckSig (verify variant)
pub(crate) fn parse_check_sig_from_stack_verify(pair: Pair<Rule>) -> Result<Requirement, String> {
    Ok(Requirement::Expression(
        parse_check_sig_from_stack_verify_expr(pair)?,
    ))
}

/// Parse checkSigFromStackVerify for primary expression context
pub(crate) fn parse_check_sig_from_stack_verify_expr(
    pair: Pair<Rule>,
) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    let signature = parse_operand(
        inner
            .next()
            .ok_or("Missing signature in checkSigFromStackVerify")?,
    )?;
    let pubkey = parse_operand(
        inner
            .next()
            .ok_or("Missing pubkey in checkSigFromStackVerify")?,
    )?;
    let message = parse_operand(
        inner
            .next()
            .ok_or("Missing message in checkSigFromStackVerify")?,
    )?;

    Ok(Expression::CheckSigFromStackVerify {
        signature: Box::new(signature),
        pubkey: Box::new(pubkey),
        message: Box::new(message),
    })
}

/// Parse pubkey(x) / signature(x) / bytes20(x) / bytes32(x) → Expression::Cast
pub(crate) fn parse_cast(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    let target = inner
        .next()
        .ok_or("Missing cast type")?
        .as_str()
        .to_string();
    let data = parse_general_expression(inner.next().ok_or("Missing data in cast")?)?;
    Ok(Expression::Cast {
        target,
        data: Box::new(data),
    })
}
