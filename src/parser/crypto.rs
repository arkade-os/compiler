use super::Rule;
#[allow(unused_imports)]
use super::*;
use crate::models::*;
use pest::iterators::Pair;

// ─── Crypto Opcodes Parsing ────────────────────────────────────────────

pub(crate) fn parse_ec_add(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    Ok(Expression::EcAdd {
        point_p: Box::new(parse_general_expression(
            inner.next().ok_or("Missing point P in ecAdd")?,
        )?),
        point_q: Box::new(parse_general_expression(
            inner.next().ok_or("Missing point Q in ecAdd")?,
        )?),
        curve_id: Box::new(parse_general_expression(
            inner.next().ok_or("Missing curve ID in ecAdd")?,
        )?),
    })
}

pub(crate) fn parse_ec_mul(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    Ok(Expression::EcMul {
        point: Box::new(parse_general_expression(
            inner.next().ok_or("Missing point P in ecMul")?,
        )?),
        scalar: Box::new(parse_general_expression(
            inner.next().ok_or("Missing scalar in ecMul")?,
        )?),
        curve_id: Box::new(parse_general_expression(
            inner.next().ok_or("Missing curve ID in ecMul")?,
        )?),
    })
}

pub(crate) fn parse_ec_pairing(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    Ok(Expression::EcPairing {
        g1: Box::new(parse_general_expression(
            inner.next().ok_or("Missing G1 points in ecPairing")?,
        )?),
        g2: Box::new(parse_general_expression(
            inner.next().ok_or("Missing G2 points in ecPairing")?,
        )?),
        curve_id: Box::new(parse_general_expression(
            inner.next().ok_or("Missing curve ID in ecPairing")?,
        )?),
    })
}

/// Parse ecMulScalarVerify(k, P, Q) → Expression::EcMulScalarVerify
pub(crate) fn parse_ec_mul_scalar_verify(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();

    let scalar_pair = inner
        .next()
        .ok_or("Missing scalar k in ecMulScalarVerify")?;
    let scalar = parse_general_expression(scalar_pair)?;

    let point_p_pair = inner.next().ok_or("Missing point P in ecMulScalarVerify")?;
    let point_p = parse_general_expression(point_p_pair)?;

    let point_q_pair = inner.next().ok_or("Missing point Q in ecMulScalarVerify")?;
    let point_q = parse_general_expression(point_q_pair)?;

    Ok(Expression::EcMulScalarVerify {
        scalar: Box::new(scalar),
        point_p: Box::new(point_p),
        point_q: Box::new(point_q),
    })
}

/// Parse tweakVerify(P, k, Q) → Expression::TweakVerify
pub(crate) fn parse_tweak_verify(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();

    let point_p_pair = inner.next().ok_or("Missing point P in tweakVerify")?;
    let point_p = parse_general_expression(point_p_pair)?;

    let tweak_pair = inner.next().ok_or("Missing tweak k in tweakVerify")?;
    let tweak = parse_general_expression(tweak_pair)?;

    let point_q_pair = inner.next().ok_or("Missing point Q in tweakVerify")?;
    let point_q = parse_general_expression(point_q_pair)?;

    Ok(Expression::TweakVerify {
        point_p: Box::new(point_p),
        tweak: Box::new(tweak),
        point_q: Box::new(point_q),
    })
}

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
