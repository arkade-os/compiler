use super::Rule;
#[allow(unused_imports)]
use super::*;
use crate::models::*;
use pest::iterators::Pair;

// ─── Streaming SHA256 Parsing ──────────────────────────────────────────

/// Parse sha256Initialize(data) → Expression::Sha256Initialize
pub(crate) fn parse_sha256_initialize(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    let data_pair = inner.next().ok_or("Missing data in sha256Initialize")?;
    let data = parse_general_expression(data_pair)?;
    Ok(Expression::Sha256Initialize {
        data: Box::new(data),
    })
}

/// Parse sha256Update(ctx, chunk) → Expression::Sha256Update
pub(crate) fn parse_sha256_update(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    let ctx_pair = inner.next().ok_or("Missing context in sha256Update")?;
    let context = parse_general_expression(ctx_pair)?;

    let chunk_pair = inner.next().ok_or("Missing chunk in sha256Update")?;
    let chunk = parse_general_expression(chunk_pair)?;
    Ok(Expression::Sha256Update {
        context: Box::new(context),
        chunk: Box::new(chunk),
    })
}

/// Parse sha256Finalize(ctx, lastChunk) → Expression::Sha256Finalize
pub(crate) fn parse_sha256_finalize(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    let ctx_pair = inner.next().ok_or("Missing context in sha256Finalize")?;
    let context = parse_general_expression(ctx_pair)?;

    let chunk_pair = inner.next().ok_or("Missing lastChunk in sha256Finalize")?;
    let last_chunk = parse_general_expression(chunk_pair)?;
    Ok(Expression::Sha256Finalize {
        context: Box::new(context),
        last_chunk: Box::new(last_chunk),
    })
}

pub(crate) fn parse_sighash(pair: Pair<Rule>) -> Result<Expression, String> {
    let hash_type = pair
        .into_inner()
        .next()
        .ok_or("Missing hash type in sighash")?;
    Ok(Expression::Sighash {
        hash_type: Box::new(parse_general_expression(hash_type)?),
    })
}

pub(crate) fn parse_digest(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    let data = parse_general_expression(inner.next().ok_or("Missing data in digest")?)?;
    let hash_type = parse_general_expression(inner.next().ok_or("Missing hash type in digest")?)?;
    Ok(Expression::Digest {
        data: Box::new(data),
        hash_type: Box::new(hash_type),
    })
}

// ─── Arithmetic Parsing ────────────────────────────────────────────────

/// Parse modExp(base, exponent, modulus) → Expression::ModExp
pub(crate) fn parse_mod_exp(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    Ok(Expression::ModExp {
        base: Box::new(parse_general_expression(
            inner.next().ok_or("Missing base in modExp")?,
        )?),
        exponent: Box::new(parse_general_expression(
            inner.next().ok_or("Missing exponent in modExp")?,
        )?),
        modulus: Box::new(parse_general_expression(
            inner.next().ok_or("Missing modulus in modExp")?,
        )?),
    })
}

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

/// Parse substr(data, offset, size) → Expression::Substr
pub(crate) fn parse_substr(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    let data = parse_byte_value(inner.next().ok_or("Missing data in substr")?)?;
    let offset = parse_general_expression(inner.next().ok_or("Missing offset in substr")?)?;
    let size = parse_general_expression(inner.next().ok_or("Missing size in substr")?)?;
    Ok(Expression::Substr {
        data: Box::new(data),
        offset: Box::new(offset),
        size: Box::new(size),
    })
}

/// Parse cat(a, b) → Expression::Cat
pub(crate) fn parse_cat(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    let left = parse_byte_value(inner.next().ok_or("Missing first argument in cat")?)?;
    let right = parse_byte_value(inner.next().ok_or("Missing second argument in cat")?)?;
    Ok(Expression::Cat {
        left: Box::new(left),
        right: Box::new(right),
    })
}

/// Parse bitAnd/bitOr/bitXor(a, b) → Expression::Bitwise
pub(crate) fn parse_bitwise(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    let op = match inner.next().ok_or("Missing bitwise builtin name")?.as_str() {
        "bitAnd" => BitwiseOp::And,
        "bitOr" => BitwiseOp::Or,
        _ => BitwiseOp::Xor,
    };
    let left = parse_byte_value(inner.next().ok_or("Missing first bitwise operand")?)?;
    let right = parse_byte_value(inner.next().ok_or("Missing second bitwise operand")?)?;
    Ok(Expression::Bitwise {
        op,
        left: Box::new(left),
        right: Box::new(right),
    })
}

/// Parse bitNot(data) → Expression::BitNot
pub(crate) fn parse_bit_not(pair: Pair<Rule>) -> Result<Expression, String> {
    let data = parse_byte_value(pair.into_inner().next().ok_or("Missing data in bitNot")?)?;
    Ok(Expression::BitNot {
        data: Box::new(data),
    })
}

/// Parse bin2num(data) → Expression::Bin2Num
pub(crate) fn parse_bin2num(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    let data = parse_byte_value(inner.next().ok_or("Missing data in bin2num")?)?;
    Ok(Expression::Bin2Num {
        data: Box::new(data),
    })
}

/// Parse num2bin(value, size) → Expression::Num2Bin
pub(crate) fn parse_num2bin(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    let value = parse_general_expression(inner.next().ok_or("Missing value in num2bin")?)?;
    let size = parse_general_expression(inner.next().ok_or("Missing size in num2bin")?)?;
    Ok(Expression::Num2Bin {
        value: Box::new(value),
        size: Box::new(size),
    })
}

/// Parse reverseBytes(data) → Expression::ReverseBytes
pub(crate) fn parse_reverse_bytes(pair: Pair<Rule>) -> Result<Expression, String> {
    let data = parse_byte_value(
        pair.into_inner()
            .next()
            .ok_or("Missing data in reverseBytes")?,
    )?;
    Ok(Expression::ReverseBytes {
        data: Box::new(data),
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

/// Parse size(data) → Expression::SizeOf
pub(crate) fn parse_size(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    let data = parse_byte_value(inner.next().ok_or("Missing data in size")?)?;
    Ok(Expression::SizeOf {
        data: Box::new(data),
    })
}
