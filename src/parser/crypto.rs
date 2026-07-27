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
    let data = match data_pair.as_rule() {
        Rule::identifier => Expression::Variable(data_pair.as_str().to_string()),
        Rule::number_literal => Expression::Literal(data_pair.as_str().to_string()),
        _ => Expression::Property(data_pair.as_str().to_string()),
    };
    Ok(Expression::Sha256Initialize {
        data: Box::new(data),
    })
}

/// Parse sha256Update(ctx, chunk) → Expression::Sha256Update
pub(crate) fn parse_sha256_update(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    let ctx_pair = inner.next().ok_or("Missing context in sha256Update")?;
    let context = Expression::Variable(ctx_pair.as_str().to_string());

    let chunk_pair = inner.next().ok_or("Missing chunk in sha256Update")?;
    let chunk = match chunk_pair.as_rule() {
        Rule::identifier => Expression::Variable(chunk_pair.as_str().to_string()),
        Rule::number_literal => Expression::Literal(chunk_pair.as_str().to_string()),
        _ => Expression::Property(chunk_pair.as_str().to_string()),
    };
    Ok(Expression::Sha256Update {
        context: Box::new(context),
        chunk: Box::new(chunk),
    })
}

/// Parse sha256Finalize(ctx, lastChunk) → Expression::Sha256Finalize
pub(crate) fn parse_sha256_finalize(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    let ctx_pair = inner.next().ok_or("Missing context in sha256Finalize")?;
    let context = Expression::Variable(ctx_pair.as_str().to_string());

    let chunk_pair = inner.next().ok_or("Missing lastChunk in sha256Finalize")?;
    let last_chunk = match chunk_pair.as_rule() {
        Rule::identifier => Expression::Variable(chunk_pair.as_str().to_string()),
        Rule::number_literal => Expression::Literal(chunk_pair.as_str().to_string()),
        _ => Expression::Property(chunk_pair.as_str().to_string()),
    };
    Ok(Expression::Sha256Finalize {
        context: Box::new(context),
        last_chunk: Box::new(last_chunk),
    })
}

// ─── Arithmetic Parsing ────────────────────────────────────────────────

/// Parse negate(value) → Expression::Negate
pub(crate) fn parse_negate(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    let value_pair = inner.next().ok_or("Missing value in negate")?;
    let value = match value_pair.as_rule() {
        Rule::identifier => Expression::Variable(value_pair.as_str().to_string()),
        Rule::number_literal => Expression::Literal(value_pair.as_str().to_string()),
        _ => Expression::Property(value_pair.as_str().to_string()),
    };
    Ok(Expression::Negate {
        value: Box::new(value),
    })
}

/// Parse modExp(base, exponent, modulus) → Expression::ModExp
pub(crate) fn parse_mod_exp(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    Ok(Expression::ModExp {
        base: Box::new(parse_atom_pair(
            inner.next().ok_or("Missing base in modExp")?,
        )),
        exponent: Box::new(parse_atom_pair(
            inner.next().ok_or("Missing exponent in modExp")?,
        )),
        modulus: Box::new(parse_atom_pair(
            inner.next().ok_or("Missing modulus in modExp")?,
        )),
    })
}

// ─── Crypto Opcodes Parsing ────────────────────────────────────────────

/// Parse ecMulScalarVerify(k, P, Q) → Expression::EcMulScalarVerify
pub(crate) fn parse_ec_mul_scalar_verify(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();

    let scalar_pair = inner
        .next()
        .ok_or("Missing scalar k in ecMulScalarVerify")?;
    let scalar = match scalar_pair.as_rule() {
        Rule::identifier => Expression::Variable(scalar_pair.as_str().to_string()),
        Rule::number_literal => Expression::Literal(scalar_pair.as_str().to_string()),
        _ => Expression::Property(scalar_pair.as_str().to_string()),
    };

    let point_p_pair = inner.next().ok_or("Missing point P in ecMulScalarVerify")?;
    let point_p = match point_p_pair.as_rule() {
        Rule::identifier => Expression::Variable(point_p_pair.as_str().to_string()),
        Rule::number_literal => Expression::Literal(point_p_pair.as_str().to_string()),
        _ => Expression::Property(point_p_pair.as_str().to_string()),
    };

    let point_q_pair = inner.next().ok_or("Missing point Q in ecMulScalarVerify")?;
    let point_q = match point_q_pair.as_rule() {
        Rule::identifier => Expression::Variable(point_q_pair.as_str().to_string()),
        Rule::number_literal => Expression::Literal(point_q_pair.as_str().to_string()),
        _ => Expression::Property(point_q_pair.as_str().to_string()),
    };

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
    let point_p = match point_p_pair.as_rule() {
        Rule::identifier => Expression::Variable(point_p_pair.as_str().to_string()),
        Rule::number_literal => Expression::Literal(point_p_pair.as_str().to_string()),
        _ => Expression::Property(point_p_pair.as_str().to_string()),
    };

    let tweak_pair = inner.next().ok_or("Missing tweak k in tweakVerify")?;
    let tweak = match tweak_pair.as_rule() {
        Rule::identifier => Expression::Variable(tweak_pair.as_str().to_string()),
        Rule::number_literal => Expression::Literal(tweak_pair.as_str().to_string()),
        _ => Expression::Property(tweak_pair.as_str().to_string()),
    };

    let point_q_pair = inner.next().ok_or("Missing point Q in tweakVerify")?;
    let point_q = match point_q_pair.as_rule() {
        Rule::identifier => Expression::Variable(point_q_pair.as_str().to_string()),
        Rule::number_literal => Expression::Literal(point_q_pair.as_str().to_string()),
        _ => Expression::Property(point_q_pair.as_str().to_string()),
    };

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
    let signature = inner
        .next()
        .ok_or("Missing signature in checkSigFromStackVerify")?
        .as_str()
        .to_string();
    let pubkey = inner
        .next()
        .ok_or("Missing pubkey in checkSigFromStackVerify")?
        .as_str()
        .to_string();
    let message = inner
        .next()
        .ok_or("Missing message in checkSigFromStackVerify")?
        .as_str()
        .to_string();

    Ok(Expression::CheckSigFromStackVerify {
        signature,
        pubkey,
        message,
    })
}

/// Parse substr(data, offset, size) → Expression::Substr
pub(crate) fn parse_substr(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    let data = parse_byte_value(inner.next().ok_or("Missing data in substr")?)?;
    let offset = parse_atom_pair(inner.next().ok_or("Missing offset in substr")?);
    let size = parse_atom_pair(inner.next().ok_or("Missing size in substr")?);
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
    let value = parse_atom_pair(inner.next().ok_or("Missing value in num2bin")?);
    let size = parse_atom_pair(inner.next().ok_or("Missing size in num2bin")?);
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

/// Parse size(data) → Expression::SizeOf
pub(crate) fn parse_size(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    let data = parse_byte_value(inner.next().ok_or("Missing data in size")?)?;
    Ok(Expression::SizeOf {
        data: Box::new(data),
    })
}
