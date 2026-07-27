use super::Rule;
#[allow(unused_imports)]
use super::*;
use crate::models::*;
use pest::iterators::Pair;

/// Parse tx.time >= variable → After requirement
pub(crate) fn parse_time_comparison(pair: Pair<Rule>) -> Result<Requirement, String> {
    let mut inner = pair.into_inner();
    let timelock_var = inner.next().ok_or("Missing timelock")?.as_str().to_string();
    Ok(Requirement::After {
        blocks: 0,
        timelock_var: Some(timelock_var),
    })
}

/// Parse sha256(preimage) == hash → HashEqual requirement
pub(crate) fn parse_hash_comparison(pair: Pair<Rule>) -> Result<Requirement, String> {
    let mut inner = pair.into_inner();
    let hash_func = inner.next().ok_or("Missing hash function")?;
    let mut hash_func_inner = hash_func.into_inner();
    let fn_name = hash_func_inner
        .next()
        .ok_or("Missing hash function name")?
        .as_str();
    let hash_fn = crate::models::HashFn::parse(fn_name)
        .ok_or_else(|| format!("unknown hash function {fn_name}"))?;
    let preimage_pair = hash_func_inner.next().ok_or("Missing preimage")?;
    let rhs_pair = inner.next().ok_or("Missing the hash")?;

    // The grammar wraps the hash argument in `additive_expr`, so identifiers
    // and literals surface as `Variable` / `Literal`, while byte-producing
    // primitives (substr/cat/…) and arithmetic surface as their own variants.
    let preimage_expr = parse_additive_expr(preimage_pair)?;
    let rhs_is_identifier = matches!(rhs_pair.as_rule(), Rule::identifier);

    // Fast path: a bare identifier/literal preimage AND identifier RHS keep the
    // structured HashEqual emission (`<preimage> OP_<HASH> <hash> OP_EQUAL`).
    if rhs_is_identifier {
        if let Expression::Variable(name) | Expression::Literal(name) = &preimage_expr {
            return Ok(Requirement::HashEqual {
                hash_fn,
                preimage: name.clone(),
                hash: rhs_pair.as_str().to_string(),
            });
        }
    }

    // Complex preimage and/or complex RHS: emit via Comparison so byte-producing
    // primitives expand inline. Only sha256 supports byte-expression operands.
    if !matches!(hash_fn, crate::models::HashFn::Sha256) {
        return Err(format!(
            "{fn_name} with byte-expression operands is not supported; \
             only sha256 allows substr/cat operands"
        ));
    }
    let rhs_expr = match rhs_pair.as_rule() {
        Rule::substr_func => parse_substr(rhs_pair)?,
        Rule::cat_func => parse_cat(rhs_pair)?,
        Rule::num2bin_func => parse_num2bin(rhs_pair)?,
        Rule::identifier => Expression::Variable(rhs_pair.as_str().to_string()),
        Rule::number_literal => Expression::Literal(rhs_pair.as_str().to_string()),
        _ => Expression::Property(rhs_pair.as_str().to_string()),
    };

    Ok(Requirement::Comparison {
        left: Expression::Sha256 {
            data: Box::new(preimage_expr),
        },
        op: "==".to_string(),
        right: rhs_expr,
    })
}
