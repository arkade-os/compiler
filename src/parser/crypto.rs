use super::Rule;
#[allow(unused_imports)]
use super::*;
use crate::models::*;
use pest::iterators::Pair;

/// Parse pubkey(x) / signature(x) / bytes20(x) / bytes32(x) / int(x) / bool(x) → Expression::Cast,
/// folding int(0x..) into a decimal literal.
pub(crate) fn parse_cast(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    let target = inner
        .next()
        .ok_or("Missing cast type")?
        .as_str()
        .to_string();
    let data_pair = inner.next().ok_or("Missing data in cast")?;
    let text = data_pair.as_str().trim();
    let data = parse_general_expression(data_pair)?;
    if target == "int" && matches!(&data, Expression::Literal(lit) if lit == text) {
        if let Some(hex) = text.strip_prefix("0x") {
            return Ok(Expression::Literal(hex_to_decimal(hex)));
        }
    }
    Ok(Expression::Cast {
        target,
        data: Box::new(data),
    })
}

/// Big-endian hex digits → decimal text, unbounded like BigNum literals.
fn hex_to_decimal(hex: &str) -> String {
    let mut digits = vec![0u32]; // little-endian decimal digits
    for nibble in hex.chars().filter_map(|c| c.to_digit(16)) {
        let mut carry = nibble;
        for digit in &mut digits {
            let value = *digit * 16 + carry;
            *digit = value % 10;
            carry = value / 10;
        }
        while carry > 0 {
            digits.push(carry % 10);
            carry /= 10;
        }
    }
    digits.iter().rev().map(|d| d.to_string()).collect()
}
