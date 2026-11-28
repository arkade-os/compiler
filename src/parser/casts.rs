//! Cast calls such as `bytes32(x)`, parsed into `ExprKind::Cast`.

use super::error::Result;
use super::{expr, Rule};
use crate::diagnostics::Span;
use crate::models::{ExprKind, Expression};
use pest::iterators::Pair;

/// Whether a one-argument call of `name` is a cast; no function can be named after a cast type.
pub(crate) fn is_cast(name: &str) -> bool {
    matches!(
        name,
        "pubkey" | "signature" | "bytes20" | "bytes32" | "bytes" | "int" | "bool"
    )
}

/// `type(x)`, folding `int(0x..)` big-endian into a decimal literal.
pub(crate) fn parse_cast(target: &str, data_pair: Pair<Rule>, span: Span) -> Result<Expression> {
    let target = target.to_string();
    let text = super::trim_trivia_end(data_pair.as_str());
    let data = expr::parse_general_expression(data_pair)?;
    if target == "int"
        && matches!(&data.kind, ExprKind::Literal(lit) if lit.eq_ignore_ascii_case(text))
    {
        if let Some(hex) = text.strip_prefix("0x") {
            return Ok(Expression::new(
                ExprKind::Literal(hex_to_decimal(hex)),
                span,
            ));
        }
    }
    Ok(Expression::new(
        ExprKind::Cast {
            target,
            data: Box::new(data),
        },
        span,
    ))
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
