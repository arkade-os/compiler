use super::Rule;
use crate::models::ExprKind;
use crate::models::Expression;
use crate::parser::expr;
#[allow(unused_imports)]
use pest::iterators::Pair;

/// Whether a call by `name` with one argument is a cast. Function names cannot be cast types.
///
/// Narrowing cast from bytes: bytes20/bytes32 verify the length at runtime;
/// pubkey/signature are semantic because the VM validates them when consumed.
/// int(0x..) folds a hex literal big-endian; int(bool) and bool(int) convert scalars.
/// bytes(int) produces minimal Script-number bytes; bytes-like casts widen unchanged.
/// bytes(bool) normalizes false to empty bytes and true to 0x01.
pub(crate) fn is_cast(name: &str) -> bool {
    matches!(
        name,
        "pubkey" | "signature" | "bytes20" | "bytes32" | "bytes" | "int" | "bool"
    )
}

/// Parse type(x) → ExprKind::Cast,
/// folding int(0x..) into a decimal literal.
pub(crate) fn parse_cast(
    target: &str,
    data_pair: Pair<Rule>,
    span: crate::diagnostics::Span,
) -> Result<Expression, String> {
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
