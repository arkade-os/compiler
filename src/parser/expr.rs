use super::Rule;
#[allow(unused_imports)]
use super::*;
use crate::models::*;
use pest::iterators::Pair;

/// Whether `rule` is one of the grammar's binary-operator precedence levels.
pub(crate) fn is_operator_level(rule: Rule) -> bool {
    matches!(
        rule,
        Rule::general_expression
            | Rule::logical_or_expr
            | Rule::logical_and_expr
            | Rule::comparison_expr
            | Rule::bit_or_expr
            | Rule::bit_xor_expr
            | Rule::bit_and_expr
            | Rule::shift_expr
            | Rule::additive_expr
            | Rule::multiplicative_expr
    )
}

// Parse general expression (with operator precedence)
pub(crate) fn parse_general_expression(pair: Pair<Rule>) -> Result<Expression, String> {
    match pair.as_rule() {
        rule if is_operator_level(rule) => {
            let mut inner = pair.into_inner();
            let mut result = parse_general_expression(inner.next().ok_or("Empty expression")?)?;
            while let Some(op) = inner.next() {
                let right = parse_general_expression(inner.next().ok_or("Missing right operand")?)?;
                let op = crate::operators::BinaryOperator::from_symbol(op.as_str())
                    .ok_or_else(|| format!("unknown operator '{}'", op.as_str()))?;
                let span = crate::diagnostics::Span {
                    start: result.span.start,
                    end: right.span.end,
                };
                result = Expression::new(
                    ExprKind::BinaryOp {
                        left: Box::new(result),
                        op,
                        right: Box::new(right),
                    },
                    span,
                );
            }
            Ok(result)
        }
        _ => parse_primary_expr(pair),
    }
}

// Parse primary expression (atoms)
pub(crate) fn reject_reserved_function_call(pair: &Pair<Rule>) -> Result<(), String> {
    if pair.as_rule() != Rule::function_call {
        return Ok(());
    }

    let name = pair
        .clone()
        .into_inner()
        .next()
        .ok_or("Missing call name")?
        .as_str()
        .to_string();

    if let Some(signature) = reserved_function_signature(&name) {
        let args = pair.clone().into_inner().count() - 1;
        if crate::builtins::tapscript_params(&name).is_some_and(|params| params.len() == args) {
            let hint = match name.as_str() {
                "older" | "after" => "; covenant functions use `checkTime(timestamp)`",
                "tweak" => ", as a key inside checkSig or checkMultisig",
                _ => ", inside older(...) or after(...)",
            };
            return Err(format!(
                "`{name}(...)` is only available in tapscript functions{hint}"
            ));
        }
        return Err(format!("wrong arguments to `{name}`: expected {signature}"));
    }

    Ok(())
}

pub(crate) fn reserved_function_signature(name: &str) -> Option<String> {
    if let Some(builtin) = crate::builtins::find(name) {
        return Some(builtin.signature());
    }
    if let Some(params) = crate::builtins::tapscript_params(name) {
        return Some(format!("{name}({})", params.join(", ")));
    }
    (name == "this.tunnel").then(|| "this.tunnel(outputIndex, policy?, exceptions?)".to_string())
}

pub(crate) fn parse_string_literal(text: &str) -> Result<String, String> {
    serde_json::from_str(text).map_err(|error| format!("Invalid string literal: {error}"))
}

pub(crate) fn parse_named_operand(pair: Pair<Rule>) -> Result<String, String> {
    let text = pair.as_str();
    if text.starts_with('"') {
        use std::fmt::Write;
        let mut hex = String::from("0x");
        for byte in parse_string_literal(text)?.bytes() {
            write!(hex, "{byte:02x}").expect("writing to String");
        }
        Ok(hex)
    } else {
        Ok(text.to_ascii_lowercase())
    }
}

pub(crate) fn parse_primary_expr(pair: Pair<Rule>) -> Result<Expression, String> {
    let span: crate::diagnostics::Span = pair.as_span().into();
    match pair.as_rule() {
        Rule::primary_expr => {
            let mut inner = pair.into_inner();
            let value = parse_primary_expr(inner.next().ok_or("Empty primary expression")?)?;
            parse_suffixes(value, inner)
        }
        Rule::parenthesized_expr => {
            let inner = pair.into_inner().next().ok_or("Empty grouped expression")?;
            let mut value = parse_primary_expr(inner)?;
            value.span = span;
            Ok(value)
        }
        Rule::unary_expr | Rule::unary_atom => {
            let mut inner = pair.into_inner();
            let operand = inner.next_back().ok_or("Empty unary expression")?;
            let mut value = parse_primary_expr(operand)?;
            for operator in inner.rev() {
                use crate::operators::UnaryOperator;
                let op = match operator.as_rule() {
                    Rule::sub_op => UnaryOperator::Neg,
                    Rule::not_op => UnaryOperator::Not,
                    Rule::invert_op => UnaryOperator::Invert,
                    _ => return Err("Unexpected unary operator".to_string()),
                };
                let span = crate::diagnostics::Span {
                    start: operator.as_span().start(),
                    end: value.span.end,
                };
                value = Expression::new(
                    ExprKind::Unary {
                        op,
                        value: Box::new(value),
                    },
                    span,
                );
            }
            Ok(value)
        }
        rule if is_operator_level(rule) => {
            // Parenthesized expression
            parse_general_expression(pair)
        }
        Rule::identifier | Rule::qualified_name => Ok(Expression::new(
            ExprKind::Name(Path::from_key(pair.as_str())),
            span,
        )),
        // A number's `_` digit separators carry no value.
        Rule::bool_literal | Rule::number_literal => Ok(Expression::new(
            ExprKind::Literal(pair.as_str().replace('_', "")),
            span,
        )),
        Rule::hex_literal | Rule::string_literal => Ok(Expression::new(
            ExprKind::Literal(parse_named_operand(pair)?),
            span,
        )),
        Rule::array_index_access => {
            let mut inner = pair.into_inner();
            let array = Path::from_key(inner.next().ok_or("Missing array name")?.as_str());
            let index = inner.next().ok_or("Missing array index")?;
            Ok(Expression::new(
                ExprKind::ArrayIndex {
                    array,
                    index: Box::new(parse_general_expression(index)?),
                },
                span,
            ))
        }
        Rule::array_literal => Ok(Expression::new(
            ExprKind::ArrayLiteral(
                pair.into_inner()
                    .map(parse_general_expression)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            span,
        )),
        Rule::typed_struct_literal => {
            let mut inner = pair.into_inner();
            let name = inner
                .next()
                .ok_or("Missing struct type")?
                .as_str()
                .to_string();
            let mut literal = parse_primary_expr(inner.next().ok_or("Missing struct literal")?)?;
            if let ExprKind::StructLiteral { name: ty, .. } = &mut literal.kind {
                *ty = Some(name);
            }
            literal.span = span;
            Ok(literal)
        }
        Rule::struct_literal => Ok(Expression::new(
            ExprKind::StructLiteral {
                name: None,
                fields: pair
                    .into_inner()
                    .map(|field| {
                        let mut field = field.into_inner();
                        let name = field
                            .next()
                            .ok_or("Missing struct literal field name")?
                            .as_str()
                            .to_string();
                        let value = parse_general_expression(
                            field.next().ok_or("Missing struct literal field value")?,
                        )?;
                        Ok((name, value))
                    })
                    .collect::<Result<Vec<_>, String>>()?,
            },
            span,
        )),
        Rule::array_length_access => {
            let array = pair
                .into_inner()
                .next()
                .ok_or("Missing array name")?
                .as_str()
                .to_string();
            Ok(Expression::new(
                ExprKind::Name(Path::from_key(&array).field("length")),
                span,
            ))
        }
        Rule::tx_property_access => parse_tx_property_to_expr(pair),
        Rule::this_property_access => {
            let property = pair.into_inner().next().ok_or("Missing this property")?;
            Ok(Expression::new(
                ExprKind::This(super::introspection::named(
                    property,
                    crate::properties::ThisProperty::from_name,
                )?),
                span,
            ))
        }
        Rule::tunnel => parse_tunnel(pair),
        Rule::intent_field | Rule::intent_has => parse_intent_inspect(pair),
        // Byte-string manipulation
        Rule::cast_func => parse_cast(pair),
        // Packet introspection
        Rule::packet_inspect | Rule::packet_has => parse_packet_inspect(pair),
        Rule::input_packet_inspect | Rule::input_packet_has => parse_input_packet_inspect(pair),
        Rule::asset_lookup | Rule::asset_has | Rule::asset_try_lookup => {
            parse_asset_lookup_to_expression(pair)
        }
        Rule::asset_count => parse_asset_count_to_expression(pair),
        Rule::asset_at => parse_asset_at_to_expression(pair),
        Rule::group_control_is => parse_group_control_is_to_expression(pair),
        Rule::identifier_property_access => parse_property_access(pair),
        Rule::input_introspection => parse_input_introspection_to_expression(pair),
        Rule::output_introspection => parse_output_introspection_to_expression(pair),
        Rule::tx_introspection => parse_tx_introspection_to_expression(pair),
        Rule::constructor => parse_constructor_to_expression(pair),
        Rule::function_call => {
            let name = pair
                .clone()
                .into_inner()
                .next()
                .ok_or("Missing function name")?;
            if let Some(builtin) = crate::builtins::find(name.as_str()) {
                return parse_builtin_call(builtin, pair);
            }
            reject_reserved_function_call(&pair)?;
            let mut inner = pair.into_inner();
            let name = inner
                .next()
                .ok_or("Missing function name")?
                .as_str()
                .to_string();
            let args = inner
                .map(parse_general_expression)
                .collect::<Result<_, _>>()?;
            Ok(Expression::new(
                ExprKind::Call {
                    name,
                    args,
                    return_type: None,
                },
                span,
            ))
        }
        _ => {
            // Default to treating as a property string
            Ok(Expression::new(
                ExprKind::Name(Path::from_key(pair.as_str())),
                span,
            ))
        }
    }
}

// ─── Byte-string Manipulation Parsing ──────────────────────────────────

pub(crate) fn parse_property_access(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    let name = inner.next().ok_or("Missing binding name")?;
    let value = Expression::new(
        ExprKind::Name(Path::new(name.as_str())),
        name.as_span().into(),
    );
    parse_suffixes(value, inner)
}

/// Apply `binding_suffix` pairs to `value`, extending a binding path while it is one.
fn parse_suffixes<'a>(
    mut value: Expression,
    suffixes: impl Iterator<Item = Pair<'a, Rule>>,
) -> Result<Expression, String> {
    let start = value.span.start;
    for suffix in suffixes {
        let span = crate::diagnostics::Span {
            start,
            end: suffix.as_span().end(),
        };
        let part = suffix.into_inner().next().ok_or("Missing binding suffix")?;
        let kind = match part.as_rule() {
            Rule::identifier => {
                let field = part.as_str().to_string();
                match value {
                    Expression {
                        kind: ExprKind::Name(path),
                        ..
                    } => ExprKind::Name(path.field(field)),
                    value => ExprKind::FieldAccess {
                        value: Box::new(value),
                        field,
                    },
                }
            }
            Rule::general_expression => {
                let index = Box::new(parse_general_expression(part)?);
                match value {
                    Expression {
                        kind: ExprKind::Name(path),
                        ..
                    } => ExprKind::ArrayIndex { array: path, index },
                    value => ExprKind::IndexAccess {
                        value: Box::new(value),
                        index,
                    },
                }
            }
            rule => return Err(format!("Unexpected binding suffix: {rule:?}")),
        };
        value = Expression::new(kind, span);
    }
    Ok(value)
}

/// Parse a `function_call` whose name is a builtin into a `Builtin` node.
fn parse_builtin_call(
    builtin: &'static crate::builtins::Builtin,
    pair: Pair<Rule>,
) -> Result<Expression, String> {
    let span: crate::diagnostics::Span = pair.as_span().into();
    let args: Vec<Expression> = pair
        .into_inner()
        .skip(1)
        .map(parse_general_expression)
        .collect::<Result<_, _>>()?;
    if !builtin.accepts_arity(args.len()) {
        return Err(format!(
            "wrong number of arguments to `{}`: expected {}, got {}",
            builtin.name,
            builtin.signature(),
            args.len()
        ));
    }
    Ok(Expression::new(ExprKind::Builtin { builtin, args }, span))
}

// ─── Constructor Parsing ───────────────────────────────────────────────────────

/// Parse a `constructor` rule pair into an `ExprKind::ContractInstance`.
///
/// Handles `new ContractName(arg1, arg2, ...)` and produces
/// `ContractInstance { contract_name, args }` which the compiler lowers to
/// a `<CONTRACT:ContractName(...)>` 32-byte Taproot output-key placeholder.
pub(crate) fn parse_constructor_to_expression(pair: Pair<Rule>) -> Result<Expression, String> {
    let span: crate::diagnostics::Span = pair.as_span().into();
    let mut inner = pair.into_inner();

    // First child: contract name identifier
    let contract_name = inner
        .next()
        .ok_or("Parse error: Missing contract name in constructor")?
        .as_str()
        .to_string();

    // Second child (optional): constructor_args rule
    let args = if let Some(args_pair) = inner.next() {
        parse_constructor_args(args_pair)?
    } else {
        Vec::new()
    };

    Ok(Expression::new(
        ExprKind::ContractInstance {
            contract_name,
            args,
        },
        span,
    ))
}

/// Parse constructor arguments into a Vec<Expression>.
///
/// Constructor arguments use the same expression parser as builtin calls.
pub(crate) fn parse_constructor_args(pair: Pair<Rule>) -> Result<Vec<Expression>, String> {
    pair.into_inner().map(parse_general_expression).collect()
}
