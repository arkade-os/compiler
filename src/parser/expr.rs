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
    let span: crate::diagnostics::Span = pair.as_span().into();
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
        Rule::unary_expr | Rule::primary_expr => parse_primary_expr(pair),
        Rule::identifier | Rule::qualified_name => Ok(Expression::new(
            ExprKind::Variable(pair.as_str().to_string()),
            span,
        )),
        Rule::bool_literal => Ok(Expression::new(
            ExprKind::Literal(pair.as_str().to_string()),
            span,
        )),
        Rule::number_literal => Ok(Expression::new(
            ExprKind::Literal(pair.as_str().to_string()),
            span,
        )),
        Rule::tx_property_access => parse_tx_property_to_expr(pair),
        Rule::this_property_access => parse_primary_expr(pair),
        _ => {
            // Try to parse as a primary expression
            parse_primary_expr(pair)
        }
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

    if name == "negate" {
        return Err(
            "`negate(value)` was replaced by the unary minus operator; write `-value`".to_string(),
        );
    }

    if matches!(name.as_str(), "neg64" | "le64ToScriptNum" | "le32ToLe64") {
        return Err(format!(
            "`{name}` was removed with fixed-width arithmetic; use BigNum arithmetic or bin2num/num2bin"
        ));
    }

    if matches!(name.as_str(), "hash160" | "hash256" | "ripemd160") {
        return Err(format!(
            "`{name}` is only supported as `{name}(preimage) == hash` with a named or literal hash; \
             only sha256 accepts computed operands"
        ));
    }

    if let Some(signature) = reserved_function_signature(&name) {
        return Err(format!(
            "malformed reserved function call `{name}(...)`; expected {signature}"
        ));
    }

    Ok(())
}

pub(crate) fn reserved_function_signature(name: &str) -> Option<String> {
    if let Some(builtin) = crate::builtins::find(name) {
        return Some(builtin.signature());
    }
    let signature = match name {
        "checkSig" => Some("checkSig(signature, pubkey)"),
        "checkSigFromStack" => Some("checkSigFromStack(signature, pubkey, message)"),
        "checkSigFromStackVerify" => Some("checkSigFromStackVerify(signature, pubkey, message)"),
        "checkMultisig" => Some("checkMultisig([pubkeys], [sigs], threshold?)"),
        "hash160" => Some("hash160(data)"),
        "hash256" => Some("hash256(data)"),
        "ripemd160" => Some("ripemd160(data)"),
        "older" => Some("older(value)"),
        "after" => Some("after(value)"),
        "this.tunnel" => Some("this.tunnel(outputIndex, policy?, exceptions?)"),
        _ => None,
    };
    signature.map(str::to_string)
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
        Ok(text.to_string())
    }
}

/// Parse a crypto-check operand: a binding access or a byte literal.
pub(crate) fn parse_operand(pair: Pair<Rule>) -> Result<Expression, String> {
    let span: crate::diagnostics::Span = pair.as_span().into();
    match pair.as_rule() {
        Rule::sig_arg | Rule::key_expr => {
            parse_operand(pair.into_inner().next().ok_or("Missing operand")?)
        }
        Rule::named_binding => parse_property_access(pair),
        Rule::tweak_key => Err("tweak(...) is only available in tapscript functions".to_string()),
        _ => Ok(Expression::new(
            ExprKind::Literal(parse_named_operand(pair)?),
            span,
        )),
    }
}

pub(crate) fn parse_primary_expr(pair: Pair<Rule>) -> Result<Expression, String> {
    let span: crate::diagnostics::Span = pair.as_span().into();
    match pair.as_rule() {
        Rule::primary_expr => {
            let inner = pair.into_inner().next().ok_or("Empty primary expression")?;
            parse_primary_expr(inner)
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
            ExprKind::Variable(pair.as_str().to_string()),
            span,
        )),
        Rule::bool_literal => Ok(Expression::new(
            ExprKind::Literal(pair.as_str().to_string()),
            span,
        )),
        Rule::number_literal => Ok(Expression::new(
            ExprKind::Literal(pair.as_str().to_string()),
            span,
        )),
        Rule::hex_literal | Rule::string_literal => Ok(Expression::new(
            ExprKind::Literal(parse_named_operand(pair)?),
            span,
        )),
        Rule::array_index_access => {
            let mut inner = pair.into_inner();
            let array = inner
                .next()
                .ok_or("Missing array name")?
                .as_str()
                .to_string();
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
        Rule::struct_literal => Ok(Expression::new(
            ExprKind::StructLiteral(
                pair.into_inner()
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
            ),
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
                ExprKind::Property(format!("{array}.length")),
                span,
            ))
        }
        Rule::tx_property_access => parse_tx_property_to_expr(pair),
        Rule::this_property_access => {
            let property = pair.into_inner().next().ok_or("Missing this property")?;
            Ok(Expression::new(
                ExprKind::Property(format!("this.{}", property.as_str())),
                span,
            ))
        }
        Rule::tunnel => parse_tunnel(pair),
        Rule::intent_field | Rule::intent_has => parse_intent_inspect(pair),
        Rule::check_sig => {
            let mut inner = pair.into_inner();
            let signature = Box::new(parse_operand(inner.next().ok_or("Missing signature")?)?);
            let pubkey = Box::new(parse_operand(inner.next().ok_or("Missing pubkey")?)?);
            Ok(Expression::new(
                ExprKind::CheckSigExpr { signature, pubkey },
                span,
            ))
        }
        Rule::check_sig_from_stack => {
            let mut inner = pair.into_inner();
            let signature = Box::new(parse_operand(inner.next().ok_or("Missing signature")?)?);
            let pubkey = Box::new(parse_operand(inner.next().ok_or("Missing pubkey")?)?);
            let message = Box::new(parse_operand(inner.next().ok_or("Missing message")?)?);
            Ok(Expression::new(
                ExprKind::CheckSigFromStackExpr {
                    signature,
                    pubkey,
                    message,
                },
                span,
            ))
        }
        Rule::check_sig_from_stack_verify => parse_check_sig_from_stack_verify_expr(pair),
        // Byte-string manipulation
        Rule::cast_func => parse_cast(pair),
        // Packet introspection
        Rule::packet_inspect => parse_packet_inspect(pair),
        Rule::input_packet_inspect => parse_input_packet_inspect(pair),
        Rule::asset_lookup => parse_asset_lookup_to_expression(pair),
        Rule::asset_has => parse_asset_has_to_expression(pair),
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
                ExprKind::Property(pair.as_str().to_string()),
                span,
            ))
        }
    }
}

/// Parse a complex expression into a Requirement AST node
pub(crate) fn parse_complex_expression(
    pair: Pair<Rule>,
    constants: &[Constant],
) -> Result<Requirement, String> {
    match pair.as_rule() {
        Rule::general_expression => {
            let expression = parse_general_expression(pair)?;
            let span = expression.span;
            if let ExprKind::BinaryOp { left, op, right } = expression.kind {
                if op.compares() {
                    return Ok(Requirement::Comparison {
                        left: *left,
                        op,
                        right: *right,
                    });
                }
                return Ok(Requirement::Expression(Expression::new(
                    ExprKind::BinaryOp { left, op, right },
                    span,
                )));
            }
            Ok(Requirement::Expression(expression))
        }
        Rule::check_sig => parse_check_sig(pair),
        Rule::check_sig_from_stack => parse_check_sig_from_stack(pair),
        Rule::check_sig_from_stack_verify => parse_check_sig_from_stack_verify(pair),
        Rule::check_multisig => parse_check_multisig(pair, constants),
        Rule::time_comparison => parse_time_comparison(pair),
        Rule::hash_comparison => parse_hash_comparison(pair),
        _ => Err(format!(
            "Unexpected rule in complex expression: {:?}",
            pair.as_rule()
        )),
    }
}

// ─── Byte-string Manipulation Parsing ──────────────────────────────────

pub(crate) fn parse_property_access(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    let name = inner.next().ok_or("Missing binding name")?;
    let start = name.as_span().start();
    let mut value = Expression::new(
        ExprKind::Variable(name.as_str().to_string()),
        name.as_span().into(),
    );
    for suffix in inner {
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
                        kind: ExprKind::Variable(name) | ExprKind::Property(name),
                        ..
                    } => ExprKind::Property(format!("{name}.{field}")),
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
                        kind: ExprKind::Variable(array) | ExprKind::Property(array),
                        ..
                    } => ExprKind::ArrayIndex { array, index },
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
    if args.len() != builtin.params.len() {
        return Err(format!(
            "malformed reserved function call `{}(...)`; expected {}",
            builtin.name,
            builtin.signature()
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
/// `constructor_args` is a named (non-silent) rule whose children are the
/// alternatives matched by the silent `complex_expression` rule — so we
/// see the raw inner rules (identifier, number_literal, etc.) directly.
pub(crate) fn parse_constructor_args(pair: Pair<Rule>) -> Result<Vec<Expression>, String> {
    pair.into_inner().map(parse_general_expression).collect()
}

// ─── Helper Functions ──────────────────────────────────────────────────────────

/// Parse tx_property_access into the appropriate Expression type
/// Handles special patterns like tx.assetGroups[idx].sumInputs/sumOutputs
/// Reject malformed asset-API calls that fell through to the generic property
/// path. A well-formed `.assets.lookup`/`.assets.has` matches the dedicated
/// `asset_lookup`/`asset_has` rules (which require exactly two operands) before
/// any property fallback, so seeing one of these method names in a property
/// string means a legacy single-argument or otherwise malformed call.
pub(crate) fn reject_malformed_asset_call(text: &str) -> Result<(), String> {
    if text.contains(".assets.lookup(") {
        return Err(format!(
            "asset lookup requires two operands `lookup(txid, gidx)`: {text}"
        ));
    }
    if text.contains(".assets.has(") {
        return Err(format!(
            "asset presence check requires two operands `has(txid, gidx)`: {text}"
        ));
    }
    Ok(())
}
