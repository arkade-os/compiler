use super::{crypto, introspection, Rule};
use crate::builtins;
use crate::diagnostics::Span;
use crate::models::{ExprKind, Expression, Path};
use crate::operators::BinaryOperator;
#[allow(unused_imports)]
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
                let op = BinaryOperator::from_symbol(op.as_str())
                    .ok_or_else(|| format!("unknown operator '{}'", op.as_str()))?;
                let span = Span {
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

fn reject_reserved_call(name: &str, args: usize) -> Result<(), String> {
    if let Some(signature) = reserved_function_signature(name) {
        if builtins::tapscript_params(name).is_some_and(|params| params.len() == args) {
            let hint = match name {
                "older" | "after" => "; Arkade Script functions use `checkTime(timestamp)`",
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
    if let Some(builtin) = builtins::find(name) {
        return Some(builtin.signature());
    }
    if let Some(params) = builtins::tapscript_params(name) {
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
    let span: Span = pair.as_span().into();
    match pair.as_rule() {
        Rule::primary_expr => {
            let text = pair.as_str();
            let mut inner = pair.into_inner();
            let head = inner.next().ok_or("Empty primary expression")?;
            parse_chain(head, suffixes(inner)?, text)
        }
        Rule::parenthesized_expr => {
            let inner = pair.into_inner().next().ok_or("Empty grouped expression")?;
            let mut value = parse_primary_expr(inner)?;
            value.span = span;
            Ok(value)
        }
        Rule::unary_expr => {
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
                let span = Span {
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
        Rule::identifier => Ok(Expression::new(
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
        Rule::empty_list => {
            Err("`[]` is an empty list, which only `this.tunnel` takes, for its exceptions".into())
        }
        Rule::constructor => parse_constructor_to_expression(pair),
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
    apply_suffixes(value, false, &suffixes(inner)?)
}

/// A field, member-call or index suffix, and the offset where it ends.
pub(crate) enum Suffix<'a> {
    Field(&'a str, usize),
    Call(&'a str, Vec<Pair<'a, Rule>>, usize),
    Index(Pair<'a, Rule>, usize),
}

/// The suffixes `postfix` or `binding_suffix` pairs spell.
fn suffixes<'a>(pairs: impl Iterator<Item = Pair<'a, Rule>>) -> Result<Vec<Suffix<'a>>, String> {
    pairs
        .map(|pair| {
            // A pair's span can run past its last term over trailing whitespace.
            let end = pair.as_span().end();
            let mut parts = pair.into_inner();
            let part = parts.next().ok_or("Missing suffix")?;
            Ok(match (part.as_rule(), parts.next()) {
                (Rule::identifier, None) => Suffix::Field(part.as_str(), part.as_span().end()),
                (Rule::identifier, Some(args)) => {
                    let end = args.as_span().end();
                    Suffix::Call(part.as_str(), args.into_inner().collect(), end)
                }
                _ => Suffix::Index(part, end),
            })
        })
        .collect()
}

/// Resolve an operand and its suffixes: a member of `tx` or `this`, a group's
/// `.controlIs(id)`, a library call, or fields and indexes of any value.
fn parse_chain(head: Pair<Rule>, suffixes: Vec<Suffix>, text: &str) -> Result<Expression, String> {
    let span: Span = head.as_span().into();
    let root = match head.as_rule() {
        Rule::identifier => head.as_str(),
        Rule::function_call => {
            let mut inner = head.into_inner();
            let name = inner.next().ok_or("Missing function name")?.as_str();
            let args: Vec<_> = inner.collect();
            let value = match args.as_slice() {
                [data] if crypto::is_cast(name) => crypto::parse_cast(name, data.clone(), span)?,
                _ => parse_call(name.to_string(), args, span)?,
            };
            return apply_suffixes(value, false, &suffixes);
        }
        _ => return apply_suffixes(parse_primary_expr(head)?, false, &suffixes),
    };
    let name = Expression::new(ExprKind::Name(Path::new(root)), span);
    match root {
        "tx" => introspection::parse_tx_chain(name, &suffixes, text),
        "this" => introspection::parse_this_chain(name, &suffixes, text),
        _ => apply_suffixes(name, true, &suffixes),
    }
}

/// The one operand an expression pair consists of, below its operator levels and prefixes, or
/// the pair where it has more than one.
pub(crate) fn lone<'a>(pair: &Pair<'a, Rule>) -> Pair<'a, Rule> {
    let mut lone = pair.clone();
    while is_operator_level(lone.as_rule())
        || matches!(lone.as_rule(), Rule::unary_expr | Rule::primary_expr)
    {
        let mut inner = lone.clone().into_inner();
        match (inner.next(), inner.next()) {
            (Some(only), None) => lone = only,
            _ => break,
        }
    }
    lone
}

/// Apply `suffixes` to `value`, extending a binding path while it is one. A call is a library
/// call on a bare name, or `.controlIs(id)` on a `group` binding: a `plain` value, one read
/// through fields and indexes only.
pub(crate) fn apply_suffixes(
    mut value: Expression,
    mut plain: bool,
    suffixes: &[Suffix],
) -> Result<Expression, String> {
    let start = value.span.start;
    for suffix in suffixes {
        let (kind, end) = match (suffix, value.kind) {
            (Suffix::Field(field, end), ExprKind::Name(path)) => {
                (ExprKind::Name(path.field(*field)), end)
            }
            (Suffix::Index(index, end), ExprKind::Name(array)) => {
                let index = Box::new(parse_general_expression(index.clone())?);
                (ExprKind::ArrayIndex { array, index }, end)
            }
            (Suffix::Call("controlIs", args, end), kind) if plain && args.len() == 1 => {
                let group = Box::new(Expression { kind, ..value });
                let asset_id = Box::new(parse_general_expression(args[0].clone())?);
                (ExprKind::GroupControlIs { group, asset_id }, end)
            }
            (Suffix::Call(name, args, end), ExprKind::Name(path))
                if plain && path.segments.is_empty() =>
            {
                let span = Span { start, end: *end };
                let name = format!("{}.{name}", path.root);
                (parse_call(name, args.clone(), span)?.kind, end)
            }
            (Suffix::Call(name, ..), _) => {
                return Err(format!(
                    "cannot call `.{name}(...)` here; only library functions, `tx` and `this` \
                     members and `controlIs` on a group binding take arguments"
                ));
            }
            (Suffix::Field(field, end), kind) => {
                let value = Box::new(Expression { kind, ..value });
                let field = field.to_string();
                (ExprKind::FieldAccess { value, field }, end)
            }
            (Suffix::Index(index, end), kind) => {
                let value = Box::new(Expression { kind, ..value });
                let index = Box::new(parse_general_expression(index.clone())?);
                (ExprKind::IndexAccess { value, index }, end)
            }
        };
        // A call's value is no binding.
        plain &= !matches!(suffix, Suffix::Call(..));
        value = Expression::new(kind, Span { start, end: *end });
    }
    Ok(value)
}

/// A call of the function or builtin `name`.
pub(crate) fn parse_call(
    name: String,
    args: Vec<Pair<Rule>>,
    span: Span,
) -> Result<Expression, String> {
    let builtin = builtins::find(&name);
    if builtin.is_none() {
        reject_reserved_call(&name, args.len())?;
    }
    let args: Vec<Expression> = args
        .into_iter()
        .map(parse_general_expression)
        .collect::<Result<_, _>>()?;
    let Some(builtin) = builtin else {
        let return_type = None;
        return Ok(Expression::new(
            ExprKind::Call {
                name,
                args,
                return_type,
            },
            span,
        ));
    };
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
    let span: Span = pair.as_span().into();
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
