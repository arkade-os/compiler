//! `tx` and `this` member chains, resolved into introspection nodes. A chain that spells no
//! member parses as the plain path it spells, which validation reports.

use std::array;

use super::expr;
use super::expr::Suffix;
use super::Rule;
use crate::diagnostics::Span;
use crate::models::AssetLookupSource;
use crate::models::ExprKind;
use crate::models::Expression;
use crate::models::Path;
use crate::properties::{
    AssetProperty, GroupIoProperty, GroupProperty, InputProperty, OutputProperty, ThisProperty,
    TxProperty,
};
use crate::types;
use pest::iterators::Pair;
use Suffix::{Call, Field, Index};

/// A resolved member, where it ends, and the suffixes after it.
type Member<'s, 'a> = (ExprKind, usize, &'s [Suffix<'a>]);

/// Resolve the member chain of `this`: `this.tunnel(...)`, `this.activeInputIndex` or
/// `this.expiry`, then the suffixes after it. A chain that spells no member reads as the path
/// it spells, which validation reports.
pub(crate) fn parse_this_chain(
    this: Expression,
    suffixes: &[Suffix],
    text: &str,
) -> Result<Expression, String> {
    let start = this.span.start;
    let member = match suffixes {
        [Index(..), ..] => return expr::apply_suffixes(this, false, suffixes),
        [Call("tunnel", args, end), rest @ ..] => {
            let span = Span { start, end: *end };
            Some((parse_tunnel(args, span)?, *end, rest))
        }
        [Field(name, end), rest @ ..] => {
            ThisProperty::from_name(name).map(|property| (ExprKind::This(property), *end, rest))
        }
        _ => None,
    };
    let (kind, end, rest) = member.unwrap_or((this.kind, this.span.end, suffixes));
    member_value(kind, start, end, rest, text)
}

/// Resolve the member chain of `tx` left to right, then the suffixes after the member. A chain
/// that spells no member reads as the path it spells, which validation reports.
pub(crate) fn parse_tx_chain(
    tx: Expression,
    suffixes: &[Suffix],
    text: &str,
) -> Result<Expression, String> {
    let start = tx.span.start;
    let (kind, end, rest) = match suffixes {
        [] | [Index(..), ..] => return expr::apply_suffixes(tx, false, suffixes),
        // LIMITATION: accepts `tx.intent`, the deprecated spelling of `tx.proof`; remove it in 0.2.
        [Field("proof" | "intent", _), Call(member @ ("field" | "has"), args, end), rest @ ..]
            if args.len() == 1 =>
        {
            let path = Box::new(parse_proof_path(&args[0])?);
            let presence_only = *member == "has";
            (
                ExprKind::IntentInspect {
                    path,
                    presence_only,
                },
                *end,
                rest,
            )
        }
        // `.packet.has(type)` reads the presence flag instead of the bytes.
        [Field("packet", _), Call(method @ "has", args, end), rest @ ..]
        | [Call(method @ "packet", args, end), rest @ ..]
            if args.len() == 1 =>
        {
            let packet_type = operand(&args[0])?;
            let presence_only = *method == "has";
            (
                ExprKind::PacketInspect {
                    packet_type,
                    presence_only,
                },
                *end,
                rest,
            )
        }
        [Field("inputs", _), Index(index, _), Field("packet", _), Call(method @ "has", args, end), rest @ ..]
        | [Field("inputs", _), Index(index, _), Call(method @ "packet", args, end), rest @ ..]
            if args.len() == 1 =>
        {
            let (index, packet_type) = (operand(index)?, operand(&args[0])?);
            let presence_only = *method == "has";
            (
                ExprKind::InputPacketInspect {
                    index,
                    packet_type,
                    presence_only,
                },
                *end,
                rest,
            )
        }
        [Field(io @ ("inputs" | "outputs"), _), Field("length", end), rest @ ..] => {
            let property = match *io {
                "inputs" => TxProperty::NumInputs,
                _ => TxProperty::NumOutputs,
            };
            (ExprKind::TxIntrospection { property }, *end, rest)
        }
        [Field(io @ ("inputs" | "outputs"), _), Index(index, _), Field("assets", _), assets @ ..] =>
        {
            let source = match *io {
                "inputs" => AssetLookupSource::Input,
                _ => AssetLookupSource::Output,
            };
            match asset_member(source, index, assets)? {
                Some(member) => member,
                None => return Ok(member_path(text, start)),
            }
        }
        [Field(io @ ("inputs" | "outputs"), _), Index(index, _), Field(property, end), rest @ ..] =>
        {
            let index = operand(index)?;
            let kind = match *io {
                "inputs" => InputProperty::from_name(property)
                    .map(|property| ExprKind::InputIntrospection { index, property }),
                _ => OutputProperty::from_name(property)
                    .map(|property| ExprKind::OutputIntrospection { index, property }),
            };
            match kind {
                Some(kind) => (kind, *end, rest),
                None => return Ok(member_path(text, start)),
            }
        }
        [Field("input", _), Field("current", _), rest @ ..] => {
            let current = match rest {
                [Field(name, end), rest @ ..] => {
                    InputProperty::from_name(name).map(|property| (property, *end, rest))
                }
                _ => None,
            };
            let Some((property, end, rest)) = current else {
                return Err(format!(
                    "tx.input.current requires one of: {} (got '{}')",
                    InputProperty::ALL
                        .iter()
                        .map(|property| property.name())
                        .collect::<Vec<_>>()
                        .join(", "),
                    super::without_trivia(super::trim_trivia_end(text))
                ));
            };
            (current_input(property, Span { start, end }).kind, end, rest)
        }
        [Field("assetGroups", end), rest @ ..] => match rest {
            [Call("has", args, end), rest @ ..] if args.len() == 1 => {
                let asset_id = operand(&args[0])?;
                (ExprKind::GroupHas { asset_id }, *end, rest)
            }
            [Field("length", end), rest @ ..] => (ExprKind::AssetGroupsLength, *end, rest),
            [Call("lookup", args, end), members @ ..] if args.len() == 1 => {
                let kind = ExprKind::GroupLookup {
                    asset_id: operand(&args[0])?,
                };
                let group = Expression::new(kind, Span { start, end: *end });
                match group_member(group, members)? {
                    Some(member) => member,
                    None => return Ok(member_path(text, start)),
                }
            }
            [Index(index, end), members @ ..] => {
                let kind = ExprKind::AssetGroupAt {
                    index: operand(index)?,
                };
                let group = Expression::new(kind, Span { start, end: *end });
                match group_member(group, members)? {
                    Some(member) => member,
                    None => return Ok(member_path(text, start)),
                }
            }
            rest => (ExprKind::Name(Path::from_key("tx.assetGroups")), *end, rest),
        },
        [Field(name, end), rest @ ..] => match TxProperty::from_name(name) {
            Some(property) => (ExprKind::TxIntrospection { property }, *end, rest),
            None => return Ok(member_path(text, start)),
        },
        _ => return Ok(member_path(text, start)),
    };
    member_value(kind, start, end, rest, text)
}

/// A member's value with the field and index suffixes after it applied. A member's value has no
/// members to call, so a call after it reads the whole chain as the path `text` spells.
fn member_value(
    kind: ExprKind,
    start: usize,
    end: usize,
    rest: &[Suffix],
    text: &str,
) -> Result<Expression, String> {
    if rest.iter().any(|suffix| matches!(suffix, Call(..))) {
        return Ok(member_path(text, start));
    }
    expr::apply_suffixes(Expression::new(kind, Span { start, end }), false, rest)
}

/// The member read on the assets of input or output `index`, if `assets` spells one.
fn asset_member<'s, 'a>(
    source: AssetLookupSource,
    index: &Pair<Rule>,
    assets: &'s [Suffix<'a>],
) -> Result<Option<Member<'s, 'a>>, String> {
    let index = operand(index)?;
    Ok(Some(match assets {
        [Index(asset, end), rest @ ..] => {
            let read = match rest {
                [Field(name, end), rest @ ..] => {
                    AssetProperty::from_name(name).map(|property| (Some(property), *end, rest))
                }
                _ => None,
            };
            let (property, end, rest) = read.unwrap_or((None, *end, rest));
            let kind = ExprKind::AssetAt {
                source,
                io_index: index,
                asset_index: operand(asset)?,
                property,
            };
            (kind, end, rest)
        }
        [Field("length", end), rest @ ..] => (ExprKind::AssetCount { source, index }, *end, rest),
        [Call(method @ ("has" | "lookup" | "tryLookup"), args, end), rest @ ..]
            if args.len() == 1 =>
        {
            let asset_id = operand(&args[0])?;
            let kind = match *method {
                "has" => ExprKind::AssetHas {
                    source,
                    index,
                    asset_id,
                },
                "lookup" => ExprKind::AssetLookup {
                    source,
                    index,
                    asset_id,
                },
                _ => ExprKind::AssetTryLookup {
                    source,
                    index,
                    asset_id,
                },
            };
            (kind, *end, rest)
        }
        _ => return Ok(None),
    }))
}

/// The member read on an asset group of a `tx` chain, or the group itself when `members`
/// starts with none; `None` when a field read on a group record is not one of its own.
fn group_member<'s, 'a>(
    group: Expression,
    members: &'s [Suffix<'a>],
) -> Result<Option<Member<'s, 'a>>, String> {
    Ok(Some(match members {
        [Call("controlIs", args, end), rest @ ..] if args.len() == 1 => {
            let asset_id = operand(&args[0])?;
            let group = Box::new(group);
            (ExprKind::GroupControlIs { group, asset_id }, *end, rest)
        }
        [Field(source @ ("inputs" | "outputs"), _), Index(index, end), rest @ ..] => {
            let (property, end, rest) = match rest {
                [Field(name, end), rest @ ..] => match GroupIoProperty::from_name(name) {
                    Some(property) => (Some(property), *end, rest),
                    None => return Ok(None),
                },
                _ => (None, *end, rest),
            };
            let kind = ExprKind::GroupIOAccess {
                group: Box::new(group),
                io_index: operand(index)?,
                source: types::group_io_source(source).ok_or("Invalid asset group io source")?,
                property,
            };
            (kind, end, rest)
        }
        [Field(name, end), rest @ ..] => match GroupProperty::from_name(name) {
            Some(property) => {
                let group = Box::new(group);
                (ExprKind::GroupProperty { group, property }, *end, rest)
            }
            None => (group.kind, group.span.end, members),
        },
        _ => (group.kind, group.span.end, members),
    }))
}

/// A member chain that spells no member, as the path its `text` spells.
fn member_path(text: &str, start: usize) -> Expression {
    let text = super::trim_trivia_end(text);
    let span = Span {
        start,
        end: start + text.len(),
    };
    Expression::new(
        ExprKind::Name(Path::from_key(&super::without_trivia(text))),
        span,
    )
}

fn operand(pair: &Pair<Rule>) -> Result<Box<Expression>, String> {
    expr::parse_general_expression(pair.clone()).map(Box::new)
}

/// A proof message path operand; a lone string literal is checked at compile time, any other
/// bytes expression by the VM.
fn parse_proof_path(operand: &Pair<Rule>) -> Result<Expression, String> {
    let literal = expr::lone(operand);
    if literal.as_rule() != Rule::string_literal {
        return expr::parse_general_expression(operand.clone());
    }
    let text = expr::parse_string_literal(literal.as_str())?;
    if !is_proof_path(&text) {
        return Err(format!("invalid proof message path '{text}'"));
    }
    let span = literal.as_span().into();
    Ok(Expression::new(
        ExprKind::Literal(expr::parse_named_operand(literal)?),
        span,
    ))
}

/// The VM's simple path syntax: dot-separated lowercase keys and array indexes.
fn is_proof_path(path: &str) -> bool {
    path.len() <= 520
        && path
            .split('.')
            .all(|segment| match segment.as_bytes().first() {
                Some(b'0'..=b'9') => {
                    !(segment.len() > 1 && segment.starts_with('0'))
                        && segment
                            .parse::<u64>()
                            .is_ok_and(|index| index < 1024 * 1024)
                }
                Some(b'a'..=b'z' | b'_') => segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'),
                _ => false,
            })
}

/// `this.tunnel(outputIndex, policy?, exceptions?)`, its policy a struct literal and its
/// exceptions a list literal.
fn parse_tunnel(args: &[Pair<Rule>], span: Span) -> Result<ExprKind, String> {
    let literal = |at: usize, rules: &[Rule]| match args.get(at).map(expr::lone) {
        Some(arg) if rules.contains(&arg.as_rule()) => Ok(Some(arg)),
        Some(_) => Err(()),
        None => Ok(None),
    };
    let (Some(index), Ok(policy), Ok(exceptions)) = (
        args.first().filter(|_| args.len() <= 3),
        literal(1, &[Rule::struct_literal]),
        literal(2, &[Rule::array_literal, Rule::empty_list]),
    ) else {
        // Arguments no tunnel takes read as a call, which reports the signature.
        return expr::parse_call("this.tunnel".to_string(), args.to_vec(), span)
            .map(|call| call.kind);
    };
    let output_index = expr::parse_general_expression(index.clone())?;
    let policy = if let Some(policy) = policy {
        let ExprKind::StructLiteral { fields, .. } = expr::parse_primary_expr(policy)?.kind else {
            return Err("tunnel policy must be a struct literal".to_string());
        };
        let mut values = [None, None, None];
        for (name, value) in fields {
            let index = match name.as_str() {
                "script" => 0,
                "value" => 1,
                "assets" => 2,
                _ => return Err(format!("unknown tunnel policy field '{name}'")),
            };
            if values[index].replace(value).is_some() {
                return Err(format!("duplicate tunnel policy field '{name}'"));
            }
        }
        let [script, value, assets] = values;
        [
            script.ok_or("missing tunnel policy field 'script'")?,
            value.ok_or("missing tunnel policy field 'value'")?,
            assets.ok_or("missing tunnel policy field 'assets'")?,
        ]
    } else {
        array::from_fn(|_| Expression::new(ExprKind::Literal("true".to_string()), span))
    };
    let exceptions = exceptions
        .map(|list| {
            list.into_inner()
                .map(expr::parse_general_expression)
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    Ok(ExprKind::Tunnel {
        output_index: Box::new(output_index),
        policy: Box::new(policy),
        exceptions,
    })
}

/// `tx.inputs[this.activeInputIndex].<property>`, which `tx.input.current.*` spells.
fn current_input(property: InputProperty, span: Span) -> Expression {
    let index = Expression::new(ExprKind::This(ThisProperty::ActiveInputIndex), span);
    Expression::new(
        ExprKind::InputIntrospection {
            index: Box::new(index),
            property,
        },
        span,
    )
}
