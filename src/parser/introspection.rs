use super::Rule;
#[allow(unused_imports)]
use super::*;
use crate::diagnostics::Span;
use crate::models::*;
use crate::properties::{
    AssetProperty, GroupIoProperty, GroupProperty, InputProperty, OutputProperty, ThisProperty,
    TxProperty,
};
use pest::iterators::Pair;
use Suffix::{Call, Field, Index};

/// A resolved member, where it ends, and the suffixes after it.
type Member<'s, 'a> = (ExprKind, usize, &'s [Suffix<'a>]);

/// Resolve the member chain of `this`: `this.activeInputIndex` or `this.expiry`, or else the
/// binding path it spells, which validation reports.
pub(crate) fn parse_this_chain(
    this: Expression,
    suffixes: &[Suffix],
) -> Result<Expression, String> {
    if let [Field(name, end), rest @ ..] = suffixes {
        if let Some(property) = ThisProperty::from_name(name) {
            let span = Span {
                start: this.span.start,
                end: *end,
            };
            return apply_suffixes(Expression::new(ExprKind::This(property), span), false, rest);
        }
    }
    apply_suffixes(this, true, suffixes)
}

/// Resolve the member chain of `tx` left to right, then apply the field and index suffixes
/// after the member. A chain that spells no member reads as the path it spells, `text`, which
/// validation reports.
pub(crate) fn parse_tx_chain(
    tx: Expression,
    suffixes: &[Suffix],
    text: &str,
) -> Result<Expression, String> {
    let start = tx.span.start;
    let (kind, end, rest) = match suffixes {
        [] | [Index(..), ..] => return apply_suffixes(tx, true, suffixes),
        [Field("intent", _), Call(member @ ("field" | "has"), args, end), rest @ ..]
            if args.len() == 1 =>
        {
            let path = Box::new(parse_intent_path(&args[0])?);
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
        [Field("packet", _), Call("has", args, end), rest @ ..]
        | [Call("packet", args, end), rest @ ..]
            if args.len() == 1 =>
        {
            let packet_type = operand(&args[0])?;
            let presence_only = matches!(suffixes[0], Field(..));
            (
                ExprKind::PacketInspect {
                    packet_type,
                    presence_only,
                },
                *end,
                rest,
            )
        }
        [Field("inputs", _), Index(index, _), Field("packet", _), Call("has", args, end), rest @ ..]
        | [Field("inputs", _), Index(index, _), Call("packet", args, end), rest @ ..]
            if args.len() == 1 =>
        {
            let (index, packet_type) = (operand(index)?, operand(&args[0])?);
            let presence_only = matches!(suffixes[2], Field(..));
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
        [Field(io @ ("inputs" | "outputs"), _), Index(index, _), Field("assets", _), assets @ ..] =>
        {
            let source = match *io {
                "inputs" => AssetLookupSource::Input,
                _ => AssetLookupSource::Output,
            };
            match asset_member(source, index, assets)? {
                Some(member) => member,
                None => return tx_path(text, start, suffixes),
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
                None => return tx_path(text, start, suffixes),
            }
        }
        [Field("input", _), Field("current", _), Field(property, end), rest @ ..]
            if InputProperty::from_name(property).is_some() =>
        {
            let property = InputProperty::from_name(property).ok_or("Missing input property")?;
            let span = Span { start, end: *end };
            (current_input(property, span).kind, *end, rest)
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
                group_member(Expression::new(kind, Span { start, end: *end }), members)?
            }
            [Index(index, end), members @ ..] => {
                let kind = ExprKind::AssetGroupAt {
                    index: operand(index)?,
                };
                group_member(Expression::new(kind, Span { start, end: *end }), members)?
            }
            rest => (ExprKind::Name(Path::from_key("tx.assetGroups")), *end, rest),
        },
        [Field(property, end), rest @ ..] if TxProperty::from_name(property).is_some() => {
            let property = TxProperty::from_name(property).ok_or("Missing tx property")?;
            (ExprKind::TxIntrospection { property }, *end, rest)
        }
        _ => return tx_path(text, start, suffixes),
    };
    // No member's value has members of its own to call.
    if rest.iter().any(|suffix| matches!(suffix, Call(..))) {
        return tx_path(text, start, suffixes);
    }
    apply_suffixes(Expression::new(kind, Span { start, end }), false, rest)
}

/// The member read on the assets of input or output `index`, if `assets` spells one.
fn asset_member<'s, 'a>(
    source: AssetLookupSource,
    index: &Pair<Rule>,
    assets: &'s [Suffix<'a>],
) -> Result<Option<Member<'s, 'a>>, String> {
    let index = operand(index)?;
    Ok(Some(match assets {
        [Index(asset, _), Field(property, end), rest @ ..]
            if AssetProperty::from_name(property).is_some() =>
        {
            let kind = ExprKind::AssetAt {
                source,
                io_index: index,
                asset_index: operand(asset)?,
                property: AssetProperty::from_name(property),
            };
            (kind, *end, rest)
        }
        [Index(asset, end), rest @ ..] => {
            let kind = ExprKind::AssetAt {
                source,
                io_index: index,
                asset_index: operand(asset)?,
                property: None,
            };
            (kind, *end, rest)
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
/// starts with none.
fn group_member<'s, 'a>(
    group: Expression,
    members: &'s [Suffix<'a>],
) -> Result<Member<'s, 'a>, String> {
    let io = |source: &str, index: &Pair<Rule>, property: Option<GroupIoProperty>| {
        Ok::<_, String>(ExprKind::GroupIOAccess {
            group: Box::new(group.clone()),
            io_index: operand(index)?,
            source: crate::types::group_io_source(source).ok_or("Invalid asset group io source")?,
            property,
        })
    };
    Ok(match members {
        [Call("controlIs", args, end), rest @ ..] if args.len() == 1 => {
            let asset_id = operand(&args[0])?;
            let group = Box::new(group);
            (ExprKind::GroupControlIs { group, asset_id }, *end, rest)
        }
        [Field(source @ ("inputs" | "outputs"), _), Index(index, _), Field(property, end), rest @ ..]
            if GroupIoProperty::from_name(property).is_some() =>
        {
            let property = GroupIoProperty::from_name(property);
            (io(source, index, property)?, *end, rest)
        }
        [Field(source @ ("inputs" | "outputs"), _), Index(index, end), rest @ ..] => {
            (io(source, index, None)?, *end, rest)
        }
        [Field(property, end), rest @ ..] if GroupProperty::from_name(property).is_some() => {
            let property = GroupProperty::from_name(property).ok_or("Missing group property")?;
            let group = Box::new(group);
            (ExprKind::GroupProperty { group, property }, *end, rest)
        }
        rest => (group.kind, group.span.end, rest),
    })
}

/// A `tx` chain that spells no member, as the path its `text` spells; `tx.inputs.length` and
/// `tx.outputs.length` count the inputs and outputs.
fn tx_path(text: &str, start: usize, suffixes: &[Suffix]) -> Result<Expression, String> {
    let text = trim_trivia_end(text);
    let span = Span {
        start,
        end: start + text.len(),
    };
    let text = without_trivia(text);
    let kind = match text.as_str() {
        "tx.inputs.length" => ExprKind::TxIntrospection {
            property: TxProperty::NumInputs,
        },
        "tx.outputs.length" => ExprKind::TxIntrospection {
            property: TxProperty::NumOutputs,
        },
        // `tx.input.current` needs a property it accepts.
        _ if matches!(suffixes, [Field("input", _), Field("current", _), ..]) => {
            return Err(format!(
                "tx.input.current requires one of: {} (got '{text}')",
                InputProperty::ALL
                    .iter()
                    .map(|property| property.name())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        }
        _ => ExprKind::Name(Path::from_key(&text)),
    };
    Ok(Expression::new(kind, span))
}

fn operand(pair: &Pair<Rule>) -> Result<Box<Expression>, String> {
    parse_general_expression(pair.clone()).map(Box::new)
}

/// An intent path operand; a lone string literal is checked at compile time, any other bytes
/// expression by the VM.
fn parse_intent_path(operand: &Pair<Rule>) -> Result<Expression, String> {
    let mut lone = operand.clone();
    while is_operator_level(lone.as_rule())
        || matches!(lone.as_rule(), Rule::unary_expr | Rule::primary_expr)
    {
        let mut inner = lone.clone().into_inner();
        match (inner.next(), inner.next()) {
            (Some(only), None) => lone = only,
            _ => break,
        }
    }
    if lone.as_rule() != Rule::string_literal {
        return parse_general_expression(operand.clone());
    }
    let text = parse_string_literal(lone.as_str())?;
    if !is_intent_path(&text) {
        return Err(format!("invalid intent message path '{text}'"));
    }
    let span = lone.as_span().into();
    Ok(Expression::new(
        ExprKind::Literal(parse_named_operand(lone)?),
        span,
    ))
}

/// The VM's simple path syntax: dot-separated lowercase keys and array indexes.
fn is_intent_path(path: &str) -> bool {
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

pub(crate) fn parse_tunnel(pair: Pair<Rule>) -> Result<Expression, String> {
    let span: crate::diagnostics::Span = pair.as_span().into();
    let mut inner = pair.into_inner();
    let output_index =
        parse_general_expression(inner.next().ok_or("Missing tunnel output index")?)?;
    let policy = if let Some(policy) = inner.next() {
        let ExprKind::StructLiteral { fields, .. } = parse_primary_expr(policy)?.kind else {
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
        std::array::from_fn(|_| Expression::new(ExprKind::Literal("true".to_string()), span))
    };
    let exceptions = inner
        .next()
        .map(|list| {
            list.into_inner()
                .map(parse_general_expression)
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    Ok(Expression::new(
        ExprKind::Tunnel {
            output_index: Box::new(output_index),
            policy: Box::new(policy),
            exceptions,
        },
        span,
    ))
}

/// `tx.inputs[this.activeInputIndex].<property>`, which `tx.input.current.*` spells.
fn current_input(property: InputProperty, span: crate::diagnostics::Span) -> Expression {
    let index = Expression::new(ExprKind::This(ThisProperty::ActiveInputIndex), span);
    Expression::new(
        ExprKind::InputIntrospection {
            index: Box::new(index),
            property,
        },
        span,
    )
}

/// `text` without the whitespace and comments the grammar allows between terms.
fn without_trivia(text: &str) -> String {
    let mut code = String::new();
    let mut rest = text;
    while let Some(c) = rest.chars().next() {
        match comment_len(rest) {
            Some(comment) => rest = &rest[comment..],
            None => {
                if !c.is_whitespace() {
                    code.push(c);
                }
                rest = &rest[c.len_utf8()..];
            }
        }
    }
    code
}
