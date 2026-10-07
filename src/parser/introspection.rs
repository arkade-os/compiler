use super::Rule;
#[allow(unused_imports)]
use super::*;
use crate::models::*;
use pest::iterators::Pair;

pub(crate) fn parse_intent_inspect(pair: Pair<Rule>) -> Result<Expression, String> {
    let span: crate::diagnostics::Span = pair.as_span().into();
    let presence_only = pair.as_rule() == Rule::intent_has;
    let literal = pair.into_inner().next().ok_or("Missing intent path")?;
    let path = parse_string_literal(literal.as_str())?;
    if path.len() > 520
        || !path
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
    {
        return Err(format!("invalid intent message path '{path}'"));
    }
    Ok(Expression::new(
        ExprKind::IntentInspect {
            path: parse_named_operand(literal)?,
            presence_only,
        },
        span,
    ))
}

pub(crate) fn parse_tunnel(pair: Pair<Rule>) -> Result<Expression, String> {
    let span: crate::diagnostics::Span = pair.as_span().into();
    let mut inner = pair.into_inner();
    let output_index =
        parse_general_expression(inner.next().ok_or("Missing tunnel output index")?)?;
    let policy = if let Some(policy) = inner.next() {
        let ExprKind::StructLiteral(fields) = parse_primary_expr(policy)?.kind else {
            return Err("tunnel policy must be a struct literal".to_string());
        };
        let mut values = [None, None, None];
        for (name, value) in fields {
            let index = match name.as_str() {
                "scriptPubKey" => 0,
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
            script.ok_or("missing tunnel policy field 'scriptPubKey'")?,
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

// ─── Transaction Introspection Parsing ─────────────────────────────────────────

/// Parse tx_introspection pair into an ExprKind::TxIntrospection
pub(crate) fn parse_tx_introspection_to_expression(pair: Pair<Rule>) -> Result<Expression, String> {
    let span: crate::diagnostics::Span = pair.as_span().into();
    let mut inner = pair.into_inner();

    // Parse the property
    let property = inner
        .next()
        .ok_or("Missing tx introspection property")?
        .as_str()
        .to_string();

    Ok(Expression::new(
        ExprKind::TxIntrospection { property },
        span,
    ))
}

// ─── Input/Output Introspection Parsing ─────────────────────────────────────────

/// Parse input_introspection pair into an ExprKind::InputIntrospection
/// tx.inputs[i].value, tx.inputs[i].scriptPubKey, etc.
pub(crate) fn parse_input_introspection_to_expression(
    pair: Pair<Rule>,
) -> Result<Expression, String> {
    let span: crate::diagnostics::Span = pair.as_span().into();
    let mut inner = pair.into_inner();

    // Parse array access (the index)
    let array_access = inner.next().ok_or("Missing input index")?;
    let index_pair = array_access
        .into_inner()
        .next()
        .ok_or("Missing index value")?;
    let index = parse_general_expression(index_pair)?;

    // Parse the property
    let property = inner
        .next()
        .ok_or("Missing input introspection property")?
        .as_str()
        .to_string();

    Ok(Expression::new(
        ExprKind::InputIntrospection {
            index: Box::new(index),
            property,
        },
        span,
    ))
}

/// Parse output_introspection pair into an ExprKind::OutputIntrospection
/// tx.outputs[o].value, tx.outputs[o].scriptPubKey
pub(crate) fn parse_output_introspection_to_expression(
    pair: Pair<Rule>,
) -> Result<Expression, String> {
    let span: crate::diagnostics::Span = pair.as_span().into();
    let mut inner = pair.into_inner();

    // Parse array access (the index)
    let array_access = inner.next().ok_or("Missing output index")?;
    let index_pair = array_access
        .into_inner()
        .next()
        .ok_or("Missing index value")?;
    let index = parse_general_expression(index_pair)?;

    // Parse the property
    let property = inner
        .next()
        .ok_or("Missing output introspection property")?
        .as_str()
        .to_string();

    Ok(Expression::new(
        ExprKind::OutputIntrospection {
            index: Box::new(index),
            property,
        },
        span,
    ))
}

/// Parse tx.packet(packetType) → ExprKind::PacketInspect
pub(crate) fn parse_packet_inspect(pair: Pair<Rule>) -> Result<Expression, String> {
    let span: crate::diagnostics::Span = pair.as_span().into();
    let mut inner = pair.into_inner();
    let packet_type =
        parse_general_expression(inner.next().ok_or("Missing packet type in tx.packet()")?)?;
    Ok(Expression::new(
        ExprKind::PacketInspect {
            packet_type: Box::new(packet_type),
        },
        span,
    ))
}

/// Parse tx.inputs[i].packet(packetType) → ExprKind::InputPacketInspect
pub(crate) fn parse_input_packet_inspect(pair: Pair<Rule>) -> Result<Expression, String> {
    let span: crate::diagnostics::Span = pair.as_span().into();
    let mut inner = pair.into_inner();

    // First child: array_access — extract the index expression
    let array_access = inner
        .next()
        .ok_or("Missing input index in tx.inputs[i].packet()")?;
    let index_pair = array_access
        .into_inner()
        .next()
        .ok_or("Empty array access in tx.inputs[i].packet()")?;
    let index = parse_general_expression(index_pair)?;

    let packet_type = parse_general_expression(
        inner
            .next()
            .ok_or("Missing packet type in tx.inputs[i].packet()")?,
    )?;

    Ok(Expression::new(
        ExprKind::InputPacketInspect {
            index: Box::new(index),
            packet_type: Box::new(packet_type),
        },
        span,
    ))
}

pub(crate) fn parse_tx_property_to_expr(pair: Pair<Rule>) -> Result<Expression, String> {
    let span: crate::diagnostics::Span = pair.as_span().into();
    let text = without_trivia(pair.as_str());

    reject_malformed_asset_call(&text)?;

    // tx.assetGroups.find(txid, gidx) or tx.assetGroups[k], with an optional member
    if let Some(body) = pair
        .clone()
        .into_inner()
        .next()
        .filter(|body| body.as_rule() == Rule::tx_property_body)
    {
        let mut parts = body.into_inner();
        if let Some(group) = parts
            .next()
            .filter(|p| p.as_rule() == Rule::asset_group_ref)
        {
            return parse_asset_group_access(pair.as_span().start(), group, parts.next());
        }
    }

    // Handle tx.assetGroups.has(txid, gidx)
    if text.starts_with("tx.assetGroups.has(") && text.ends_with(')') {
        let (asset_txid, asset_gidx) = parse_asset_group_id_operands(pair)?;
        return Ok(Expression::new(
            ExprKind::GroupHas {
                asset_txid: Box::new(asset_txid),
                asset_gidx: Box::new(asset_gidx),
            },
            span,
        ));
    }

    // Handle tx.assetGroups.length
    if text == "tx.assetGroups.length" {
        return Ok(Expression::new(ExprKind::AssetGroupsLength, span));
    }

    // Handle tx.input.current.<property> — same property set as
    // tx.inputs[i].<property>, since this *is* tx.inputs[i] for the current i.
    if text.starts_with("tx.input.current") {
        return match text.strip_prefix("tx.input.current.") {
            Some(
                p @ ("value" | "scriptPubKey" | "witnessVersion" | "sequence" | "outpoint"
                | "arkadeScriptHash" | "arkadeWitnessHash"),
            ) => Ok(Expression::new(
                ExprKind::CurrentInput(Some(p.to_string())),
                span,
            )),
            _ => Err(format!(
                "tx.input.current requires one of: value, scriptPubKey, witnessVersion, sequence, \
                 outpoint, arkadeScriptHash, arkadeWitnessHash (got '{text}')"
            )),
        };
    }

    // Default: treat as a property string
    Ok(Expression::new(ExprKind::Property(text), span))
}

/// An `AssetGroup` reference and the member accessed on it, if any.
fn parse_asset_group_access(
    start: usize,
    group: Pair<Rule>,
    member: Option<Pair<Rule>>,
) -> Result<Expression, String> {
    let span = crate::diagnostics::Span {
        start,
        end: group.as_span().end(),
    };
    let mut operands = group.into_inner();
    let first = operands.next().ok_or("Missing asset group")?;
    let group = Box::new(Expression::new(
        if first.as_rule() == Rule::array_access {
            ExprKind::AssetGroupAt {
                index: Box::new(parse_array_access_index(first)?),
            }
        } else {
            ExprKind::GroupFind {
                asset_txid: Box::new(parse_asset_id_txid(first)?),
                asset_gidx: Box::new(parse_general_expression(
                    operands.next().ok_or("Missing asset group gidx")?,
                )?),
            }
        },
        span,
    ));
    let Some(member) = member else {
        return Ok(*group);
    };
    let span = crate::diagnostics::Span {
        start: span.start,
        end: member.as_span().end(),
    };
    let mut parts = member.into_inner();
    let part = parts.next().ok_or("Missing asset group member")?;
    Ok(match part.as_rule() {
        Rule::asset_group_control_is => parse_group_control_is(group, part, span)?,
        Rule::asset_group_io_source => Expression::new(
            ExprKind::GroupIOAccess {
                group,
                source: crate::typechecker::group_io_source(part.as_str())
                    .ok_or("Invalid asset group io source")?,
                io_index: Box::new(parse_array_access_index(
                    parts.next().ok_or("Missing asset group io index")?,
                )?),
                property: parts.next().map(|p| p.as_str().to_string()),
            },
            span,
        ),
        _ => Expression::new(
            ExprKind::GroupProperty {
                group,
                property: part.as_str().to_string(),
            },
            span,
        ),
    })
}

/// `text` without the whitespace and comments the grammar allows between terms.
fn without_trivia(text: &str) -> String {
    text.lines()
        .flat_map(|line| {
            line.split_once("//")
                .map_or(line, |(code, _)| code)
                .split_whitespace()
        })
        .collect()
}

/// The index inside an `array_access` pair, without surrounding trivia.
fn parse_array_access_index(array_access: Pair<Rule>) -> Result<Expression, String> {
    parse_general_expression(
        array_access
            .into_inner()
            .next()
            .ok_or("Missing index value")?,
    )
}
