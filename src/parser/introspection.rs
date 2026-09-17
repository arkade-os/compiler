use super::Rule;
#[allow(unused_imports)]
use super::*;
use crate::models::*;
use pest::iterators::Pair;

pub(crate) fn parse_intent_inspect(pair: Pair<Rule>) -> Result<Expression, String> {
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
    Ok(Expression::IntentInspect {
        path: parse_named_operand(literal)?,
        presence_only,
    })
}

pub(crate) fn parse_tunnel(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    let output_index =
        parse_general_expression(inner.next().ok_or("Missing tunnel output index")?)?;
    let policy = if let Some(policy) = inner.next() {
        let Expression::StructLiteral(fields) = parse_primary_expr(policy)? else {
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
        std::array::from_fn(|_| Expression::Literal("true".to_string()))
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
    Ok(Expression::Tunnel {
        output_index: Box::new(output_index),
        policy: Box::new(policy),
        exceptions,
    })
}

// ─── Transaction Introspection Parsing ─────────────────────────────────────────

/// Parse tx_introspection pair into an Expression::TxIntrospection
pub(crate) fn parse_tx_introspection_to_expression(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();

    // Parse the property
    let property = inner
        .next()
        .ok_or("Missing tx introspection property")?
        .as_str()
        .to_string();

    Ok(Expression::TxIntrospection { property })
}

// ─── Input/Output Introspection Parsing ─────────────────────────────────────────

/// Parse input_introspection pair into an Expression::InputIntrospection
/// tx.inputs[i].value, tx.inputs[i].scriptPubKey, etc.
pub(crate) fn parse_input_introspection_to_expression(
    pair: Pair<Rule>,
) -> Result<Expression, String> {
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

    Ok(Expression::InputIntrospection {
        index: Box::new(index),
        property,
    })
}

/// Parse output_introspection pair into an Expression::OutputIntrospection
/// tx.outputs[o].value, tx.outputs[o].scriptPubKey
pub(crate) fn parse_output_introspection_to_expression(
    pair: Pair<Rule>,
) -> Result<Expression, String> {
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

    Ok(Expression::OutputIntrospection {
        index: Box::new(index),
        property,
    })
}

/// Parse tx.packet(packetType) → Expression::PacketInspect
pub(crate) fn parse_packet_inspect(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    let packet_type =
        parse_general_expression(inner.next().ok_or("Missing packet type in tx.packet()")?)?;
    Ok(Expression::PacketInspect {
        packet_type: Box::new(packet_type),
    })
}

/// Parse tx.inputs[i].packet(packetType) → Expression::InputPacketInspect
pub(crate) fn parse_input_packet_inspect(pair: Pair<Rule>) -> Result<Expression, String> {
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

    Ok(Expression::InputPacketInspect {
        index: Box::new(index),
        packet_type: Box::new(packet_type),
    })
}

pub(crate) fn parse_tx_property_to_expr(pair: Pair<Rule>) -> Result<Expression, String> {
    let text = pair.as_str();

    reject_malformed_asset_call(text)?;

    // Handle tx.assetGroups.find(txid, gidx)
    if text.starts_with("tx.assetGroups.find(") && text.ends_with(')') {
        let (asset_txid, asset_gidx) = parse_asset_group_id_operands(pair)?;
        return Ok(Expression::GroupFind {
            asset_txid: Box::new(asset_txid),
            asset_gidx: Box::new(asset_gidx),
        });
    }

    // Handle tx.assetGroups.has(txid, gidx)
    if text.starts_with("tx.assetGroups.has(") && text.ends_with(')') {
        let (asset_txid, asset_gidx) = parse_asset_group_id_operands(pair)?;
        return Ok(Expression::GroupHas {
            asset_txid: Box::new(asset_txid),
            asset_gidx: Box::new(asset_gidx),
        });
    }

    // Handle tx.assetGroups.length
    if text == "tx.assetGroups.length" {
        return Ok(Expression::AssetGroupsLength);
    }

    // Handle tx.assetGroups[idx].sumInputs or tx.assetGroups[idx].sumOutputs
    if text.starts_with("tx.assetGroups[") {
        if let Some(bracket_start) = text.find('[') {
            if let Some(bracket_end) = text.find(']') {
                let idx_str = &text[bracket_start + 1..bracket_end];
                let index = if idx_str.chars().all(|c| c.is_ascii_digit()) {
                    Expression::Literal(idx_str.to_string())
                } else {
                    Expression::Variable(idx_str.to_string())
                };

                if text.ends_with(".sumInputs") {
                    return Ok(Expression::GroupSum {
                        index: Box::new(index),
                        source: GroupSumSource::Inputs,
                    });
                } else if text.ends_with(".sumOutputs") {
                    return Ok(Expression::GroupSum {
                        index: Box::new(index),
                        source: GroupSumSource::Outputs,
                    });
                } else if text.ends_with(".numInputs") {
                    return Ok(Expression::GroupNumIO {
                        index: Box::new(index),
                        source: GroupIOSource::Inputs,
                    });
                } else if text.ends_with(".numOutputs") {
                    return Ok(Expression::GroupNumIO {
                        index: Box::new(index),
                        source: GroupIOSource::Outputs,
                    });
                }
            }
        }
    }

    // Handle tx.input.current
    if text.starts_with("tx.input.current") {
        let property = if text == "tx.input.current" {
            None
        } else {
            text.strip_prefix("tx.input.current.")
                .map(|rest| rest.to_string())
        };
        return Ok(Expression::CurrentInput(property));
    }

    // Default: treat as a property string
    Ok(Expression::Property(text.to_string()))
}
