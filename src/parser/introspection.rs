use super::Rule;
#[allow(unused_imports)]
use super::*;
use crate::models::*;
use pest::iterators::Pair;

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

/// Parse a standalone tx_introspection (not in a comparison context)
pub(crate) fn parse_standalone_tx_introspection(pair: Pair<Rule>) -> Result<Requirement, String> {
    let expr = parse_tx_introspection_to_expression(pair)?;
    Ok(Requirement::Comparison {
        left: expr,
        op: "==".to_string(),
        right: Expression::Literal("true".to_string()),
    })
}

/// Parse tx_introspection_comparison: tx_introspection op expression
pub(crate) fn parse_tx_introspection_comparison(pair: Pair<Rule>) -> Result<Requirement, String> {
    let mut inner = pair.into_inner();

    let left_pair = inner.next().ok_or("Missing left tx introspection")?;
    let left = parse_tx_introspection_to_expression(left_pair)?;

    let op = inner
        .next()
        .ok_or("Missing comparison operator")?
        .as_str()
        .to_string();

    let right_pair = inner.next().ok_or("Missing right expression")?;
    let right = match right_pair.as_rule() {
        Rule::identifier => Expression::Variable(right_pair.as_str().to_string()),
        Rule::number_literal => Expression::Literal(right_pair.as_str().to_string()),
        _ => {
            return Err(format!(
                "Unexpected right side in tx introspection comparison: {:?}",
                right_pair.as_rule()
            ))
        }
    };

    Ok(Requirement::Comparison { left, op, right })
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
    let index = match index_pair.as_rule() {
        Rule::number_literal => Expression::Literal(index_pair.as_str().to_string()),
        Rule::identifier => Expression::Variable(index_pair.as_str().to_string()),
        _ => Expression::Literal(index_pair.as_str().to_string()),
    };

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
/// tx.outputs[o].value, tx.outputs[o].scriptPubKey, tx.outputs[o].nonce
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
    let index = match index_pair.as_rule() {
        Rule::number_literal => Expression::Literal(index_pair.as_str().to_string()),
        Rule::identifier => Expression::Variable(index_pair.as_str().to_string()),
        _ => Expression::Literal(index_pair.as_str().to_string()),
    };

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

/// Parse a standalone input_introspection (not in a comparison context)
pub(crate) fn parse_standalone_input_introspection(
    pair: Pair<Rule>,
) -> Result<Requirement, String> {
    let expr = parse_input_introspection_to_expression(pair)?;
    Ok(Requirement::Comparison {
        left: expr,
        op: "==".to_string(),
        right: Expression::Literal("true".to_string()),
    })
}

/// Parse a standalone output_introspection (not in a comparison context)
pub(crate) fn parse_standalone_output_introspection(
    pair: Pair<Rule>,
) -> Result<Requirement, String> {
    let expr = parse_output_introspection_to_expression(pair)?;
    Ok(Requirement::Comparison {
        left: expr,
        op: "==".to_string(),
        right: Expression::Literal("true".to_string()),
    })
}

/// Parse input_introspection_comparison: input_introspection op expression
pub(crate) fn parse_input_introspection_comparison(
    pair: Pair<Rule>,
) -> Result<Requirement, String> {
    let mut inner = pair.into_inner();

    let left_pair = inner.next().ok_or("Missing left input introspection")?;
    let left = parse_input_introspection_to_expression(left_pair)?;

    let op = inner
        .next()
        .ok_or("Missing comparison operator")?
        .as_str()
        .to_string();

    let right_pair = inner.next().ok_or("Missing right expression")?;
    let right = match right_pair.as_rule() {
        Rule::substr_func => parse_substr(right_pair)?,
        Rule::input_introspection => parse_input_introspection_to_expression(right_pair)?,
        Rule::output_introspection => parse_output_introspection_to_expression(right_pair)?,
        Rule::tx_property_access | Rule::this_property_access => {
            parse_tx_property_to_expression(right_pair)
        }
        Rule::constructor => parse_constructor_to_expression(right_pair)?,
        Rule::identifier => Expression::Variable(right_pair.as_str().to_string()),
        Rule::number_literal => Expression::Literal(right_pair.as_str().to_string()),
        _ => {
            return Err(format!(
                "Unexpected right side in input introspection comparison: {:?}",
                right_pair.as_rule()
            ))
        }
    };

    Ok(Requirement::Comparison { left, op, right })
}

/// Parse output_introspection_comparison: output_introspection op expression
pub(crate) fn parse_output_introspection_comparison(
    pair: Pair<Rule>,
) -> Result<Requirement, String> {
    let mut inner = pair.into_inner();

    let left_pair = inner.next().ok_or("Missing left output introspection")?;
    let left = parse_output_introspection_to_expression(left_pair)?;

    let op = inner
        .next()
        .ok_or("Missing comparison operator")?
        .as_str()
        .to_string();

    let right_pair = inner.next().ok_or("Missing right expression")?;
    let right = match right_pair.as_rule() {
        Rule::substr_func => parse_substr(right_pair)?,
        Rule::input_introspection => parse_input_introspection_to_expression(right_pair)?,
        Rule::output_introspection => parse_output_introspection_to_expression(right_pair)?,
        Rule::tx_property_access | Rule::this_property_access => {
            parse_tx_property_to_expression(right_pair)
        }
        Rule::constructor => parse_constructor_to_expression(right_pair)?,
        Rule::identifier => Expression::Variable(right_pair.as_str().to_string()),
        Rule::number_literal => Expression::Literal(right_pair.as_str().to_string()),
        _ => {
            return Err(format!(
                "Unexpected right side in output introspection comparison: {:?}",
                right_pair.as_rule()
            ))
        }
    };

    Ok(Requirement::Comparison { left, op, right })
}

/// Parse tx.packet(packetType) → Expression::PacketInspect
pub(crate) fn parse_packet_inspect(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    let packet_type = parse_atom_pair(inner.next().ok_or("Missing packet type in tx.packet()")?);
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
    let index = parse_atom_pair(index_pair);

    let packet_type = parse_atom_pair(
        inner
            .next()
            .ok_or("Missing packet type in tx.inputs[i].packet()")?,
    );

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

/// Convert a tx_property_access or this_property_access pair into an Expression
pub(crate) fn parse_tx_property_to_expression(pair: Pair<Rule>) -> Expression {
    let property_access = pair.as_str().to_string();

    // Special handling for tx.input.current
    if property_access.starts_with("tx.input.current") {
        let property = if property_access == "tx.input.current" {
            None
        } else {
            let parts: Vec<&str> = property_access.split('.').collect();
            if parts.len() >= 4 {
                Some(parts[3].to_string())
            } else {
                None
            }
        };
        Expression::CurrentInput(property)
    } else {
        Expression::Property(property_access)
    }
}

/// Parse a tx_property_access or this_property_access as a standalone Requirement
pub(crate) fn parse_property_access_as_requirement(
    pair: Pair<Rule>,
) -> Result<Requirement, String> {
    let expr = parse_tx_property_to_expression(pair);
    Ok(Requirement::Comparison {
        left: expr,
        op: "==".to_string(),
        right: Expression::Literal("true".to_string()),
    })
}

/// Helper to convert an Expression index to a string representation
pub(crate) fn index_pair_to_string(expr: &Expression) -> String {
    match expr {
        Expression::Literal(s) => s.clone(),
        Expression::Variable(s) => s.clone(),
        _ => "?".to_string(),
    }
}
