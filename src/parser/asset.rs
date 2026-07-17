use super::Rule;
#[allow(unused_imports)]
use super::*;
use crate::models::*;
use pest::iterators::Pair;

// ─── Asset Lookup Parsing ──────────────────────────────────────────────────────

/// Parse asset_lookup_comparison: asset_lookup op (arith_expr | asset_lookup | identifier | literal)
pub(crate) fn parse_asset_lookup_comparison(pair: Pair<Rule>) -> Result<Requirement, String> {
    let mut inner = pair.into_inner();

    let left_pair = inner.next().ok_or("Missing left asset lookup")?;
    let left = parse_asset_lookup_to_expression(left_pair)?;

    let op = inner
        .next()
        .ok_or("Missing comparison operator")?
        .as_str()
        .to_string();

    let right_pair = inner.next().ok_or("Missing right expression")?;
    let right = match right_pair.as_rule() {
        Rule::asset_lookup_arith_expr => parse_arith_expr_to_expression(right_pair)?,
        Rule::asset_lookup => parse_asset_lookup_to_expression(right_pair)?,
        Rule::bin2num_func => parse_bin2num(right_pair)?,
        Rule::identifier => Expression::Variable(right_pair.as_str().to_string()),
        Rule::number_literal => Expression::Literal(right_pair.as_str().to_string()),
        _ => {
            return Err(format!(
                "Unexpected right side in asset lookup comparison: {:?}",
                right_pair.as_rule()
            ))
        }
    };

    Ok(Requirement::Comparison { left, op, right })
}

/// Parse a standalone asset_lookup (not in a comparison context)
pub(crate) fn parse_standalone_asset_lookup(pair: Pair<Rule>) -> Result<Requirement, String> {
    let expr = parse_asset_lookup_to_expression(pair)?;
    // Wrap in a dummy comparison for standalone usage
    Ok(Requirement::Comparison {
        left: expr,
        op: "==".to_string(),
        right: Expression::Literal("true".to_string()),
    })
}

/// Parse an asset-id txid operand (a bytes32 identifier).
pub(crate) fn parse_asset_id_txid(pair: Pair<Rule>) -> Expression {
    Expression::Variable(pair.as_str().to_string())
}

/// Parse an asset-id gidx operand (an int identifier or a numeric literal).
pub(crate) fn parse_asset_id_gidx(pair: Pair<Rule>) -> Expression {
    match pair.as_rule() {
        Rule::number_literal => Expression::Literal(pair.as_str().to_string()),
        _ => Expression::Variable(pair.as_str().to_string()),
    }
}

/// Parse the two Asset ID operands from an asset-group access pair.
pub(crate) fn parse_asset_group_id_operands(
    pair: Pair<Rule>,
) -> Result<(Expression, Expression), String> {
    let operand_parent = match pair.as_rule() {
        Rule::tx_property_access => {
            let mut inner = pair.into_inner();
            let body = inner
                .next()
                .ok_or("asset id requires (txid, gidx) operands")?;
            if body.as_rule() != Rule::tx_property_body || inner.next().is_some() {
                return Err("asset id requires (txid, gidx) operands".to_string());
            }
            body
        }
        Rule::tx_property_body | Rule::asset_group_access => pair,
        rule => return Err(format!("unexpected asset group operand parent: {rule:?}")),
    };

    let mut operands = operand_parent.into_inner();
    let txid_pair = operands
        .next()
        .ok_or("asset id requires (txid, gidx) operands")?;
    let gidx_pair = operands
        .next()
        .ok_or("asset id requires (txid, gidx) operands")?;

    if txid_pair.as_rule() != Rule::identifier
        || !matches!(gidx_pair.as_rule(), Rule::identifier | Rule::number_literal)
        || operands.next().is_some()
    {
        return Err("asset id requires (txid, gidx) operands".to_string());
    }

    Ok((
        parse_asset_id_txid(txid_pair),
        parse_asset_id_gidx(gidx_pair),
    ))
}

/// Shared parse for `tx.{inputs,outputs}[i].assets.{lookup,has}(txid, gidx)`:
/// returns the source, the input/output index, and the two Asset ID operands.
pub(crate) fn parse_asset_lookup_operands(
    pair: Pair<Rule>,
) -> Result<(AssetLookupSource, Expression, Expression, Expression), String> {
    let mut inner = pair.into_inner();

    // Parse source: "inputs" or "outputs"
    let source_pair = inner.next().ok_or("Missing asset lookup source")?;
    let source = match source_pair.as_str() {
        "inputs" => AssetLookupSource::Input,
        "outputs" => AssetLookupSource::Output,
        _ => {
            return Err(format!(
                "Invalid asset lookup source: {}",
                source_pair.as_str()
            ))
        }
    };

    // Parse array access index
    let array_access = inner.next().ok_or("Missing array index")?;
    let index_pair = array_access
        .into_inner()
        .next()
        .ok_or("Missing index value")?;
    let index = match index_pair.as_rule() {
        Rule::number_literal => Expression::Literal(index_pair.as_str().to_string()),
        Rule::identifier => Expression::Variable(index_pair.as_str().to_string()),
        _ => Expression::Literal(index_pair.as_str().to_string()),
    };

    // Parse the canonical Asset ID operands: txid (bytes32) then gidx (int).
    let asset_txid = parse_asset_id_txid(inner.next().ok_or("Missing asset txid")?);
    let asset_gidx = parse_asset_id_gidx(inner.next().ok_or("Missing asset gidx")?);

    Ok((source, index, asset_txid, asset_gidx))
}

/// Parse an asset_lookup pair into an Expression::AssetLookup
pub(crate) fn parse_asset_lookup_to_expression(pair: Pair<Rule>) -> Result<Expression, String> {
    let (source, index, asset_txid, asset_gidx) = parse_asset_lookup_operands(pair)?;
    Ok(Expression::AssetLookup {
        source,
        index: Box::new(index),
        asset_txid: Box::new(asset_txid),
        asset_gidx: Box::new(asset_gidx),
    })
}

/// Parse an asset_has pair into an Expression::AssetHas
pub(crate) fn parse_asset_has_to_expression(pair: Pair<Rule>) -> Result<Expression, String> {
    let (source, index, asset_txid, asset_gidx) = parse_asset_lookup_operands(pair)?;
    Ok(Expression::AssetHas {
        source,
        index: Box::new(index),
        asset_txid: Box::new(asset_txid),
        asset_gidx: Box::new(asset_gidx),
    })
}

/// Parse an asset_count pair into an Expression::AssetCount
/// tx.inputs[i].assets.length or tx.outputs[o].assets.length
pub(crate) fn parse_asset_count_to_expression(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();

    // Parse source: "inputs" or "outputs"
    let source_pair = inner.next().ok_or("Missing asset count source")?;
    let source = match source_pair.as_str() {
        "inputs" => AssetLookupSource::Input,
        "outputs" => AssetLookupSource::Output,
        _ => {
            return Err(format!(
                "Invalid asset count source: {}",
                source_pair.as_str()
            ))
        }
    };

    // Parse array access index
    let array_access = inner.next().ok_or("Missing array index")?;
    let index_pair = array_access
        .into_inner()
        .next()
        .ok_or("Missing index value")?;
    let index = match index_pair.as_rule() {
        Rule::number_literal => Expression::Literal(index_pair.as_str().to_string()),
        Rule::identifier => Expression::Variable(index_pair.as_str().to_string()),
        _ => Expression::Literal(index_pair.as_str().to_string()),
    };

    Ok(Expression::AssetCount {
        source,
        index: Box::new(index),
    })
}

/// Parse an asset_at pair into an Expression::AssetAt
/// tx.inputs[i].assets[t].assetId or tx.outputs[o].assets[t].amount
pub(crate) fn parse_asset_at_to_expression(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();

    // Parse source: "inputs" or "outputs"
    let source_pair = inner.next().ok_or("Missing asset at source")?;
    let source = match source_pair.as_str() {
        "inputs" => AssetLookupSource::Input,
        "outputs" => AssetLookupSource::Output,
        _ => return Err(format!("Invalid asset at source: {}", source_pair.as_str())),
    };

    // Parse first array access (io_index)
    let io_array_access = inner.next().ok_or("Missing io array index")?;
    let io_index_pair = io_array_access
        .into_inner()
        .next()
        .ok_or("Missing io index value")?;
    let io_index = match io_index_pair.as_rule() {
        Rule::number_literal => Expression::Literal(io_index_pair.as_str().to_string()),
        Rule::identifier => Expression::Variable(io_index_pair.as_str().to_string()),
        _ => Expression::Literal(io_index_pair.as_str().to_string()),
    };

    // Parse second array access (asset_index)
    let asset_array_access = inner.next().ok_or("Missing asset array index")?;
    let asset_index_pair = asset_array_access
        .into_inner()
        .next()
        .ok_or("Missing asset index value")?;
    let asset_index = match asset_index_pair.as_rule() {
        Rule::number_literal => Expression::Literal(asset_index_pair.as_str().to_string()),
        Rule::identifier => Expression::Variable(asset_index_pair.as_str().to_string()),
        _ => Expression::Literal(asset_index_pair.as_str().to_string()),
    };

    // Parse property: "assetId" or "amount"
    let property = inner
        .next()
        .ok_or("Missing asset property")?
        .as_str()
        .to_string();

    Ok(Expression::AssetAt {
        source,
        io_index: Box::new(io_index),
        asset_index: Box::new(asset_index),
        property,
    })
}

/// Parse a standalone asset_count (not in a comparison context)
pub(crate) fn parse_standalone_asset_count(pair: Pair<Rule>) -> Result<Requirement, String> {
    let expr = parse_asset_count_to_expression(pair)?;
    Ok(Requirement::Comparison {
        left: expr,
        op: "==".to_string(),
        right: Expression::Literal("true".to_string()),
    })
}

/// Parse a standalone asset_at (not in a comparison context)
pub(crate) fn parse_standalone_asset_at(pair: Pair<Rule>) -> Result<Requirement, String> {
    let expr = parse_asset_at_to_expression(pair)?;
    Ok(Requirement::Comparison {
        left: expr,
        op: "==".to_string(),
        right: Expression::Literal("true".to_string()),
    })
}

/// Parse asset_count_comparison: asset_count op expression
pub(crate) fn parse_asset_count_comparison(pair: Pair<Rule>) -> Result<Requirement, String> {
    let mut inner = pair.into_inner();

    let left_pair = inner.next().ok_or("Missing left asset count")?;
    let left = parse_asset_count_to_expression(left_pair)?;

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
                "Unexpected right side in asset count comparison: {:?}",
                right_pair.as_rule()
            ))
        }
    };

    Ok(Requirement::Comparison { left, op, right })
}

/// Parse a standalone asset_has (require-bare): leaves the presence flag.
pub(crate) fn parse_standalone_asset_has(pair: Pair<Rule>) -> Result<Requirement, String> {
    let expr = parse_asset_has_to_expression(pair)?;
    Ok(Requirement::Comparison {
        left: expr,
        op: "==".to_string(),
        right: Expression::Literal("true".to_string()),
    })
}

/// Parse asset_has_comparison: asset_has op (identifier | number_literal)
pub(crate) fn parse_asset_has_comparison(pair: Pair<Rule>) -> Result<Requirement, String> {
    let mut inner = pair.into_inner();

    let left_pair = inner.next().ok_or("Missing left asset has")?;
    let left = parse_asset_has_to_expression(left_pair)?;

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
                "Unexpected right side in asset has comparison: {:?}",
                right_pair.as_rule()
            ))
        }
    };

    Ok(Requirement::Comparison { left, op, right })
}

/// Parse a group_control_is pair: `group.controlIs(txid, gidx)` → GroupControlIs.
pub(crate) fn parse_group_control_is_to_expression(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    let group = inner
        .next()
        .ok_or("Missing group in controlIs")?
        .as_str()
        .to_string();
    let asset_txid = parse_asset_id_txid(inner.next().ok_or("Missing controlIs txid")?);
    let asset_gidx = parse_asset_id_gidx(inner.next().ok_or("Missing controlIs gidx")?);
    Ok(Expression::GroupControlIs {
        group,
        asset_txid: Box::new(asset_txid),
        asset_gidx: Box::new(asset_gidx),
    })
}

/// Parse a standalone group_control_is (require-bare): leaves the boolean.
pub(crate) fn parse_standalone_group_control_is(pair: Pair<Rule>) -> Result<Requirement, String> {
    let expr = parse_group_control_is_to_expression(pair)?;
    Ok(Requirement::Comparison {
        left: expr,
        op: "==".to_string(),
        right: Expression::Literal("true".to_string()),
    })
}

/// Parse group_control_is_comparison: group.controlIs(...) op (identifier | number_literal)
pub(crate) fn parse_group_control_is_comparison(pair: Pair<Rule>) -> Result<Requirement, String> {
    let mut inner = pair.into_inner();

    let left_pair = inner.next().ok_or("Missing left controlIs")?;
    let left = parse_group_control_is_to_expression(left_pair)?;

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
                "Unexpected right side in controlIs comparison: {:?}",
                right_pair.as_rule()
            ))
        }
    };

    Ok(Requirement::Comparison { left, op, right })
}

/// Parse asset_at_comparison: asset_at op expression
pub(crate) fn parse_asset_at_comparison(pair: Pair<Rule>) -> Result<Requirement, String> {
    let mut inner = pair.into_inner();

    let left_pair = inner.next().ok_or("Missing left asset at")?;
    let left = parse_asset_at_to_expression(left_pair)?;

    let op = inner
        .next()
        .ok_or("Missing comparison operator")?
        .as_str()
        .to_string();

    let right_pair = inner.next().ok_or("Missing right expression")?;
    let right = match right_pair.as_rule() {
        Rule::asset_at => parse_asset_at_to_expression(right_pair)?,
        Rule::identifier => Expression::Variable(right_pair.as_str().to_string()),
        Rule::number_literal => Expression::Literal(right_pair.as_str().to_string()),
        _ => {
            return Err(format!(
                "Unexpected right side in asset at comparison: {:?}",
                right_pair.as_rule()
            ))
        }
    };

    Ok(Requirement::Comparison { left, op, right })
}

// ─── Asset Group Parsing ───────────────────────────────────────────────────────

/// Parse asset_group_access: tx.assetGroups.find(id), tx.assetGroups.length,
/// tx.assetGroups[k].property
pub(crate) fn parse_asset_group_access(pair: Pair<Rule>) -> Result<Requirement, String> {
    let text = pair.as_str();

    // Determine which variant of asset group access
    if text.contains(".find(") {
        // tx.assetGroups.find(txid, gidx)
        let (asset_txid, asset_gidx) = parse_asset_group_id_operands(pair)?;
        Ok(Requirement::Comparison {
            left: Expression::GroupFind {
                asset_txid: Box::new(asset_txid),
                asset_gidx: Box::new(asset_gidx),
            },
            op: "==".to_string(),
            right: Expression::Literal("true".to_string()),
        })
    } else if text.contains(".has(") {
        // tx.assetGroups.has(txid, gidx)
        let (asset_txid, asset_gidx) = parse_asset_group_id_operands(pair)?;
        Ok(Requirement::Comparison {
            left: Expression::GroupHas {
                asset_txid: Box::new(asset_txid),
                asset_gidx: Box::new(asset_gidx),
            },
            op: "==".to_string(),
            right: Expression::Literal("true".to_string()),
        })
    } else if text.contains(".length") {
        // tx.assetGroups.length
        Ok(Requirement::Comparison {
            left: Expression::AssetGroupsLength,
            op: "==".to_string(),
            right: Expression::Literal("true".to_string()),
        })
    } else {
        // tx.assetGroups[k].property
        let mut inner = pair.into_inner();
        let array_access = inner.next().ok_or("Missing group index")?;
        let index_pair = array_access
            .into_inner()
            .next()
            .ok_or("Missing index value")?;
        let index = match index_pair.as_rule() {
            Rule::number_literal => Expression::Literal(index_pair.as_str().to_string()),
            Rule::identifier => Expression::Variable(index_pair.as_str().to_string()),
            _ => Expression::Literal(index_pair.as_str().to_string()),
        };

        let property = inner
            .next()
            .ok_or("Missing group property")?
            .as_str()
            .to_string();

        let expr = match property.as_str() {
            "sumInputs" => Expression::GroupSum {
                index: Box::new(index),
                source: GroupSumSource::Inputs,
            },
            "sumOutputs" => Expression::GroupSum {
                index: Box::new(index),
                source: GroupSumSource::Outputs,
            },
            "numInputs" => Expression::GroupNumIO {
                index: Box::new(index),
                source: GroupIOSource::Inputs,
            },
            "numOutputs" => Expression::GroupNumIO {
                index: Box::new(index),
                source: GroupIOSource::Outputs,
            },
            _ => Expression::GroupProperty {
                group: format!("assetGroups[{}]", index_pair_to_string(&index)),
                property,
            },
        };

        Ok(Requirement::Comparison {
            left: expr,
            op: "==".to_string(),
            right: Expression::Literal("true".to_string()),
        })
    }
}

/// Parse group_property_comparison: variable.property op expression
pub(crate) fn parse_group_property_comparison(pair: Pair<Rule>) -> Result<Requirement, String> {
    let mut inner = pair.into_inner();

    let group_name = inner
        .next()
        .ok_or("Missing group variable name")?
        .as_str()
        .to_string();

    let property = inner
        .next()
        .ok_or("Missing group property")?
        .as_str()
        .to_string();

    let op = inner
        .next()
        .ok_or("Missing comparison operator")?
        .as_str()
        .to_string();

    let right_pair = inner.next().ok_or("Missing right side expression")?;
    let right = match right_pair.as_rule() {
        Rule::group_property_arith_expr => {
            // Parse group.property +/- value (e.g., tokenGroup.sumOutputs + amount)
            let mut arith_inner = right_pair.into_inner();
            let prop_access = arith_inner
                .next()
                .ok_or("Missing property access in arithmetic expression")?;
            let mut prop_inner = prop_access.into_inner();
            let var_name = prop_inner
                .next()
                .ok_or("Missing variable name in property access")?
                .as_str()
                .to_string();
            let prop_name = prop_inner
                .next()
                .ok_or("Missing property name in property access")?
                .as_str()
                .to_string();
            let left_expr = Expression::GroupProperty {
                group: var_name,
                property: prop_name,
            };
            let arith_op = arith_inner
                .next()
                .ok_or("Missing arithmetic operator")?
                .as_str()
                .to_string();
            let right_operand = arith_inner
                .next()
                .ok_or("Missing right operand in arithmetic")?;
            let right_expr = match right_operand.as_rule() {
                Rule::bin2num_func => parse_bin2num(right_operand)?,
                Rule::identifier => Expression::Variable(right_operand.as_str().to_string()),
                Rule::number_literal => Expression::Literal(right_operand.as_str().to_string()),
                _ => Expression::Property(right_operand.as_str().to_string()),
            };
            Expression::BinaryOp {
                left: Box::new(left_expr),
                op: arith_op,
                right: Box::new(right_expr),
            }
        }
        Rule::asset_lookup => parse_asset_lookup_to_expression(right_pair)?,
        Rule::asset_group_access => {
            // Parse the group access and extract the expression
            let req = parse_asset_group_access(right_pair)?;
            if let Requirement::Comparison { left, .. } = req {
                left
            } else {
                return Err("Expected expression from asset group access".to_string());
            }
        }
        Rule::identifier_property_access => {
            // Parse variable.property (e.g., group.sumInputs)
            let mut prop_inner = right_pair.into_inner();
            let var_name = prop_inner
                .next()
                .ok_or("Missing variable name in property access")?
                .as_str()
                .to_string();
            let prop_name = prop_inner
                .next()
                .ok_or("Missing property name in property access")?
                .as_str()
                .to_string();
            Expression::GroupProperty {
                group: var_name,
                property: prop_name,
            }
        }
        Rule::bin2num_func => parse_bin2num(right_pair)?,
        Rule::identifier => Expression::Variable(right_pair.as_str().to_string()),
        Rule::number_literal => Expression::Literal(right_pair.as_str().to_string()),
        _ => {
            return Err(format!(
                "Unexpected right side in group property comparison: {:?}",
                right_pair.as_rule()
            ))
        }
    };

    let left = Expression::GroupProperty {
        group: group_name,
        property,
    };

    Ok(Requirement::Comparison { left, op, right })
}
