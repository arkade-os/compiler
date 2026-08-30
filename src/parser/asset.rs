use super::Rule;
#[allow(unused_imports)]
use super::*;
use crate::models::*;
use pest::iterators::Pair;

// ─── Asset Lookup Parsing ──────────────────────────────────────────────────────

pub(crate) fn parse_asset_id_txid(pair: Pair<Rule>) -> Result<Expression, String> {
    match pair.as_rule() {
        Rule::identifier_property_access => parse_property_access(pair),
        _ => Ok(Expression::Variable(pair.as_str().to_string())),
    }
}

pub(crate) fn parse_asset_id_gidx(pair: Pair<Rule>) -> Result<Expression, String> {
    match pair.as_rule() {
        Rule::number_literal => Ok(Expression::Literal(pair.as_str().to_string())),
        Rule::identifier_property_access => parse_property_access(pair),
        _ => Ok(Expression::Variable(pair.as_str().to_string())),
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

    if !matches!(
        txid_pair.as_rule(),
        Rule::identifier | Rule::identifier_property_access
    ) || !matches!(
        gidx_pair.as_rule(),
        Rule::identifier | Rule::identifier_property_access | Rule::number_literal
    ) || operands.next().is_some()
    {
        return Err("asset id requires (txid, gidx) operands".to_string());
    }

    Ok((
        parse_asset_id_txid(txid_pair)?,
        parse_asset_id_gidx(gidx_pair)?,
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
    let asset_txid = parse_asset_id_txid(inner.next().ok_or("Missing asset txid")?)?;
    let asset_gidx = parse_asset_id_gidx(inner.next().ok_or("Missing asset gidx")?)?;

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

/// Parse a group_control_is pair: `group.controlIs(txid, gidx)` → GroupControlIs.
pub(crate) fn parse_group_control_is_to_expression(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    let group = inner
        .next()
        .ok_or("Missing group in controlIs")?
        .as_str()
        .to_string();
    let asset_txid = parse_asset_id_txid(inner.next().ok_or("Missing controlIs txid")?)?;
    let asset_gidx = parse_asset_id_gidx(inner.next().ok_or("Missing controlIs gidx")?)?;
    Ok(Expression::GroupControlIs {
        group,
        asset_txid: Box::new(asset_txid),
        asset_gidx: Box::new(asset_gidx),
    })
}
