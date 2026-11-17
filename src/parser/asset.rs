use super::Rule;
#[allow(unused_imports)]
use super::*;
use crate::models::*;
use pest::iterators::Pair;

// ─── Asset Lookup Parsing ──────────────────────────────────────────────────────

/// Shared parse for `tx.{inputs,outputs}[i].assets.{lookup,has,tryLookup}(id)`:
/// returns the source, the input/output index, and the Asset ID operand.
pub(crate) fn parse_asset_lookup_operands(
    pair: Pair<Rule>,
) -> Result<(AssetLookupSource, Box<Expression>, Box<Expression>), String> {
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
    let index = parse_general_expression(index_pair)?;

    let asset_id = parse_general_expression(inner.next().ok_or("Missing asset id")?)?;

    Ok((source, Box::new(index), Box::new(asset_id)))
}

/// Parse an asset_lookup, asset_has or asset_try_lookup pair.
pub(crate) fn parse_asset_lookup_to_expression(pair: Pair<Rule>) -> Result<Expression, String> {
    let span: crate::diagnostics::Span = pair.as_span().into();
    let rule = pair.as_rule();
    let (source, index, asset_id) = parse_asset_lookup_operands(pair)?;
    let kind = match rule {
        Rule::asset_has => ExprKind::AssetHas {
            source,
            index,
            asset_id,
        },
        Rule::asset_try_lookup => ExprKind::AssetTryLookup {
            source,
            index,
            asset_id,
        },
        _ => ExprKind::AssetLookup {
            source,
            index,
            asset_id,
        },
    };
    Ok(Expression::new(kind, span))
}

/// Parse an asset_count pair into an ExprKind::AssetCount
/// tx.inputs[i].assets.length or tx.outputs[o].assets.length
pub(crate) fn parse_asset_count_to_expression(pair: Pair<Rule>) -> Result<Expression, String> {
    let span: crate::diagnostics::Span = pair.as_span().into();
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
    let index = parse_general_expression(index_pair)?;

    Ok(Expression::new(
        ExprKind::AssetCount {
            source,
            index: Box::new(index),
        },
        span,
    ))
}

/// Parse an asset_at pair into an ExprKind::AssetAt
/// tx.inputs[i].assets[t].assetId or tx.outputs[o].assets[t].amount
pub(crate) fn parse_asset_at_to_expression(pair: Pair<Rule>) -> Result<Expression, String> {
    let span: crate::diagnostics::Span = pair.as_span().into();
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
    let io_index = parse_general_expression(io_index_pair)?;

    // Parse second array access (asset_index)
    let asset_array_access = inner.next().ok_or("Missing asset array index")?;
    let asset_index_pair = asset_array_access
        .into_inner()
        .next()
        .ok_or("Missing asset index value")?;
    let asset_index = parse_general_expression(asset_index_pair)?;

    let property = inner
        .next()
        .map(|pair| super::introspection::named(pair, crate::properties::AssetProperty::from_name))
        .transpose()?;

    Ok(Expression::new(
        ExprKind::AssetAt {
            source,
            io_index: Box::new(io_index),
            asset_index: Box::new(asset_index),
            property,
        },
        span,
    ))
}

/// Parse a group_control_is pair: `group.controlIs(id)` → GroupControlIs.
pub(crate) fn parse_group_control_is_to_expression(pair: Pair<Rule>) -> Result<Expression, String> {
    let span = pair.as_span().into();
    let mut inner = pair.into_inner();
    let group = parse_property_access(inner.next().ok_or("Missing group in controlIs")?)?;
    parse_group_control_is(
        Box::new(group),
        inner.next().ok_or("Missing controlIs operand")?,
        span,
    )
}

/// Parse an asset_group_control_is pair applied to `group`; `span` covers the
/// group as well as the call.
pub(crate) fn parse_group_control_is(
    group: Box<Expression>,
    pair: Pair<Rule>,
    span: crate::diagnostics::Span,
) -> Result<Expression, String> {
    let asset_id = parse_asset_id(pair)?;
    Ok(Expression::new(
        ExprKind::GroupControlIs { group, asset_id },
        span,
    ))
}

/// The Asset ID operand of a call pair that has nothing else.
pub(crate) fn parse_asset_id(pair: Pair<Rule>) -> Result<Box<Expression>, String> {
    let operand = pair.into_inner().next().ok_or("Missing asset id")?;
    Ok(Box::new(parse_general_expression(operand)?))
}
