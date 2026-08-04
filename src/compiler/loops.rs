use crate::models::*;

use super::internal_array_binding_name;

// ─── Loop Unrolling ─────────────────────────────────────────────────────────────

/// Substitute loop variables in the body for a specific iteration index k.
///
/// Transforms:
/// - `GroupProperty { group: value_var, property: "sumOutputs" }` → `GroupSum { index: k, source: Outputs }`
/// - `GroupProperty { group: value_var, property: "sumInputs" }` → `GroupSum { index: k, source: Inputs }`
/// - `Variable(index_var)` → `Literal(k)`
/// - `Variable(value_var)` → its internal array-element binding
/// - Property-form indexing `arr[index_var]` → the same internal binding
pub(crate) fn substitute_loop_body(
    body: &[Statement],
    index_var: &str,
    value_var: &str,
    k: usize,
    array_name: &str,
) -> Vec<Statement> {
    body.iter()
        .map(|stmt| substitute_statement(stmt, index_var, value_var, k, array_name))
        .collect()
}

pub(crate) fn substitute_statement(
    stmt: &Statement,
    index_var: &str,
    value_var: &str,
    k: usize,
    array_name: &str,
) -> Statement {
    match stmt {
        Statement::Require(req) => Statement::Require(substitute_requirement(
            req, index_var, value_var, k, array_name,
        )),
        Statement::LetBinding {
            name,
            declared_type,
            value,
        } => Statement::LetBinding {
            name: name.clone(),
            declared_type: declared_type.clone(),
            value: substitute_expression(value, index_var, value_var, k, array_name),
        },
        Statement::VarAssign { name, value } => Statement::VarAssign {
            name: name.clone(),
            value: substitute_expression(value, index_var, value_var, k, array_name),
        },
        Statement::IfElse {
            condition,
            then_body,
            else_body,
        } => Statement::IfElse {
            condition: substitute_expression(condition, index_var, value_var, k, array_name),
            then_body: substitute_loop_body(then_body, index_var, value_var, k, array_name),
            else_body: else_body
                .as_ref()
                .map(|b| substitute_loop_body(b, index_var, value_var, k, array_name)),
        },
        Statement::ForIn {
            index_var: inner_idx,
            value_var: inner_val,
            iterable,
            body,
        } => Statement::ForIn {
            index_var: inner_idx.clone(),
            value_var: inner_val.clone(),
            iterable: substitute_expression(iterable, index_var, value_var, k, array_name),
            body: substitute_loop_body(body, index_var, value_var, k, array_name),
        },
    }
}

pub(crate) fn substitute_requirement(
    req: &Requirement,
    index_var: &str,
    value_var: &str,
    k: usize,
    array_name: &str,
) -> Requirement {
    match req {
        Requirement::Expression(expr) => Requirement::Expression(substitute_expression(
            expr, index_var, value_var, k, array_name,
        )),
        Requirement::Comparison { left, op, right } => Requirement::Comparison {
            left: substitute_expression(left, index_var, value_var, k, array_name),
            op: op.clone(),
            right: substitute_expression(right, index_var, value_var, k, array_name),
        },
        Requirement::CheckSig { signature, pubkey } => Requirement::CheckSig {
            signature: substitute_loop_name(signature, index_var, value_var, k, array_name),
            pubkey: substitute_loop_name(pubkey, index_var, value_var, k, array_name),
        },
        Requirement::CheckSigFromStack {
            signature,
            pubkey,
            message,
        } => Requirement::CheckSigFromStack {
            signature: substitute_loop_name(signature, index_var, value_var, k, array_name),
            pubkey: substitute_loop_name(pubkey, index_var, value_var, k, array_name),
            message: substitute_loop_name(message, index_var, value_var, k, array_name),
        },
        Requirement::CheckMultisig {
            pubkeys,
            signatures,
            threshold,
        } => Requirement::CheckMultisig {
            pubkeys: pubkeys
                .iter()
                .map(|name| substitute_loop_name(name, index_var, value_var, k, array_name))
                .collect(),
            signatures: signatures
                .iter()
                .map(|name| substitute_loop_name(name, index_var, value_var, k, array_name))
                .collect(),
            threshold: *threshold,
        },
        Requirement::After {
            blocks,
            timelock_var,
        } => Requirement::After {
            blocks: *blocks,
            timelock_var: timelock_var
                .as_ref()
                .map(|name| substitute_loop_name(name, index_var, value_var, k, array_name)),
        },
        Requirement::HashEqual {
            hash_fn,
            preimage,
            hash,
        } => Requirement::HashEqual {
            hash_fn: hash_fn.clone(),
            preimage: substitute_loop_name(preimage, index_var, value_var, k, array_name),
            hash: substitute_loop_name(hash, index_var, value_var, k, array_name),
        },
    }
}

fn substitute_loop_name(
    name: &str,
    index_var: &str,
    value_var: &str,
    k: usize,
    array_name: &str,
) -> String {
    if name == index_var {
        return k.to_string();
    }
    if name == value_var {
        return internal_array_binding_name(array_name, &k.to_string());
    }
    if let Some(open) = name.find('[') {
        if name.ends_with(']') {
            let index = &name[open + 1..name.len() - 1];
            if index == index_var {
                return internal_array_binding_name(&name[..open], &k.to_string());
            }
            if index == value_var {
                return format!(
                    "{}[{}]",
                    &name[..open],
                    internal_array_binding_name(array_name, &k.to_string())
                );
            }
        }
    }
    name.to_string()
}

pub(crate) fn substitute_expression(
    expr: &Expression,
    index_var: &str,
    value_var: &str,
    k: usize,
    array_name: &str,
) -> Expression {
    match expr {
        // Replace index variable with literal k
        Expression::Variable(var) if var == index_var => Expression::Literal(k.to_string()),
        // Replace the value variable with its source-impossible stack binding.
        Expression::Variable(var) if var == value_var => {
            Expression::Variable(internal_array_binding_name(array_name, &k.to_string()))
        }
        Expression::ArrayLiteral(elements) => Expression::ArrayLiteral(
            elements
                .iter()
                .map(|element| substitute_expression(element, index_var, value_var, k, array_name))
                .collect(),
        ),
        Expression::StructLiteral(fields) => Expression::StructLiteral(
            fields
                .iter()
                .map(|(name, value)| {
                    (
                        name.clone(),
                        substitute_expression(value, index_var, value_var, k, array_name),
                    )
                })
                .collect(),
        ),
        Expression::ArrayIndex { array, index } => Expression::ArrayIndex {
            array: array.clone(),
            index: Box::new(substitute_expression(
                index, index_var, value_var, k, array_name,
            )),
        },
        Expression::GroupProperty { group, property } => Expression::GroupProperty {
            group: substitute_loop_name(group, index_var, value_var, k, array_name),
            property: property.clone(),
        },
        // Handle property strings that represent array indexing (e.g., "oracles[i]").
        Expression::Property(prop) => {
            // Check if this looks like array indexing
            if let Some(bracket_start) = prop.find('[') {
                if let Some(bracket_end) = prop.find(']') {
                    let arr_name = &prop[..bracket_start];
                    let idx = &prop[bracket_start + 1..bracket_end];
                    if idx == index_var {
                        return Expression::Variable(internal_array_binding_name(
                            arr_name,
                            &k.to_string(),
                        ));
                    }
                    if idx == value_var {
                        return Expression::Property(format!(
                            "{arr_name}[{}]",
                            internal_array_binding_name(array_name, &k.to_string())
                        ));
                    }
                }
            }
            expr.clone()
        }
        // Recursively substitute in binary operations
        Expression::BinaryOp { left, op, right } => Expression::BinaryOp {
            left: Box::new(substitute_expression(
                left, index_var, value_var, k, array_name,
            )),
            op: op.clone(),
            right: Box::new(substitute_expression(
                right, index_var, value_var, k, array_name,
            )),
        },
        Expression::CheckSigFromStackExpr {
            signature,
            pubkey,
            message,
        } => Expression::CheckSigFromStackExpr {
            signature: substitute_loop_name(signature, index_var, value_var, k, array_name),
            pubkey: substitute_loop_name(pubkey, index_var, value_var, k, array_name),
            message: substitute_loop_name(message, index_var, value_var, k, array_name),
        },
        Expression::CheckSigExpr { signature, pubkey } => Expression::CheckSigExpr {
            signature: substitute_loop_name(signature, index_var, value_var, k, array_name),
            pubkey: substitute_loop_name(pubkey, index_var, value_var, k, array_name),
        },
        Expression::CheckSigFromStackVerify {
            signature,
            pubkey,
            message,
        } => Expression::CheckSigFromStackVerify {
            signature: substitute_loop_name(signature, index_var, value_var, k, array_name),
            pubkey: substitute_loop_name(pubkey, index_var, value_var, k, array_name),
            message: substitute_loop_name(message, index_var, value_var, k, array_name),
        },
        // Handle InputIntrospection - substitute index if it matches loop variable
        Expression::InputIntrospection { index, property } => Expression::InputIntrospection {
            index: Box::new(substitute_expression(
                index, index_var, value_var, k, array_name,
            )),
            property: property.clone(),
        },
        // Handle OutputIntrospection - substitute index if it matches loop variable
        Expression::OutputIntrospection { index, property } => Expression::OutputIntrospection {
            index: Box::new(substitute_expression(
                index, index_var, value_var, k, array_name,
            )),
            property: property.clone(),
        },
        Expression::Negate { value } => Expression::Negate {
            value: Box::new(substitute_expression(
                value, index_var, value_var, k, array_name,
            )),
        },
        Expression::ReverseBytes { data } => Expression::ReverseBytes {
            data: Box::new(substitute_expression(
                data, index_var, value_var, k, array_name,
            )),
        },
        Expression::Sighash { hash_type } => Expression::Sighash {
            hash_type: Box::new(substitute_expression(
                hash_type, index_var, value_var, k, array_name,
            )),
        },
        Expression::Digest { data, hash_type } => Expression::Digest {
            data: Box::new(substitute_expression(
                data, index_var, value_var, k, array_name,
            )),
            hash_type: Box::new(substitute_expression(
                hash_type, index_var, value_var, k, array_name,
            )),
        },
        Expression::ModExp {
            base,
            exponent,
            modulus,
        } => Expression::ModExp {
            base: Box::new(substitute_expression(
                base, index_var, value_var, k, array_name,
            )),
            exponent: Box::new(substitute_expression(
                exponent, index_var, value_var, k, array_name,
            )),
            modulus: Box::new(substitute_expression(
                modulus, index_var, value_var, k, array_name,
            )),
        },
        Expression::EcAdd {
            x1,
            y1,
            x2,
            y2,
            curve_id,
        } => Expression::EcAdd {
            x1: Box::new(substitute_expression(
                x1, index_var, value_var, k, array_name,
            )),
            y1: Box::new(substitute_expression(
                y1, index_var, value_var, k, array_name,
            )),
            x2: Box::new(substitute_expression(
                x2, index_var, value_var, k, array_name,
            )),
            y2: Box::new(substitute_expression(
                y2, index_var, value_var, k, array_name,
            )),
            curve_id: Box::new(substitute_expression(
                curve_id, index_var, value_var, k, array_name,
            )),
        },
        Expression::EcMul {
            x,
            y,
            scalar,
            curve_id,
        } => Expression::EcMul {
            x: Box::new(substitute_expression(
                x, index_var, value_var, k, array_name,
            )),
            y: Box::new(substitute_expression(
                y, index_var, value_var, k, array_name,
            )),
            scalar: Box::new(substitute_expression(
                scalar, index_var, value_var, k, array_name,
            )),
            curve_id: Box::new(substitute_expression(
                curve_id, index_var, value_var, k, array_name,
            )),
        },
        Expression::EcPairing {
            g1_x,
            g1_y,
            g2_x_c1,
            g2_x_c0,
            g2_y_c1,
            g2_y_c0,
            curve_id,
        } => Expression::EcPairing {
            g1_x: Box::new(substitute_expression(
                g1_x, index_var, value_var, k, array_name,
            )),
            g1_y: Box::new(substitute_expression(
                g1_y, index_var, value_var, k, array_name,
            )),
            g2_x_c1: Box::new(substitute_expression(
                g2_x_c1, index_var, value_var, k, array_name,
            )),
            g2_x_c0: Box::new(substitute_expression(
                g2_x_c0, index_var, value_var, k, array_name,
            )),
            g2_y_c1: Box::new(substitute_expression(
                g2_y_c1, index_var, value_var, k, array_name,
            )),
            g2_y_c0: Box::new(substitute_expression(
                g2_y_c0, index_var, value_var, k, array_name,
            )),
            curve_id: Box::new(substitute_expression(
                curve_id, index_var, value_var, k, array_name,
            )),
        },
        Expression::AssetCount { source, index } => Expression::AssetCount {
            source: source.clone(),
            index: Box::new(substitute_expression(
                index, index_var, value_var, k, array_name,
            )),
        },
        Expression::GroupSum { source, index } => Expression::GroupSum {
            source: source.clone(),
            index: Box::new(substitute_expression(
                index, index_var, value_var, k, array_name,
            )),
        },
        Expression::AssetAt {
            source,
            property,
            io_index,
            asset_index,
        } => Expression::AssetAt {
            source: source.clone(),
            property: property.clone(),
            io_index: Box::new(substitute_expression(
                io_index, index_var, value_var, k, array_name,
            )),
            asset_index: Box::new(substitute_expression(
                asset_index,
                index_var,
                value_var,
                k,
                array_name,
            )),
        },
        Expression::GroupNumIO { source, index } => Expression::GroupNumIO {
            source: source.clone(),
            index: Box::new(substitute_expression(
                index, index_var, value_var, k, array_name,
            )),
        },
        Expression::GroupIOAccess {
            source,
            property,
            group_index,
            io_index,
        } => Expression::GroupIOAccess {
            source: source.clone(),
            property: property.clone(),
            group_index: Box::new(substitute_expression(
                group_index,
                index_var,
                value_var,
                k,
                array_name,
            )),
            io_index: Box::new(substitute_expression(
                io_index, index_var, value_var, k, array_name,
            )),
        },
        Expression::Concat { left, right } => Expression::Concat {
            left: Box::new(substitute_expression(
                left, index_var, value_var, k, array_name,
            )),
            right: Box::new(substitute_expression(
                right, index_var, value_var, k, array_name,
            )),
        },
        Expression::Sha256 { data } => Expression::Sha256 {
            data: Box::new(substitute_expression(
                data, index_var, value_var, k, array_name,
            )),
        },
        Expression::Sha256Initialize { data } => Expression::Sha256Initialize {
            data: Box::new(substitute_expression(
                data, index_var, value_var, k, array_name,
            )),
        },
        Expression::Sha256Update { context, chunk } => Expression::Sha256Update {
            context: Box::new(substitute_expression(
                context, index_var, value_var, k, array_name,
            )),
            chunk: Box::new(substitute_expression(
                chunk, index_var, value_var, k, array_name,
            )),
        },
        Expression::Sha256Finalize {
            context,
            last_chunk,
        } => Expression::Sha256Finalize {
            context: Box::new(substitute_expression(
                context, index_var, value_var, k, array_name,
            )),
            last_chunk: Box::new(substitute_expression(
                last_chunk, index_var, value_var, k, array_name,
            )),
        },
        Expression::EcMulScalarVerify {
            scalar,
            point_p,
            point_q,
        } => Expression::EcMulScalarVerify {
            scalar: Box::new(substitute_expression(
                scalar, index_var, value_var, k, array_name,
            )),
            point_p: Box::new(substitute_expression(
                point_p, index_var, value_var, k, array_name,
            )),
            point_q: Box::new(substitute_expression(
                point_q, index_var, value_var, k, array_name,
            )),
        },
        Expression::TweakVerify {
            point_p,
            tweak,
            point_q,
        } => Expression::TweakVerify {
            point_p: Box::new(substitute_expression(
                point_p, index_var, value_var, k, array_name,
            )),
            tweak: Box::new(substitute_expression(
                tweak, index_var, value_var, k, array_name,
            )),
            point_q: Box::new(substitute_expression(
                point_q, index_var, value_var, k, array_name,
            )),
        },
        Expression::Substr { data, offset, size } => Expression::Substr {
            data: Box::new(substitute_expression(
                data, index_var, value_var, k, array_name,
            )),
            offset: Box::new(substitute_expression(
                offset, index_var, value_var, k, array_name,
            )),
            size: Box::new(substitute_expression(
                size, index_var, value_var, k, array_name,
            )),
        },
        Expression::Cat { left, right } => Expression::Cat {
            left: Box::new(substitute_expression(
                left, index_var, value_var, k, array_name,
            )),
            right: Box::new(substitute_expression(
                right, index_var, value_var, k, array_name,
            )),
        },
        Expression::Bin2Num { data } => Expression::Bin2Num {
            data: Box::new(substitute_expression(
                data, index_var, value_var, k, array_name,
            )),
        },
        Expression::Num2Bin { value, size } => Expression::Num2Bin {
            value: Box::new(substitute_expression(
                value, index_var, value_var, k, array_name,
            )),
            size: Box::new(substitute_expression(
                size, index_var, value_var, k, array_name,
            )),
        },
        Expression::SizeOf { data } => Expression::SizeOf {
            data: Box::new(substitute_expression(
                data, index_var, value_var, k, array_name,
            )),
        },
        Expression::PacketInspect { packet_type } => Expression::PacketInspect {
            packet_type: Box::new(substitute_expression(
                packet_type,
                index_var,
                value_var,
                k,
                array_name,
            )),
        },
        Expression::InputPacketInspect { index, packet_type } => Expression::InputPacketInspect {
            index: Box::new(substitute_expression(
                index, index_var, value_var, k, array_name,
            )),
            packet_type: Box::new(substitute_expression(
                packet_type,
                index_var,
                value_var,
                k,
                array_name,
            )),
        },
        // Recurse into contract instance arguments
        Expression::ContractInstance {
            contract_name,
            args,
        } => Expression::ContractInstance {
            contract_name: contract_name.clone(),
            args: args
                .iter()
                .map(|a| substitute_expression(a, index_var, value_var, k, array_name))
                .collect(),
        },
        // Asset lookups/has: substitute the io index and both Asset ID operands
        // (e.g. `tx.outputs[i].assets.lookup(assetTxid, i)` unrolls i -> 0,1,2…).
        Expression::AssetLookup {
            source,
            index,
            asset_txid,
            asset_gidx,
        } => Expression::AssetLookup {
            source: source.clone(),
            index: Box::new(substitute_expression(
                index, index_var, value_var, k, array_name,
            )),
            asset_txid: Box::new(substitute_expression(
                asset_txid, index_var, value_var, k, array_name,
            )),
            asset_gidx: Box::new(substitute_expression(
                asset_gidx, index_var, value_var, k, array_name,
            )),
        },
        Expression::AssetHas {
            source,
            index,
            asset_txid,
            asset_gidx,
        } => Expression::AssetHas {
            source: source.clone(),
            index: Box::new(substitute_expression(
                index, index_var, value_var, k, array_name,
            )),
            asset_txid: Box::new(substitute_expression(
                asset_txid, index_var, value_var, k, array_name,
            )),
            asset_gidx: Box::new(substitute_expression(
                asset_gidx, index_var, value_var, k, array_name,
            )),
        },
        Expression::GroupFind {
            asset_txid,
            asset_gidx,
        } => Expression::GroupFind {
            asset_txid: Box::new(substitute_expression(
                asset_txid, index_var, value_var, k, array_name,
            )),
            asset_gidx: Box::new(substitute_expression(
                asset_gidx, index_var, value_var, k, array_name,
            )),
        },
        Expression::GroupHas {
            asset_txid,
            asset_gidx,
        } => Expression::GroupHas {
            asset_txid: Box::new(substitute_expression(
                asset_txid, index_var, value_var, k, array_name,
            )),
            asset_gidx: Box::new(substitute_expression(
                asset_gidx, index_var, value_var, k, array_name,
            )),
        },
        Expression::GroupControlIs {
            group,
            asset_txid,
            asset_gidx,
        } => Expression::GroupControlIs {
            group: substitute_loop_name(group, index_var, value_var, k, array_name),
            asset_txid: Box::new(substitute_expression(
                asset_txid, index_var, value_var, k, array_name,
            )),
            asset_gidx: Box::new(substitute_expression(
                asset_gidx, index_var, value_var, k, array_name,
            )),
        },
        // All other expressions are returned as-is
        _ => expr.clone(),
    }
}
