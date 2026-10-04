use crate::models::*;

// ─── Loop Unrolling ─────────────────────────────────────────────────────────────

/// Substitute loop variables in the body for a specific iteration index k.
///
/// Transforms:
/// - `index_var` → `Literal(k)`
/// - `value_var` and paths rooted at it → accesses on element `k` of `items`
pub(crate) fn substitute_loop_body(
    body: &[LocatedStatement],
    index_var: &str,
    value_var: &str,
    k: usize,
    items: &Expression,
) -> Vec<LocatedStatement> {
    body.iter()
        .map(|stmt| LocatedStatement {
            span: stmt.span,
            statement: substitute_statement(&stmt.statement, index_var, value_var, k, items),
        })
        .collect()
}

pub(crate) fn substitute_statement(
    stmt: &Statement,
    index_var: &str,
    value_var: &str,
    k: usize,
    items: &Expression,
) -> Statement {
    match stmt {
        Statement::Call(expression) => Statement::Call(substitute_expression(
            expression, index_var, value_var, k, items,
        )),
        Statement::Return(value) => {
            Statement::Return(value.as_ref().map(|expression| {
                substitute_expression(expression, index_var, value_var, k, items)
            }))
        }
        Statement::Require(req) => {
            Statement::Require(substitute_requirement(req, index_var, value_var, k, items))
        }
        Statement::LetBinding {
            name,
            declared_type,
            value,
        } => Statement::LetBinding {
            name: name.clone(),
            declared_type: declared_type.clone(),
            value: substitute_expression(value, index_var, value_var, k, items),
        },
        Statement::VarAssign { target, value } => Statement::VarAssign {
            target: match substitute_expression(
                &match target {
                    AssignmentTarget::Access(value) => (**value).clone(),
                    AssignmentTarget::Binding(name) => Expression::Property(name.clone()),
                    AssignmentTarget::ArrayIndex { array, index } => Expression::ArrayIndex {
                        array: array.clone(),
                        index: index.clone(),
                    },
                },
                index_var,
                value_var,
                k,
                items,
            ) {
                Expression::Variable(name) | Expression::Property(name) => {
                    AssignmentTarget::Binding(name)
                }
                Expression::ArrayIndex { array, index } => {
                    AssignmentTarget::ArrayIndex { array, index }
                }
                value => AssignmentTarget::Access(Box::new(value)),
            },
            value: substitute_expression(value, index_var, value_var, k, items),
        },
        Statement::IfElse {
            condition,
            then_body,
            else_body,
        } => Statement::IfElse {
            condition: substitute_expression(condition, index_var, value_var, k, items),
            then_body: substitute_loop_body(then_body, index_var, value_var, k, items),
            else_body: else_body
                .as_ref()
                .map(|b| substitute_loop_body(b, index_var, value_var, k, items)),
        },
        Statement::ForIn {
            index_var: inner_idx,
            value_var: inner_val,
            iterable,
            body,
        } => Statement::ForIn {
            index_var: inner_idx.clone(),
            value_var: inner_val.clone(),
            iterable: substitute_expression(iterable, index_var, value_var, k, items),
            body: substitute_loop_body(body, index_var, value_var, k, items),
        },
        Statement::ForCount { count, body } => Statement::ForCount {
            count: substitute_expression(count, index_var, value_var, k, items),
            body: substitute_loop_body(body, index_var, value_var, k, items),
        },
    }
}

pub(crate) fn substitute_requirement(
    req: &Requirement,
    index_var: &str,
    value_var: &str,
    k: usize,
    items: &Expression,
) -> Requirement {
    match req {
        Requirement::Expression(expr) => {
            Requirement::Expression(substitute_expression(expr, index_var, value_var, k, items))
        }
        Requirement::Comparison { left, op, right } => Requirement::Comparison {
            left: substitute_expression(left, index_var, value_var, k, items),
            op: op.clone(),
            right: substitute_expression(right, index_var, value_var, k, items),
        },
        Requirement::CheckSig { signature, pubkey } => Requirement::CheckSig {
            signature: substitute_expression(signature, index_var, value_var, k, items),
            pubkey: substitute_expression(pubkey, index_var, value_var, k, items),
        },
        Requirement::CheckSigFromStack {
            signature,
            pubkey,
            message,
        } => Requirement::CheckSigFromStack {
            signature: substitute_expression(signature, index_var, value_var, k, items),
            pubkey: substitute_expression(pubkey, index_var, value_var, k, items),
            message: substitute_expression(message, index_var, value_var, k, items),
        },
        Requirement::CheckMultisig {
            pubkeys,
            signatures,
            threshold,
        } => Requirement::CheckMultisig {
            pubkeys: pubkeys
                .iter()
                .map(|key| substitute_expression(key, index_var, value_var, k, items))
                .collect(),
            signatures: signatures
                .iter()
                .map(|sig| substitute_expression(sig, index_var, value_var, k, items))
                .collect(),
            threshold: *threshold,
        },
        Requirement::HashEqual {
            hash_fn,
            preimage,
            hash,
        } => Requirement::HashEqual {
            hash_fn: hash_fn.clone(),
            preimage: substitute_expression(preimage, index_var, value_var, k, items),
            hash: substitute_expression(hash, index_var, value_var, k, items),
        },
    }
}

/// Resolve a dotted binding path, rooting `value_var` paths at element `k` of `items`.
fn substitute_path(
    path: &str,
    index_var: &str,
    value_var: &str,
    k: usize,
    items: &Expression,
) -> Option<Expression> {
    if path == index_var {
        return Some(Expression::Literal(k.to_string()));
    }
    let mut fields = path.split('.');
    if fields.next() != Some(value_var) {
        return None;
    }
    let index = Box::new(Expression::Literal(k.to_string()));
    let element = match items {
        Expression::Variable(array) | Expression::Property(array) => Expression::ArrayIndex {
            array: array.clone(),
            index,
        },
        value => Expression::IndexAccess {
            value: Box::new(value.clone()),
            index,
        },
    };
    Some(
        fields.fold(element, |value, field| Expression::FieldAccess {
            value: Box::new(value),
            field: field.to_string(),
        }),
    )
}

pub(crate) fn substitute_expression(
    expr: &Expression,
    index_var: &str,
    value_var: &str,
    k: usize,
    items: &Expression,
) -> Expression {
    match expr {
        Expression::Call {
            name,
            args,
            return_type,
        } => Expression::Call {
            name: name.clone(),
            args: args
                .iter()
                .map(|arg| substitute_expression(arg, index_var, value_var, k, items))
                .collect(),
            return_type: return_type.clone(),
        },
        Expression::Variable(path) | Expression::Property(path) => {
            substitute_path(path, index_var, value_var, k, items).unwrap_or_else(|| expr.clone())
        }
        Expression::ArrayLiteral(elements) => Expression::ArrayLiteral(
            elements
                .iter()
                .map(|element| substitute_expression(element, index_var, value_var, k, items))
                .collect(),
        ),
        Expression::StructLiteral(fields) => Expression::StructLiteral(
            fields
                .iter()
                .map(|(name, value)| {
                    (
                        name.clone(),
                        substitute_expression(value, index_var, value_var, k, items),
                    )
                })
                .collect(),
        ),
        Expression::ArrayIndex { array, index } => {
            let index = Box::new(substitute_expression(index, index_var, value_var, k, items));
            match substitute_path(array, index_var, value_var, k, items) {
                Some(value) => Expression::IndexAccess {
                    value: Box::new(value),
                    index,
                },
                None => Expression::ArrayIndex {
                    array: array.clone(),
                    index,
                },
            }
        }
        // Recursively substitute in binary operations
        Expression::BinaryOp { left, op, right } => Expression::BinaryOp {
            left: Box::new(substitute_expression(left, index_var, value_var, k, items)),
            op: op.clone(),
            right: Box::new(substitute_expression(right, index_var, value_var, k, items)),
        },
        // Handle InputIntrospection - substitute index if it matches loop variable
        Expression::InputIntrospection { index, property } => Expression::InputIntrospection {
            index: Box::new(substitute_expression(index, index_var, value_var, k, items)),
            property: property.clone(),
        },
        // Handle OutputIntrospection - substitute index if it matches loop variable
        Expression::OutputIntrospection { index, property } => Expression::OutputIntrospection {
            index: Box::new(substitute_expression(index, index_var, value_var, k, items)),
            property: property.clone(),
        },
        Expression::Negate { value } => Expression::Negate {
            value: Box::new(substitute_expression(value, index_var, value_var, k, items)),
        },
        Expression::Not { value } => Expression::Not {
            value: Box::new(substitute_expression(value, index_var, value_var, k, items)),
        },
        Expression::ReverseBytes { data } => Expression::ReverseBytes {
            data: Box::new(substitute_expression(data, index_var, value_var, k, items)),
        },
        Expression::Cast { target, data } => Expression::Cast {
            target: target.clone(),
            data: Box::new(substitute_expression(data, index_var, value_var, k, items)),
        },
        Expression::Sighash { hash_type } => Expression::Sighash {
            hash_type: Box::new(substitute_expression(
                hash_type, index_var, value_var, k, items,
            )),
        },
        Expression::Digest { data, hash_type } => Expression::Digest {
            data: Box::new(substitute_expression(data, index_var, value_var, k, items)),
            hash_type: Box::new(substitute_expression(
                hash_type, index_var, value_var, k, items,
            )),
        },
        Expression::ModExp {
            base,
            exponent,
            modulus,
        } => Expression::ModExp {
            base: Box::new(substitute_expression(base, index_var, value_var, k, items)),
            exponent: Box::new(substitute_expression(
                exponent, index_var, value_var, k, items,
            )),
            modulus: Box::new(substitute_expression(
                modulus, index_var, value_var, k, items,
            )),
        },
        Expression::EcAdd {
            point_p,
            point_q,
            curve_id,
        } => Expression::EcAdd {
            point_p: Box::new(substitute_expression(
                point_p, index_var, value_var, k, items,
            )),
            point_q: Box::new(substitute_expression(
                point_q, index_var, value_var, k, items,
            )),
            curve_id: Box::new(substitute_expression(
                curve_id, index_var, value_var, k, items,
            )),
        },
        Expression::EcMul {
            point,
            scalar,
            curve_id,
        } => Expression::EcMul {
            point: Box::new(substitute_expression(point, index_var, value_var, k, items)),
            scalar: Box::new(substitute_expression(
                scalar, index_var, value_var, k, items,
            )),
            curve_id: Box::new(substitute_expression(
                curve_id, index_var, value_var, k, items,
            )),
        },
        Expression::EcPairing { g1, g2, curve_id } => Expression::EcPairing {
            g1: Box::new(substitute_expression(g1, index_var, value_var, k, items)),
            g2: Box::new(substitute_expression(g2, index_var, value_var, k, items)),
            curve_id: Box::new(substitute_expression(
                curve_id, index_var, value_var, k, items,
            )),
        },
        Expression::AssetCount { source, index } => Expression::AssetCount {
            source: source.clone(),
            index: Box::new(substitute_expression(index, index_var, value_var, k, items)),
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
                io_index, index_var, value_var, k, items,
            )),
            asset_index: Box::new(substitute_expression(
                asset_index,
                index_var,
                value_var,
                k,
                items,
            )),
        },
        Expression::Concat { left, right } => Expression::Concat {
            left: Box::new(substitute_expression(left, index_var, value_var, k, items)),
            right: Box::new(substitute_expression(right, index_var, value_var, k, items)),
        },
        Expression::Sha256 { data } => Expression::Sha256 {
            data: Box::new(substitute_expression(data, index_var, value_var, k, items)),
        },
        Expression::Sha256Initialize { data } => Expression::Sha256Initialize {
            data: Box::new(substitute_expression(data, index_var, value_var, k, items)),
        },
        Expression::Sha256Update { context, chunk } => Expression::Sha256Update {
            context: Box::new(substitute_expression(
                context, index_var, value_var, k, items,
            )),
            chunk: Box::new(substitute_expression(chunk, index_var, value_var, k, items)),
        },
        Expression::Sha256Finalize {
            context,
            last_chunk,
        } => Expression::Sha256Finalize {
            context: Box::new(substitute_expression(
                context, index_var, value_var, k, items,
            )),
            last_chunk: Box::new(substitute_expression(
                last_chunk, index_var, value_var, k, items,
            )),
        },
        Expression::EcMulScalarVerify {
            scalar,
            point_p,
            point_q,
        } => Expression::EcMulScalarVerify {
            scalar: Box::new(substitute_expression(
                scalar, index_var, value_var, k, items,
            )),
            point_p: Box::new(substitute_expression(
                point_p, index_var, value_var, k, items,
            )),
            point_q: Box::new(substitute_expression(
                point_q, index_var, value_var, k, items,
            )),
        },
        Expression::TweakVerify {
            point_p,
            tweak,
            point_q,
        } => Expression::TweakVerify {
            point_p: Box::new(substitute_expression(
                point_p, index_var, value_var, k, items,
            )),
            tweak: Box::new(substitute_expression(tweak, index_var, value_var, k, items)),
            point_q: Box::new(substitute_expression(
                point_q, index_var, value_var, k, items,
            )),
        },
        Expression::Substr { data, offset, size } => Expression::Substr {
            data: Box::new(substitute_expression(data, index_var, value_var, k, items)),
            offset: Box::new(substitute_expression(
                offset, index_var, value_var, k, items,
            )),
            size: Box::new(substitute_expression(size, index_var, value_var, k, items)),
        },
        Expression::Cat { left, right } => Expression::Cat {
            left: Box::new(substitute_expression(left, index_var, value_var, k, items)),
            right: Box::new(substitute_expression(right, index_var, value_var, k, items)),
        },
        Expression::Bin2Num { data } => Expression::Bin2Num {
            data: Box::new(substitute_expression(data, index_var, value_var, k, items)),
        },
        Expression::Num2Bin { value, size } => Expression::Num2Bin {
            value: Box::new(substitute_expression(value, index_var, value_var, k, items)),
            size: Box::new(substitute_expression(size, index_var, value_var, k, items)),
        },
        Expression::SizeOf { data } => Expression::SizeOf {
            data: Box::new(substitute_expression(data, index_var, value_var, k, items)),
        },
        Expression::PacketInspect { packet_type } => Expression::PacketInspect {
            packet_type: Box::new(substitute_expression(
                packet_type,
                index_var,
                value_var,
                k,
                items,
            )),
        },
        Expression::InputPacketInspect { index, packet_type } => Expression::InputPacketInspect {
            index: Box::new(substitute_expression(index, index_var, value_var, k, items)),
            packet_type: Box::new(substitute_expression(
                packet_type,
                index_var,
                value_var,
                k,
                items,
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
                .map(|a| substitute_expression(a, index_var, value_var, k, items))
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
            index: Box::new(substitute_expression(index, index_var, value_var, k, items)),
            asset_txid: Box::new(substitute_expression(
                asset_txid, index_var, value_var, k, items,
            )),
            asset_gidx: Box::new(substitute_expression(
                asset_gidx, index_var, value_var, k, items,
            )),
        },
        Expression::AssetHas {
            source,
            index,
            asset_txid,
            asset_gidx,
        } => Expression::AssetHas {
            source: source.clone(),
            index: Box::new(substitute_expression(index, index_var, value_var, k, items)),
            asset_txid: Box::new(substitute_expression(
                asset_txid, index_var, value_var, k, items,
            )),
            asset_gidx: Box::new(substitute_expression(
                asset_gidx, index_var, value_var, k, items,
            )),
        },
        Expression::GroupFind {
            asset_txid,
            asset_gidx,
        } => Expression::GroupFind {
            asset_txid: Box::new(substitute_expression(
                asset_txid, index_var, value_var, k, items,
            )),
            asset_gidx: Box::new(substitute_expression(
                asset_gidx, index_var, value_var, k, items,
            )),
        },
        Expression::GroupHas {
            asset_txid,
            asset_gidx,
        } => Expression::GroupHas {
            asset_txid: Box::new(substitute_expression(
                asset_txid, index_var, value_var, k, items,
            )),
            asset_gidx: Box::new(substitute_expression(
                asset_gidx, index_var, value_var, k, items,
            )),
        },
        _ => {
            let mut expression = expr.clone();
            for child in crate::models::child_exprs_mut(&mut expression) {
                *child = substitute_expression(child, index_var, value_var, k, items);
            }
            expression
        }
    }
}
