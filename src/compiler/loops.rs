use super::*;
use crate::models::*;

// ─── Loop Unrolling ─────────────────────────────────────────────────────────────

pub(crate) fn unroll_loop_body(
    body: &[Statement],
    index_var: &str,
    value_var: &str,
    array_name: Option<&str>,
    asm: &mut Vec<String>,
) -> Result<(), String> {
    for k in 0..DEFAULT_ARRAY_LENGTH {
        let substituted_body = substitute_loop_body(body, index_var, value_var, k, array_name);
        generate_asm_from_statements_recursive(&substituted_body, asm)?;
    }
    Ok(())
}

/// Substitute loop variables in the body for a specific iteration index k.
///
/// Transforms:
/// - `GroupProperty { group: value_var, property: "sumOutputs" }` → `GroupSum { index: k, source: Outputs }`
/// - `GroupProperty { group: value_var, property: "sumInputs" }` → `GroupSum { index: k, source: Inputs }`
/// - `Variable(index_var)` → `Literal(k)`
/// - `Variable(value_var)` when array_name is Some → `Variable("array_name_{k}")`
/// - Property-form indexing `arr[index_var]` → `Variable("arr_{k}")`
pub(crate) fn substitute_loop_body(
    body: &[Statement],
    index_var: &str,
    value_var: &str,
    k: usize,
    array_name: Option<&str>,
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
    array_name: Option<&str>,
) -> Statement {
    match stmt {
        Statement::Require(req) => Statement::Require(substitute_requirement(
            req, index_var, value_var, k, array_name,
        )),
        Statement::LetBinding { name, value } => Statement::LetBinding {
            name: name.clone(),
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
        } => {
            // Nested loops: substitute in iterable, leave inner variables alone
            Statement::ForIn {
                index_var: inner_idx.clone(),
                value_var: inner_val.clone(),
                iterable: substitute_expression(iterable, index_var, value_var, k, array_name),
                body: body.clone(), // Inner loop body keeps its own variables
            }
        }
    }
}

pub(crate) fn substitute_requirement(
    req: &Requirement,
    index_var: &str,
    value_var: &str,
    k: usize,
    array_name: Option<&str>,
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
        Requirement::CheckSig { signature, pubkey } => {
            // Substitute signature and pubkey if they match loop variables
            let new_sig = if signature == value_var {
                if let Some(arr) = array_name {
                    format!("{}_{}", arr, k)
                } else {
                    signature.clone()
                }
            } else {
                signature.clone()
            };
            Requirement::CheckSig {
                signature: new_sig,
                pubkey: pubkey.clone(),
            }
        }
        Requirement::CheckSigFromStack {
            signature,
            pubkey,
            message,
        } => {
            // Substitute signature, pubkey, and message if they match loop variables
            let new_sig = if signature == value_var {
                if let Some(arr) = array_name {
                    format!("{}_{}", arr, k)
                } else {
                    signature.clone()
                }
            } else {
                signature.clone()
            };
            Requirement::CheckSigFromStack {
                signature: new_sig,
                pubkey: pubkey.clone(),
                message: message.clone(),
            }
        }
        // Other requirement types don't need substitution
        _ => req.clone(),
    }
}

pub(crate) fn substitute_expression(
    expr: &Expression,
    index_var: &str,
    value_var: &str,
    k: usize,
    array_name: Option<&str>,
) -> Expression {
    match expr {
        // Replace index variable with literal k
        Expression::Variable(var) if var == index_var => Expression::Literal(k.to_string()),
        // Replace value_var with array_name_{k} when iterating over arrays
        Expression::Variable(var) if var == value_var => {
            if let Some(name) = array_name {
                Expression::Variable(format!("{}_{}", name, k))
            } else {
                Expression::Variable(var.clone())
            }
        }
        // Replace value_var.property with appropriate indexed expression
        Expression::GroupProperty { group, property } if group == value_var => {
            match property.as_str() {
                "sumInputs" => Expression::GroupSum {
                    index: Box::new(Expression::Literal(k.to_string())),
                    source: GroupSumSource::Inputs,
                },
                "sumOutputs" => Expression::GroupSum {
                    index: Box::new(Expression::Literal(k.to_string())),
                    source: GroupSumSource::Outputs,
                },
                // For delta, control, isFresh, assetId, metadataHash - replace group name with index literal
                _ => Expression::GroupProperty {
                    group: k.to_string(),
                    property: property.clone(),
                },
            }
        }
        // Handle property strings that represent array indexing (e.g., "oracles[i]").
        Expression::Property(prop) => {
            // Check if this looks like array indexing
            if let Some(bracket_start) = prop.find('[') {
                if let Some(bracket_end) = prop.find(']') {
                    let arr_name = &prop[..bracket_start];
                    let idx = &prop[bracket_start + 1..bracket_end];
                    if idx == index_var {
                        return Expression::Variable(format!("{}_{}", arr_name, k));
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
        // Handle CheckSigFromStackExpr
        Expression::CheckSigFromStackExpr {
            signature,
            pubkey,
            message,
        } => {
            let new_sig = if signature == value_var {
                if let Some(arr) = array_name {
                    format!("{}_{}", arr, k)
                } else {
                    signature.clone()
                }
            } else {
                signature.clone()
            };
            // Check if pubkey is an array indexed expression (string form)
            let new_pk = if pubkey.contains('[') && pubkey.contains(']') {
                if let Some(bracket_start) = pubkey.find('[') {
                    if let Some(bracket_end) = pubkey.find(']') {
                        let arr_name = &pubkey[..bracket_start];
                        let idx = &pubkey[bracket_start + 1..bracket_end];
                        if idx == index_var {
                            format!("{}_{}", arr_name, k)
                        } else {
                            pubkey.clone()
                        }
                    } else {
                        pubkey.clone()
                    }
                } else {
                    pubkey.clone()
                }
            } else {
                pubkey.clone()
            };
            Expression::CheckSigFromStackExpr {
                signature: new_sig,
                pubkey: new_pk,
                message: message.clone(),
            }
        }
        // Handle CheckSigExpr
        Expression::CheckSigExpr { signature, pubkey } => {
            let new_sig = if signature == value_var {
                if let Some(arr) = array_name {
                    format!("{}_{}", arr, k)
                } else {
                    signature.clone()
                }
            } else {
                signature.clone()
            };
            Expression::CheckSigExpr {
                signature: new_sig,
                pubkey: pubkey.clone(),
            }
        }
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
        Expression::ReverseBytes { data } => Expression::ReverseBytes {
            data: Box::new(substitute_expression(
                data, index_var, value_var, k, array_name,
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
            // Replace the group name with the loop index when iterating groups.
            group: if group == value_var {
                k.to_string()
            } else {
                group.clone()
            },
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
