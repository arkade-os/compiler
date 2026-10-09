use super::*;
use crate::models::*;
use crate::operators::{BinaryOperator, OperatorClass};
use crate::properties::{GroupIoProperty, ThisProperty};

fn push_literal_asm(lit: &str, asm: &mut Vec<String>) {
    match lit {
        "true" => asm.push(OP_1.to_string()),
        "false" | "0x" => asm.push(OP_0.to_string()),
        _ => asm.push(lit.to_string()),
    }
}

/// Push a two-field native struct with its first field deepest, as native opcodes expect.
fn emit_native_struct_asm(value: &Expression, fields: &[(&str, &str)], asm: &mut Vec<String>) {
    match &value.kind {
        ExprKind::Variable(name) | ExprKind::Property(name) if !name.starts_with("$call:") => {
            for (field, _) in fields {
                asm.push(format!("<{name}.{field}>"));
            }
        }
        _ => {
            emit_expression_asm(value, asm);
            // Helpers return structs first-field-on-top.
            if matches!(&value.kind, ExprKind::Variable(name) if name.starts_with("$call:")) {
                asm.push(OP_SWAP.to_string());
            }
        }
    }
}

/// Emit assembly for an expression (push its value onto the stack)
pub(crate) fn emit_expression_asm(expr: &Expression, asm: &mut Vec<String>) {
    match &expr.kind {
        ExprKind::Call { .. } => {
            unreachable!("private calls are extracted before raw expression emission")
        }
        ExprKind::Variable(var) => {
            asm.push(format!("<{}>", var));
        }
        ExprKind::Literal(lit) => push_literal_asm(lit, asm),
        ExprKind::IntentInspect {
            path,
            presence_only,
        } => {
            push_literal_asm(path, asm);
            asm.push(OP_INSPECTINTENTMESSAGE.to_string());
            // The opcode leaves the value below its presence flag.
            asm.push(if *presence_only { OP_NIP } else { OP_VERIFY }.to_string());
        }
        ExprKind::Tunnel {
            output_index,
            policy,
            exceptions,
        } => {
            emit_expression_asm(output_index, asm);
            let mut flags = 0;
            for (index, value) in policy.iter().enumerate() {
                if matches!(&value.kind, ExprKind::Literal(literal) if literal == "true") {
                    flags |= 1 << index;
                }
            }
            asm.push(flags.to_string());
            for exception in exceptions {
                let fields = crate::models::builtin_struct_fields("AssetId")
                    .expect("AssetId is a native struct");
                emit_native_struct_asm(exception, fields, asm);
            }
            asm.push(exceptions.len().to_string());
            asm.push(OP_TUNNEL.to_string());
        }
        // Rejected before emission; array declarations emit their elements directly.
        ExprKind::ArrayLiteral(_) => {}
        // Rejected before emission; typed struct declarations emit scalar leaves directly.
        ExprKind::StructLiteral(_) => {}
        ExprKind::FieldAccess { .. } | ExprKind::IndexAccess { .. } => {
            unreachable!("binding accesses are extracted before emission")
        }
        ExprKind::ArrayIndex { array, index } => {
            if let ExprKind::Literal(index) = &index.as_ref().kind {
                asm.push(format!("<{array}[{index}]>"));
            } else {
                emit_expression_asm(index, asm);
                asm.push(format!("{INTERNAL_ARRAY_INDEX_PREFIX}{array}"));
            }
        }
        ExprKind::Property(property) => asm.push(format!("<{}>", property.trim())),
        ExprKind::This(property) => asm.push(
            match property {
                ThisProperty::ActiveInputIndex => OP_PUSHCURRENTINPUTINDEX,
                ThisProperty::Expiry => OP_PUSHEXPIRY,
            }
            .to_string(),
        ),
        ExprKind::AssetLookup {
            source,
            index,
            asset_txid,
            asset_gidx,
        } => {
            emit_asset_lookup_asm(source, index, asset_txid, asset_gidx, asm);
        }
        ExprKind::AssetHas {
            source,
            index,
            asset_txid,
            asset_gidx,
        } => {
            emit_asset_has_asm(source, index, asset_txid, asset_gidx, asm);
        }
        ExprKind::AssetCount { source, index } => {
            emit_asset_count_asm(source, index, asm);
        }
        ExprKind::AssetAt {
            source,
            io_index,
            asset_index,
            property,
        } => {
            emit_asset_at_asm(source, io_index, asset_index, *property, asm);
        }
        ExprKind::TxIntrospection { property } => {
            emit_tx_introspection_asm(*property, asm);
        }
        ExprKind::InputIntrospection { index, property } => {
            emit_input_introspection_asm(index, *property, asm);
        }
        ExprKind::OutputIntrospection { index, property } => {
            emit_output_introspection_asm(index, *property, asm);
        }
        ExprKind::BinaryOp { left, op, right } => emit_binary_op_asm(left, *op, right, asm),
        ExprKind::GroupFind {
            asset_txid,
            asset_gidx,
        } => {
            emit_group_find_asm(asset_txid, asset_gidx, asm);
        }
        ExprKind::GroupHas {
            asset_txid,
            asset_gidx,
        } => {
            emit_group_has_asm(asset_txid, asset_gidx, asm);
        }
        ExprKind::GroupControlIs {
            group,
            asset_txid,
            asset_gidx,
        } => {
            emit_group_control_is_asm(group, asset_txid, asset_gidx, asm);
        }
        ExprKind::GroupProperty { group, property } => {
            emit_group_property_asm(group, *property, asm);
        }
        ExprKind::AssetGroupsLength => {
            asm.push(OP_INSPECTNUMASSETGROUPS.to_string());
        }
        ExprKind::AssetGroupAt { index } => emit_expression_asm(index, asm),
        ExprKind::GroupIOAccess {
            group,
            io_index,
            source,
            property,
        } => {
            emit_expression_asm(group, asm);
            emit_expression_asm(io_index, asm);
            match source {
                GroupIOSource::Inputs => asm.push(OP_0.to_string()),
                GroupIOSource::Outputs => asm.push(OP_1.to_string()),
            }
            asm.push(OP_INSPECTASSETGROUP.to_string());
            // Extract property if specified
            match property {
                Some(GroupIoProperty::Amount) => {
                    asm.push(OP_NIP.to_string());
                    asm.push(OP_NIP.to_string());
                }
                Some(GroupIoProperty::Type) => {
                    asm.push(OP_DROP.to_string()); // amount
                    asm.push(OP_DROP.to_string()); // data
                }
                Some(GroupIoProperty::Index) => {
                    asm.push(OP_DROP.to_string()); // amount
                    asm.push(OP_NIP.to_string()); // type
                }
                None => {}
            }
        }
        ExprKind::ContractInstance {
            contract_name,
            args,
        } => {
            emit_contract_instance_asm(contract_name, args, asm);
        }
        ExprKind::Builtin { builtin, args } => {
            let crate::builtins::Lowering::Opcodes(opcodes) = builtin.lowering else {
                unreachable!("pairings are extracted before raw emission")
            };
            for (arg, (_, ty)) in args.iter().zip(builtin.params) {
                match crate::models::builtin_struct_fields(ty) {
                    Some(fields) => emit_native_struct_asm(arg, fields, asm),
                    None => emit_expression_asm(arg, asm),
                }
            }
            asm.extend(opcodes.iter().map(|opcode| opcode.to_string()));
        }
        ExprKind::Unary { op, value } => {
            emit_expression_asm(value, asm);
            asm.push(op.opcode().to_string());
        }
        ExprKind::Cast { target, data } => {
            emit_expression_asm(data, asm);
            if data.ty == crate::types::ArkType::parse(target) {
                return;
            }
            match target.as_str() {
                "bytes20" => asm.extend([OP_SIZE, "20", OP_EQUALVERIFY].map(String::from)),
                "bytes32" => asm.extend([OP_SIZE, "32", OP_EQUALVERIFY].map(String::from)),
                // Witness bools are spender-supplied scriptnums; normalize to 0/1.
                "int" | "bool" => asm.push(OP_0NOTEQUAL.to_string()),
                _ => {}
            }
        }
        // Packet introspection
        ExprKind::PacketInspect { packet_type } => {
            emit_expression_asm(packet_type, asm);
            asm.push(OP_INSPECTPACKET.to_string());
            asm.push(OP_1.to_string());
            asm.push(OP_EQUALVERIFY.to_string());
        }
        ExprKind::InputPacketInspect { index, packet_type } => {
            emit_expression_asm(packet_type, asm);
            emit_expression_asm(index, asm);
            asm.push(OP_INSPECTINPUTPACKET.to_string());
            asm.push(OP_1.to_string());
            asm.push(OP_EQUALVERIFY.to_string());
        }
    }
}

/// Emit assembly for a contract instantiation: `new ContractName(arg1, arg2, ...)`
///
/// Produces a single placeholder token `<CONTRACT:ContractName(<arg1>,<arg2>)>` that
/// the runtime resolves to the 32-byte Taproot witness program (the output key)
/// of the named contract instantiated with the given constructor arguments.
/// It is compared against a witness program, not a serialized 34-byte P2TR
/// script, because that is what a scriptPubKey inspection leaves on the stack.
///
/// Options (server key, exit timelock) are inherited from the enclosing contract
/// and must be applied by the runtime when computing the child contract's taproot
/// key.
///
/// Typical usage (recursion / self-referential contract enforcement):
/// ```text
/// require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk));
/// ```
/// compiles to:
/// ```text
/// 0 OP_INSPECTOUTPUTSCRIPTPUBKEY OP_DROP <CONTRACT:SingleSig(<ownerPk>)> OP_EQUAL
/// ```
pub(crate) fn emit_contract_instance_asm(
    contract_name: &str,
    args: &[Expression],
    asm: &mut Vec<String>,
) {
    let args_str = args
        .iter()
        .map(|a| match &a.kind {
            ExprKind::Variable(v) => format!("<{}>", v),
            ExprKind::Literal(l) => l.clone(),
            _ => {
                // For complex arg expressions, emit a nested representation
                let mut nested = Vec::new();
                emit_expression_asm(a, &mut nested);
                nested.join(" ")
            }
        })
        .collect::<Vec<_>>()
        .join(",");

    asm.push(format!("<CONTRACT:{}({})>", contract_name, args_str));
}

/// Emit assembly for arithmetic or a short-circuit logical operation.
pub(crate) fn emit_binary_op_asm(
    left: &Expression,
    op: BinaryOperator,
    right: &Expression,
    asm: &mut Vec<String>,
) {
    emit_expression_asm(left, asm);
    if op.class() == OperatorClass::Logical {
        asm.push(OP_IF.to_string());
        if op == BinaryOperator::And {
            emit_expression_asm(right, asm);
        } else {
            asm.push(OP_1.to_string());
        }
        asm.push(OP_ELSE.to_string());
        if op == BinaryOperator::Or {
            emit_expression_asm(right, asm);
        } else {
            asm.push(OP_0.to_string());
        }
        asm.push(OP_ENDIF.to_string());
        return;
    }
    emit_expression_asm(right, asm);
    let concat = op == BinaryOperator::Add
        && [left, right]
            .iter()
            .any(|operand| crate::types::is_bytes_like(&operand.ty));
    if concat {
        asm.push(OP_CAT.to_string());
    } else {
        asm.extend(op.opcodes().iter().map(|opcode| opcode.to_string()));
    }
}
