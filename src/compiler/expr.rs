use super::*;
use crate::models::*;
use crate::operators::{BinaryOperator, OperatorClass};
use crate::properties::{GroupIoProperty, ThisProperty};

fn push_literal_asm(lit: &str, asm: &mut Vec<Op>) {
    match lit {
        "true" => asm.push(Int1.into()),
        "false" | "0x" => asm.push(Int0.into()),
        _ => asm.push(Op::Push(lit.to_string())),
    }
}

/// Push a two-field native struct with its first field deepest, as native opcodes expect.
fn emit_native_struct_asm(value: &Expression, fields: &[(&str, &str)], asm: &mut Vec<Op>) {
    match &value.kind {
        ExprKind::Name(path) => {
            for (field, _) in fields {
                asm.push(Op::Read(path.clone().field(*field)));
            }
        }
        _ => {
            emit_expression_asm(value, asm);
            // Helpers return structs first-field-on-top.
            if matches!(&value.kind, ExprKind::Extracted(_)) {
                asm.push(Swap.into());
            }
        }
    }
}

/// Emit assembly for an expression (push its value onto the stack)
pub(crate) fn emit_expression_asm(expr: &Expression, asm: &mut Vec<Op>) {
    match &expr.kind {
        ExprKind::Call { .. } => {
            unreachable!("private calls are extracted before raw expression emission")
        }
        ExprKind::Name(path) => asm.push(Op::Read(path.clone())),
        ExprKind::Extracted(index) => asm.push(Op::Value(*index)),
        ExprKind::Literal(lit) => push_literal_asm(lit, asm),
        ExprKind::IntentInspect {
            path,
            presence_only,
        } => {
            emit_expression_asm(path, asm);
            asm.push(InspectIntentMessage.into());
            // The opcode leaves the value below its presence flag.
            asm.push(Op::Opcode(if *presence_only { Nip } else { Verify }));
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
            asm.push(Op::Push(flags.to_string()));
            for exception in exceptions {
                let fields = crate::models::builtin_struct_fields("AssetId")
                    .expect("AssetId is a native struct");
                emit_native_struct_asm(exception, fields, asm);
            }
            asm.push(Op::Push(exceptions.len().to_string()));
            asm.push(Tunnel.into());
        }
        // Rejected before emission; array declarations emit their elements directly.
        ExprKind::ArrayLiteral(_) => {}
        // Rejected before emission; typed struct declarations emit scalar leaves directly.
        ExprKind::StructLiteral(_) => {}
        ExprKind::FieldAccess { .. } | ExprKind::IndexAccess { .. } => {
            unreachable!("binding accesses are extracted before emission")
        }
        ExprKind::ArrayIndex { array, index } => {
            // The validator rejects literal indexes that are not in range.
            if let Some(index) = index.literal_index() {
                asm.push(Op::Read(array.clone().index(index)));
            } else {
                emit_expression_asm(index, asm);
                asm.push(Op::ArrayElement(array.clone()));
            }
        }
        ExprKind::This(property) => asm.push(Op::Opcode(match property {
            ThisProperty::ActiveInputIndex => PushCurrentInputIndex,
            ThisProperty::Expiry => PushExpiry,
        })),
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
        ExprKind::AssetTryLookup {
            source,
            index,
            asset_txid,
            asset_gidx,
        } => {
            emit_asset_lookup_operands(source, index, asset_txid, asset_gidx, asm);
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
            asm.push(InspectNumAssetGroups.into());
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
                GroupIOSource::Inputs => asm.push(Int0.into()),
                GroupIOSource::Outputs => asm.push(Int1.into()),
            }
            asm.push(InspectAssetGroup.into());
            // Extract property if specified
            match property {
                Some(GroupIoProperty::Amount) => {
                    asm.push(Nip.into());
                    asm.push(Nip.into());
                }
                Some(GroupIoProperty::Type) => {
                    asm.push(Drop.into()); // amount
                    asm.push(Drop.into()); // data
                }
                Some(GroupIoProperty::Index) => {
                    asm.push(Drop.into()); // amount
                    asm.push(Nip.into()); // type
                }
                Some(GroupIoProperty::Txid) => {
                    unreachable!("input records are extracted first; output txid fails validation")
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
            asm.extend(opcodes.iter().copied().map(Op::from));
        }
        ExprKind::Unary { op, value } => {
            emit_expression_asm(value, asm);
            asm.push(op.opcode().into());
        }
        ExprKind::Cast { target, data } => {
            emit_expression_asm(data, asm);
            if data.ty == crate::types::ArkType::parse(target) {
                return;
            }
            match target.as_str() {
                // Normalize spender-supplied integers before exposing their encoding.
                "bytes" if data.ty == crate::types::ArkType::Int => asm.push(Bin2Num.into()),
                // Witness bools are spender-supplied scriptnums; normalize to 0/1.
                "bytes" if data.ty == crate::types::ArkType::Bool => asm.push(NotEqual0.into()),
                "int" | "bool" => asm.push(NotEqual0.into()),
                "bytes20" => asm.extend([Size.into(), Op::Push("20".into()), EqualVerify.into()]),
                "bytes32" => asm.extend([Size.into(), Op::Push("32".into()), EqualVerify.into()]),
                _ => {}
            }
        }
        // Packet introspection
        ExprKind::PacketInspect {
            packet_type,
            presence_only,
        } => {
            emit_expression_asm(packet_type, asm);
            asm.push(InspectPacket.into());
            emit_packet_result_asm(*presence_only, asm);
        }
        ExprKind::InputPacketInspect {
            index,
            packet_type,
            presence_only,
        } => {
            emit_expression_asm(packet_type, asm);
            emit_expression_asm(index, asm);
            asm.push(InspectInputPacket.into());
            emit_packet_result_asm(*presence_only, asm);
        }
    }
}

/// Reduce a packet inspection's `[bytes, found]` to the flag or to the asserted bytes.
fn emit_packet_result_asm(presence_only: bool, asm: &mut Vec<Op>) {
    if presence_only {
        asm.push(Nip.into());
    } else {
        asm.push(Int1.into());
        asm.push(EqualVerify.into());
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
    asm: &mut Vec<Op>,
) {
    let args = args
        .iter()
        .map(|arg| match &arg.kind {
            ExprKind::Name(path) => vec![Op::Param(path.key())],
            ExprKind::Literal(literal) => vec![Op::Push(literal.clone())],
            _ => {
                let mut nested = Vec::new();
                emit_expression_asm(arg, &mut nested);
                nested
            }
        })
        .collect();
    asm.push(Op::Contract {
        name: contract_name.to_string(),
        args,
    });
}

/// Emit assembly for arithmetic or a short-circuit logical operation.
pub(crate) fn emit_binary_op_asm(
    left: &Expression,
    op: BinaryOperator,
    right: &Expression,
    asm: &mut Vec<Op>,
) {
    emit_expression_asm(left, asm);
    if op.class() == OperatorClass::Logical {
        asm.push(If.into());
        if op == BinaryOperator::And {
            emit_expression_asm(right, asm);
        } else {
            asm.push(Int1.into());
        }
        asm.push(Else.into());
        if op == BinaryOperator::Or {
            emit_expression_asm(right, asm);
        } else {
            asm.push(Int0.into());
        }
        asm.push(EndIf.into());
        return;
    }
    emit_expression_asm(right, asm);
    let concat = op == BinaryOperator::Add
        && [left, right]
            .iter()
            .any(|operand| crate::types::is_bytes_like(&operand.ty));
    if concat {
        asm.push(Cat.into());
    } else {
        asm.extend(op.opcodes().iter().copied().map(Op::from));
    }
}
