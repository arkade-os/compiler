//! Lowers a typed expression into `Op`s that read bindings by path; stack positions are resolved
//! later, when the generator replays them.

use super::ir::Op;
use super::{asset, introspection};
use crate::models::{self, ExprKind, Expression, GroupIOSource};
use crate::opcodes::Opcode;
use crate::operators::{BinaryOperator, OperatorClass};
use crate::properties::{GroupIoProperty, ThisProperty};
use crate::types::{self, ArkType};

fn push_literal_asm(lit: &str, asm: &mut Vec<Op>) {
    match lit {
        "true" => asm.push(Opcode::Int1.into()),
        "false" | "0x" => asm.push(Opcode::Int0.into()),
        _ => asm.push(Op::Push(lit.to_string())),
    }
}

/// A binding's leaves or a literal's values, in `fields` order; `None` for a computed value.
// LIMITATION: every native struct field is a scalar today, so leaves are not recursed into; a
// native struct with struct fields needs recursive emission.
pub(crate) fn native_struct_leaves(
    value: &Expression,
    fields: &[(&str, &str)],
) -> Option<Vec<Expression>> {
    match &value.kind {
        ExprKind::Name(path) => Some(
            fields
                .iter()
                .map(|(field, _)| value.with_kind(ExprKind::Name(path.clone().field(*field))))
                .collect(),
        ),
        ExprKind::StructLiteral { fields: values, .. } => Some(
            fields
                .iter()
                .map(|(field, _)| {
                    let (_, value) = values
                        .iter()
                        .find(|(name, _)| name == field)
                        .expect("validated struct literal has every field");
                    value.clone()
                })
                .collect(),
        ),
        _ => None,
    }
}

/// Push a two-field native struct with its first field deepest, as native opcodes expect.
fn emit_native_struct_asm(value: &Expression, fields: &[(&str, &str)], asm: &mut Vec<Op>) {
    match native_struct_leaves(value, fields) {
        Some(leaves) => leaves
            .iter()
            .for_each(|leaf| emit_expression_asm(leaf, asm)),
        None => {
            emit_expression_asm(value, asm);
            // Helpers return structs first-field-on-top.
            if matches!(&value.kind, ExprKind::Extracted(_)) {
                asm.push(Opcode::Swap.into());
            }
        }
    }
}

pub(crate) fn asset_id_fields() -> &'static [(&'static str, &'static str)] {
    models::builtin_struct_fields("AssetId").expect("AssetId is a native struct")
}

/// Push an `AssetId` value: its txid, then its gidx on top.
pub(crate) fn emit_asset_id_asm(asset_id: &Expression, asm: &mut Vec<Op>) {
    emit_native_struct_asm(asset_id, asset_id_fields(), asm);
}

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
            asm.push(Opcode::InspectIntentMessage.into());
            // The opcode leaves the value below its presence flag.
            asm.push(Op::Opcode(if *presence_only {
                Opcode::Nip
            } else {
                Opcode::Verify
            }));
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
                emit_asset_id_asm(exception, asm);
            }
            asm.push(Op::Push(exceptions.len().to_string()));
            asm.push(Opcode::Tunnel.into());
        }
        // Rejected before emission; array declarations emit their elements directly.
        ExprKind::ArrayLiteral(_) => {}
        // Rejected before emission; typed struct declarations emit scalar leaves directly.
        ExprKind::StructLiteral { .. } => {}
        ExprKind::FieldAccess { .. } | ExprKind::IndexAccess { .. } => {
            unreachable!("binding accesses are extracted before emission")
        }
        ExprKind::ArrayIndex { array, index } => {
            // `read_binding` checks a literal index past the end at runtime.
            if let Some(index) = index.literal_index() {
                asm.push(Op::Read(array.clone().index(index)));
            } else {
                emit_expression_asm(index, asm);
                asm.push(Op::ArrayElement(array.clone()));
            }
        }
        ExprKind::This(property) => asm.push(Op::Opcode(match property {
            ThisProperty::ActiveInputIndex => Opcode::PushCurrentInputIndex,
            ThisProperty::Expiry => Opcode::PushExpiry,
        })),
        ExprKind::AssetLookup {
            source,
            index,
            asset_id,
        } => asset::emit_asset_lookup_asm(source, index, asset_id, asm),
        ExprKind::AssetHas {
            source,
            index,
            asset_id,
        } => asset::emit_asset_has_asm(source, index, asset_id, asm),
        ExprKind::AssetTryLookup {
            source,
            index,
            asset_id,
        } => asset::emit_asset_lookup_operands(source, index, asset_id, asm),
        ExprKind::AssetCount { source, index } => {
            asset::emit_asset_count_asm(source, index, asm);
        }
        ExprKind::AssetAt {
            source,
            io_index,
            asset_index,
            property,
        } => {
            asset::emit_asset_at_asm(source, io_index, asset_index, *property, asm);
        }
        ExprKind::TxIntrospection { property } => {
            introspection::emit_tx_introspection_asm(*property, asm);
        }
        ExprKind::InputIntrospection { index, property } => {
            introspection::emit_input_introspection_asm(index, *property, asm);
        }
        ExprKind::OutputIntrospection { index, property } => {
            introspection::emit_output_introspection_asm(index, *property, asm);
        }
        ExprKind::BinaryOp { left, op, right } => emit_binary_op_asm(left, *op, right, asm),
        ExprKind::GroupLookup { asset_id } => asset::emit_group_lookup_asm(asset_id, asm),
        ExprKind::GroupHas { asset_id } => asset::emit_group_has_asm(asset_id, asm),
        ExprKind::GroupControlIs { group, asset_id } => {
            asset::emit_group_control_is_asm(group, asset_id, asm)
        }
        ExprKind::GroupProperty { group, property } => {
            asset::emit_group_property_asm(group, *property, asm);
        }
        ExprKind::AssetGroupsLength => {
            asm.push(Opcode::InspectNumAssetGroups.into());
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
                GroupIOSource::Inputs => asm.push(Opcode::Int0.into()),
                GroupIOSource::Outputs => asm.push(Opcode::Int1.into()),
            }
            asm.push(Opcode::InspectAssetGroup.into());
            // The record is `[type, index, amount]`.
            match property {
                Some(GroupIoProperty::Amount) => {
                    asm.push(Opcode::Nip.into());
                    asm.push(Opcode::Nip.into());
                }
                Some(GroupIoProperty::Type) => {
                    asm.push(Opcode::Drop.into());
                    asm.push(Opcode::Drop.into());
                }
                Some(GroupIoProperty::Index) => {
                    asm.push(Opcode::Drop.into());
                    asm.push(Opcode::Nip.into());
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
            use crate::builtins::Lowering;
            let (Lowering::Opcodes(opcodes) | Lowering::Check(opcodes)) = builtin.lowering else {
                unreachable!("pairings are extracted before raw emission")
            };
            for (arg, (_, ty)) in args.iter().zip(builtin.params) {
                match models::builtin_struct_fields(ty) {
                    Some(fields) => emit_native_struct_asm(arg, fields, asm),
                    None => emit_expression_asm(arg, asm),
                }
            }
            if builtin.name == "bytes2uint" {
                asm.push(Op::Push("0x00".into()));
            }
            asm.extend(opcodes.iter().copied().map(Op::from));
            if matches!(builtin.lowering, Lowering::Check(_)) {
                asm.push(Opcode::Int1.into());
            }
        }
        ExprKind::Unary { op, value } => {
            emit_expression_asm(value, asm);
            asm.push(op.opcode().into());
        }
        ExprKind::Cast { target, data } => {
            emit_expression_asm(data, asm);
            if data.ty == ArkType::parse(target) {
                return;
            }
            match target.as_str() {
                // Normalize spender-supplied integers before exposing their encoding.
                "bytes" if data.ty == ArkType::Int => asm.push(Opcode::Bin2Num.into()),
                // Constructor bools are not checked like witness bools; normalize to 0/1.
                "bytes" if data.ty == ArkType::Bool => asm.push(Opcode::NotEqual0.into()),
                "int" | "bool" => asm.push(Opcode::NotEqual0.into()),
                "bytes20" => asm.extend([
                    Opcode::Size.into(),
                    Op::Push("20".into()),
                    Opcode::EqualVerify.into(),
                ]),
                "bytes32" => asm.extend([
                    Opcode::Size.into(),
                    Op::Push("32".into()),
                    Opcode::EqualVerify.into(),
                ]),
                _ => {}
            }
        }
        ExprKind::PacketInspect {
            packet_type,
            presence_only,
        } => {
            emit_expression_asm(packet_type, asm);
            asm.push(Opcode::InspectPacket.into());
            emit_packet_result_asm(*presence_only, asm);
        }
        ExprKind::InputPacketInspect {
            index,
            packet_type,
            presence_only,
        } => {
            emit_expression_asm(packet_type, asm);
            emit_expression_asm(index, asm);
            asm.push(Opcode::InspectInputPacket.into());
            emit_packet_result_asm(*presence_only, asm);
        }
    }
}

/// Reduce a packet inspection's `[bytes, found]` to the flag or to the asserted bytes.
fn emit_packet_result_asm(presence_only: bool, asm: &mut Vec<Op>) {
    if presence_only {
        asm.push(Opcode::Nip.into());
    } else {
        asm.push(Opcode::Int1.into());
        asm.push(Opcode::EqualVerify.into());
    }
}

/// A placeholder for the child's 32-byte Taproot witness program, then witness version 1. The
/// runtime applies the enclosing contract's options (operator key, exit timelock) when it
/// computes the child's key.
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
    asm.push(Opcode::Int1.into());
}

pub(crate) fn emit_binary_op_asm(
    left: &Expression,
    op: BinaryOperator,
    right: &Expression,
    asm: &mut Vec<Op>,
) {
    emit_expression_asm(left, asm);
    if op.class() == OperatorClass::Logical {
        asm.push(Opcode::If.into());
        if op == BinaryOperator::And {
            emit_expression_asm(right, asm);
        } else {
            asm.push(Opcode::Int1.into());
        }
        asm.push(Opcode::Else.into());
        if op == BinaryOperator::Or {
            emit_expression_asm(right, asm);
        } else {
            asm.push(Opcode::Int0.into());
        }
        asm.push(Opcode::EndIf.into());
        return;
    }
    emit_expression_asm(right, asm);
    let concat = op == BinaryOperator::Add
        && [left, right]
            .iter()
            .any(|operand| operand.ty.is_bytes_like());
    if concat {
        asm.push(Opcode::Cat.into());
    } else {
        asm.extend(
            operator_opcodes(op, left, right)
                .iter()
                .copied()
                .map(Op::from),
        );
    }
}

fn operator_opcodes(
    op: BinaryOperator,
    left: &Expression,
    right: &Expression,
) -> &'static [Opcode] {
    let numeric = [left, right]
        .iter()
        .all(|operand| types::is_numeric(&operand.ty));
    op.opcodes_for(numeric)
}
