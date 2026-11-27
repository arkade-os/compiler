//! Emits asset introspection: per-input/output asset lookups and asset group properties.

use super::expr;
use super::ir::Op;
use crate::models::{AssetLookupSource, Expression};
use crate::opcodes::Opcode;
use crate::properties::{AssetProperty, GroupProperty};

/// The opcode pops gidx, then txid, then the io index, and leaves `[amount, success_flag]`.
pub(crate) fn emit_asset_lookup_operands(
    source: &AssetLookupSource,
    index: &Expression,
    asset_id: &Expression,
    asm: &mut Vec<Op>,
) {
    expr::emit_expression_asm(index, asm);
    expr::emit_asset_id_asm(asset_id, asm);
    match source {
        AssetLookupSource::Input => asm.push(Opcode::InspectInAssetLookup.into()),
        AssetLookupSource::Output => asm.push(Opcode::InspectOutAssetLookup.into()),
    }
}

pub(crate) fn emit_asset_lookup_asm(
    source: &AssetLookupSource,
    index: &Expression,
    asset_id: &Expression,
    asm: &mut Vec<Op>,
) {
    emit_asset_lookup_operands(source, index, asset_id, asm);
    asm.push(Opcode::Verify.into());
}

pub(crate) fn emit_asset_has_asm(
    source: &AssetLookupSource,
    index: &Expression,
    asset_id: &Expression,
    asm: &mut Vec<Op>,
) {
    emit_asset_lookup_operands(source, index, asset_id, asm);
    asm.push(Opcode::Nip.into());
}

/// OP_FINDASSETGROUPBYASSETID leaves `[k, success_flag]`.
pub(crate) fn emit_group_lookup_asm(asset_id: &Expression, asm: &mut Vec<Op>) {
    expr::emit_asset_id_asm(asset_id, asm);
    asm.push(Opcode::FindAssetGroupByAssetId.into());
    asm.push(Opcode::Verify.into());
}

pub(crate) fn emit_group_has_asm(asset_id: &Expression, asm: &mut Vec<Op>) {
    expr::emit_asset_id_asm(asset_id, asm);
    asm.push(Opcode::FindAssetGroupByAssetId.into());
    asm.push(Opcode::Nip.into());
}

/// OP_INSPECTASSETGROUPCTRL leaves `[ctrl_txid, ctrl_gidx, flag]`, or `[empty, 0, 0]` when the
/// group has no control asset; an empty txid never equals a 32-byte one, so absence is false.
/// A non-minimal gidx fails the spend in OP_NUMEQUAL.
pub(crate) fn emit_group_control_is_asm(
    group: &Expression,
    asset_id: &Expression,
    asm: &mut Vec<Op>,
) {
    expr::emit_expression_asm(group, asm);
    asm.push(Opcode::InspectAssetGroupCtrl.into());
    asm.push(Opcode::Drop.into());
    match expr::native_struct_leaves(asset_id, expr::asset_id_fields()).as_deref() {
        // A binding's or literal's fields are pushed where each comparison needs them.
        Some([txid, gidx]) => {
            expr::emit_expression_asm(gidx, asm);
            asm.push(Opcode::NumEqual.into()); // ctrl_gidx == gidx -> [ctrl_txid, bool]
            asm.push(Opcode::Swap.into()); // -> [bool, ctrl_txid]
            expr::emit_expression_asm(txid, asm);
        }
        _ => {
            expr::emit_asset_id_asm(asset_id, asm); // -> [ctrl_txid, ctrl_gidx, txid, gidx]
            asm.push(Opcode::Rot.into()); // -> [ctrl_txid, txid, gidx, ctrl_gidx]
            asm.push(Opcode::NumEqual.into()); // -> [ctrl_txid, txid, bool]
            asm.push(Opcode::Swap.into()); // -> [ctrl_txid, bool, txid]
            asm.push(Opcode::Rot.into()); // -> [bool, txid, ctrl_txid]
        }
    }
    asm.push(Opcode::Equal.into()); // ctrl_txid == txid -> [bool, bool]
    asm.push(Opcode::BoolAnd.into());
}

pub(crate) fn emit_asset_count_asm(
    source: &AssetLookupSource,
    index: &Expression,
    asm: &mut Vec<Op>,
) {
    expr::emit_expression_asm(index, asm);

    match source {
        AssetLookupSource::Input => {
            asm.push(Opcode::InspectInAssetCount.into());
        }
        AssetLookupSource::Output => {
            asm.push(Opcode::InspectOutAssetCount.into());
        }
    }
}

/// OP_INSPECTINASSETAT and OP_INSPECTOUTASSETAT leave `[txid, gidx, amount]`.
pub(crate) fn emit_asset_at_asm(
    source: &AssetLookupSource,
    io_index: &Expression,
    asset_index: &Expression,
    property: Option<AssetProperty>,
    asm: &mut Vec<Op>,
) {
    expr::emit_expression_asm(io_index, asm);

    expr::emit_expression_asm(asset_index, asm);

    match source {
        AssetLookupSource::Input => {
            asm.push(Opcode::InspectInAssetAt.into());
        }
        AssetLookupSource::Output => {
            asm.push(Opcode::InspectOutAssetAt.into());
        }
    }

    match property {
        None => {}
        Some(AssetProperty::AssetId) => {
            asm.push(Opcode::Drop.into());
        }
        Some(AssetProperty::Amount) => {
            asm.push(Opcode::Nip.into());
            asm.push(Opcode::Nip.into());
        }
    }
}

pub(crate) fn emit_group_property_asm(
    group: &Expression,
    property: GroupProperty,
    asm: &mut Vec<Op>,
) {
    expr::emit_expression_asm(group, asm);
    match property {
        GroupProperty::SumInputs
        | GroupProperty::SumOutputs
        | GroupProperty::NumInputs
        | GroupProperty::NumOutputs => {
            let inputs = matches!(
                property,
                GroupProperty::SumInputs | GroupProperty::NumInputs
            );
            asm.push(Op::Opcode(if inputs { Opcode::Int0 } else { Opcode::Int1 }));
            let sum = matches!(
                property,
                GroupProperty::SumInputs | GroupProperty::SumOutputs
            );
            asm.push(Op::Opcode(if sum {
                Opcode::InspectAssetGroupSum
            } else {
                Opcode::InspectAssetGroupNum
            }));
        }
        GroupProperty::Delta => {
            asm.push(Opcode::Dup.into());
            asm.push(Opcode::Int1.into());
            asm.push(Opcode::InspectAssetGroupSum.into());
            asm.push(Opcode::Swap.into());
            asm.push(Opcode::Int0.into());
            asm.push(Opcode::InspectAssetGroupSum.into());
            asm.push(Opcode::Sub.into());
        }
        GroupProperty::HasControl => {
            asm.push(Opcode::InspectAssetGroupCtrl.into());
            asm.push(Opcode::Nip.into());
            asm.push(Opcode::Nip.into());
        }
        GroupProperty::ControlAssetId => {
            asm.push(Opcode::InspectAssetGroupCtrl.into());
            asm.push(Opcode::Verify.into());
        }
        GroupProperty::MetadataHash => asm.push(Opcode::InspectAssetGroupMetadataHash.into()),
        GroupProperty::AssetId => asm.push(Opcode::InspectAssetGroupAssetId.into()),
        GroupProperty::IsFresh => {
            // A fresh group's asset is issued by this transaction.
            asm.push(Opcode::InspectAssetGroupAssetId.into());
            asm.push(Opcode::Drop.into());
            asm.push(Opcode::Txid.into());
            asm.push(Opcode::Equal.into());
        }
    }
}
