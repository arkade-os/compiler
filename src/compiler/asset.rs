use crate::compiler::expr;
use crate::compiler::ir::Op;
use crate::models::AssetLookupSource;
use crate::models::Expression;
use crate::opcodes::Opcode;
use crate::properties::{AssetProperty, GroupProperty};

/// Push the lookup operands and the source-appropriate lookup opcode.
///
/// Push order follows the opcode (`popAssetID` pops gidx top, then txid; then
/// the io index `o`/`i`): index, then txid, then gidx. Stack after the opcode is
/// `[amount, success_flag]` (flag on top).
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

/// Emit `tx.{inputs,outputs}[i].assets.lookup(id)`: assert the asset is
/// present (consume the success flag with OP_VERIFY) and leave the typed amount.
pub(crate) fn emit_asset_lookup_asm(
    source: &AssetLookupSource,
    index: &Expression,
    asset_id: &Expression,
    asm: &mut Vec<Op>,
) {
    emit_asset_lookup_operands(source, index, asset_id, asm);
    asm.push(Opcode::Verify.into()); // consume success flag, leave amount
}

/// Emit `tx.{inputs,outputs}[i].assets.has(id)`: boolean presence —
/// keep the success flag, drop the amount below it with OP_NIP.
pub(crate) fn emit_asset_has_asm(
    source: &AssetLookupSource,
    index: &Expression,
    asset_id: &Expression,
    asm: &mut Vec<Op>,
) {
    emit_asset_lookup_operands(source, index, asset_id, asm);
    asm.push(Opcode::Nip.into()); // drop amount, leave success flag (Bool)
}

/// Emit `tx.assetGroups.lookup(id)`: assert existence (consume the success
/// flag with OP_VERIFY) and leave the resolved packet position k.
pub(crate) fn emit_group_lookup_asm(asset_id: &Expression, asm: &mut Vec<Op>) {
    expr::emit_asset_id_asm(asset_id, asm);
    asm.push(Opcode::FindAssetGroupByAssetId.into());
    asm.push(Opcode::Verify.into()); // consume success flag, leave k; fail if absent
}

/// Emit `tx.assetGroups.has(id)`: boolean presence — keep the success
/// flag, drop the resolved position k below it with OP_NIP.
pub(crate) fn emit_group_has_asm(asset_id: &Expression, asm: &mut Vec<Op>) {
    expr::emit_asset_id_asm(asset_id, asm);
    asm.push(Opcode::FindAssetGroupByAssetId.into());
    asm.push(Opcode::Nip.into()); // drop k, leave success flag (Bool)
}

/// Emit `group.controlIs(id)`: boolean equality over the complete canonical
/// control Asset ID. Stack after OP_INSPECTASSETGROUPCTRL is
/// `[ctrl_txid, ctrl_gidx, flag]`; drop the flag, compare gidx as a number (a
/// non-minimal gidx fails the spend) then txid as bytes (no OP_EQUALVERIFY),
/// and AND the two booleans. The absent tuple
/// `[empty_bytes, 0, 0]` cannot equal a valid bytes32 txid, so absence is false.
pub(crate) fn emit_group_control_is_asm(
    group: &Expression,
    asset_id: &Expression,
    asm: &mut Vec<Op>,
) {
    expr::emit_expression_asm(group, asm);
    asm.push(Opcode::InspectAssetGroupCtrl.into());
    asm.push(Opcode::Drop.into()); // drop success flag -> [ctrl_txid, ctrl_gidx]
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
    asm.push(Opcode::BoolAnd.into()); // combine -> Bool
}

/// Emit assembly for asset count: tx.inputs[i].assets.length or tx.outputs[o].assets.length
///
/// Pushes the count of assets at the given input/output index.
pub(crate) fn emit_asset_count_asm(
    source: &AssetLookupSource,
    index: &Expression,
    asm: &mut Vec<Op>,
) {
    // Push the index
    expr::emit_expression_asm(index, asm);

    // Emit the appropriate count opcode
    match source {
        AssetLookupSource::Input => {
            asm.push(Opcode::InspectInAssetCount.into());
        }
        AssetLookupSource::Output => {
            asm.push(Opcode::InspectOutAssetCount.into());
        }
    }
}

/// Emit assembly for indexed asset access: tx.inputs[i].assets[t].property
///
/// OP_INSPECTINASSETAT / OP_INSPECTOUTASSETAT returns: txid32, gidx_u16, amount_u64
/// We extract based on the property requested.
pub(crate) fn emit_asset_at_asm(
    source: &AssetLookupSource,
    io_index: &Expression,
    asset_index: &Expression,
    property: Option<AssetProperty>,
    asm: &mut Vec<Op>,
) {
    // Push io_index
    expr::emit_expression_asm(io_index, asm);

    // Push asset_index
    expr::emit_expression_asm(asset_index, asm);

    // Emit the appropriate opcode
    match source {
        AssetLookupSource::Input => {
            asm.push(Opcode::InspectInAssetAt.into());
        }
        AssetLookupSource::Output => {
            asm.push(Opcode::InspectOutAssetAt.into());
        }
    }

    // Stack after opcode: txid32, gidx_u16, amount_u64 (top)
    // Extract based on property
    match property {
        None => {}
        Some(AssetProperty::AssetId) => {
            // Drop the amount, keep the canonical Asset ID (asset_txid, asset_gidx).
            asm.push(Opcode::Drop.into());
        }
        Some(AssetProperty::Amount) => {
            asm.push(Opcode::Nip.into()); // Remove gidx_u16
            asm.push(Opcode::Nip.into()); // Remove txid32
        }
    }
}

/// Emit assembly for group property access
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
            // delta = sumOutputs - sumInputs
            asm.push(Opcode::Dup.into());
            asm.push(Opcode::Int1.into());
            asm.push(Opcode::InspectAssetGroupSum.into());
            asm.push(Opcode::Swap.into());
            asm.push(Opcode::Int0.into());
            asm.push(Opcode::InspectAssetGroupSum.into());
            asm.push(Opcode::Sub.into());
        }
        GroupProperty::HasControl => {
            // group.hasControl: presence only.
            // [ctrl_txid, ctrl_gidx, flag] -> OP_NIP OP_NIP -> flag (Bool)
            asm.push(Opcode::InspectAssetGroupCtrl.into());
            asm.push(Opcode::Nip.into());
            asm.push(Opcode::Nip.into());
        }
        GroupProperty::ControlAssetId => {
            // [ctrl_txid, ctrl_gidx, flag]: aborts when the group has no control asset.
            asm.push(Opcode::InspectAssetGroupCtrl.into());
            asm.push(Opcode::Verify.into());
        }
        GroupProperty::MetadataHash => asm.push(Opcode::InspectAssetGroupMetadataHash.into()),
        // Returns the canonical Asset ID (asset_txid, asset_gidx).
        GroupProperty::AssetId => asm.push(Opcode::InspectAssetGroupAssetId.into()),
        GroupProperty::IsFresh => {
            // The group's asset txid equals the current transaction's txid.
            asm.push(Opcode::InspectAssetGroupAssetId.into());
            asm.push(Opcode::Drop.into());
            asm.push(Opcode::Txid.into());
            asm.push(Opcode::Equal.into());
        }
    }
}
