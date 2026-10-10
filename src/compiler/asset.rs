use super::*;
use crate::models::*;
use crate::properties::{AssetProperty, GroupProperty};

/// Push the lookup operands and the source-appropriate lookup opcode.
///
/// Push order follows the opcode (`popAssetID` pops gidx top, then txid; then
/// the io index `o`/`i`): index, then txid, then gidx. Stack after the opcode is
/// `[amount, success_flag]` (flag on top).
pub(crate) fn emit_asset_lookup_operands(
    source: &AssetLookupSource,
    index: &Expression,
    asset_txid: &Expression,
    asset_gidx: &Expression,
    asm: &mut Vec<Op>,
) {
    emit_expression_asm(index, asm);
    emit_expression_asm(asset_txid, asm); // -> <fooTxid>
    emit_expression_asm(asset_gidx, asm); // -> <fooGidx> or pushed literal
    match source {
        AssetLookupSource::Input => asm.push(Op::Opcode(InspectInAssetLookup)),
        AssetLookupSource::Output => asm.push(Op::Opcode(InspectOutAssetLookup)),
    }
}

/// Emit `tx.{inputs,outputs}[i].assets.lookup(txid, gidx)`: assert the asset is
/// present (consume the success flag with OP_VERIFY) and leave the typed amount.
pub(crate) fn emit_asset_lookup_asm(
    source: &AssetLookupSource,
    index: &Expression,
    asset_txid: &Expression,
    asset_gidx: &Expression,
    asm: &mut Vec<Op>,
) {
    emit_asset_lookup_operands(source, index, asset_txid, asset_gidx, asm);
    asm.push(Op::Opcode(Verify)); // consume success flag, leave amount
}

/// Emit `tx.{inputs,outputs}[i].assets.has(txid, gidx)`: boolean presence —
/// keep the success flag, drop the amount below it with OP_NIP.
pub(crate) fn emit_asset_has_asm(
    source: &AssetLookupSource,
    index: &Expression,
    asset_txid: &Expression,
    asset_gidx: &Expression,
    asm: &mut Vec<Op>,
) {
    emit_asset_lookup_operands(source, index, asset_txid, asset_gidx, asm);
    asm.push(Op::Opcode(Nip)); // drop amount, leave success flag (Bool)
}

/// Emit `tx.assetGroups.find(txid, gidx)`: assert existence (consume the success
/// flag with OP_VERIFY) and leave the resolved packet position k.
pub(crate) fn emit_group_find_asm(
    asset_txid: &Expression,
    asset_gidx: &Expression,
    asm: &mut Vec<Op>,
) {
    emit_expression_asm(asset_txid, asm);
    emit_expression_asm(asset_gidx, asm);
    asm.push(Op::Opcode(FindAssetGroupByAssetId));
    asm.push(Op::Opcode(Verify)); // consume success flag, leave k; fail if absent
}

/// Emit `tx.assetGroups.has(txid, gidx)`: boolean presence — keep the success
/// flag, drop the resolved position k below it with OP_NIP.
pub(crate) fn emit_group_has_asm(
    asset_txid: &Expression,
    asset_gidx: &Expression,
    asm: &mut Vec<Op>,
) {
    emit_expression_asm(asset_txid, asm);
    emit_expression_asm(asset_gidx, asm);
    asm.push(Op::Opcode(FindAssetGroupByAssetId));
    asm.push(Op::Opcode(Nip)); // drop k, leave success flag (Bool)
}

/// Emit `group.controlIs(txid, gidx)`: boolean equality over the complete
/// canonical control Asset ID. Stack after OP_INSPECTASSETGROUPCTRL is
/// `[ctrl_txid, ctrl_gidx, flag]`; drop the flag, compare gidx then txid (no
/// OP_EQUALVERIFY), and AND the two booleans. The absent tuple
/// `[empty_bytes, 0, 0]` cannot equal a valid bytes32 txid, so absence is false.
pub(crate) fn emit_group_control_is_asm(
    group: &Expression,
    asset_txid: &Expression,
    asset_gidx: &Expression,
    asm: &mut Vec<Op>,
) {
    emit_expression_asm(group, asm);
    asm.push(Op::Opcode(InspectAssetGroupCtrl));
    asm.push(Op::Opcode(Drop)); // drop success flag -> [ctrl_txid, ctrl_gidx]
    emit_expression_asm(asset_gidx, asm);
    asm.push(Op::Opcode(Equal)); // ctrl_gidx == gidx -> [ctrl_txid, bool]
    asm.push(Op::Opcode(Swap)); // -> [bool, ctrl_txid]
    emit_expression_asm(asset_txid, asm);
    asm.push(Op::Opcode(Equal)); // ctrl_txid == txid -> [bool, bool]
    asm.push(Op::Opcode(BoolAnd)); // combine -> Bool
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
    emit_expression_asm(index, asm);

    // Emit the appropriate count opcode
    match source {
        AssetLookupSource::Input => {
            asm.push(Op::Opcode(InspectInAssetCount));
        }
        AssetLookupSource::Output => {
            asm.push(Op::Opcode(InspectOutAssetCount));
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
    emit_expression_asm(io_index, asm);

    // Push asset_index
    emit_expression_asm(asset_index, asm);

    // Emit the appropriate opcode
    match source {
        AssetLookupSource::Input => {
            asm.push(Op::Opcode(InspectInAssetAt));
        }
        AssetLookupSource::Output => {
            asm.push(Op::Opcode(InspectOutAssetAt));
        }
    }

    // Stack after opcode: txid32, gidx_u16, amount_u64 (top)
    // Extract based on property
    match property {
        None => {}
        Some(AssetProperty::AssetId) => {
            // Drop the amount, keep the canonical Asset ID (asset_txid, asset_gidx).
            asm.push(Op::Opcode(Drop));
        }
        Some(AssetProperty::Amount) => {
            asm.push(Op::Opcode(Nip)); // Remove gidx_u16
            asm.push(Op::Opcode(Nip)); // Remove txid32
        }
    }
}

/// Emit assembly for group property access
pub(crate) fn emit_group_property_asm(
    group: &Expression,
    property: GroupProperty,
    asm: &mut Vec<Op>,
) {
    emit_expression_asm(group, asm);
    match property {
        GroupProperty::SumInputs
        | GroupProperty::SumOutputs
        | GroupProperty::NumInputs
        | GroupProperty::NumOutputs => {
            let inputs = matches!(
                property,
                GroupProperty::SumInputs | GroupProperty::NumInputs
            );
            asm.push(Op::Opcode(if inputs { Int0 } else { Int1 }));
            let sum = matches!(
                property,
                GroupProperty::SumInputs | GroupProperty::SumOutputs
            );
            asm.push(Op::Opcode(if sum {
                InspectAssetGroupSum
            } else {
                InspectAssetGroupNum
            }));
        }
        GroupProperty::Delta => {
            // delta = sumOutputs - sumInputs
            asm.push(Op::Opcode(Dup));
            asm.push(Op::Opcode(Int1));
            asm.push(Op::Opcode(InspectAssetGroupSum));
            asm.push(Op::Opcode(Swap));
            asm.push(Op::Opcode(Int0));
            asm.push(Op::Opcode(InspectAssetGroupSum));
            asm.push(Op::Opcode(Sub));
        }
        GroupProperty::HasControl => {
            // group.hasControl: presence only.
            // [ctrl_txid, ctrl_gidx, flag] -> OP_NIP OP_NIP -> flag (Bool)
            asm.push(Op::Opcode(InspectAssetGroupCtrl));
            asm.push(Op::Opcode(Nip));
            asm.push(Op::Opcode(Nip));
        }
        GroupProperty::ControlAssetId => {
            // [ctrl_txid, ctrl_gidx, flag]: aborts when the group has no control asset.
            asm.push(Op::Opcode(InspectAssetGroupCtrl));
            asm.push(Op::Opcode(Verify));
        }
        GroupProperty::MetadataHash => asm.push(Op::Opcode(InspectAssetGroupMetadataHash)),
        // Returns the canonical Asset ID (asset_txid, asset_gidx).
        GroupProperty::AssetId => asm.push(Op::Opcode(InspectAssetGroupAssetId)),
        GroupProperty::IsFresh => {
            // The group's asset txid equals the current transaction's txid.
            asm.push(Op::Opcode(InspectAssetGroupAssetId));
            asm.push(Op::Opcode(Drop));
            asm.push(Op::Opcode(Txid));
            asm.push(Op::Opcode(Equal));
        }
    }
}
