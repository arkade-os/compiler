use super::*;
use crate::models::*;

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
    asm: &mut Vec<String>,
) {
    emit_expression_asm(index, asm);
    emit_expression_asm(asset_txid, asm); // -> <fooTxid>
    emit_expression_asm(asset_gidx, asm); // -> <fooGidx> or pushed literal
    match source {
        AssetLookupSource::Input => asm.push(OP_INSPECTINASSETLOOKUP.to_string()),
        AssetLookupSource::Output => asm.push(OP_INSPECTOUTASSETLOOKUP.to_string()),
    }
}

/// Emit `tx.{inputs,outputs}[i].assets.lookup(txid, gidx)`: assert the asset is
/// present (consume the success flag with OP_VERIFY) and leave the typed amount.
pub(crate) fn emit_asset_lookup_asm(
    source: &AssetLookupSource,
    index: &Expression,
    asset_txid: &Expression,
    asset_gidx: &Expression,
    asm: &mut Vec<String>,
) {
    emit_asset_lookup_operands(source, index, asset_txid, asset_gidx, asm);
    asm.push(OP_VERIFY.to_string()); // consume success flag, leave amount
}

/// Emit `tx.{inputs,outputs}[i].assets.has(txid, gidx)`: boolean presence —
/// keep the success flag, drop the amount below it with OP_NIP.
pub(crate) fn emit_asset_has_asm(
    source: &AssetLookupSource,
    index: &Expression,
    asset_txid: &Expression,
    asset_gidx: &Expression,
    asm: &mut Vec<String>,
) {
    emit_asset_lookup_operands(source, index, asset_txid, asset_gidx, asm);
    asm.push(OP_NIP.to_string()); // drop amount, leave success flag (Bool)
}

/// Emit `tx.assetGroups.find(txid, gidx)`: assert existence (consume the success
/// flag with OP_VERIFY) and leave the resolved packet position k.
pub(crate) fn emit_group_find_asm(
    asset_txid: &Expression,
    asset_gidx: &Expression,
    asm: &mut Vec<String>,
) {
    emit_expression_asm(asset_txid, asm);
    emit_expression_asm(asset_gidx, asm);
    asm.push(OP_FINDASSETGROUPBYASSETID.to_string());
    asm.push(OP_VERIFY.to_string()); // consume success flag, leave k; fail if absent
}

/// Emit `tx.assetGroups.has(txid, gidx)`: boolean presence — keep the success
/// flag, drop the resolved position k below it with OP_NIP.
pub(crate) fn emit_group_has_asm(
    asset_txid: &Expression,
    asset_gidx: &Expression,
    asm: &mut Vec<String>,
) {
    emit_expression_asm(asset_txid, asm);
    emit_expression_asm(asset_gidx, asm);
    asm.push(OP_FINDASSETGROUPBYASSETID.to_string());
    asm.push(OP_NIP.to_string()); // drop k, leave success flag (Bool)
}

/// Emit `group.controlIs(txid, gidx)`: boolean equality over the complete
/// canonical control Asset ID. Stack after OP_INSPECTASSETGROUPCTRL is
/// `[ctrl_txid, ctrl_gidx, flag]`; drop the flag, compare gidx then txid (no
/// OP_EQUALVERIFY), and AND the two booleans. The absent tuple
/// `[empty_bytes, 0, 0]` cannot equal a valid bytes32 txid, so absence is false.
pub(crate) fn emit_group_control_is_asm(
    group: &str,
    asset_txid: &Expression,
    asset_gidx: &Expression,
    asm: &mut Vec<String>,
) {
    asm.push(format!("<{}>", group));
    asm.push(OP_INSPECTASSETGROUPCTRL.to_string());
    asm.push(OP_DROP.to_string()); // drop success flag -> [ctrl_txid, ctrl_gidx]
    emit_expression_asm(asset_gidx, asm);
    asm.push(OP_EQUAL.to_string()); // ctrl_gidx == gidx -> [ctrl_txid, bool]
    asm.push(OP_SWAP.to_string()); // -> [bool, ctrl_txid]
    emit_expression_asm(asset_txid, asm);
    asm.push(OP_EQUAL.to_string()); // ctrl_txid == txid -> [bool, bool]
    asm.push(OP_BOOLAND.to_string()); // combine -> Bool
}

/// Emit assembly for asset count: tx.inputs[i].assets.length or tx.outputs[o].assets.length
///
/// Pushes the count of assets at the given input/output index.
pub(crate) fn emit_asset_count_asm(
    source: &AssetLookupSource,
    index: &Expression,
    asm: &mut Vec<String>,
) {
    // Push the index
    emit_expression_asm(index, asm);

    // Emit the appropriate count opcode
    match source {
        AssetLookupSource::Input => {
            asm.push(OP_INSPECTINASSETCOUNT.to_string());
        }
        AssetLookupSource::Output => {
            asm.push(OP_INSPECTOUTASSETCOUNT.to_string());
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
    property: &str,
    asm: &mut Vec<String>,
) {
    // Push io_index
    emit_expression_asm(io_index, asm);

    // Push asset_index
    emit_expression_asm(asset_index, asm);

    // Emit the appropriate opcode
    match source {
        AssetLookupSource::Input => {
            asm.push(OP_INSPECTINASSETAT.to_string());
        }
        AssetLookupSource::Output => {
            asm.push(OP_INSPECTOUTASSETAT.to_string());
        }
    }

    // Stack after opcode: txid32, gidx_u16, amount_u64 (top)
    // Extract based on property
    match property {
        "assetId" => {
            // Drop the amount, keep the canonical Asset ID (asset_txid, asset_gidx).
            // TODO(asset-id-struct): this intentionally leaves TWO stack items, so
            // `.assetId` needs a composite `AssetId` struct return type before it
            // can be destructured (.txid/.gidx) or compared safely. Deferred to a
            // separate PR.
            asm.push(OP_DROP.to_string());
        }
        "amount" => {
            // Keep only the amount (top of stack)
            // NIP removes the second item from the top
            asm.push(OP_NIP.to_string()); // Remove gidx_u16
            asm.push(OP_NIP.to_string()); // Remove txid32
        }
        _ => {
            // Unknown property, leave stack as-is
        }
    }
}

/// Emit assembly for group property access
pub(crate) fn emit_group_property_asm(group: &str, property: &str, asm: &mut Vec<String>) {
    match property {
        "sumInputs" => {
            asm.push(format!("<{}>", group));
            asm.push(OP_0.to_string()); // source=inputs
            asm.push(OP_INSPECTASSETGROUPSUM.to_string());
        }
        "sumOutputs" => {
            asm.push(format!("<{}>", group));
            asm.push(OP_1.to_string()); // source=outputs
            asm.push(OP_INSPECTASSETGROUPSUM.to_string());
        }
        "numInputs" => {
            asm.push(format!("<{}>", group));
            asm.push(OP_0.to_string()); // source=inputs
            asm.push(OP_INSPECTASSETGROUPNUM.to_string());
        }
        "numOutputs" => {
            asm.push(format!("<{}>", group));
            asm.push(OP_1.to_string()); // source=outputs
            asm.push(OP_INSPECTASSETGROUPNUM.to_string());
        }
        "delta" => {
            // delta = sumOutputs - sumInputs
            asm.push(format!("<{}>", group));
            asm.push(OP_1.to_string());
            asm.push(OP_INSPECTASSETGROUPSUM.to_string());
            asm.push(format!("<{}>", group));
            asm.push(OP_0.to_string());
            asm.push(OP_INSPECTASSETGROUPSUM.to_string());
            asm.push(OP_SUB.to_string());
        }
        "hasControl" => {
            // group.hasControl: presence only.
            // [ctrl_txid, ctrl_gidx, flag] -> OP_NIP OP_NIP -> flag (Bool)
            asm.push(format!("<{}>", group));
            asm.push(OP_INSPECTASSETGROUPCTRL.to_string());
            asm.push(OP_NIP.to_string());
            asm.push(OP_NIP.to_string());
        }
        "metadataHash" => {
            asm.push(format!("<{}>", group));
            asm.push(OP_INSPECTASSETGROUPMETADATAHASH.to_string());
        }
        "assetId" => {
            // Returns the canonical Asset ID (asset_txid, asset_gidx) — TWO stack items.
            // TODO(asset-id-struct): like asset_at `.assetId`, this needs a composite
            // `AssetId` struct return type before it can be destructured (.txid/.gidx)
            // or compared with `==` (a single OP_EQUAL only sees the top item, the
            // gidx). Deferred to a separate PR.
            asm.push(format!("<{}>", group));
            asm.push(OP_INSPECTASSETGROUPASSETID.to_string());
        }
        "isFresh" => {
            // isFresh: compares assetId.txid with current transaction's txid
            // 1. Get group's assetId (returns txid32, gidx_u16)
            asm.push(format!("<{}>", group));
            asm.push(OP_INSPECTASSETGROUPASSETID.to_string());
            // 2. Drop gidx_u16, keep txid32
            asm.push(OP_DROP.to_string());
            // 3. Get current transaction hash
            asm.push(OP_TXID.to_string());
            // 4. Compare txids - result is bool
            asm.push(OP_EQUAL.to_string());
        }
        _ => {
            // Unknown group property
            asm.push(format!("<{}.{}>", group, property));
        }
    }
}
