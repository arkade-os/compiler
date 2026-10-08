use super::*;
use crate::models::*;
use crate::properties::{InputProperty, OutputProperty, TxProperty};

/// Emit assembly for transaction introspection: tx.version, tx.locktime, etc.
pub(crate) fn emit_tx_introspection_asm(property: TxProperty, asm: &mut Vec<String>) {
    asm.push(
        match property {
            TxProperty::Version => OP_INSPECTVERSION,
            TxProperty::Locktime => OP_INSPECTLOCKTIME,
            TxProperty::NumInputs => OP_INSPECTNUMINPUTS,
            TxProperty::NumOutputs => OP_INSPECTNUMOUTPUTS,
            TxProperty::Weight => OP_TXWEIGHT,
            TxProperty::Id => OP_TXID,
        }
        .to_string(),
    );
}

/// Emit a scriptPubKey inspection opcode and reduce its result to one item.
///
/// `OP_INSPECT{IN,OUT}PUTSCRIPTPUBKEY` pushes two items: the witness program,
/// then the witness version as a scriptnum on top. Everything downstream
/// (`==`, `let`, hashing) consumes a single value, so the version is dropped
/// and the witness program is what a scriptPubKey compares against.
pub(crate) fn emit_script_pubkey_asm(opcode: &str, asm: &mut Vec<String>) {
    asm.push(opcode.to_string());
    asm.push(OP_DROP.to_string());
}

/// Emit a scriptPubKey inspection opcode and keep only the witness version.
pub(crate) fn emit_witness_version_asm(opcode: &str, asm: &mut Vec<String>) {
    asm.push(opcode.to_string());
    asm.push(OP_NIP.to_string());
}

/// Emit assembly for input introspection: tx.inputs[i].property
pub(crate) fn emit_input_introspection_asm(
    index: &Expression,
    property: InputProperty,
    asm: &mut Vec<String>,
) {
    emit_expression_asm(index, asm);
    match property {
        InputProperty::Value => asm.push(OP_INSPECTINPUTVALUE.to_string()),
        InputProperty::ScriptPubKey => emit_script_pubkey_asm(OP_INSPECTINPUTSCRIPTPUBKEY, asm),
        InputProperty::WitnessVersion => emit_witness_version_asm(OP_INSPECTINPUTSCRIPTPUBKEY, asm),
        InputProperty::Sequence => asm.push(OP_INSPECTINPUTSEQUENCE.to_string()),
        InputProperty::Outpoint => asm.push(OP_INSPECTINPUTOUTPOINT.to_string()),
        InputProperty::ArkadeScriptHash => asm.push(OP_INSPECTINPUTARKADESCRIPTHASH.to_string()),
        InputProperty::ArkadeWitnessHash => asm.push(OP_INSPECTINPUTARKADEWITNESSHASH.to_string()),
    }
}

/// Emit assembly for output introspection: tx.outputs[o].property
pub(crate) fn emit_output_introspection_asm(
    index: &Expression,
    property: OutputProperty,
    asm: &mut Vec<String>,
) {
    emit_expression_asm(index, asm);
    match property {
        OutputProperty::Value => asm.push(OP_INSPECTOUTPUTVALUE.to_string()),
        OutputProperty::ScriptPubKey => emit_script_pubkey_asm(OP_INSPECTOUTPUTSCRIPTPUBKEY, asm),
        OutputProperty::WitnessVersion => {
            emit_witness_version_asm(OP_INSPECTOUTPUTSCRIPTPUBKEY, asm)
        }
    }
}
