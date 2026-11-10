use super::*;
use crate::models::*;
use crate::properties::{InputProperty, OutputProperty, TxProperty};

/// Emit assembly for transaction introspection: tx.version, tx.locktime, etc.
pub(crate) fn emit_tx_introspection_asm(property: TxProperty, asm: &mut Vec<Op>) {
    asm.push(Op::Opcode(match property {
        TxProperty::Version => InspectVersion,
        TxProperty::Locktime => InspectLockTime,
        TxProperty::NumInputs => InspectNumInputs,
        TxProperty::NumOutputs => InspectNumOutputs,
        TxProperty::Weight => TxWeight,
        TxProperty::Id => Txid,
    }));
}

/// Emit a scriptPubKey inspection opcode and keep only the witness version.
pub(crate) fn emit_witness_version_asm(opcode: Opcode, asm: &mut Vec<Op>) {
    asm.push(opcode.into());
    asm.push(Nip.into());
}

/// Emit assembly for input introspection: tx.inputs[i].property
pub(crate) fn emit_input_introspection_asm(
    index: &Expression,
    property: InputProperty,
    asm: &mut Vec<Op>,
) {
    emit_expression_asm(index, asm);
    match property {
        InputProperty::Value => asm.push(InspectInputValue.into()),
        InputProperty::WitnessVersion => emit_witness_version_asm(InspectInputScriptPubKey, asm),
        InputProperty::Sequence => asm.push(InspectInputSequence.into()),
        InputProperty::Outpoint => asm.push(InspectInputOutpoint.into()),
        InputProperty::ArkadeScriptHash => asm.push(InspectInputArkadeScriptHash.into()),
        InputProperty::ArkadeWitnessHash => asm.push(InspectInputArkadeWitnessHash.into()),
        InputProperty::Script => asm.push(InspectInputScriptPubKey.into()),
    }
}

/// Emit assembly for output introspection: tx.outputs[o].property
pub(crate) fn emit_output_introspection_asm(
    index: &Expression,
    property: OutputProperty,
    asm: &mut Vec<Op>,
) {
    emit_expression_asm(index, asm);
    match property {
        OutputProperty::Value => asm.push(InspectOutputValue.into()),
        OutputProperty::WitnessVersion => emit_witness_version_asm(InspectOutputScriptPubKey, asm),
        OutputProperty::Script => asm.push(InspectOutputScriptPubKey.into()),
    }
}
