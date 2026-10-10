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

/// Emit a scriptPubKey inspection opcode and reduce its result to one item.
///
/// `OP_INSPECT{IN,OUT}PUTSCRIPTPUBKEY` pushes two items: the witness program,
/// then the witness version as a scriptnum on top. Everything downstream
/// (`==`, `let`, hashing) consumes a single value, so the version is dropped
/// and the witness program is what a scriptPubKey compares against.
pub(crate) fn emit_script_pubkey_asm(opcode: Opcode, asm: &mut Vec<Op>) {
    asm.push(Op::Opcode(opcode));
    asm.push(Op::Opcode(Drop));
}

/// Emit a scriptPubKey inspection opcode and keep only the witness version.
pub(crate) fn emit_witness_version_asm(opcode: Opcode, asm: &mut Vec<Op>) {
    asm.push(Op::Opcode(opcode));
    asm.push(Op::Opcode(Nip));
}

/// Emit assembly for input introspection: tx.inputs[i].property
pub(crate) fn emit_input_introspection_asm(
    index: &Expression,
    property: InputProperty,
    asm: &mut Vec<Op>,
) {
    emit_expression_asm(index, asm);
    match property {
        InputProperty::Value => asm.push(Op::Opcode(InspectInputValue)),
        InputProperty::ScriptPubKey => emit_script_pubkey_asm(InspectInputScriptPubKey, asm),
        InputProperty::WitnessVersion => emit_witness_version_asm(InspectInputScriptPubKey, asm),
        InputProperty::Sequence => asm.push(Op::Opcode(InspectInputSequence)),
        InputProperty::Outpoint => asm.push(Op::Opcode(InspectInputOutpoint)),
        InputProperty::ArkadeScriptHash => asm.push(Op::Opcode(InspectInputArkadeScriptHash)),
        InputProperty::ArkadeWitnessHash => asm.push(Op::Opcode(InspectInputArkadeWitnessHash)),
        InputProperty::Script => asm.push(Op::Opcode(InspectInputScriptPubKey)),
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
        OutputProperty::Value => asm.push(Op::Opcode(InspectOutputValue)),
        OutputProperty::ScriptPubKey => emit_script_pubkey_asm(InspectOutputScriptPubKey, asm),
        OutputProperty::WitnessVersion => emit_witness_version_asm(InspectOutputScriptPubKey, asm),
        OutputProperty::Script => asm.push(Op::Opcode(InspectOutputScriptPubKey)),
    }
}
