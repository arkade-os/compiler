use super::expr;
use super::ir::Op;
use crate::models::Expression;
use crate::opcodes::Opcode;
use crate::properties::{InputProperty, OutputProperty, TxProperty};

/// Emit assembly for transaction introspection: tx.version, tx.locktime, etc.
pub(crate) fn emit_tx_introspection_asm(property: TxProperty, asm: &mut Vec<Op>) {
    asm.push(Op::Opcode(match property {
        TxProperty::Version => Opcode::InspectVersion,
        TxProperty::Locktime => Opcode::InspectLockTime,
        TxProperty::NumInputs => Opcode::InspectNumInputs,
        TxProperty::NumOutputs => Opcode::InspectNumOutputs,
        TxProperty::Weight => Opcode::TxWeight,
        TxProperty::Id => Opcode::Txid,
    }));
}

/// Emit a scriptPubKey inspection opcode and keep only the witness version.
pub(crate) fn emit_witness_version_asm(opcode: Opcode, asm: &mut Vec<Op>) {
    asm.push(opcode.into());
    asm.push(Opcode::Nip.into());
}

/// Emit assembly for input introspection: tx.inputs[i].property
pub(crate) fn emit_input_introspection_asm(
    index: &Expression,
    property: InputProperty,
    asm: &mut Vec<Op>,
) {
    expr::emit_expression_asm(index, asm);
    match property {
        InputProperty::Value => asm.push(Opcode::InspectInputValue.into()),
        InputProperty::WitnessVersion => {
            emit_witness_version_asm(Opcode::InspectInputScriptPubKey, asm)
        }
        InputProperty::Sequence => asm.push(Opcode::InspectInputSequence.into()),
        InputProperty::Outpoint => asm.push(Opcode::InspectInputOutpoint.into()),
        InputProperty::ArkadeScriptHash => asm.push(Opcode::InspectInputArkadeScriptHash.into()),
        InputProperty::ArkadeWitnessHash => asm.push(Opcode::InspectInputArkadeWitnessHash.into()),
        InputProperty::Script => asm.push(Opcode::InspectInputScriptPubKey.into()),
    }
}

/// Emit assembly for output introspection: tx.outputs[o].property
pub(crate) fn emit_output_introspection_asm(
    index: &Expression,
    property: OutputProperty,
    asm: &mut Vec<Op>,
) {
    expr::emit_expression_asm(index, asm);
    match property {
        OutputProperty::Value => asm.push(Opcode::InspectOutputValue.into()),
        OutputProperty::WitnessVersion => {
            emit_witness_version_asm(Opcode::InspectOutputScriptPubKey, asm)
        }
        OutputProperty::Script => asm.push(Opcode::InspectOutputScriptPubKey.into()),
    }
}
