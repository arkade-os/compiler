use super::*;
use crate::models::*;

/// Emit assembly for transaction introspection: tx.version, tx.locktime, etc.
pub(crate) fn emit_tx_introspection_asm(property: &str, asm: &mut Vec<String>) {
    match property {
        "version" => asm.push(OP_INSPECTVERSION.to_string()),
        "locktime" => asm.push(OP_INSPECTLOCKTIME.to_string()),
        "numInputs" => asm.push(OP_INSPECTNUMINPUTS.to_string()),
        "numOutputs" => asm.push(OP_INSPECTNUMOUTPUTS.to_string()),
        "weight" => asm.push(OP_TXWEIGHT.to_string()),
        "id" => asm.push(OP_TXID.to_string()),
        _ => {
            // Unknown property, emit as placeholder
            asm.push(format!("<tx.{}>", property));
        }
    }
}

/// Emit assembly for input introspection: tx.inputs[i].property
pub(crate) fn emit_input_introspection_asm(
    index: &Expression,
    property: &str,
    asm: &mut Vec<String>,
) {
    // Push the index
    emit_expression_asm(index, asm);

    // Emit the appropriate opcode
    match property {
        "value" => asm.push(OP_INSPECTINPUTVALUE.to_string()),
        "scriptPubKey" => asm.push(OP_INSPECTINPUTSCRIPTPUBKEY.to_string()),
        "sequence" => asm.push(OP_INSPECTINPUTSEQUENCE.to_string()),
        "outpoint" => asm.push(OP_INSPECTINPUTOUTPOINT.to_string()),
        "arkadeScriptHash" => asm.push(OP_INSPECTINPUTARKADESCRIPTHASH.to_string()),
        "arkadeWitnessHash" => asm.push(OP_INSPECTINPUTARKADEWITNESSHASH.to_string()),
        _ => {
            // Unknown property, emit as placeholder
            asm.push(format!("<tx.inputs[?].{}>", property));
        }
    }
}

/// Emit assembly for output introspection: tx.outputs[o].property
pub(crate) fn emit_output_introspection_asm(
    index: &Expression,
    property: &str,
    asm: &mut Vec<String>,
) {
    // Push the index
    emit_expression_asm(index, asm);

    // Emit the appropriate opcode
    match property {
        "value" => asm.push(OP_INSPECTOUTPUTVALUE.to_string()),
        "scriptPubKey" => asm.push(OP_INSPECTOUTPUTSCRIPTPUBKEY.to_string()),
        _ => {
            // Unknown property, emit as placeholder
            asm.push(format!("<tx.outputs[?].{}>", property));
        }
    }
}
