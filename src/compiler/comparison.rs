use super::*;
use crate::binops::{EQUAL, GREATER_OR_EQUAL, GREATER_THAN, LESS_OR_EQUAL, LESS_THAN, NOT_EQUAL};
use crate::models::*;

/// Emit assembly for a comparison requirement.
///
/// Handles both simple comparisons and complex expression operands.
pub(crate) fn emit_comparison_asm(
    left: &Expression,
    op: &str,
    right: &Expression,
    asm: &mut Vec<String>,
) {
    // Emit left operand
    emit_expression_asm(left, asm);

    // Emit right operand
    emit_expression_asm(right, asm);

    // Emit comparison operator (correct Bitcoin Script order: left, right, op)
    emit_comparison_op(op, asm);
}

/// Emit standard comparison operator (CScriptNum / non-64-bit)
pub(crate) fn emit_comparison_op(op: &str, asm: &mut Vec<String>) {
    match op {
        EQUAL => asm.push(OP_EQUAL.to_string()),
        NOT_EQUAL => {
            asm.push(OP_EQUAL.to_string());
            asm.push(OP_NOT.to_string());
        }
        GREATER_OR_EQUAL => asm.push(OP_GREATERTHANOREQUAL.to_string()),
        GREATER_THAN => asm.push(OP_GREATERTHAN.to_string()),
        LESS_OR_EQUAL => asm.push(OP_LESSTHANOREQUAL.to_string()),
        LESS_THAN => asm.push(OP_LESSTHAN.to_string()),
        _ => asm.push(format!("OP_{}", op)),
    }
}
