use super::*;
use crate::models::*;

/// Generate assembly for comparison expressions
pub(crate) fn generate_comparison_asm(
    left: &Expression,
    op: &str,
    right: &Expression,
    asm: &mut Vec<String>,
) {
    match (left, op, right) {
        (Expression::Variable(var), ">=", Expression::Literal(value)) => {
            asm.push(format!("<{}>", var));
            asm.push(value.clone());
            asm.push(OP_GREATERTHANOREQUAL.to_string());
        }
        (Expression::Variable(var), "==", Expression::Variable(var2)) => {
            asm.push(format!("<{}>", var));
            asm.push(format!("<{}>", var2));
            asm.push(OP_EQUAL.to_string());
        }
        (Expression::Variable(var), ">=", Expression::Variable(var2)) => {
            asm.push(format!("<{}>", var));
            asm.push(format!("<{}>", var2));
            asm.push(OP_GREATERTHANOREQUAL.to_string());
        }
        (Expression::Variable(var), "==", Expression::Property(prop)) => {
            asm.push(format!("<{}>", var));
            asm.push(format!("<{}>", prop));
            asm.push(OP_EQUAL.to_string());
        }
        (Expression::Variable(var), ">=", Expression::Property(prop)) => {
            asm.push(format!("<{}>", var));
            asm.push(format!("<{}>", prop));
            asm.push(OP_GREATERTHANOREQUAL.to_string());
        }
        (Expression::Literal(lit), "==", Expression::Variable(var)) => {
            asm.push(lit.clone());
            asm.push(format!("<{}>", var));
            asm.push(OP_EQUAL.to_string());
        }
        (Expression::Literal(lit), ">=", Expression::Variable(var)) => {
            asm.push(lit.clone());
            asm.push(format!("<{}>", var));
            asm.push(OP_GREATERTHANOREQUAL.to_string());
        }
        (Expression::Literal(lit), "==", Expression::Literal(value)) => {
            asm.push(lit.clone());
            asm.push(value.clone());
            asm.push(OP_EQUAL.to_string());
        }
        (Expression::Literal(lit), ">=", Expression::Literal(value)) => {
            asm.push(lit.clone());
            asm.push(value.clone());
            asm.push(OP_GREATERTHANOREQUAL.to_string());
        }
        (Expression::Literal(lit), "==", Expression::Property(prop)) => {
            asm.push(lit.clone());
            asm.push(format!("<{}>", prop));
            asm.push(OP_EQUAL.to_string());
        }
        (Expression::Literal(lit), ">=", Expression::Property(prop)) => {
            asm.push(lit.clone());
            asm.push(format!("<{}>", prop));
            asm.push(OP_GREATERTHANOREQUAL.to_string());
        }
        (Expression::Property(prop), "==", Expression::Variable(var)) => {
            asm.push(format!("<{}>", prop));
            asm.push(format!("<{}>", var));
            asm.push(OP_EQUAL.to_string());
        }
        (Expression::Property(prop), ">=", Expression::Variable(var)) => {
            asm.push(format!("<{}>", prop));
            asm.push(format!("<{}>", var));
            asm.push(OP_GREATERTHANOREQUAL.to_string());
        }
        (Expression::Property(prop), "==", Expression::Literal(value)) => {
            // Map "this" properties to their dedicated opcodes (mirrors
            // generate_expression_asm); otherwise keep the placeholder.
            let emit_left = |asm: &mut Vec<String>| match prop.as_str() {
                "this.activeInputIndex" => asm.push(OP_PUSHCURRENTINPUTINDEX.to_string()),
                "this.activeBytecode" => asm.push(OP_INPUTBYTECODE.to_string()),
                _ => asm.push(format!("<{}>", prop)),
            };
            if value == "true" {
                // `require(expr)` is parsed as `expr == true`; this dummy
                // comparison just pushes the introspection result.
                emit_left(asm);
            } else {
                // Correct Bitcoin Script order is left, right, OP_EQUAL.
                emit_left(asm);
                asm.push(value.clone());
                asm.push(OP_EQUAL.to_string());
            }
        }
        (Expression::Property(prop), ">=", Expression::Literal(value)) => {
            asm.push(format!("<{}>", prop));
            asm.push(value.clone());
            asm.push(OP_GREATERTHANOREQUAL.to_string());
        }
        (Expression::Property(prop), "==", Expression::Property(prop2)) => {
            asm.push(format!("<{}>", prop));
            asm.push(format!("<{}>", prop2));
            asm.push(OP_EQUAL.to_string());
        }
        (Expression::Property(prop), ">=", Expression::Property(prop2)) => {
            asm.push(format!("<{}>", prop));
            asm.push(format!("<{}>", prop2));
            asm.push(OP_GREATERTHANOREQUAL.to_string());
        }
        (Expression::CurrentInput(property), "==", Expression::Literal(value)) => {
            if value == "true" {
                if let Some(prop) = property {
                    match prop.as_str() {
                        "scriptPubKey" => asm.push(OP_INPUTBYTECODE.to_string()),
                        "value" => asm.push(OP_INPUTVALUE.to_string()),
                        "sequence" => asm.push(OP_INPUTSEQUENCE.to_string()),
                        "outpoint" => asm.push(OP_INPUTOUTPOINT.to_string()),
                        _ => asm.push(OP_INPUTBYTECODE.to_string()),
                    }
                } else {
                    asm.push(OP_INPUTBYTECODE.to_string());
                }
            }
        }
        _ => {
            // For all other expression types, delegate to emit_comparison_asm
            emit_comparison_asm(left, op, right, asm);
        }
    }
}

/// Emit assembly for a comparison requirement.
///
/// Handles both simple comparisons (variable/literal/property) and complex
/// expressions involving asset lookups and 64-bit arithmetic.
pub(crate) fn emit_comparison_asm(
    left: &Expression,
    op: &str,
    right: &Expression,
    asm: &mut Vec<String>,
) {
    // Special case: standalone property/function call introspection (dummy comparison)
    if op == "==" {
        if let Expression::Literal(val) = right {
            if val == "true" {
                // Bare `tx.assetGroups.find(...)`: the find already asserts
                // existence via its internal OP_VERIFY and leaves the resolved
                // packet position k. k is NOT a boolean (k == 0 is a valid
                // successful find), so drop it and leave an explicit OP_1 as the
                // requirement's true result.
                if let Expression::GroupFind {
                    asset_txid,
                    asset_gidx,
                } = left
                {
                    emit_group_find_asm(asset_txid, asset_gidx, asm);
                    asm.push(OP_DROP.to_string());
                    asm.push(OP_1.to_string());
                    return;
                }
                // Other dummy-wrapped expressions (has/controlIs/checkSig/…)
                // already leave a boolean — emit directly.
                emit_expression_asm(left, asm);
                return;
            }
        }
    }

    // Determine if this comparison involves 64-bit values (asset lookups, group sums)
    let is_64bit = is_64bit_expression(left) || is_64bit_expression(right);

    // Emit left operand
    emit_expression_asm(left, asm);

    // Emit right operand
    emit_expression_asm(right, asm);

    // Emit comparison operator (correct Bitcoin Script order: left, right, op)
    if is_64bit {
        emit_comparison_op_64(op, asm);
    } else {
        emit_comparison_op(op, asm);
    }
}

/// Emit standard comparison operator (CScriptNum / non-64-bit)
pub(crate) fn emit_comparison_op(op: &str, asm: &mut Vec<String>) {
    match op {
        "==" => asm.push(OP_EQUAL.to_string()),
        "!=" => {
            asm.push(OP_EQUAL.to_string());
            asm.push(OP_NOT.to_string());
        }
        ">=" => asm.push(OP_GREATERTHANOREQUAL.to_string()),
        ">" => asm.push(OP_GREATERTHAN.to_string()),
        "<=" => asm.push(OP_LESSTHANOREQUAL.to_string()),
        "<" => asm.push(OP_LESSTHAN.to_string()),
        _ => asm.push(format!("OP_{}", op)),
    }
}

/// Emit 64-bit comparison operator (u64le operands)
pub(crate) fn emit_comparison_op_64(op: &str, asm: &mut Vec<String>) {
    match op {
        "==" => {
            asm.push(OP_EQUAL.to_string());
            asm.push(OP_VERIFY.to_string());
        }
        "!=" => {
            asm.push(OP_EQUAL.to_string());
            asm.push(OP_NOT.to_string());
            asm.push(OP_VERIFY.to_string());
        }
        ">=" => {
            asm.push(OP_GREATERTHANOREQUAL64.to_string());
            asm.push(OP_VERIFY.to_string());
        }
        ">" => {
            asm.push(OP_GREATERTHAN64.to_string());
            asm.push(OP_VERIFY.to_string());
        }
        "<=" => {
            asm.push(OP_LESSTHANOREQUAL64.to_string());
            asm.push(OP_VERIFY.to_string());
        }
        "<" => {
            asm.push(OP_LESSTHAN64.to_string());
            asm.push(OP_VERIFY.to_string());
        }
        _ => {
            asm.push(format!("OP_{}", op));
            asm.push(OP_VERIFY.to_string());
        }
    }
}
