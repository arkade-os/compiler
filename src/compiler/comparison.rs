use super::*;
use crate::models::*;
use crate::opcodes::OP_ROLL;
use crate::typechecker::{bind_local_type, infer_type, ArkType};

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

impl Generator {
    pub(super) fn composite_type(&self, expression: &Expression) -> Option<String> {
        match infer_type(expression, &self.scope) {
            composite @ (ArkType::Array(..) | ArkType::Struct(_)) => Some(composite.as_str()),
            _ => None,
        }
    }

    pub(super) fn bind_type(&mut self, name: &str, ty: &str) {
        bind_local_type(
            &mut self.scope,
            name,
            Some(ty),
            ArkType::Unknown,
            &self.structs,
        );
    }

    pub(super) fn emit_composite_requirement(
        &mut self,
        left: &Expression,
        op: &str,
        right: &Expression,
        ty: &str,
    ) -> Result<(), String> {
        if !matches!(op, "==" | "!=") {
            return Err(format!("'{op}' is not defined for '{ty}' values"));
        }
        let width = self.value_leaves("", ty)?.len();
        self.emit_typed_value(left, ty)?;
        self.emit_typed_value(right, ty)?;
        for remaining in (1..=width).rev() {
            if op == "==" {
                if remaining > 1 {
                    self.roll(remaining)?;
                }
                self.apply(OP_EQUALVERIFY, 2, 0)?;
            } else if remaining == width {
                self.roll(width)?;
                self.apply(OP_EQUAL, 2, 1)?;
            } else {
                self.roll(remaining + 1)?;
                self.roll(2)?;
                self.apply(OP_EQUAL, 2, 1)?;
                self.apply(OP_BOOLAND, 2, 1)?;
            }
        }
        if op == "!=" {
            self.apply(OP_NOT, 1, 1)?;
            self.apply(OP_VERIFY, 1, 0)?;
        }
        Ok(())
    }

    fn roll(&mut self, depth: usize) -> Result<(), String> {
        self.push_integer_temporary(depth);
        self.pop_temporaries(1, OP_ROLL)?;
        self.asm.push(OP_ROLL.to_string());
        Ok(())
    }
}
