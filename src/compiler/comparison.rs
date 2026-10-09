use super::*;
use crate::models::*;
use crate::opcodes::OP_ROLL;
use crate::operators::{BinaryOperator, OperatorClass};
use crate::types::{bind_local_type, ArkType};

impl Generator {
    pub(super) fn composite_type(&self, expression: &Expression) -> Option<String> {
        match &expression.ty {
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
        op: BinaryOperator,
        right: &Expression,
        ty: &str,
    ) -> Result<(), String> {
        if op.class() != OperatorClass::Equality {
            return Err(format!("'{op}' is not defined for '{ty}' values"));
        }
        let width = self.value_leaves("", ty)?.len();
        self.emit_typed_value(left, ty)?;
        self.emit_typed_value(right, ty)?;
        for remaining in (1..=width).rev() {
            if op == BinaryOperator::Eq {
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
        if op == BinaryOperator::Ne {
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
