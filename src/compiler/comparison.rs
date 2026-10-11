use super::*;
use crate::models::*;
use crate::opcodes::Opcode::Roll;
use crate::operators::{BinaryOperator, OperatorClass};
use crate::types::{bind_local_type, ArkType};

impl Generator {
    pub(super) fn composite_type(&self, expression: &Expression) -> Option<TypeName> {
        match &expression.ty {
            composite @ (ArkType::Array(..) | ArkType::Struct(_)) => Some(composite.into()),
            _ => None,
        }
    }

    pub(super) fn bind_type(&mut self, name: &str, ty: &TypeName) {
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
        ty: &TypeName,
    ) -> Result<(), String> {
        if op.class() != OperatorClass::Equality {
            return Err(format!("'{op}' is not defined for '{ty}' values"));
        }
        let width = self.width(ty)?;
        self.emit_typed_value(left, ty)?;
        self.emit_typed_value(right, ty)?;
        for remaining in (1..=width).rev() {
            if op == BinaryOperator::Eq {
                if remaining > 1 {
                    self.roll(remaining)?;
                }
                self.apply(EqualVerify, 2, 0)?;
            } else if remaining == width {
                self.roll(width)?;
                self.apply(Equal, 2, 1)?;
            } else {
                self.roll(remaining + 1)?;
                self.roll(2)?;
                self.apply(Equal, 2, 1)?;
                self.apply(BoolAnd, 2, 1)?;
            }
        }
        if op == BinaryOperator::Ne {
            self.apply(Not, 1, 1)?;
            self.apply(Verify, 1, 0)?;
        }
        Ok(())
    }

    fn roll(&mut self, depth: usize) -> Result<(), String> {
        self.push_integer_temporary(depth);
        self.pop_temporaries(1, Roll)?;
        self.asm.push(Roll.into());
        Ok(())
    }
}
