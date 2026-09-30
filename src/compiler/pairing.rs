use super::*;
use crate::typechecker::ArkType;

impl Generator {
    pub(super) fn emit_pairing_product(
        &mut self,
        coordinates: &Expression,
        curve_id: &Expression,
    ) -> Result<(), String> {
        let ArkType::Array(element, length) = typechecker::infer_type(coordinates, &self.scope)
        else {
            return Err("ecPairingProduct coordinates must be a fixed int array".to_string());
        };
        if *element != ArkType::Int || !(6..=96).contains(&length) || length % 6 != 0 {
            return Err("ecPairingProduct expects 1..16 groups of six int coordinates".to_string());
        }
        // The curve operand was checked before loop lowering. At this stage a
        // loop value may be an internal scalar alias absent from the type scope.

        // Evaluate the aggregate once, including any array-returning helper.
        // Typed aggregates have their first element on top; the VM expects it deepest.
        self.emit_typed_value(coordinates, &format!("int[{length}]"))?;
        for depth in 1..length {
            self.push_integer_temporary(depth);
            self.pop_temporaries(1, OP_ROLL)?;
            self.asm.push(OP_ROLL.to_string());
            // All rolled elements are temporaries, so their abstract stack state is unchanged.
        }
        self.push_integer_temporary(length / 6);
        self.emit_expression(curve_id)?;
        // Account for EVERY coordinate, not the one-pair raw opcode's eight inputs.
        self.apply(OP_ECPAIRING, length + 2, 1)
    }
}
