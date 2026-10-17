pub use arkade_artifact::opcodes::*;

#[cfg(test)]
mod tests {
    use super::stack_effect;
    use crate::builtins::{Lowering, BUILTINS};
    use crate::operators::{BinaryOperator, UnaryOperator};

    #[test]
    fn every_table_opcode_has_a_stack_effect() {
        let builtins = BUILTINS
            .iter()
            .filter_map(|builtin| match builtin.lowering {
                Lowering::Opcodes(opcodes) => Some(opcodes),
                _ => None,
            });
        let binary = BinaryOperator::ALL.map(BinaryOperator::opcodes);
        let unary = [
            UnaryOperator::Neg,
            UnaryOperator::Not,
            UnaryOperator::Invert,
        ]
        .map(UnaryOperator::opcode);
        for opcode in builtins.chain(binary).flatten().chain(&unary) {
            assert!(stack_effect(opcode).is_some(), "{opcode}");
        }
    }
}
