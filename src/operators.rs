//! The language's operators. Each one is described once here; the type
//! checks, constant folding and code generation read these properties
//! instead of matching operator text.

use crate::opcodes::*;

/// What an operator takes and gives, which decides how it is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorClass {
    /// `int` operands and result. `+` with a bytes operand is concatenation instead.
    Arithmetic,
    /// An `int` value and a non-negative `int` count.
    Shift,
    /// Bytes of equal length; the result has their length.
    Bytewise,
    /// `int` operands, `bool` result.
    Ordering,
    /// Operands of one type, `bool` result.
    Equality,
    /// `bool` operands; the right one is evaluated only when it decides the result.
    Logical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOperator {
    Mul,
    Div,
    Add,
    Sub,
    Shl,
    Shr,
    BitAnd,
    BitXor,
    BitOr,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
}

impl BinaryOperator {
    pub const ALL: [Self; 17] = [
        Self::Mul,
        Self::Div,
        Self::Add,
        Self::Sub,
        Self::Shl,
        Self::Shr,
        Self::BitAnd,
        Self::BitXor,
        Self::BitOr,
        Self::Eq,
        Self::Ne,
        Self::Lt,
        Self::Le,
        Self::Gt,
        Self::Ge,
        Self::And,
        Self::Or,
    ];

    /// Symbol, class, and the opcodes emitted after both operands. Logical
    /// operators emit none here: they lower to a branch.
    fn describe(self) -> (&'static str, OperatorClass, &'static [&'static str]) {
        use OperatorClass::*;
        match self {
            Self::Mul => ("*", Arithmetic, &[OP_MUL]),
            Self::Div => ("/", Arithmetic, &[OP_DIV]),
            Self::Add => ("+", Arithmetic, &[OP_ADD]),
            Self::Sub => ("-", Arithmetic, &[OP_SUB]),
            Self::Shl => ("<<", Shift, &[OP_LSHIFT]),
            Self::Shr => (">>", Shift, &[OP_RSHIFT]),
            Self::BitAnd => ("&", Bytewise, &[OP_AND]),
            Self::BitXor => ("^", Bytewise, &[OP_XOR]),
            Self::BitOr => ("|", Bytewise, &[OP_OR]),
            Self::Eq => ("==", Equality, &[OP_EQUAL]),
            Self::Ne => ("!=", Equality, &[OP_EQUAL, OP_NOT]),
            Self::Lt => ("<", Ordering, &[OP_LESSTHAN]),
            Self::Le => ("<=", Ordering, &[OP_LESSTHANOREQUAL]),
            Self::Gt => (">", Ordering, &[OP_GREATERTHAN]),
            Self::Ge => (">=", Ordering, &[OP_GREATERTHANOREQUAL]),
            Self::And => ("&&", Logical, &[]),
            Self::Or => ("||", Logical, &[]),
        }
    }

    pub fn symbol(self) -> &'static str {
        self.describe().0
    }

    pub fn class(self) -> OperatorClass {
        self.describe().1
    }

    pub fn opcodes(self) -> &'static [&'static str] {
        self.describe().2
    }

    /// Whether the result is a `bool` comparing its operands.
    pub fn compares(self) -> bool {
        matches!(
            self.class(),
            OperatorClass::Ordering | OperatorClass::Equality
        )
    }

    pub fn from_symbol(symbol: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|op| op.symbol() == symbol)
    }
}

impl std::fmt::Display for BinaryOperator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.symbol())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOperator {
    Neg,
    Not,
    Invert,
}

impl UnaryOperator {
    /// Symbol, operand and result type, and opcode.
    fn describe(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::Neg => ("-", "int", OP_NEGATE),
            Self::Not => ("!", "bool", OP_NOT),
            Self::Invert => ("~", "bytes", OP_INVERT),
        }
    }

    pub fn symbol(self) -> &'static str {
        self.describe().0
    }

    pub fn operand_type(self) -> &'static str {
        self.describe().1
    }

    pub fn opcode(self) -> &'static str {
        self.describe().2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_operator_has_a_unique_symbol_that_round_trips() {
        for op in BinaryOperator::ALL {
            assert_eq!(BinaryOperator::from_symbol(op.symbol()), Some(op));
            assert_eq!(
                op.opcodes().is_empty(),
                op.class() == OperatorClass::Logical,
                "{op}"
            );
        }
    }
}
