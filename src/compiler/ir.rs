//! Expression instructions: what an expression pushes, before the generator
//! places it on its stack model and spells it as assembly.

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Op {
    /// An opcode; its stack effect comes from the opcode table.
    Opcode(&'static str),
    /// A constant: a number, `0x` bytes, or a small-number opcode such as `OP_3`.
    Push(String),
    /// A binding, by its scope key.
    Read(String),
    /// The value extracted at this index, which the generator emits itself.
    Value(usize),
    /// The element of `array` at the index on top of the stack.
    ArrayElement(String),
    /// A child contract's witness program, resolved when it is instantiated.
    Contract(String),
}

impl Op {
    /// The assembly token, as an artifact placeholder spells nested arguments.
    pub(crate) fn spell(&self) -> String {
        match self {
            Op::Opcode(opcode) => opcode.to_string(),
            Op::Push(value) | Op::Contract(value) => value.clone(),
            Op::Read(key) => format!("<{key}>"),
            Op::Value(index) => format!("<$call:{index}>"),
            Op::ArrayElement(array) => format!("$array-index:{array}"),
        }
    }
}
