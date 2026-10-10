//! Expression instructions: what an expression pushes, before the generator
//! places it on its stack model and spells it as assembly.

use crate::models::Path;
use crate::opcodes::Opcode;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Op {
    /// An opcode; its stack effect comes from the opcode table.
    Opcode(Opcode),
    /// A constant: a number or `0x` bytes.
    Push(String),
    /// A binding's stack slot.
    Read(Path),
    /// The value extracted at this index, which the generator emits itself.
    Value(usize),
    /// The element of `array` at the index on top of the stack.
    ArrayElement(Path),
    /// A constructor argument's placeholder, filled in when the contract is instantiated.
    Param(String),
    /// A child contract's witness program, resolved when it is instantiated; each
    /// argument is spelled from its own instructions.
    Contract { name: String, args: Vec<Vec<Op>> },
}

impl Op {
    /// The assembly token, as an artifact placeholder spells nested arguments.
    pub(crate) fn spell(&self) -> String {
        match self {
            Op::Opcode(opcode) => opcode.name().to_string(),
            Op::Push(value) => value.clone(),
            Op::Contract { name, args } => {
                let args = args
                    .iter()
                    .map(|arg| arg.iter().map(Op::spell).collect::<Vec<_>>().join(" "))
                    .collect::<Vec<_>>()
                    .join(",");
                format!("<CONTRACT:{name}({args})>")
            }
            Op::Read(path) => format!("<{path}>"),
            Op::Param(name) => format!("<{name}>"),
            Op::Value(index) => format!("<$call:{index}>"),
            Op::ArrayElement(array) => format!("$array-index:{array}"),
        }
    }
}
