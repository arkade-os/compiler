//! Expression instructions: what an expression pushes, before the generator
//! places it on its stack model and spells it as assembly.

use crate::diagnostics::Span;
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

/// An instruction and the span of the statement it was emitted for.
pub(crate) type Spanned = (Op, Option<Span>);

/// Instructions, each with the span of the source statement it was emitted for.
#[derive(Debug, Default)]
pub(crate) struct Assembly {
    ops: Vec<Op>,
    spans: Vec<Option<Span>>,
    /// The span of instructions pushed from now on.
    span: Option<Span>,
    /// While positive, `set_span` keeps the current span, as for an imported helper's body,
    /// whose spans index another file.
    pinned: usize,
}

impl Assembly {
    pub(crate) fn push(&mut self, op: Op) {
        self.ops.push(op);
        self.spans.push(self.span);
    }

    pub(crate) fn extend(&mut self, ops: impl IntoIterator<Item = Op>) {
        for op in ops {
            self.push(op);
        }
    }

    /// Append instructions split off earlier, keeping their spans.
    pub(crate) fn append(&mut self, mut other: Assembly) {
        self.ops.append(&mut other.ops);
        self.spans.append(&mut other.spans);
    }

    pub(crate) fn split_off(&mut self, at: usize) -> Assembly {
        Assembly {
            ops: self.ops.split_off(at),
            spans: self.spans.split_off(at),
            ..Default::default()
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.ops.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    pub(crate) fn last(&self) -> Option<&Op> {
        self.ops.last()
    }

    #[cfg(test)]
    pub(crate) fn iter(&self) -> std::slice::Iter<'_, Op> {
        self.ops.iter()
    }

    pub(crate) fn span(&self) -> Option<Span> {
        self.span
    }

    pub(crate) fn set_span(&mut self, span: Option<Span>) {
        if self.pinned == 0 {
            self.span = span;
        }
    }

    pub(crate) fn pin(&mut self) {
        self.pinned += 1;
    }

    pub(crate) fn unpin(&mut self) {
        self.pinned -= 1;
    }

    pub(crate) fn into_spanned(self) -> Vec<Spanned> {
        self.ops.into_iter().zip(self.spans).collect()
    }
}

impl From<Opcode> for Op {
    fn from(opcode: Opcode) -> Self {
        Op::Opcode(opcode)
    }
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

    /// The fewest bytes this takes once assembled with canonical pushes;
    /// `param_width` is the data width a parameter's type guarantees.
    pub(crate) fn min_size(&self, param_width: &dyn Fn(&str) -> usize) -> usize {
        match self {
            Op::Opcode(_) => 1,
            Op::Push(value) => match value.strip_prefix("0x") {
                Some(hex) => push_size(hex.len() / 2),
                None => match value.parse::<i64>() {
                    Ok(-1..=16) => 1,
                    Ok(number) => 1 + scriptnum_len(number),
                    // Beyond i64 the magnitude alone takes eight bytes.
                    Err(_) => 1 + 8,
                },
            },
            Op::Param(name) => push_size(param_width(name)),
            Op::Contract { .. } => push_size(32),
            // The generator replaces these before a covenant is assembled.
            Op::Read(_) | Op::Value(_) | Op::ArrayElement(_) => 0,
        }
    }
}

/// A data push's size, counting a one-byte push as a possible `OP_1`…`OP_16`.
fn push_size(len: usize) -> usize {
    match len {
        0 | 1 => 1,
        2..=75 => 1 + len,
        76..=255 => 2 + len,
        256..=65535 => 3 + len,
        _ => 5 + len,
    }
}

fn scriptnum_len(number: i64) -> usize {
    let magnitude = number.unsigned_abs();
    if magnitude == 0 {
        return 0;
    }
    let bytes = (u64::BITS - magnitude.leading_zeros()).div_ceil(8) as usize;
    // A set top bit needs an extra byte for the sign.
    bytes + usize::from(magnitude >> (bytes * 8 - 1) & 1 == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_match_canonical_pushes() {
        let none = |_: &str| 0;
        let size = |value: &str| Op::Push(value.into()).min_size(&none);
        assert_eq!(scriptnum_len(0), 0);
        assert_eq!(size("16"), 1);
        assert_eq!(size("-1"), 1);
        assert_eq!(size("17"), 2);
        assert_eq!(size("127"), 2);
        assert_eq!(size("128"), 3);
        assert_eq!(size("-255"), 3);
        assert_eq!(size("0x"), 1);
        assert_eq!(size(&format!("0x{}", "ab".repeat(76))), 78);
        assert_eq!(Op::Param("key".into()).min_size(&|_| 32), 33);
        assert_eq!(Op::Opcode(Opcode::Equal).min_size(&none), 1);
    }
}
