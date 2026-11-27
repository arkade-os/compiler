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

#[derive(Debug, Default)]
pub(crate) struct Assembly {
    ops: Vec<Spanned>,
    /// The span of instructions pushed from now on.
    span: Option<Span>,
    /// While positive, `set_span` keeps the current span, as for an imported helper's body,
    /// whose spans index another file.
    pinned: usize,
}

impl Assembly {
    pub(crate) fn push(&mut self, op: Op) {
        self.ops.push((op, self.span));
    }

    pub(crate) fn extend(&mut self, ops: impl IntoIterator<Item = Op>) {
        for op in ops {
            self.push(op);
        }
    }

    /// Append instructions split off earlier, keeping their spans.
    pub(crate) fn append(&mut self, mut other: Assembly) {
        self.ops.append(&mut other.ops);
    }

    pub(crate) fn split_off(&mut self, at: usize) -> Assembly {
        Assembly {
            ops: self.ops.split_off(at),
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
        self.ops.last().map(|(op, _)| op)
    }

    #[cfg(test)]
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Op> {
        self.ops.iter().map(|(op, _)| op)
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
        self.pinned = self.pinned.checked_sub(1).expect("unpin follows a pin");
    }

    pub(crate) fn into_spanned(self) -> Vec<Spanned> {
        self.ops
    }
}

impl From<Opcode> for Op {
    fn from(opcode: Opcode) -> Self {
        Op::Opcode(opcode)
    }
}

impl Op {
    /// The instruction that pushes `value`: `OP_0` to `OP_16`, else a number push.
    pub(crate) fn push_int(value: usize) -> Op {
        use Opcode::{
            Int0, Int1, Int10, Int11, Int12, Int13, Int14, Int15, Int16, Int2, Int3, Int4, Int5,
            Int6, Int7, Int8, Int9,
        };
        const SMALL: [Opcode; 17] = [
            Int0, Int1, Int2, Int3, Int4, Int5, Int6, Int7, Int8, Int9, Int10, Int11, Int12, Int13,
            Int14, Int15, Int16,
        ];
        match SMALL.get(value) {
            Some(&opcode) => opcode.into(),
            None => Op::Push(value.to_string()),
        }
    }

    /// Whether this is `opcode`; a literal `1` assembles to `OP_1`, so it counts as one.
    pub(crate) fn is(&self, opcode: Opcode) -> bool {
        match self {
            Op::Opcode(op) => *op == opcode,
            Op::Push(value) => value == "1" && opcode == Opcode::Int1,
            _ => false,
        }
    }

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

    pub(crate) fn pushes_more_than(&self, limit: usize) -> bool {
        let Self::Push(value) = self else {
            return false;
        };
        if let Some(hex) = value.strip_prefix("0x") {
            return hex.len() / 2 > limit;
        }
        if let Ok(number) = value.parse::<i64>() {
            return scriptnum_len(number) > limit;
        }
        decimal_len(value, limit) > limit
    }

    /// The fewest bytes this takes once assembled with canonical pushes;
    /// `param_width` is the data width a parameter's type guarantees.
    pub(crate) fn min_size(&self, param_width: &dyn Fn(&str) -> usize) -> usize {
        match self {
            Op::Opcode(_) => 1,
            Op::Push(value) => match value.strip_prefix("0x") {
                // Of one-byte values, only 0x01…0x10 and 0x81 push as a single opcode.
                Some(hex) if hex.len() == 2 => match u8::from_str_radix(hex, 16) {
                    Ok(0x01..=0x10 | 0x81) => 1,
                    _ => 2,
                },
                Some(hex) => push_size(hex.len() / 2),
                None => match value.parse::<i64>() {
                    Ok(-1..=16) => 1,
                    Ok(number) => 1 + scriptnum_len(number),
                    // The element limit rejects a longer push, so counting stops just past it.
                    Err(_) => push_size(decimal_len(value, super::MAX_ELEMENT_SIZE)),
                },
            },
            Op::Param(name) => push_size(param_width(name)),
            Op::Contract { .. } => push_size(32),
            // The generator replaces these before an Arkade Script is assembled.
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

/// A decimal literal's Script-number length, or `limit + 1` once it exceeds `limit`.
fn decimal_len(value: &str, limit: usize) -> usize {
    let mut bytes = vec![0u8];
    for digit in value.trim_start_matches('-').bytes() {
        let mut carry = digit - b'0';
        for byte in &mut bytes {
            let [low, high] = (u16::from(*byte) * 10 + u16::from(carry)).to_le_bytes();
            *byte = low;
            carry = high;
        }
        if carry != 0 {
            bytes.push(carry);
        }
        // Stop once the magnitude alone exceeds the limit, bounding conversion memory.
        if bytes.len() > limit {
            return limit + 1;
        }
    }
    // A set top bit needs an extra byte for the sign.
    bytes.len() + usize::from(bytes.last().is_some_and(|top| top & 0x80 != 0))
}

fn scriptnum_len(number: i64) -> usize {
    let magnitude = number.unsigned_abs();
    if magnitude == 0 {
        return 0;
    }
    let bytes = usize::try_from((u64::BITS - magnitude.leading_zeros()).div_ceil(8))
        .expect("an i64 has at most 8 bytes");
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
        // 2^63 needs a sign byte after its eight magnitude bytes.
        assert_eq!(size("9223372036854775808"), 10);
        assert_eq!(size("-9223372036854775809"), 10);
        assert_eq!(
            size("14474011154664524427946373126085988481658748083205070504932198000989141204997"),
            33
        );
        assert_eq!(size("0x"), 1);
        assert_eq!(size("0x10"), 1);
        assert_eq!(size("0x81"), 1);
        assert_eq!(size("0x00"), 2);
        assert_eq!(size(&format!("0x{}", "ab".repeat(76))), 78);
        assert_eq!(Op::Param("key".into()).min_size(&|_| 32), 33);
        assert_eq!(Op::Opcode(Opcode::Equal).min_size(&none), 1);
    }
}
