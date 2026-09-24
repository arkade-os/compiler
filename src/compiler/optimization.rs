use crate::opcodes::{OP_0, OP_1, OP_DUP, OP_NIP, OP_PICK, OP_PUT, OP_VERIFY};

pub(super) fn optimize(asm: Vec<String>) -> Vec<String> {
    let mut optimized = Vec::with_capacity(asm.len());
    let mut tokens = asm.into_iter().peekable();
    while let Some(token) = tokens.next() {
        let replacement = match (token.as_str(), tokens.peek().map(String::as_str)) {
            (OP_0, Some(OP_PICK)) => Some(OP_DUP),
            (OP_0, Some(OP_PUT)) => Some(OP_NIP),
            _ => None,
        };
        if let Some(replacement) = replacement {
            tokens.next();
            optimized.push(replacement.to_string());
        } else {
            optimized.push(token);
        }
    }

    // The final clean-stack truth check already enforces a trailing `OP_VERIFY OP_1`, so a
    // failing last requirement reports a false stack entry instead. The NIPs clear items below it.
    let tail = optimized
        .iter()
        .rposition(|token| token != OP_NIP)
        .unwrap_or(0);
    if tail > 0 && optimized[tail - 1] == OP_VERIFY && optimized[tail] == OP_1 {
        optimized.drain(tail - 1..=tail);
    }
    optimized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shallow_stack_operations_and_final_requirement() {
        assert_eq!(
            optimize(
                ["<owner>", OP_0, OP_PICK, "9", OP_0, OP_PUT, OP_VERIFY, OP_1, OP_NIP]
                    .into_iter()
                    .map(String::from)
                    .collect()
            ),
            ["<owner>", OP_DUP, "9", OP_NIP, OP_NIP]
        );
        assert_eq!(
            optimize([OP_VERIFY, OP_1, OP_NIP, OP_1].map(String::from).to_vec()),
            [OP_VERIFY, OP_1, OP_NIP, OP_1]
        );
    }
}
