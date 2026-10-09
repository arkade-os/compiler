use crate::opcodes::{
    OP_0, OP_1, OP_1ADD, OP_2, OP_2DROP, OP_ADD, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_DROP, OP_DUP,
    OP_EQUAL, OP_EQUALVERIFY, OP_NIP, OP_OVER, OP_PICK, OP_PUT, OP_ROLL, OP_ROT, OP_SWAP,
    OP_VERIFY,
};

/// Adjacent pairs and what they become; `None` removes the pair.
const REWRITES: &[([&str; 2], Option<&str>)] = &[
    ([OP_0, OP_PICK], Some(OP_DUP)),
    ([OP_DUP, OP_SWAP], Some(OP_DUP)),
    ([OP_0, OP_PUT], Some(OP_NIP)),
    ([OP_1, OP_PICK], Some(OP_OVER)),
    ([OP_0, OP_ROLL], None),
    ([OP_SWAP, OP_SWAP], None),
    ([OP_1, OP_ROLL], Some(OP_SWAP)),
    ([OP_2, OP_ROLL], Some(OP_ROT)),
    ([OP_SWAP, OP_DROP], Some(OP_NIP)),
    ([OP_DROP, OP_DROP], Some(OP_2DROP)),
    ([OP_1, OP_ADD], Some(OP_1ADD)),
    (["1", OP_ADD], Some(OP_1ADD)),
    ([OP_1, OP_1ADD], Some(OP_2)),
    (["1", OP_1ADD], Some(OP_2)),
    ([OP_EQUAL, OP_VERIFY], Some(OP_EQUALVERIFY)),
    ([OP_DUP, OP_EQUALVERIFY], Some(OP_DROP)),
    ([OP_CHECKSIG, OP_VERIFY], Some(OP_CHECKSIGVERIFY)),
];

pub(super) fn optimize(mut asm: Vec<String>) -> Vec<String> {
    // The final clean-stack truth check already enforces a trailing `OP_VERIFY OP_1`, so a
    // failing last requirement reports a false stack entry instead. The NIPs clear items below it.
    let tail = asm.iter().rposition(|token| token != OP_NIP).unwrap_or(0);
    if tail > 0 && asm[tail - 1] == OP_VERIFY && asm[tail] == OP_1 {
        asm.drain(tail - 1..=tail);
    }

    let mut optimized = Vec::with_capacity(asm.len());
    for token in asm {
        optimized.push(token);
        while optimized.len() >= 2 {
            let len = optimized.len();
            let pair = [optimized[len - 2].as_str(), optimized[len - 1].as_str()];
            let Some(&(_, replacement)) = REWRITES.iter().find(|(from, _)| *from == pair) else {
                break;
            };
            optimized.truncate(len - 2);
            if let Some(replacement) = replacement {
                optimized.push(replacement.to_string());
            }
        }
    }
    optimized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_keep_the_stack_height() {
        let effect = |op: &str| match op {
            "1" => Some((0, 1)),
            _ => crate::opcodes::stack_effect(op),
        };
        let height = |(pops, pushes): (usize, usize)| pushes as isize - pops as isize;
        let mut checked = 0;
        for &(pair, replacement) in REWRITES {
            let (Some(first), Some(second)) = (effect(pair[0]), effect(pair[1])) else {
                continue;
            };
            let Some(after) = replacement.map_or(Some((0, 0)), effect) else {
                continue;
            };
            assert_eq!(height(first) + height(second), height(after), "{pair:?}");
            checked += 1;
        }
        assert_eq!(checked, 11);
    }

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
        assert_eq!(
            optimize(["<x>", OP_0, OP_PICK, OP_SWAP].map(String::from).to_vec()),
            ["<x>", OP_DUP]
        );
    }

    #[test]
    fn adjacent_rewrites_revisit_newly_exposed_tokens() {
        let asm = [
            OP_0,
            OP_ROLL,
            OP_1,
            OP_PICK,
            OP_2,
            OP_ROLL,
            OP_1,
            OP_ROLL,
            OP_1,
            OP_ROLL,
            OP_EQUAL,
            OP_0,
            OP_ROLL,
            OP_VERIFY,
            OP_CHECKSIG,
            OP_VERIFY,
            OP_1,
            OP_ROLL,
            OP_1,
            OP_ROLL,
        ];
        assert_eq!(
            optimize(asm.map(String::from).to_vec()),
            [OP_OVER, OP_ROT, OP_EQUALVERIFY, OP_CHECKSIGVERIFY]
        );
        assert_eq!(
            optimize(
                [OP_EQUAL, OP_VERIFY, OP_1, OP_NIP]
                    .map(String::from)
                    .to_vec()
            ),
            [OP_EQUAL, OP_NIP]
        );
        assert_eq!(
            optimize(
                [OP_DUP, OP_EQUAL, OP_VERIFY, "<next>"]
                    .map(String::from)
                    .to_vec()
            ),
            [OP_DROP, "<next>"]
        );
        assert_eq!(
            optimize([OP_DUP, OP_EQUAL].map(String::from).to_vec()),
            [OP_DUP, OP_EQUAL]
        );
    }

    #[test]
    fn stack_and_arithmetic_rewrites() {
        let asm = [
            "<a>", "<b>", OP_1, OP_ROLL, OP_DROP, "<c>", "<d>", OP_DROP, OP_DROP, "<x>", OP_1,
            OP_ADD, OP_1, OP_1, OP_ADD,
        ];
        assert_eq!(
            optimize(asm.map(String::from).to_vec()),
            ["<a>", "<b>", OP_NIP, "<c>", "<d>", OP_2DROP, "<x>", OP_1ADD, OP_2]
        );
        assert_eq!(
            optimize(["1", "1", OP_ADD].map(String::from).to_vec()),
            [OP_2]
        );
    }
}
