use crate::opcodes::{
    OP_0, OP_0NOTEQUAL, OP_1, OP_1ADD, OP_2, OP_2DROP, OP_ADD, OP_BOOLAND, OP_BOOLOR, OP_CHECKSIG,
    OP_CHECKSIGVERIFY, OP_DROP, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_GREATERTHAN,
    OP_GREATERTHANOREQUAL, OP_INSPECTINPUTPACKET, OP_INSPECTPACKET, OP_LESSTHAN,
    OP_LESSTHANOREQUAL, OP_NIP, OP_NOT, OP_NUMEQUAL, OP_OVER, OP_PICK, OP_PUT, OP_ROLL, OP_ROT,
    OP_SWAP, OP_VERIFY,
};

/// Opcodes that leave a minimal 0 or 1, which `OP_0NOTEQUAL` returns unchanged.
const BOOLEAN_RESULTS: [&str; 11] = [
    OP_EQUAL,
    OP_NUMEQUAL,
    OP_LESSTHAN,
    OP_LESSTHANOREQUAL,
    OP_GREATERTHAN,
    OP_GREATERTHANOREQUAL,
    OP_NOT,
    OP_0NOTEQUAL,
    OP_BOOLAND,
    OP_BOOLOR,
    OP_CHECKSIG,
];

pub(super) fn optimize(mut asm: Vec<String>) -> Vec<String> {
    // The NIPs clear every item below the final truthy value. The final clean-stack truth check
    // already enforces a trailing `OP_VERIFY OP_1`, so a failing last requirement reports a false
    // stack entry instead.
    let nips = asm
        .iter()
        .rev()
        .take_while(|token| *token == OP_NIP)
        .count();
    let body = asm.len() - nips;
    let mut kept = asm.clone();
    if body >= 2 && kept[body - 2] == OP_VERIFY && kept[body - 1] == OP_1 {
        kept.drain(body - 2..body);
    }
    // Verifying the final value first lets the cleared items go in pairs with OP_2DROP.
    asm.truncate(body);
    asm.push(OP_VERIFY.to_string());
    asm.extend(std::iter::repeat_n(OP_DROP.to_string(), nips));
    asm.push(OP_1.to_string());

    let (kept, dropped) = (rewrite(kept), rewrite(asm));
    if dropped.len() < kept.len() {
        dropped
    } else {
        kept
    }
}

fn rewrite(asm: Vec<String>) -> Vec<String> {
    let mut optimized = Vec::with_capacity(asm.len());
    for token in asm {
        optimized.push(token);
        while optimized.len() >= 2 {
            let len = optimized.len();
            if optimized[len - 1] == OP_0NOTEQUAL
                && BOOLEAN_RESULTS.contains(&optimized[len - 2].as_str())
            {
                optimized.pop();
                continue;
            }
            let replacement = match (optimized[len - 2].as_str(), optimized[len - 1].as_str()) {
                (OP_0, OP_PICK) => Some(Some(OP_DUP)),
                (OP_DUP, OP_SWAP) => Some(Some(OP_DUP)),
                (OP_0, OP_PUT) => Some(Some(OP_NIP)),
                (OP_1, OP_PICK) => Some(Some(OP_OVER)),
                (OP_0, OP_ROLL) | (OP_SWAP, OP_SWAP) => Some(None),
                (OP_1, OP_ROLL) => Some(Some(OP_SWAP)),
                (OP_2, OP_ROLL) => Some(Some(OP_ROT)),
                (OP_SWAP, OP_DROP) => Some(Some(OP_NIP)),
                (OP_DROP, OP_DROP) => Some(Some(OP_2DROP)),
                (OP_1 | "1", OP_ADD) => Some(Some(OP_1ADD)),
                (OP_1 | "1", OP_1ADD) => Some(Some(OP_2)),
                (OP_1 | "1", OP_VERIFY) => Some(None),
                (OP_EQUAL, OP_VERIFY) => Some(Some(OP_EQUALVERIFY)),
                (OP_DUP, OP_EQUALVERIFY) => Some(Some(OP_DROP)),
                // Packet lookups push a 0 or 1 presence flag.
                (OP_1, OP_EQUALVERIFY)
                    if len > 2
                        && [OP_INSPECTPACKET, OP_INSPECTINPUTPACKET]
                            .contains(&optimized[len - 3].as_str()) =>
                {
                    Some(Some(OP_VERIFY))
                }
                (OP_CHECKSIG, OP_VERIFY) => Some(Some(OP_CHECKSIGVERIFY)),
                (OP_NOT, OP_NOT) => Some(Some(OP_0NOTEQUAL)),
                (OP_0NOTEQUAL, OP_NOT) => Some(Some(OP_NOT)),
                _ => None,
            };
            let Some(replacement) = replacement else {
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
    use crate::opcodes::OP_ENDIF;

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
    fn boolean_presence_and_trailing_cleanup_rewrites() {
        let optimize = |asm: &[&str]| optimize(asm.iter().map(|token| token.to_string()).collect());
        assert_eq!(
            optimize(&[
                "<a>",
                "<b>",
                OP_LESSTHAN,
                OP_0NOTEQUAL,
                OP_NOT,
                OP_NOT,
                "<c>"
            ]),
            ["<a>", "<b>", OP_LESSTHAN, "<c>"]
        );
        assert_eq!(
            optimize(&["<x>", OP_0NOTEQUAL, OP_NOT, "<y>", OP_0NOTEQUAL]),
            ["<x>", OP_NOT, "<y>", OP_0NOTEQUAL]
        );
        assert_eq!(
            optimize(&[
                "5",
                OP_INSPECTPACKET,
                OP_1,
                OP_EQUALVERIFY,
                OP_1,
                OP_EQUALVERIFY,
                "<z>"
            ]),
            [
                "5",
                OP_INSPECTPACKET,
                OP_VERIFY,
                OP_1,
                OP_EQUALVERIFY,
                "<z>"
            ]
        );
        // Paired drops win only once they cover the added `OP_VERIFY OP_1`; ties keep the NIPs.
        assert_eq!(
            optimize(&[OP_ENDIF, OP_1, OP_NIP, OP_NIP, OP_NIP, OP_NIP, OP_NIP]),
            [OP_ENDIF, OP_2DROP, OP_2DROP, OP_DROP, OP_1]
        );
        assert_eq!(
            optimize(&[OP_EQUAL, OP_NIP, OP_NIP, OP_NIP, OP_NIP]),
            [OP_EQUALVERIFY, OP_2DROP, OP_2DROP, OP_1]
        );
        assert_eq!(
            optimize(&[OP_EQUAL, OP_NIP, OP_NIP, OP_NIP]),
            [OP_EQUAL, OP_NIP, OP_NIP, OP_NIP]
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
