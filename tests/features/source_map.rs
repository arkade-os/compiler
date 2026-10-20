use arkade_compiler::models::{ContractJson, SourceRange};
use arkade_compiler::{compile_sources_with_options, CompileOptions};
use std::collections::BTreeMap;

const FEES: &str =
    "library Fees { function check(int amount) { require(amount > 0, \"no fee\"); } }";

const MAIN: &str = "import \"fees.ark\";
contract Vault(pubkey owner) {
    function spend(signature sig, int amount, int[2] parts) {
        require(checkSig(sig, owner), \"not the owner\");
        if (amount > 10) {
            require(parts[0] == amount);
        }
        for (i, part) in parts {
            require(part > i);
        }
        Fees.check(amount);
        require(double(amount) == 4);
    }
    private function double(int x) int {
        return x * 2;
    }
}";

fn compiled(optimize: bool) -> ContractJson {
    let files = BTreeMap::from([
        ("main.ark".to_string(), MAIN.to_string()),
        ("fees.ark".to_string(), FEES.to_string()),
    ]);
    compile_sources_with_options("main.ark", &files, CompileOptions { optimize }).unwrap()
}

/// The source line of each range and the tokens it covers.
fn lines(output: &ContractJson) -> Vec<(String, String, Option<String>)> {
    let covenant = output.functions[0].arkade.as_ref().unwrap();
    let source: Vec<&str> = MAIN.lines().collect();
    covenant
        .source_map
        .iter()
        .map(
            |SourceRange {
                 asm,
                 start,
                 message,
                 ..
             }| {
                let line = source[start[0] - 1][start[1] - 1..].to_string();
                let tokens = covenant.asm[asm[0]..asm[1]].join(" ");
                (line, tokens, message.clone())
            },
        )
        .collect()
}

#[test]
fn every_statement_maps_its_tokens_and_requires_carry_their_messages() {
    for optimize in [true, false] {
        let output = compiled(optimize);
        let covenant = output.functions[0].arkade.as_ref().unwrap();
        let mut previous_end = 0;
        for range in &covenant.source_map {
            assert!(range.asm[0] >= previous_end && range.asm[0] < range.asm[1]);
            assert!(range.asm[1] <= covenant.asm.len());
            previous_end = range.asm[1];
        }
        let lines = lines(&output);
        let first = &lines[0];
        assert!(
            first.0.starts_with("require(checkSig(sig, owner)"),
            "{lines:?}"
        );
        assert!(first.1.contains("OP_CHECKSIG"), "{lines:?}");
        assert_eq!(first.2.as_deref(), Some("not the owner"));
        for (statement, opcode) in [
            // An `if` maps its branch opcodes to the condition alone.
            ("amount > 10)", "OP_IF"),
            ("require(parts[0] == amount);", "OP_EQUAL"),
            ("require(part > i);", "OP_GREATERTHAN"),
            ("Fees.check(amount);", "OP_GREATERTHAN"),
            ("return x * 2;", "OP_MUL"),
            ("require(double(amount) == 4);", "OP_EQUAL"),
        ] {
            assert!(
                lines
                    .iter()
                    .any(|(line, tokens, _)| line.starts_with(statement) && tokens.contains(opcode)),
                "{statement} maps {opcode} (optimize {optimize}): {lines:?}"
            );
        }
        // The imported helper's statements are in another file, so they map to the call.
        assert!(lines.iter().all(|(line, _, _)| !line.contains("no fee")));
        assert!(lines
            .iter()
            .all(|(_, _, message)| message.as_deref() != Some("no fee")));
    }
}

#[test]
fn rewritten_instructions_keep_their_statement() {
    let output = compiled(true);
    let lines = lines(&output);
    let (_, tokens, _) = lines
        .iter()
        .find(|(line, _, _)| line.starts_with("require(checkSig(sig, owner)"))
        .unwrap();
    assert!(tokens.ends_with("OP_CHECKSIGVERIFY"), "{tokens}");
    let covenant = output.functions[0].arkade.as_ref().unwrap();
    let last = covenant.source_map.last().unwrap().asm[1];
    assert!(last <= covenant.asm.len());
}
