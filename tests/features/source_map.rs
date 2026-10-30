use arkade_compiler::diagnostics::offset;
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
            require(parts[0] == amount, \"first part\");
        } else {
            require(parts[1] == amount);
        }
        for (i, part) in parts {
            require(part > i, \"ordered\");
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

/// The source text of each range, the tokens it covers and its message.
fn lines(output: &ContractJson) -> Vec<(String, String, Option<String>)> {
    let covenant = output.functions[0].arkade.as_ref().unwrap();
    let at = |[line, column]: [usize; 2]| offset(MAIN, line, column).unwrap();
    covenant
        .source_map
        .iter()
        .map(
            |SourceRange {
                 asm,
                 start,
                 end,
                 message,
             }| {
                let text = MAIN[at(*start)..at(*end)].to_string();
                let tokens = covenant.asm[asm[0]..asm[1]].join(" ");
                (text, tokens, message.clone())
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
        assert_eq!(
            first.0, "require(checkSig(sig, owner), \"not the owner\");",
            "{lines:?}"
        );
        assert!(first.1.contains("OP_CHECKSIG"), "{lines:?}");
        assert_eq!(first.2.as_deref(), Some("not the owner"));
        for (statement, opcode, message) in [
            // An `if` maps its branch opcodes to the condition alone.
            ("amount > 10", "OP_IF", None),
            ("amount > 10", "OP_ELSE", None),
            ("amount > 10", "OP_ENDIF", None),
            (
                "require(parts[0] == amount, \"first part\");",
                "OP_NUMEQUAL",
                Some("first part"),
            ),
            ("require(parts[1] == amount);", "OP_NUMEQUAL", None),
            (
                "require(part > i, \"ordered\");",
                "OP_GREATERTHAN",
                Some("ordered"),
            ),
            ("Fees.check(amount);", "OP_GREATERTHAN", None),
            ("return x * 2;", "OP_MUL", None),
            ("require(double(amount) == 4);", "OP_NUMEQUAL", None),
        ] {
            assert!(
                lines.iter().any(|(text, tokens, found)| text == statement
                    && tokens.contains(opcode)
                    && found.as_deref() == message),
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
    // The final stack cleanup is not mapped.
    let last = covenant.source_map.last().unwrap().asm[1];
    assert!(last < covenant.asm.len());
}

#[test]
fn the_artifact_leaves_the_map_to_the_debug_file() {
    let output = compiled(true);
    assert!(!serde_json::to_string(&output)
        .unwrap()
        .contains("sourceMap"));
    let debug = output.debug_info();
    assert_eq!(debug["artifactFingerprint"], output.fingerprint.unwrap());
    assert_eq!(
        debug["functions"]["spend"]["sourceMap"],
        serde_json::to_value(&output.functions[0].arkade.as_ref().unwrap().source_map).unwrap()
    );
}
