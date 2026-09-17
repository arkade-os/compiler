use crate::common::{arkade_asm, arkade_inputs, group, witness_names};
use arkade_compiler::compile;

#[test]
fn expiry_is_an_integer_in_the_covenant_only() {
    let output = compile(
        r#"
        contract Expiry(int margin) {
            function spend(int deadline) {
                int expiry = this . expiry;
                require(expiry - margin >= deadline);
            }
        }
    "#,
    )
    .unwrap();
    assert!(arkade_asm(&output, "spend").contains("OP_PUSHEXPIRY"));
    assert_eq!(arkade_inputs(&output, "spend"), ["deadline"]);
    let spend = group(&output, "spend");
    assert_eq!(spend.leaves.len(), 1);
    assert_eq!(
        spend.leaves[0].asm,
        [
            "<SERVER_KEY>",
            "OP_CHECKSIGVERIFY",
            "<EMULATOR_KEY:spend>",
            "OP_CHECKSIG"
        ]
    );
    assert_eq!(
        witness_names(&output, "spend", &spend.leaves[0].name),
        ["serverSig", "emulatorSig"]
    );
    for source in [
        "contract Bad() { function spend() { bool expiry = this.expiry; } }",
        "contract Bad() { function spend() { require(this.expiryExtra > 0); } }",
        "contract Bad() { function spend() tapscript { require(this.expiry); } }",
    ] {
        assert!(compile(source).is_err(), "{source}");
    }
}

#[test]
fn check_time_uses_the_emulator_clock_and_preserves_operand_order() {
    let output = compile(
        r#"
        contract Clock(int window) {
            function spend(int deadline) {
                bool reached = checkTime(deadline);
                require(reached);
                require(!checkTime(this.expiry - window));
                require(tx.time >= deadline);
            }
        }
    "#,
    )
    .unwrap();
    let asm = arkade_asm(&output, "spend");
    assert_eq!(
        asm.split_whitespace()
            .filter(|op| *op == "OP_CHECKTIME")
            .count(),
        2
    );
    assert!(
        asm.contains("OP_SUB OP_CHECKTIME OP_NOT OP_VERIFY"),
        "{asm}"
    );
    assert!(asm.contains("OP_INSPECTLOCKTIME"), "{asm}");
    assert_eq!(arkade_inputs(&output, "spend"), ["deadline"]);
    assert!(!group(&output, "spend").leaves[0]
        .asm
        .iter()
        .any(|op| op == "OP_CHECKTIME"));
    for body in [
        "require(checkTime());",
        "require(checkTime(1, 2));",
        "require(checkTime(true));",
        "require(checkTime(\"123\"));",
        "require(checkTime(unknown));",
        "int time = checkTime(0);",
        "require(checkTime(checkTime(0)));",
    ] {
        let source = format!("contract Bad() {{ function spend() {{ {body} }} }}");
        assert!(compile(&source).is_err(), "{source}");
    }
    assert!(
        compile("contract Bad() { function spend() tapscript { require(checkTime(0)); } }")
            .is_err()
    );
}

#[test]
fn check_time_substitutes_loop_bindings_and_extracts_helper_calls() {
    let output = compile(
        r#"
        contract Clock(int[2] deadlines) {
            private function offset(int timestamp) int { return timestamp - 1; }
            function spend() {
                for (i, deadline) in deadlines {
                    require(checkTime(offset(deadline) + i));
                }
            }
        }
    "#,
    )
    .unwrap();
    let asm = arkade_asm(&output, "spend");
    assert_eq!(
        asm.split_whitespace()
            .filter(|op| *op == "OP_CHECKTIME")
            .count(),
        2
    );
    assert!(!asm.contains("<deadline>"), "{asm}");
    assert!(!asm.contains("$call"), "{asm}");
}
