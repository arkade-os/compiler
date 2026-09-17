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
