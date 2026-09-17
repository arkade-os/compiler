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
fn intent_fields_assert_presence_and_has_keeps_the_flag() {
    let output = compile(
        r#"
        contract Intent() {
            private function kind() bytes { return tx.intent.field("type"); }
            function spend() {
                require(kind() == "register");
                int expiry = bin2num(tx . intent . field("expire_at"));
                require(expiry >= 0);
                bool present = tx.intent.has("cosigners.0");
                require(present);
                require(!tx.intent.has("missing"));
                require(size(tx.intent.field("items.0")) >= 0);
            }
        }
    "#,
    )
    .unwrap();
    let asm = arkade_asm(&output, "spend");
    assert!(
        asm.contains("0x74797065 OP_INSPECTINTENTMESSAGE OP_VERIFY"),
        "{asm}"
    );
    assert!(
        asm.contains("0x6578706972655f6174 OP_INSPECTINTENTMESSAGE OP_VERIFY OP_BIN2NUM"),
        "{asm}"
    );
    assert!(
        asm.contains("OP_INSPECTINTENTMESSAGE OP_NIP OP_NOT OP_VERIFY"),
        "{asm}"
    );
    assert!(arkade_inputs(&output, "spend").is_empty());
    assert!(!group(&output, "spend").leaves[0]
        .asm
        .iter()
        .any(|op| op == "OP_INSPECTINTENTMESSAGE"));
}

#[test]
fn intent_paths_match_the_emulator_restrictions() {
    for path in ["type", "_key.a1", "items.0", "items.1048575", "0"] {
        let source = format!(
            "contract C() {{ function spend() {{ require(tx.intent.has(\"{path}\")); }} }}"
        );
        compile(&source).unwrap();
    }
    for path in [
        "",
        ".type",
        "type.",
        "a..b",
        "Type",
        "items.00",
        "items.01",
        "items.1048576",
        "items.18446744073709551616",
        "a.*",
        "a.#",
        "a|b",
        "a-b",
        "a.+1",
        "é",
    ] {
        let source = format!(
            "contract C() {{ function spend() {{ require(tx.intent.has(\"{path}\")); }} }}"
        );
        assert!(compile(&source).is_err(), "{path}");
    }
    let long_path = "a".repeat(521);
    assert!(compile(&format!(
        "contract C() {{ function spend() {{ require(tx.intent.has(\"{long_path}\")); }} }}"
    ))
    .is_err());
    let escaped =
        compile(r#"contract C() { function spend() { require(tx.intent.has("typ\u0065")); } }"#)
            .unwrap();
    assert!(arkade_asm(&escaped, "spend").contains("0x74797065 OP_INSPECTINTENTMESSAGE OP_NIP"));
}

#[test]
fn intent_accessors_validate_arity_types_and_context() {
    for body in [
        "require(tx.intent.has());",
        "require(tx.intent.has(\"type\", \"other\"));",
        "require(tx.intent.has(1));",
        "require(tx.intent.has(path));",
        "int value = tx.intent.field(\"expire_at\");",
        "bytes value = tx.intent.has(\"type\");",
    ] {
        let source = format!("contract C(bytes path) {{ function spend() {{ {body} }} }}");
        assert!(compile(&source).is_err(), "{source}");
    }
    for call in ["tx.intent.field(\"type\")", "tx.intent.has(\"type\")"] {
        assert!(compile(&format!(
            "contract C() {{ function spend() tapscript {{ require({call}); }} }}"
        ))
        .is_err());
    }
}

#[test]
fn tunnel_defaults_and_constant_policies() {
    let output = compile(
        r#"
        contract Continuation() {
            const bool PRESERVE = 1 == 1;
            function spend() {
                require(this.tunnel(0));
                bool continued = this . tunnel(1, {
                    assets: false,
                    scriptPubKey: PRESERVE,
                    value: !false
                }, []);
                require(continued);
            }
        }
    "#,
    )
    .unwrap();
    let asm = arkade_asm(&output, "spend");
    assert!(asm.contains("0 7 0 OP_TUNNEL OP_VERIFY"), "{asm}");
    assert!(asm.contains("1 3 0 OP_TUNNEL"), "{asm}");
    assert!(arkade_inputs(&output, "spend").is_empty());
    assert!(!group(&output, "spend").leaves[0]
        .asm
        .iter()
        .any(|op| op == "OP_TUNNEL"));
}

#[test]
fn tunnel_exceptions_accept_bound_native_and_helper_asset_ids() {
    let output = compile(
        r#"
        contract Continuation() {
            private function identity(AssetId id) AssetId { return id; }
            function spend(int outputIndex, AssetId feeAsset) {
                require(this.tunnel(outputIndex, {
                    scriptPubKey: true, value: true, assets: true
                }, [feeAsset, identity(feeAsset), tx.inputs[0].assets[0].assetId]));
                require(outputIndex >= 0);
            }
        }
    "#,
    )
    .unwrap();
    let asm = arkade_asm(&output, "spend");
    assert!(
        asm.contains("OP_INSPECTINASSETAT OP_DROP 3 OP_TUNNEL OP_VERIFY"),
        "{asm}"
    );
    assert!(asm.contains("OP_SWAP"), "{asm}");
    assert_eq!(arkade_inputs(&output, "spend"), ["outputIndex", "feeAsset"]);
    assert!(!asm.contains("$call"), "{asm}");
}

#[test]
fn tunnel_validates_policy_shape_types_and_exceptions() {
    for call in [
        "this.tunnel()",
        "this.tunnel(true)",
        "this.tunnel(0, {value: true, assets: true})",
        "this.tunnel(0, {scriptPubKey: true, value: true, assets: true, other: true})",
        "this.tunnel(0, {scriptPubKey: true, value: true, assets: true, value: false})",
        "this.tunnel(0, {scriptPubKey: false, value: false, assets: false})",
        "this.tunnel(0, {scriptPubKey: 1, value: true, assets: true})",
        "this.tunnel(0, {scriptPubKey: runtime, value: true, assets: true})",
        "this.tunnel(0, {scriptPubKey: true, value: true, assets: false}, [assetId])",
        "this.tunnel(0, {scriptPubKey: true, value: true, assets: true}, [1])",
        "this.tunnel(0, {scriptPubKey: true, value: true, assets: true}, [unknown])",
    ] {
        let source = format!("contract Bad(AssetId assetId, bool runtime) {{ function spend() {{ require({call}); }} }}");
        assert!(compile(&source).is_err(), "{source}");
    }
    assert!(
        compile("contract Bad() { function spend() tapscript { require(this.tunnel(0)); } }")
            .is_err()
    );
}

#[test]
fn tunnel_substitutes_loop_output_indexes() {
    let output = compile(
        r#"
        contract Continuation(int[2] indexes) {
            function spend() {
                for (i, outputIndex) in indexes {
                    require(this.tunnel(outputIndex + i));
                }
            }
        }
    "#,
    )
    .unwrap();
    let asm = arkade_asm(&output, "spend");
    assert_eq!(
        asm.split_whitespace()
            .filter(|op| *op == "OP_TUNNEL")
            .count(),
        2
    );
    assert!(!asm.contains("<outputIndex>"), "{asm}");
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
