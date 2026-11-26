use crate::common::{
    arkade_asm, arkade_asm_tokens, arkade_inputs, compile_unoptimized, group, project,
    witness_names,
};
use arkade_compiler::compile;

#[test]
fn arkade_script_opcodes_report_their_context_in_tapscript() {
    for (expression, name) in [
        ("this . expiry > 0", "this.expiry"),
        ("after(this.expiry)", "this.expiry"),
        ("checkTime(0)", "checkTime(...)"),
        ("!checkTime(0)", "checkTime(...)"),
        ("this.tunnel(0)", "this.tunnel(...)"),
        ("this.tunnel()", "this.tunnel(...)"),
        ("this.tunnel(0) == true", "this.tunnel(...)"),
        ("this.renew()", "this.renew(...)"),
        ("this.renew(1, {script: true})", "this.renew(...)"),
        ("!this.renew()", "this.renew(...)"),
        ("tx.proof.output.value > 0", "tx.proof.output"),
        (
            "tx . proof . output . script == tx.proof.output",
            "tx.proof.output",
        ),
        ("substr(0x00, 0, 1) == 0x00", "substr(...)"),
        ("within(1, 0, 2)", "within(...)"),
        (
            "checkSigFromStack(0x00, operator, 0x00)",
            "checkSigFromStack(...)",
        ),
        (
            "checkSigFromStackVerify(0x00, operator, 0x00)",
            "checkSigFromStackVerify(...)",
        ),
        (
            "tx.proof.field(\"type\") == \"register\"",
            "tx.proof.field(...)",
        ),
        ("tx.proof.has(\"type\")", "tx.proof.has(...)"),
        ("!tx.proof.has(\"type\")", "tx.proof.has(...)"),
        ("tx.intent.has(\"type\")", "tx.intent.has(...)"),
    ] {
        let source =
            format!("contract C() {{ function spend() tapscript {{ require({expression}); }} }}");
        let error = compile(&source).unwrap_err().to_string();
        assert!(
            error.contains(&format!(
                "`{name}` is only available in Arkade Script functions"
            )),
            "{expression}: {error}"
        );
    }
    for (expression, place) in [
        (
            "sha256(0x00)",
            "`sha256` only as `require(sha256(preimage) == hash)`",
        ),
        (
            "sha256(0x00) != 0x00",
            "`sha256` only as `require(sha256(preimage) == hash)`",
        ),
        (
            "0x00 == hash160(0x00)",
            "`hash160` only as `require(hash160(preimage) == hash)`",
        ),
        (
            "older(1) == true",
            "`older` only as `require(older(sequence))`",
        ),
        (
            "older(1 + after(1))",
            "`after` only as `require(after(locktime))`",
        ),
        (
            "older(blocks(1) + 1)",
            "`blocks` only as `older(blocks(count))` or `after(blocks(count))`",
        ),
        (
            "after(seconds(seconds(1)))",
            "`seconds` only as `older(seconds(count))` or `after(seconds(count))`",
        ),
        (
            "sha256(tweak(operator, spend)) == 0x00",
            "`tweak` only as a key inside checkSig or checkMultisig",
        ),
    ] {
        let source =
            format!("contract C() {{ function spend() tapscript {{ require({expression}); }} }}");
        let error = compile(&source).unwrap_err().to_string();
        assert!(
            error.contains(&format!("a tapscript function can use {place}")),
            "{expression}: {error}"
        );
    }
}

#[test]
fn tapscript_opcodes_report_their_context_in_arkade_script_functions() {
    for (expression, name, hint) in [
        (
            "older(1)",
            "older",
            "Arkade Script functions use `checkTime(timestamp)`",
        ),
        (
            "after(t)",
            "after",
            "Arkade Script functions use `checkTime(timestamp)`",
        ),
        ("blocks(1) > 0", "blocks", "inside older(...) or after(...)"),
        (
            "seconds(t) > 0",
            "seconds",
            "inside older(...) or after(...)",
        ),
        (
            "checkSig(s, tweak(operator, spend))",
            "tweak",
            "as a key inside checkSig or checkMultisig",
        ),
    ] {
        let source = format!(
            "contract C(int t) {{ function spend(signature s) {{ require({expression}); }} }}"
        );
        let error = compile(&source).unwrap_err().to_string();
        assert!(
            error.contains(&format!(
                "`{name}(...)` is only available in tapscript functions"
            )) && error.contains(hint),
            "{expression}: {error}"
        );
    }
    for (expression, signature) in [
        ("older()", "older(sequence)"),
        ("after(1, 2)", "after(locktime)"),
        ("blocks(1, 2) > 0", "blocks(count)"),
        ("tweak(operator) == 0x00", "tweak(base, name)"),
    ] {
        let source = format!("contract C() {{ function spend() {{ require({expression}); }} }}");
        let error = compile(&source).unwrap_err().to_string();
        assert!(
            error.contains(&format!("expected {signature}")),
            "{expression}: {error}"
        );
    }
}

#[test]
fn tunnel_indexes_require_integer_helper_returns() {
    let output = compile(
        "contract C() { private function index() int { return 0; } function spend() { require(this.tunnel(index())); } }",
    )
    .unwrap();
    assert!(arkade_asm(&output, "spend").contains("OP_TUNNEL"));
    for (helper, message) in [
        (
            "private function index() { require(true); }",
            "function 'index' does not return a value",
        ),
        (
            "private function index() bool { return true; }",
            "tunnel output index must be int, got",
        ),
    ] {
        let source = format!(
            "contract C() {{ {helper} function spend() {{ require(this.tunnel(index())); }} }}"
        );
        let error = compile(&source).unwrap_err().to_string();
        assert!(error.contains(message), "{error}");
    }
}

#[test]
fn expiry_is_an_integer_in_arkade_script_functions_only() {
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
    assert_eq!(spend.leaves[0].asm, ["<OPERATOR_KEY:spend>", "OP_CHECKSIG"]);
    assert_eq!(
        witness_names(&output, "spend", &spend.leaves[0].name),
        ["operatorSig"]
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
fn proof_fields_assert_presence_and_has_keeps_the_flag() {
    let output = compile(
        r#"
        contract Proof() {
            private function kind() bytes { return tx.proof.field("type"); }
            function spend() {
                require(kind() == "register");
                int expiry = bytes2int(tx . proof . field("expire_at"));
                require(expiry >= 0);
                bool present = tx.proof.has("cosigners.0");
                require(present);
                require(!tx.proof.has("missing"));
                require(size(tx.proof.field("items.0")) >= 0);
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
fn proof_paths_match_the_emulator_restrictions() {
    for path in ["type", "_key.a1", "items.0", "items.1048575", "0"] {
        let source =
            format!("contract C() {{ function spend() {{ require(tx.proof.has(\"{path}\")); }} }}");
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
        let source =
            format!("contract C() {{ function spend() {{ require(tx.proof.has(\"{path}\")); }} }}");
        assert!(compile(&source).is_err(), "{path}");
    }
    let long_path = "a".repeat(521);
    assert!(compile(&format!(
        "contract C() {{ function spend() {{ require(tx.proof.has(\"{long_path}\")); }} }}"
    ))
    .is_err());
    let escaped =
        compile(r#"contract C() { function spend() { require(tx.proof.has("typ\u0065")); } }"#)
            .unwrap();
    assert!(arkade_asm(&escaped, "spend").contains("0x74797065 OP_INSPECTINTENTMESSAGE OP_NIP"));
}

#[test]
fn deprecated_intent_spelling_compiles_as_proof() {
    let asm = |owner: &str| {
        let source = format!(
            r#"contract C() {{ function spend() {{ require(tx.{owner}.has("type")); require(tx.{owner}.field("type") == "register"); }} }}"#
        );
        arkade_asm(&compile(&source).unwrap(), "spend")
    };
    assert_eq!(asm("intent"), asm("proof"));
}

#[test]
fn proof_paths_can_be_runtime_bytes() {
    let output = compile(
        "contract C(bytes path) { function spend(bytes key) { require(tx.proof.has(path)); require(tx.proof.field(key) == path); } }",
    )
    .expect("runtime paths compile");
    let asm = arkade_asm(&output, "spend");
    assert!(asm.contains("OP_INSPECTINTENTMESSAGE OP_NIP"), "{asm}");
    assert!(asm.contains("OP_INSPECTINTENTMESSAGE OP_VERIFY"), "{asm}");
    assert!(!asm.contains("0x"), "paths come from the stack: {asm}");

    let output = compile(
        "contract C() { function spend(bytes i) { require(tx.proof.has(\"cosigners.\" + i)); } }",
    )
    .expect("a quoted prefix starts a runtime path");
    let asm = arkade_asm(&output, "spend");
    assert!(
        asm.contains("0x636f7369676e6572732e OP_SWAP OP_CAT OP_INSPECTINTENTMESSAGE OP_NIP"),
        "{asm}"
    );

    let error = compile("contract C() { function spend(int n) { require(tx.proof.has(n)); } }")
        .expect_err("a path is bytes")
        .to_string();
    assert!(
        error.contains("tx.proof operand has type 'int', expected 'bytes'"),
        "{error}"
    );
}

#[test]
fn proof_accessors_validate_arity_types_and_context() {
    for body in [
        "require(tx.proof.has());",
        "require(tx.proof.has({ txid: \"type\", gidx: \"other\" }));",
        "require(tx.proof.has(1));",
        "int value = tx.proof.field(\"expire_at\");",
        "bytes value = tx.proof.has(\"type\");",
    ] {
        let source = format!("contract C(bytes path) {{ function spend() {{ {body} }} }}");
        assert!(compile(&source).is_err(), "{source}");
    }
    for call in ["tx.proof.field(\"type\")", "tx.proof.has(\"type\")"] {
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
                    script: PRESERVE,
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
                    script: true, value: true, assets: true
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
        "this.tunnel(0, {script: true, value: true, assets: true, other: true})",
        "this.tunnel(0, {script: true, value: true, assets: true, value: false})",
        "this.tunnel(0, {script: false, value: false, assets: false})",
        "this.tunnel(0, {script: 1, value: true, assets: true})",
        "this.tunnel(0, {script: runtime, value: true, assets: true})",
        "this.tunnel(0, {script: true, value: true, assets: false}, [assetId])",
        "this.tunnel(0, {script: true, value: true, assets: true}, [1])",
        "this.tunnel(0, {script: true, value: true, assets: true}, [unknown])",
    ] {
        let source = format!("contract Bad(AssetId assetId, bool runtime) {{ function spend() {{ require({call}); }} }}");
        assert!(compile(&source).is_err(), "{source}");
    }
    assert!(
        compile("contract Bad() { function spend() tapscript { require(this.tunnel(0)); } }")
            .is_err()
    );
}

/// The requirements `require(this.renew(...), "renew")` stands for, for its window and for the
/// policy and exceptions it gives its tunnel.
fn renewal(window: &str, tunnel: &str) -> String {
    format!(
        r#"require(checkTime(this.expiry - {window}), "renew");
        require(tx.proof.field("type") == "register", "renew");
        require(tx.proof.field("onchain_output_indexes") == "[]", "renew");
        require(this.tunnel(this.activeInputIndex - 1{tunnel}), "renew");"#
    )
}

const RENEWAL_POLICY: &str = "{ script: true, value: false, assets: true }";

#[test]
fn renew_compiles_as_its_four_requirements() {
    // Each script, and the lints that fire on it.
    let scripts = |body: &str| {
        let source = format!(
            "contract Vault(int window, int maxFee, AssetId feeAsset) {{ private function twice(int x) int {{ return x * 2; }} function renew() {{ require(twice(maxFee) >= 0); {body} }} }}"
        );
        [compile(&source), compile_unoptimized(&source)].map(|output| {
            let output = output.unwrap_or_else(|e| panic!("{body}: {e}"));
            let lints = output.warnings.iter().map(|warning| {
                let (lint, _) = warning.split_once(']').expect("a lint id");
                lint.to_string()
            });
            (
                arkade_asm_tokens(&output, "renew"),
                lints.collect::<Vec<_>>(),
            )
        })
    };
    let fee = "require(tx.proof.output.value + maxFee >= tx.input.current.value, \"fee\");";
    for (arguments, window, tunnel) in [
        (String::new(), "86400", String::new()),
        ("window".to_string(), "window", String::new()),
        (
            "window * 2 + 1,".to_string(),
            "(window * 2 + 1)",
            String::new(),
        ),
        ("twice(window)".to_string(), "twice(window)", String::new()),
        (
            RENEWAL_POLICY.to_string(),
            "86400",
            format!(", {RENEWAL_POLICY}"),
        ),
        (
            format!("{RENEWAL_POLICY}, [feeAsset]"),
            "86400",
            format!(", {RENEWAL_POLICY}, [feeAsset]"),
        ),
        (
            format!("window, {RENEWAL_POLICY}"),
            "window",
            format!(", {RENEWAL_POLICY}"),
        ),
        (
            format!("window, {RENEWAL_POLICY}, [feeAsset, tx.inputs[0].assets[0].assetId],"),
            "window",
            format!(", {RENEWAL_POLICY}, [feeAsset, tx.inputs[0].assets[0].assetId]"),
        ),
        (
            "1, { script: true, value: true, assets: true }, []".to_string(),
            "1",
            String::new(),
        ),
    ] {
        let call = format!("require(this . renew({arguments}), \"renew\");");
        let written = renewal(window, &tunnel);
        for (before, after) in [
            ("", String::new()),
            ("", fee.to_string()),
            ("require(maxFee > 0);", fee.to_string()),
            (
                "if (maxFee > 0) {",
                format!("}} else {{ require(maxFee == 0); }} {fee}"),
            ),
            ("for (i) in 0..2 { require(maxFee > i);", "}".to_string()),
        ] {
            assert_eq!(
                scripts(&format!("{before} {call} {after}")),
                scripts(&format!("{before} {written} {after}")),
                "this.renew({arguments}) between `{before}` and `{after}`"
            );
        }
    }
}

#[test]
fn renew_defaults_to_a_day_and_keeps_its_checks_out_of_the_leaf() {
    let output =
        compile("contract Vault() { function renew() { require(this.renew()); } }").unwrap();
    assert_eq!(
        arkade_asm_tokens(&output, "renew"),
        [
            "OP_PUSHEXPIRY",
            "86400",
            "OP_SUB",
            "OP_CHECKTIME",
            "OP_VERIFY",
            "0x74797065",
            "OP_INSPECTINTENTMESSAGE",
            "OP_VERIFY",
            "0x7265676973746572",
            "OP_EQUALVERIFY",
            "0x6f6e636861696e5f6f75747075745f696e6465786573",
            "OP_INSPECTINTENTMESSAGE",
            "OP_VERIFY",
            "0x5b5d",
            "OP_EQUALVERIFY",
            "OP_PUSHCURRENTINPUTINDEX",
            "1",
            "OP_SUB",
            "7",
            "0",
            "OP_TUNNEL",
        ]
    );
    assert!(arkade_inputs(&output, "renew").is_empty());
    let renew = group(&output, "renew");
    assert_eq!(renew.leaves.len(), 1);
    assert_eq!(renew.leaves[0].asm, ["<OPERATOR_KEY:renew>", "OP_CHECKSIG"]);
    assert_eq!(
        witness_names(&output, "renew", &renew.leaves[0].name),
        ["operatorSig"]
    );
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("unsigned-spend-path")),
        "{:?}",
        output.warnings
    );
}

#[test]
fn renew_maps_its_checks_to_the_one_statement_and_message() {
    let statement = "require(this.renew(window), \"too early or no renewal\");";
    let source = format!(
        "contract Vault(int window) {{\n    function renew() {{\n        {statement}\n        require(tx.proof.output.value > 0, \"fee\");\n    }}\n}}"
    );
    let output = compile(&source).unwrap();
    let script = output.functions[0].arkade.as_ref().unwrap();
    let range = &script.source_map[0];
    let at = |[line, column]: [usize; 2]| {
        arkade_compiler::diagnostics::offset(&source, line, column).unwrap()
    };
    assert_eq!(&source[at(range.start)..at(range.end)], statement);
    assert_eq!(range.message.as_deref(), Some("too early or no renewal"));
    let tokens = &script.asm[range.asm[0]..range.asm[1]];
    assert_eq!(tokens.first().map(String::as_str), Some("OP_PUSHEXPIRY"));
    assert_eq!(tokens.last().map(String::as_str), Some("OP_VERIFY"));
    assert!(tokens.contains(&"OP_TUNNEL".to_string()), "{tokens:?}");
    assert_eq!(script.source_map[1].message.as_deref(), Some("fee"));
    assert_eq!(script.source_map[1].asm[0], range.asm[1]);
}

#[test]
fn renew_takes_the_lint_attributes_of_its_statement() {
    let warnings = |attribute: &str, window: &str| {
        let source = format!(
            "contract Vault(int window) {{ function renew() {{\n{attribute}\nrequire(this.renew({window}, {RENEWAL_POLICY}, [tx.inputs[0].assets[0].assetId, tx.inputs[0].assets[0].assetId])); }} }}"
        );
        compile(&source).map(|output| output.warnings.join("\n"))
    };
    let unattributed = warnings("", "window").unwrap();
    assert!(
        unattributed.contains("repeated-inspection"),
        "{unattributed}"
    );
    let expected = warnings("@expect(repeated-inspection, \"one read each\")", "window").unwrap();
    assert!(
        !expected.contains("repeated-inspection") && !expected.contains("unfulfilled-expectation"),
        "{expected}"
    );
    let unfulfilled = warnings("@expect(self-comparison, \"none\")", "window").unwrap();
    assert_eq!(
        unfulfilled.matches("unfulfilled-expectation").count(),
        1,
        "{unfulfilled}"
    );
    let denied = warnings("", "window + tx.locktime")
        .unwrap_err()
        .to_string();
    assert!(denied.contains("offchain-locktime"), "{denied}");
    warnings(
        "@allow(offchain-locktime, \"tested\")",
        "window + tx.locktime",
    )
    .unwrap();
}

#[test]
fn renew_works_in_private_helpers_and_imported_libraries() {
    let helper = |body: &str| {
        let source = format!(
            "contract Vault(int window, AssetId feeAsset) {{ private function renewal(int opens) {{ {body} }} function renew() {{ renewal(window); require(window > 0); }} }}"
        );
        arkade_asm_tokens(&compile(&source).unwrap(), "renew")
    };
    let tunnel = format!(", {RENEWAL_POLICY}, [feeAsset]");
    let sugared = helper(&format!(
        "require(this.renew(opens, {RENEWAL_POLICY}, [feeAsset]), \"renew\");"
    ));
    assert_eq!(sugared, helper(&renewal("opens", &tunnel)));
    assert!(sugared.contains(&"OP_TUNNEL".to_string()), "{sugared:?}");

    let library = |body: &str| {
        let main = "import \"renewal.ark\"; contract Vault(int window) { function renew() { Renewal.check(window); require(window > 0); } }";
        let library = format!(
            "library Renewal {{ const int MARGIN = 60; function check(int opens) {{ {body} }} }}"
        );
        let output = project("main.ark", &[("main.ark", main), ("renewal.ark", &library)]);
        arkade_asm_tokens(&output.unwrap(), "renew")
    };
    let sugared = library("require(this.renew(opens + MARGIN), \"renew\");");
    assert_eq!(sugared, library(&renewal("(opens + MARGIN)", "")));
    assert!(sugared.contains(&"OP_CHECKTIME".to_string()), "{sugared:?}");
}

#[test]
fn renew_validates_its_arguments_and_window() {
    let error = |call: &str| {
        let source = format!(
            "contract Bad(AssetId assetId, bool runtime, int window, bytes data) {{ const int ZERO = 0; const int DAY = 86400; function spend() {{ require({call}); }} }}"
        );
        match compile(&source) {
            Ok(_) => panic!("{call} compiles"),
            Err(error) => error.to_string(),
        }
    };
    for arguments in [
        "[]",
        "[assetId]",
        "window, [assetId]",
        "window, window",
        "window, {script: true, value: true, assets: true}, [assetId], 1",
        "window, {script: true, value: true, assets: true}, window",
        "{script: true, value: true, assets: true}, window",
        "{script: true, value: true, assets: true}, {script: true, value: true, assets: true}",
        "{script: true, value: true, assets: true}, [assetId], window",
        "window, ({script: true, value: true, assets: true})",
    ] {
        let error = error(&format!("this.renew({arguments})"));
        assert!(
            error.contains(
                "wrong arguments to `this.renew`: expected this.renew(window?, policy?, exceptions?)"
            ),
            "{arguments}: {error}"
        );
    }
    for (window, ty) in [("true", "bool"), ("runtime", "bool"), ("data", "bytes")] {
        let error = error(&format!("this.renew({window})"));
        assert!(
            error.contains(&format!("operand has type '{ty}', expected 'int'")),
            "{window}: {error}"
        );
    }
    for (window, value) in [
        ("0", "0"),
        ("-1", "-1"),
        ("ZERO", "0"),
        ("DAY - DAY - 5", "-5"),
        ("Bad.ZERO, {script: true, value: true, assets: true}", "0"),
    ] {
        let error = error(&format!("this.renew({window})"));
        assert!(
            error.contains(&format!(
                "this.renew window must be at least 1, got {value}"
            )),
            "{window}: {error}"
        );
    }
    for arguments in ["1", "DAY", "DAY - 86399", "window", "window - window"] {
        let source = format!(
            "contract C(int window) {{ const int DAY = 86400; function spend() {{ require(this.renew({arguments})); }} }}"
        );
        compile(&source).unwrap_or_else(|error| panic!("{arguments}: {error}"));
    }
    // The policy and exceptions are the tunnel's, and fail as its own do.
    for (literals, message) in [
        (
            "{value: true, assets: true}",
            "missing tunnel policy field 'script'",
        ),
        (
            "{script: true, value: true, assets: true, other: true}",
            "unknown tunnel policy field 'other'",
        ),
        (
            "{script: true, value: true, assets: true, value: false}",
            "duplicate tunnel policy field 'value'",
        ),
        (
            "{script: false, value: false, assets: false}",
            "tunnel policy must preserve at least one property",
        ),
        (
            "{script: 1, value: true, assets: true}",
            "tunnel policy fields must be compile-time bool constants",
        ),
        (
            "{script: runtime, value: true, assets: true}",
            "tunnel policy fields must be compile-time bool constants",
        ),
        (
            "{script: true, value: true, assets: false}, [assetId]",
            "tunnel exceptions require asset preservation",
        ),
        (
            "{script: true, value: true, assets: true}, [1]",
            "tunnel exceptions must be AssetId values",
        ),
        (
            "{script: true, value: true, assets: true}, [unknown]",
            "unknown",
        ),
    ] {
        for call in [
            format!("this.renew({literals})"),
            format!("this.renew(window, {literals})"),
            format!("this.tunnel(0, {literals})"),
        ] {
            let error = error(&call);
            assert!(error.contains(message), "{call}: {error}");
        }
    }
}

#[test]
fn renew_is_only_the_whole_condition_of_a_require() {
    for body in [
        "let renewed = this.renew(); require(renewed);",
        "bool renewed = this.renew(window); require(renewed);",
        "bool renewed; renewed = this.renew(); require(renewed);",
        "if (this.renew()) { require(window > 0); }",
        "for (this.renew()) { require(window > 0); }",
        "require(this.renew() && window > 0);",
        "require(window > 0 || this.renew());",
        "require(!this.renew());",
        "require(this.renew() == true);",
        "require((this.renew()));",
        "require(this.renew().value);",
        "require(this.renew()[0]);",
        "require(this.renew(this.renew()));",
        "require(checked(this.renew()));",
        "require(this.tunnel(0, { script: this.renew(), value: true, assets: true }));",
        "require(this.renew([]) == true);",
    ] {
        let source = format!(
            "contract Bad(int window) {{ private function checked(bool ok) bool {{ return ok; }} function spend() {{\n{body} }} }}"
        );
        let error = compile(&source).expect_err(body).to_string();
        assert!(
            error.contains("line 2, column ")
                && error.contains("`this.renew(...)` must be the whole condition of a require"),
            "{body}: {error}"
        );
    }
    for (source, message) in [
        (
            "contract Bad() { private function renewed() bool { return this.renew(); } function spend() { require(renewed()); } }",
            "`this.renew(...)` must be the whole condition of a require",
        ),
        (
            "contract Bad() { const bool RENEWED = this.renew(); function spend() { require(RENEWED); } }",
            "`this.renew(...)` must be the whole condition of a require",
        ),
        (
            "contract Bad() { function spend() { this.renew(); } }",
            "`this.renew(...)` cannot be a statement; use it inside require()",
        ),
        (
            "contract Bad() { function spend() { require(this.renew); } }",
            "'this.renew' is not a value on its own",
        ),
    ] {
        let error = compile(source).expect_err(source).to_string();
        assert!(error.contains(message), "{source}: {error}");
    }
}

#[test]
fn proof_output_is_the_output_paired_with_the_current_input() {
    let script = |output: &str| {
        let source = format!(
            r#"contract C(AssetId id, bytes32 program, int maxFee) {{
                function spend() {{
                    require({output}.value + maxFee >= tx.input.current.value);
                    require({output}.witnessVersion == 1);
                    require({output}.assets.lookup(id) > 0);
                    require({output}.assets.has(id));
                    require({output}.assets.tryLookup(id).found);
                    require({output}.assets.length == 1);
                    require({output}.assets[0].amount > 0);
                    require({output}.assets[0].assetId == id);
                    let script = {output}.script;
                    require(script.program == program);
                    require(script.version == 1);
                }}
            }}"#
        );
        [compile(&source), compile_unoptimized(&source)]
            .map(|compiled| arkade_asm_tokens(&compiled.unwrap(), "spend"))
    };
    let written = script("tx.outputs[this.activeInputIndex - 1]");
    assert_eq!(script("tx.proof.output"), written);
    assert_eq!(script("tx . proof /* paired */ . output"), written);
    let value = [
        "OP_PUSHCURRENTINPUTINDEX",
        "1",
        "OP_SUB",
        "OP_INSPECTOUTPUTVALUE",
    ];
    assert!(
        written[0].windows(4).any(|tokens| tokens == value),
        "{written:?}"
    );

    for (expression, message) in [
        (
            "tx.proof.output == tx.proof.output",
            "'tx.proof.output' is not a value on its own",
        ),
        (
            "tx.proof.output.missing > 0",
            "unknown member 'missing' of 'tx.proof.output'; expected one of",
        ),
        (
            "tx.proof.output.sequence > 0",
            "unknown member 'sequence' of 'tx.proof.output'",
        ),
        ("tx.proof.output.value(0) > 0", "tx.proof.output.value(0)"),
        ("tx.proof.output[0].value > 0", "tx.proof.output[0]"),
        (
            "tx.proof.outputs[0].value > 0",
            "unknown member 'outputs' of 'tx.proof'",
        ),
        (
            "tx.intent.output.value > 0",
            "unknown member 'intent' of 'tx'",
        ),
        (
            "tx.intent.output.assets.length > 0",
            "unknown member 'intent' of 'tx'",
        ),
    ] {
        let source = format!("contract Bad() {{ function spend() {{ require({expression}); }} }}");
        let error = compile(&source).expect_err(expression).to_string();
        assert!(error.contains(message), "{expression}: {error}");
    }
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
                @allow(offchain-locktime, "tests nLockTime inspection")
                require(tx.locktime >= deadline);
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
    let tapscript = |body: &str| {
        compile(&format!(
            "contract Bad(bytes a) {{ function spend() tapscript {{ {body} }} }}"
        ))
        .expect_err(body)
        .to_string()
    };
    assert!(tapscript("require(checkTime(0));")
        .contains("`checkTime(...)` is only available in Arkade Script functions"));
    assert!(tapscript("require(cat(a, a) == a);")
        .contains("`cat(...)` is only available in Arkade Script functions"));
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
