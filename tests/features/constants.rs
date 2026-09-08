use crate::common::*;
use arkade_compiler::compile;

fn error(source: &str) -> String {
    compile(source)
        .expect_err("expected compile error")
        .to_string()
}

#[test]
fn constants_fold_into_covenant_and_tapleaf() {
    let output = compile(
        r#"
contract Vault(pubkey owner) {
    const int EXIT_DELAY = 144;
    const bool STRICT = true;
    function spend(signature sig, int amount) {
        require(checkSig(sig, owner));
        require(amount > EXIT_DELAY);
        require(STRICT);
    }
    function exit(signature sig) tapscript {
        require(older(EXIT_DELAY));
        require(checkSig(sig, owner));
    }
}
"#,
    )
    .expect("constants");
    assert!(output.warnings.is_empty(), "{:?}", output.warnings);
    assert!(arkade_asm_tokens(&output, "spend").contains(&"144".to_string()));
    assert_eq!(
        leaf_asm_tokens(&output, "exit", "exit")[0],
        "144".to_string()
    );
    assert!(!arkade_asm(&output, "spend").contains("EXIT_DELAY"));
    assert_eq!(
        output
            .parameters
            .iter()
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>(),
        ["owner"]
    );
}

#[test]
fn covenant_time_comparisons_use_inspection() {
    for bound in ["500000", "DEADLINE", "deadline", "deadline + 1"] {
        let source = format!(
            "contract Vault(int deadline) {{ const int DEADLINE = 500000; function spend() {{ require(tx.time >= {bound}); }} }}"
        );
        let output = compile(&source).expect("time comparison");
        let asm = arkade_asm_tokens(&output, "spend");
        assert!(asm.contains(&"OP_INSPECTLOCKTIME".to_string()), "{asm:?}");
        assert!(
            asm.contains(&"OP_GREATERTHANOREQUAL".to_string()),
            "{asm:?}"
        );
        assert!(
            !asm.contains(&"OP_CHECKLOCKTIMEVERIFY".to_string()),
            "{asm:?}"
        );
        let general = compile(&source.replace("require(tx.time", "require((tx.time)")).unwrap();
        assert_eq!(asm, arkade_asm_tokens(&general, "spend"));
        if bound == "DEADLINE" {
            let literal = compile(&source.replace(">= DEADLINE", ">= 500000")).unwrap();
            assert_eq!(asm, arkade_asm_tokens(&literal, "spend"));
        }
        assert_eq!(arkade_inputs(&output, "spend"), Vec::<String>::new());
        assert_eq!(output.functions.len(), 1);
    }
}

#[test]
fn tapleaf_time_comparisons_keep_cltv() {
    for bound in ["500000", "DEADLINE", "deadline"] {
        let output = compile(&format!(
            "contract Vault(int deadline) {{ const int DEADLINE = 500000; function exit(signature sig) tapscript {{ require(tx.time >= {bound}); require(checkSig(sig, server)); }} }}"
        )).unwrap();
        let operand = if bound == "deadline" {
            "<deadline>"
        } else {
            "500000"
        };
        assert_eq!(
            leaf_asm(&output, "exit", "exit"),
            format!("{operand} OP_CHECKLOCKTIMEVERIFY OP_DROP <SERVER_KEY> OP_CHECKSIG")
        );
        assert!(group(&output, "exit").arkade.is_none());
        assert_eq!(witness_names(&output, "exit", "exit"), ["sig"]);
    }
}

#[test]
fn constant_indices_fold_in_named_operands() {
    for body in [
        "require(checkSig(sigs[FIRST], keys[FIRST]));",
        "require(checkSig(sigs[FIRST], keys[FIRST]) == true);",
        "require(checkSigFromStack(sigs[FIRST], keys[FIRST], messages[FIRST]));",
        "require(checkSigFromStack(sigs[FIRST], keys[FIRST], messages[FIRST]) == true);",
        "require(checkSigFromStackVerify(sigs[FIRST], keys[FIRST], messages[FIRST]));",
        "require(checkMultisig([keys[FIRST]], [sigs[FIRST]], 1));",
        "require(sha256(message) == messages[FIRST]);",
        "require(size(messages[FIRST]) == 32);",
        "if (checkSig(sigs[FIRST], keys[FIRST])) { require(true); } else { require(false); }",
    ] {
        let source = format!("contract Vault(pubkey[2] keys, bytes32[2] messages) {{ const int FIRST = 0; function spend(signature[2] sigs, bytes32 message) {{ {body} }} }}");
        let output = compile(&source).unwrap_or_else(|e| panic!("{body}: {e}"));
        let literal = compile(&source.replace("[FIRST]", "[0]")).unwrap();
        assert_eq!(
            arkade_asm_tokens(&output, "spend"),
            arkade_asm_tokens(&literal, "spend"),
            "{body}"
        );
        assert_eq!(
            arkade_inputs(&output, "spend"),
            arkade_inputs(&literal, "spend")
        );
    }
    let source = "contract Vault(pubkey[2] keys, bytes32[2] hashes) { const int FIRST = 0; function exit(signature sig, bytes preimage) tapscript { require(sha256(preimage) == hashes[FIRST]); require(older(10)); require(checkSig(sig, keys[FIRST])); } }";
    let output = compile(source).unwrap();
    let literal = compile(&source.replace("[FIRST]", "[0]")).unwrap();
    assert_eq!(
        leaf_asm(&output, "exit", "exit"),
        leaf_asm(&literal, "exit", "exit")
    );
    assert_eq!(witness_names(&output, "exit", "exit"), ["sig", "preimage"]);

    for value in ["2", "true"] {
        let ty = if value == "true" { "bool" } else { "int" };
        let source = format!("contract Vault(pubkey[2] keys) {{ const {ty} FIRST = {value}; function spend(signature sig) {{ require(checkSig(sig, keys[FIRST])); }} }}");
        assert!(compile(&source).is_err(), "{value} is not a valid index");
    }
}

#[test]
fn multisig_threshold_constants_resolve_before_and_after_functions() {
    for declaration_first in [true, false] {
        for modifier in ["", " tapscript"] {
            let declaration = "const int QUORUM = 2;";
            let timelock = if modifier.is_empty() {
                ""
            } else {
                "require(older(10));"
            };
            let function = format!("function spend(signature firstSig, signature secondSig){modifier} {{ {timelock} require(checkMultisig([owner, backup], [firstSig, secondSig], QUORUM)); }}");
            let members = if declaration_first {
                format!("{declaration} {function}")
            } else {
                format!("{function} {declaration}")
            };
            let source = format!("contract Vault(pubkey owner, pubkey backup) {{ {members} }}");
            let output = compile(&source).unwrap();
            let literal = compile(&source.replace(", QUORUM)", ", 2)")).unwrap();
            assert_eq!(output.functions.len(), 1);
            assert_eq!(
                leaf_asm(&output, "spend", "spend"),
                leaf_asm(&literal, "spend", "spend")
            );
            assert_eq!(
                witness_names(&output, "spend", "spend"),
                witness_names(&literal, "spend", "spend")
            );
            if modifier.is_empty() {
                assert_eq!(
                    arkade_asm_tokens(&output, "spend"),
                    arkade_asm_tokens(&literal, "spend")
                );
                assert_eq!(arkade_inputs(&output, "spend"), ["firstSig", "secondSig"]);
            } else {
                assert!(group(&output, "spend").arkade.is_none());
            }
        }
    }
}

#[test]
fn multisig_threshold_rejects_non_constants_and_invalid_values() {
    for declaration in [
        "",
        "const bool QUORUM = true;",
        "const int QUORUM = 65536;",
        "const int QUORUM = 0;",
        "const int QUORUM = 3;",
    ] {
        for modifier in ["", " tapscript"] {
            let timelock = if modifier.is_empty() {
                ""
            } else {
                "require(older(10));"
            };
            let source = format!("contract Vault(pubkey owner, int QUORUM_INPUT) {{ {declaration} function spend(signature sig){modifier} {{ {timelock} require(checkMultisig([owner], [sig], QUORUM)); }} }}");
            compile(&source.replace(", QUORUM)", ", 1)")).expect("literal threshold");
            assert!(compile(&source).is_err(), "{declaration} {modifier}");
            assert!(compile(&source.replace(", QUORUM)", ", QUORUM_INPUT)")).is_err());
        }
    }
}

#[test]
fn reserved_names_cannot_be_constants() {
    for name in ["true", "false", "server", "emulator", "SERVER_KEY"] {
        let source = format!(
            "contract Vault() {{ const int {name} = 10; function spend() {{ require(true); }} }}"
        );
        assert!(error(&source).contains(&format!("constant name '{name}' is reserved")));
    }
}

#[test]
fn constant_is_readable_from_a_static_function() {
    let output = compile(
        r#"
contract Vault(pubkey owner) {
    const int BPS = 10000;
    static function pct(int amount, int bps) int { return amount * bps / BPS; }
    function spend(signature sig, int amount) {
        require(checkSig(sig, owner));
        require(pct(amount, 50) > 0);
    }
}
"#,
    )
    .expect("constant in static function");
    assert!(arkade_asm_tokens(&output, "spend").contains(&"10000".to_string()));
}

#[test]
fn constant_is_usable_as_a_loop_bound_and_array_index() {
    let output = compile(
        r#"
contract Vault(pubkey owner, int[3] limits) {
    const int FIRST = 0;
    function spend(signature sig) {
        require(checkSig(sig, owner));
        require(limits[FIRST] > 0);
    }
}
"#,
    )
    .expect("constant index");
    assert!(!arkade_asm(&output, "spend").contains("FIRST"));
}

#[test]
fn constant_must_be_int_or_bool() {
    assert!(error(
        r#"
contract Vault(pubkey owner) {
    const pubkey KEY = 1;
    function spend(int amount) { require(amount > 0); }
}
"#
    )
    .contains("constant 'KEY' must be int or bool"));
}

#[test]
fn constant_literal_must_match_its_declared_type() {
    assert!(error(
        r#"
contract Vault(pubkey owner) {
    const bool FLAG = 3;
    function spend(int amount) { require(amount > 0); }
}
"#
    )
    .contains("constant 'FLAG' is not a valid 'bool' literal"));
}

#[test]
fn constant_initializer_must_be_a_literal() {
    for initializer in ["fee", "1 + 1", "-1"] {
        let source = format!(
            r#"
contract Vault(pubkey owner, int fee) {{
    const int A = {initializer};
    function spend(int amount) {{ require(amount > A); }}
}}
"#
        );
        assert!(
            error(&source).contains("constant 'A' must be initialized with a literal"),
            "{initializer} should be rejected"
        );
    }
}

#[test]
fn constant_names_must_be_unique_and_not_collide() {
    assert!(error(
        r#"
contract Vault(pubkey owner) {
    const int A = 1;
    const int A = 2;
    function spend(int amount) { require(amount > A); }
}
"#
    )
    .contains("duplicate constant 'A'"));
    assert!(error(
        r#"
contract Vault(pubkey owner, int fee) {
    const int fee = 1;
    function spend(int amount) { require(amount > fee); }
}
"#
    )
    .contains("constant 'fee' collides with constructor parameter 'fee'"));
    assert!(error(
        r#"
contract Vault(pubkey owner) {
    const int spend = 1;
    function spend(int amount) { require(amount > 0); }
}
"#
    )
    .contains("constant 'spend' collides with function 'spend'"));
}

#[test]
fn bindings_may_not_shadow_a_constant() {
    assert!(error(
        r#"
contract Vault(pubkey owner) {
    const int A = 1;
    function spend(int A) { require(A > 0); }
}
"#
    )
    .contains("parameter 'A' in function 'spend' shadows constant 'A'"));
    assert!(error(
        r#"
contract Vault(pubkey owner) {
    const int A = 1;
    function spend(int amount) { let A = 2; require(amount > A); }
}
"#
    )
    .contains("binding 'A' in function 'spend' shadows an in-scope binding"));
    assert!(error(
        r#"
contract Vault(pubkey owner) {
    const int A = 1;
    function spend(signature sig) {
        require(checkSig(sig, owner));
    }
    function exit(signature A) tapscript {
        require(older(10));
        require(checkSig(A, owner));
    }
}
"#
    )
    .contains("input 'A' in tapscript 'exit' shadows constant 'A'"));
}

#[test]
fn constants_cannot_be_assigned() {
    assert!(error(
        r#"
contract Vault(pubkey owner) {
    const int A = 1;
    function spend(int amount) { A = 2; require(amount > 0); }
}
"#
    )
    .contains("cannot assign to constant 'A' in function 'spend'"));
}

#[test]
fn const_identifier_prefix_is_still_a_name() {
    let output = compile(
        r#"
contract Vault(pubkey owner) {
    function spend(signature sig, int constant) {
        require(checkSig(sig, owner));
        require(constant > 0);
    }
}
"#,
    )
    .expect("constant identifier");
    assert_eq!(arkade_inputs(&output, "spend"), ["sig", "constant"]);
}
