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
fn constant_folds_into_a_covenant_absolute_timelock() {
    let output = compile(
        r#"
contract Vault(pubkey owner) {
    const int DEADLINE = 500000;
    function spend(signature sig) {
        require(tx.time >= DEADLINE);
        require(checkSig(sig, owner));
    }
}
"#,
    )
    .expect("timelock constant");
    let asm = arkade_asm_tokens(&output, "spend");
    assert!(asm.contains(&"500000".to_string()), "{asm:?}");
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
