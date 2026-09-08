use crate::common::*;
use arkade_compiler::compile;

fn error(source: &str) -> String {
    compile(source)
        .expect_err("expected compile error")
        .to_string()
}

#[test]
fn static_function_compiles_like_the_private_equivalent() {
    let body = |visibility: &str| {
        format!(
            r#"
contract Vault(pubkey owner) {{
    {visibility} function pct(int amount, int bps) int {{
        return amount * bps / 10000;
    }}
    function spend(signature sig, int amount) {{
        require(checkSig(sig, owner));
        require(pct(amount, 50) > 0);
    }}
}}
"#
        )
    };
    let with_static = compile(&body("static")).expect("static");
    let with_private = compile(&body("private")).expect("private");
    assert!(
        with_static.warnings.is_empty(),
        "{:?}",
        with_static.warnings
    );
    assert_eq!(
        arkade_asm_tokens(&with_static, "spend"),
        arkade_asm_tokens(&with_private, "spend")
    );
    assert_eq!(
        with_static
            .functions
            .iter()
            .map(|g| g.name.as_str())
            .collect::<Vec<_>>(),
        ["spend"]
    );
    assert_eq!(arkade_inputs(&with_static, "spend"), ["sig", "amount"]);
}

#[test]
fn static_function_may_call_another_static_function() {
    let output = compile(
        r#"
contract Vault(pubkey owner) {
    static function double(int amount) int { return amount * 2; }
    static function quadruple(int amount) int { return double(double(amount)); }
    function spend(signature sig, int amount) {
        require(checkSig(sig, owner));
        require(quadruple(amount) > 0);
    }
}
"#,
    )
    .expect("static chain");
    assert!(arkade_asm(&output, "spend").contains("OP_MUL"));
}

#[test]
fn static_function_rejects_constructor_parameter() {
    assert!(error(
        r#"
contract Vault(pubkey owner, int fee) {
    static function net(int amount) int { return amount - fee; }
    function spend(int amount) { require(net(amount) > 0); }
}
"#
    )
    .contains("static function 'net' cannot reference constructor parameter 'fee'"));
}

#[test]
fn static_function_rejects_constructor_struct_field_and_array_element() {
    let field = error(
        r#"
struct Policy { int minimum; }
contract Vault(Policy policy) {
    static function floor(int amount) int { return amount + policy.minimum; }
    function spend(int amount) { require(floor(amount) > 0); }
}
"#,
    );
    assert!(
        field.contains("static function 'floor' cannot reference constructor parameter 'policy'"),
        "{field}"
    );
    let element = error(
        r#"
contract Vault(int[2] limits) {
    static function floor(int amount) int { return amount + limits[0]; }
    function spend(int amount) { require(floor(amount) > 0); }
}
"#,
    );
    assert!(
        element.contains("static function 'floor' cannot reference constructor parameter 'limits'"),
        "{element}"
    );
}

#[test]
fn static_function_rejects_constructor_key_in_a_signature_check() {
    assert!(error(
        r#"
contract Vault(pubkey owner) {
    static function authorize(signature sig) { require(checkSig(sig, owner)); }
    function spend(signature sig) { authorize(sig); }
}
"#
    )
    .contains("static function 'authorize' cannot reference constructor parameter 'owner'"));
}

#[test]
fn static_function_rejects_calling_a_non_static_function() {
    assert!(error(
        r#"
contract Vault(pubkey owner, int fee) {
    private function net(int amount) int { return amount - fee; }
    static function twice(int amount) int { return net(amount) * 2; }
    function spend(int amount) { require(twice(amount) > 0); }
}
"#
    )
    .contains("static function 'twice' cannot call non-static function 'net'"));
}

#[test]
fn static_visibility_cannot_be_combined_with_private_or_public() {
    for visibility in ["public static", "private static", "static private"] {
        let source = format!(
            r#"
contract Vault(pubkey owner) {{
    {visibility} function f(int amount) int {{ return amount; }}
    function spend(int amount) {{ require(f(amount) > 0); }}
}}
"#
        );
        assert!(
            error(&source).contains("Parse error"),
            "{visibility} should not parse"
        );
    }
}

#[test]
fn static_function_must_return_on_every_path() {
    assert!(error(
        r#"
contract Vault(pubkey owner) {
    static function pick(int amount) int {
        if (amount > 0) { return amount; }
    }
    function spend(int amount) { require(pick(amount) > 0); }
}
"#
    )
    .contains("must return a value on every path"));
}

#[test]
fn static_identifier_prefix_is_still_a_name() {
    let output = compile(
        r#"
contract Vault(pubkey owner) {
    function spend(signature sig, int staticFee) {
        require(checkSig(sig, owner));
        require(staticFee > 0);
    }
}
"#,
    )
    .expect("staticFee");
    assert_eq!(arkade_inputs(&output, "spend"), ["sig", "staticFee"]);
}

#[test]
fn tapscript_declarations_cannot_be_static() {
    assert!(error(
        r#"
contract Vault(pubkey owner) {
    function spend(signature sig) { require(checkSig(sig, owner)); }
    static function exit(signature sig) tapscript {
        require(older(10));
        require(checkSig(sig, owner));
    }
}
"#
    )
    .contains("tapscript functions cannot be static"));
}
