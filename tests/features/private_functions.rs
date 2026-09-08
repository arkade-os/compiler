use crate::common::*;
use arkade_compiler::compile;

#[test]
fn nested_private_calls_preserve_constructor_scope_and_public_abi() {
    let output = compile(r#"
struct Policy { int minimum; int[2] limits; }
contract Vault(Policy policy, pubkey owner) {
    public function spend(signature sig, int amount) {
        authorize(sig);
        require(sufficient(amount + 1));
    }
    private function sufficient(int amount) bool {
        return amount >= minimum();
    }
    private function minimum() int {
        if (policy.minimum > policy.limits[0]) { return policy.minimum; }
        return policy.limits[0];
    }
    private function authorize(signature sig) {
        require(checkSig(sig, owner));
    }
    public function exit(signature sig) tapscript { require(older(10)); require(checkSig(sig, owner)); }
}
"#).expect("nested calls");
    assert!(output.warnings.is_empty(), "{:?}", output.warnings);
    assert_eq!(
        output
            .functions
            .iter()
            .map(|g| g.name.as_str())
            .collect::<Vec<_>>(),
        ["spend", "exit"]
    );
    assert_eq!(arkade_inputs(&output, "spend"), ["sig", "amount"]);
    assert_eq!(
        witness_names(&output, "spend", "spend"),
        ["serverSig", "emulatorSig"]
    );
    let asm = arkade_asm_tokens(&output, "spend");
    assert_eq!(
        &asm[..4],
        [
            "<owner>",
            "<policy.limits.1>",
            "<policy.limits.0>",
            "<policy.minimum>"
        ]
    );
    assert!(asm.iter().any(|s| s == "OP_CHECKSIG"));
    assert!(asm.iter().any(|s| s == "OP_PUT"));
    assert!(asm.iter().all(|s| !s.contains('$') && s != "OP_RETURN"));
    assert_eq!(
        leaf_asm(&output, "spend", "spend"),
        "<SERVER_KEY> OP_CHECKSIGVERIFY <EMULATOR_KEY:spend> OP_CHECKSIG"
    );
}

#[test]
fn constructor_pruning_follows_only_reachable_private_calls() {
    let output = compile(
        r#"
contract C(int retained, int unused) {
    function spend() { require(outer() > 0); }
    function independent() { require(true); }
    private function outer() int { return inner(); }
    private function inner() int { return retained; }
    private function uncalled() int { return unused; }
}
"#,
    )
    .expect("constructor references in nested helpers");
    assert_eq!(output.parameters.len(), 2);
    let spend = arkade_asm_tokens(&output, "spend");
    assert_eq!(spend[0], "<retained>");
    assert!(!spend.iter().any(|token| token == "<unused>"));
    let independent = arkade_asm_tokens(&output, "independent");
    assert!(!independent.iter().any(|token| token.starts_with('<')));
}

#[test]
fn composite_arguments_and_results_and_native_result_structs() {
    let output = compile(
        r#"
struct Pair { int left; int[2] right; }
struct Wrapped { Pair pair; ECPoint point; }
contract Composite(Pair initial) {
    private function copy(Pair value) Pair { return value; }
    private function make(int x) Pair { return { left: x, right: [x + 1, x + 2] }; }
    private function values(int[2] items) int[2] { items[0] = items[0] + 1; return items; }
    private function point(int n) ECPoint { return ecMul(1, 2, n, 0); }
    private function xCoordinate(ECPoint point) int { return point.x; }
    function spend(int amount) {
        Pair nested = { left: amount, right: values([amount, amount + 1]) };
        Wrapped wrapped = { pair: make(amount), point: point(amount) };
        require(nested.right[0] == amount + 1);
        require(wrapped.pair.left == amount);
        Pair pair = copy(make(amount));
        let other = copy(initial);
        int[2] result = values(pair.right);
        let point = point(amount);
        require(xCoordinate(point) >= 0);
        require(result[0] == pair.right[0] + 1);
        require(other.left == initial.left);
    }
}
"#,
    )
    .expect("composite calls");
    assert!(output.warnings.is_empty(), "{:?}", output.warnings);
    assert_eq!(output.functions.len(), 1);
    assert!(arkade_asm_tokens(&output, "spend")
        .iter()
        .any(|s| s == "OP_ROLL"));
    assert!(arkade_asm_tokens(&output, "spend")
        .iter()
        .any(|s| s == "OP_ECMUL"));
}

#[test]
fn helper_requirements_count_on_all_paths_including_expression_calls() {
    for body in [
        "checked();",
        "let value = checkedValue();",
        "require(predicate());",
    ] {
        compile(&format!(
            r#"
contract Guards() {{
    function spend() {{ {body} }}
    private function checked() {{ require(true); }}
    private function checkedValue() int {{ checked(); return 1; }}
    private function predicate() bool {{ return true; }}
}}
"#
        ))
        .unwrap_or_else(|error| panic!("{body}: {error}"));
    }
    for helper in [
        "private function checked(bool skip) { if (skip) { return; } require(true); }",
        "private function checked(bool skip) { if (skip) { require(true); return; } }",
        "private function checked(bool skip) { return; require(true); }",
    ] {
        let source =
            format!("contract C() {{ function spend(bool skip) {{ checked(skip); }} {helper} }}");
        let error = compile(&source).expect_err("unguarded return").to_string();
        assert!(error.contains("spend path with no require"), "{error}");
    }
}

#[test]
fn invalid_function_signatures_calls_and_returns_are_rejected() {
    let cases = [
        ("function spend() bool { return true; }", "public function"),
        ("function spend() { require(true); return; }", "only allowed in private"),
        ("function spend() { missing(); require(true); }", "unknown private function"),
        ("function spend() { require(true); spend(); }", "entrypoint and cannot be called"),
        ("function spend() { helper(); } private function helper() bool { return true; }", "must be used"),
        ("function spend() { require(helper()); } private function helper() { require(true); }", "does not return a value"),
        ("function spend() { helper(); require(true); } private function helper(int x) {}", "expects 1 arguments"),
        ("function spend() { helper(true); require(true); } private function helper(int x) {}", "expected 'int', got 'bool'"),
        ("function spend() { require(true); } private function helper() bool { return 1; }", "expected 'bool', got 'int'"),
        ("function spend() { require(true); } private function helper() int { return; }", "must return a value"),
        ("function spend() { require(true); } private function helper() { return 1; }", "cannot return a value"),
        ("function spend() { require(true); } private function helper(bool x) int { if (x) { return 1; } }", "every path"),
        ("function spend() { require(true); } private function helper() Missing { return 1; }", "unknown type"),
        ("function spend() { require(true); } private function helper() int { return helper(); }", "recursive private"),
        ("function spend() { require(true); } private function a() { b(); } private function b() { a(); }", "recursive private"),
        ("function spend(int x) { require(helper()); } private function helper() bool { return x > 0; }", "undefined"),
        ("function spend() { require(true); } private function helper() { let x = 1; let x = 2; }", "shadows"),
        ("function spend() { require(true); } private function helper() int[2] { return [1]; }", "expected 2 array elements"),
        ("function spend() { require(true); } private function helper() int[2] { return [1, true]; }", "expected 'int', got 'bool'"),
        ("function spend() { require(true); } private function bad(signature sig, pubkey pk, bytes32 msg) bool { return checkSigFromStackVerify(sig, pk, msg); }", "does not produce one stack item"),
        ("function spend() { require(true); } private function helper(bool value) {} private function bad(signature sig, pubkey pk, bytes32 msg) { helper(checkSigFromStackVerify(sig, pk, msg)); }", "does not produce one stack item"),
        ("function spend() { require(true); } private function bad(signature sig, pubkey pk, bytes32 msg) bool[1] { return [checkSigFromStackVerify(sig, pk, msg)]; }", "does not produce one stack item"),
        ("function spend() { require(true); } private function checkSig() {}", "reserved"),
        ("function spend() { require(true); } function helper() internal {}", "unknown type 'internal'"),
        ("privatefunction spend() { require(true); }", "Parse error"),
        ("function spend() { require(true); } private function helper() tapscript {}", "cannot be private"),
    ];
    for (body, expected) in cases {
        let error = compile(&format!("contract C() {{ {body} }}"))
            .expect_err(body)
            .to_string();
        assert!(
            error.contains(expected),
            "{body}: expected {expected}, got {error}"
        );
    }
}

#[test]
fn tapscript_cannot_call_bind_or_tweak_private_helpers() {
    for body in [
        "function exit(signature sig) tapscript { helper(); require(checkSig(sig, owner)); }",
        "function exit(signature sig) tapscript { require(helper()); require(checkSig(sig, owner)); }",
        "function helper(signature sig) tapscript { require(checkSig(sig, owner)); }",
        "function exit(signature sig) tapscript { require(checkSig(sig, tweak(emulator, helper))); }",
    ] {
        let source = format!("contract C(pubkey owner) {{ function spend() {{ require(true); }} private function helper() bool {{ return true; }} {body} }}");
        assert!(compile(&source).is_err(), "{body}");
    }
}

#[test]
fn calls_and_returns_preserve_nested_expression_type_warnings() {
    let output = compile(
        r#"
struct Flag { bool value; }
contract C() {
    function spend() { check(1 == true); }
    private function check(bool value) { require(value); }
    private function array() bool[1] { return [1 == true]; }
    private function flag() Flag { return { value: 1 == true }; }
}
"#,
    )
    .expect("type mismatches produce warnings");
    for function in ["spend", "array", "flag"] {
        assert!(output
            .warnings
            .iter()
            .any(|warning| warning.contains(&format!(
                "fn {function}: comparison '==' is not defined between 'int' and 'bool'"
            ))));
    }
}

#[test]
fn early_returns_in_nested_loops_and_void_helpers_compile() {
    let output = compile(
        r#"
contract Early(int minimum) {
    private function first(int[2] values) int {
        for (i, value) in values {
            for (j, candidate) in values {
                if (candidate >= minimum) { return candidate + i + j; }
            }
        }
        return minimum;
    }
    private function checked(bool skip) {
        require(true);
        if (skip) { return; }
        require(false);
    }
    function spend(int[2] values, bool skip) {
        let returnValue = first(values);
        checked(skip);
        require(returnValue >= minimum);
    }
}
"#,
    )
    .expect("early returns");
    assert!(output.warnings.is_empty(), "{:?}", output.warnings);
}
