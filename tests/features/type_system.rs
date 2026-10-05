//! CashScript-style type-system error detection tests.
//!
//! CashScript pioneered compile-time type checking for smart contract languages
//! that compile to Bitcoin Script.  These tests verify that the Arkade type
//! checker surfaces the same class of errors:
//!
//! - **Swapped arguments** — `checkSig(pubkey, sig)` instead of `checkSig(sig, pubkey)`.
//! - **Undeclared variable** — assigning to a name never declared.
//! - **Numeric types** — comparing BigNum introspection values with plain `int` values.
//! - **Wrong hash type** — passing an `int` where `bytes32` is expected.
//! - **Non-boolean if condition** — using an integer expression as a branch condition.
//!
//! Type errors are fatal; `ContractJson.warnings` carries only non-type issues.

use arkade_compiler::compile;

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn compile_ok(source: &str) -> arkade_compiler::models::ContractJson {
    compile(source).unwrap_or_else(|e| panic!("unexpected compile error: {}", e))
}

fn compile_error(source: &str) -> String {
    compile(source)
        .expect_err("contract must fail validation")
        .to_string()
}

// ─── Swapped sig / pubkey ─────────────────────────────────────────────────────

#[test]
fn swapped_checksig_args_are_rejected() {
    // The contract declares `pubkey sig, signature owner` — the *names* clearly
    // describe the types but are passed in the wrong order to checkSig.
    let source = r#"
contract Swapped(pubkey owner) {
    function spend(pubkey sig, signature ownerSig) {
        require(checkSig(sig, ownerSig));
    }
}"#;
    // sig is pubkey, ownerSig is signature → arguments are swapped
    let error = compile_error(source);
    assert!(
        error.contains("expected 'signature'"),
        "swapped checkSig arguments must be rejected: {error}"
    );
}

#[test]
fn correct_checksig_order_produces_no_type_warning() {
    let source = r#"
contract Correct(pubkey owner) {
    function spend(signature ownerSig) {
        require(checkSig(ownerSig, owner));
    }
}"#;
    compile_ok(source);
}

// ─── Undeclared variable assignment ──────────────────────────────────────────

#[test]
fn assignment_to_undeclared_variable_is_rejected() {
    let source = r#"
contract UndeclaredAssign(pubkey owner) {
    function spend(signature ownerSig) {
        undeclaredVar = 42;
        require(checkSig(ownerSig, owner));
    }
}"#;
    let error = compile_error(source);
    assert!(
        error.contains("assignment to undeclared variable 'undeclaredVar'"),
        "assignment to an undeclared variable must be rejected: {error}"
    );
}

#[test]
fn assignment_to_declared_let_binding_produces_no_warning() {
    let source = r#"
contract DeclaredAssign(pubkey owner) {
    function spend(signature ownerSig) {
        let x = 1;
        x = 2;
        require(x == 2);
        require(checkSig(ownerSig, owner));
    }
}"#;
    compile_ok(source);
}

// ─── Introspection / int comparison ──────────────────────────────────────────

#[test]
fn introspected_value_vs_int_comparison_produces_no_type_warning() {
    let source = r#"
contract MixedTypes(pubkey owner, int minValue) {
    function spend(signature ownerSig) {
        require(tx.inputs[0].value >= minValue);
        require(checkSig(ownerSig, owner));
    }
}"#;
    compile_ok(source);
}

#[test]
fn integer_equality_across_widths_produces_no_type_warning() {
    // Equality between int params/literals and numeric introspection values is
    // well-defined, exactly like ordered comparisons.
    let source = r#"
contract IntEquality(pubkey owner, int expectedValue, int expectedVersion) {
    function spend(signature ownerSig) {
        require(tx.inputs[0].value == expectedValue);
        require(tx.version == expectedVersion);
        require(tx.version == 2);
        require(checkSig(ownerSig, owner));
    }
}"#;
    compile_ok(source);
}

#[test]
fn introspected_value_comparison_produces_no_type_warning() {
    // Introspected values are emitted as BigNums.
    let source = r#"
contract SameTypes(pubkey owner) {
    function spend(signature ownerSig) {
        require(tx.inputs[0].value >= tx.outputs[0].value);
        require(checkSig(ownerSig, owner));
    }
}"#;
    compile_ok(source);
}

// ─── Wrong hash type ─────────────────────────────────────────────────────────

#[test]
fn non_bytes32_hash_param_is_rejected() {
    // sha256(preimage) == hashVal where hashVal is declared as `int`.
    let source = r#"
contract BadHashType(pubkey owner, int hashVal) {
    function claim(bytes32 preimage) {
        require(sha256(preimage) == hashVal);
    }
}"#;
    let error = compile_error(source);
    assert!(
        error.contains("'hashVal' has type 'int', expected bytes32"),
        "wrong hash type must be rejected: {error}"
    );
}

#[test]
fn bytes32_hash_param_produces_no_type_warning() {
    let source = r#"
contract CorrectHashType(pubkey owner, bytes32 hashVal) {
    function claim(bytes32 preimage) {
        require(sha256(preimage) == hashVal);
    }
}"#;
    compile_ok(source);
}

// ─── Non-boolean if condition ─────────────────────────────────────────────────

#[test]
fn non_boolean_if_condition_is_rejected() {
    // `tx.inputs[0].value` is an int, not bool — using it as an if condition.
    let source = r#"
contract NonBoolCond(pubkey owner) {
    function spend(signature ownerSig) {
        if (tx.inputs[0].value) {
            require(checkSig(ownerSig, owner));
        } else {
            require(checkSig(ownerSig, owner));
        }
    }
}"#;
    let error = compile_error(source);
    assert!(
        error.contains("if condition has type 'int', expected bool"),
        "non-boolean if condition must be rejected: {error}"
    );
}

#[test]
fn checksig_expr_if_condition_is_valid() {
    // checkSig(...) as a condition returns bool — no warning expected.
    let source = r#"
contract BoolCond(pubkey owner) {
    function spend(signature ownerSig, signature altSig) {
        if (checkSig(ownerSig, owner)) {
            require(checkSig(ownerSig, owner));
        } else {
            require(checkSig(altSig, owner));
        }
    }
}"#;
    compile_ok(source);
}

// ─── Stack-unsafe type errors are fatal ───────────────────────────────────────

#[test]
fn stack_unsafe_type_errors_are_fatal() {
    let source = r#"
contract MultiTypeError(pubkey owner, int badHash) {
    function spend(pubkey sigSwapped, signature ownerSwapped) {
        require(checkSig(sigSwapped, ownerSwapped));
        require(sha256(sigSwapped) == badHash);
    }
}"#;
    let error = compile_error(source);
    assert!(
        error.contains("expected 'signature'"),
        "signature argument errors must stop compilation: {error}"
    );
}

// ─── checkSigFromStack argument order ────────────────────────────────────────

#[test]
fn swapped_checksigfromstack_args_are_rejected() {
    // checkSigFromStack(pubkey, sig, msg) — first two are swapped
    let source = r#"
contract SwappedCsfs(pubkey owner) {
    function spend(pubkey sigSwapped, signature pkSwapped, bytes32 msg) {
        require(checkSigFromStack(sigSwapped, pkSwapped, msg));
    }
}"#;
    let error = compile_error(source);
    assert!(
        error.contains("expected 'signature'"),
        "swapped checkSigFromStack arguments must be rejected: {error}"
    );
}

// ─── Warnings remain available to callers without entering artifacts ─────────

#[test]
fn warnings_are_not_serialized_in_artifacts() {
    // `minVal` is never read, which warns without failing compilation.
    let source = r#"
contract HasWarnings(pubkey owner, int minVal) {
    function spend(signature ownerSig) {
        require(checkSig(ownerSig, owner));
    }
}"#;
    let output = compile_ok(source);
    assert!(
        output.warnings.iter().any(|w| w.starts_with("warning[")),
        "warnings must be tagged with warning[...] prefix; got: {:?}",
        output.warnings
    );
    let json = serde_json::to_string(&output).expect("serialize to JSON");
    assert!(
        !json.contains("\"warnings\""),
        "warnings must stay out of serialized artifacts"
    );
}

// ─── CashScript-parity strictness ────────────────────────────────────────────

#[test]
fn cashscript_parity_rejections() {
    for (body, expected) in [
        (
            "require(true + 1 == a);",
            "arithmetic '+' operand has type 'bool'",
        ),
        ("require(a / 0 == 1);", "division by zero"),
        (
            "require(a == b);",
            "comparison '==' is not defined between 'int' and 'bytes'",
        ),
        (
            "require(h20 == h32);",
            "comparison '==' is not defined between 'bytes20' and 'bytes32'",
        ),
        (
            "require(flag == 1);",
            "comparison '==' is not defined between 'bool' and 'int'",
        ),
        (
            "int unread = a; require(a == 1);",
            "variable 'unread' in function 'spend' is never used",
        ),
        (
            "int bytes = a; require(bytes == 1);",
            "'bytes' uses a reserved keyword or type name",
        ),
    ] {
        let source = format!("contract Strict(bytes20 h20, bytes32 h32, bool flag) {{ function spend(int a, bytes b) {{ require(h20 == b && h32 == b && flag && a == a && b == b); {body} }} }}");
        let error = compile_error(&source);
        assert!(error.contains(expected), "{body}: {error}");
    }
    let error = compile_error(
        "contract Strict(pubkey owner) { function spend() { require(true); } function spend(signature sig, bytes extra) tapscript { require(checkSig(sig, owner)); } }",
    );
    assert!(
        error.contains("input 'extra' in tapscript 'spend' is never used"),
        "{error}"
    );
    let unused_param = compile_error(
        "contract Strict(pubkey owner) { function spend(signature sig, int amount) { require(checkSig(sig, owner)); } }",
    );
    assert!(
        unused_param.contains("variable 'amount' in function 'spend' is never used"),
        "{unused_param}"
    );
}

#[test]
fn cashscript_parity_acceptances() {
    let output = compile_ok(
        "contract Strict(pubkey owner, bytes key, int unused) { function spend(signature sig) { require(owner == key); require(checkSig(sig, owner)); } }",
    );
    assert_eq!(
        output.warnings,
        ["warning[validation]: constructor parameter 'unused' is never used (main.ark)"]
    );
}

// ─── Casts ───────────────────────────────────────────────────────────────────

#[test]
fn casts_narrow_bytes_and_check_sized_lengths() {
    let output = compile_ok(
        r#"
contract Casts(pubkey owner, int gidx) {
    function spend(signature sig, bytes data) {
        bytes32 id = bytes32(substr(data, 0, 32));
        bytes20 short = bytes20(substr(data, 32, 20));
        pubkey key = pubkey(substr(data, 52, 32));
        require(tx.outputs[0].assets.lookup(id, gidx) > 0);
        require(short != 0x00);
        require(checkSig(sig, key));
        require(bytes32Of(data) == id);
    }
    private function bytes32Of(bytes value) bytes32 { return sha256(value); }
}"#,
    );
    let asm = crate::common::arkade_asm(&output, "spend");
    assert!(asm.contains("OP_SUBSTR OP_SIZE 32 OP_EQUALVERIFY"), "{asm}");
    assert!(asm.contains("OP_SUBSTR OP_SIZE 20 OP_EQUALVERIFY"), "{asm}");
    assert_eq!(
        asm.matches("OP_SIZE").count(),
        2,
        "pubkey casts are unchecked: {asm}"
    );

    for (cast, source_type) in [
        ("bytes32(n)", "int"),
        ("bytes20(h)", "bytes32"),
        ("pubkey(n)", "int"),
    ] {
        let error = compile_error(&format!(
            "contract Casts(pubkey owner, bytes32 h) {{ function spend(int n) {{ let x = {cast}; require(x == x && n == n && h == h && owner == owner); }} }}"
        ));
        assert!(
            error.contains(&format!("cannot cast '{source_type}'")),
            "{cast}: {error}"
        );
    }
}

#[test]
fn int_casts_fold_hex_literals_and_convert_bools() {
    let output = compile_ok(
        r#"
contract HexCasts(pubkey owner) {
    const int MAX = int(0x7fffffffffffffff);
    function spend(signature sig, int n, bool flag) {
        require(n <= MAX && n >= int(0x0100) && n != int(0x00));
        require(n * 2 < int(0xffffffffffffffffff));
        require(int(flag) == 1);
        require(bool(n) == flag);
        require(checkSig(sig, owner));
    }
}"#,
    );
    let asm = crate::common::arkade_asm(&output, "spend");
    for expected in [
        "9223372036854775807 OP_LESSTHANOREQUAL",
        "4722366482869645213695 OP_LESSTHAN",
        "256 OP_GREATERTHANOREQUAL",
        "0 OP_EQUAL OP_NOT",
    ] {
        assert!(asm.contains(expected), "{expected}: {asm}");
    }
    assert_eq!(
        asm.matches("OP_0NOTEQUAL").count(),
        2,
        "int(bool) and bool(int) normalize: {asm}"
    );
    assert!(!asm.contains("0x"), "hex casts fold away: {asm}");

    for (source, message) in [
        ("require(int(data) == n);", "cannot cast 'bytes' to 'int'"),
        ("require(int(\"ab\") == n);", "cannot cast 'bytes' to 'int'"),
        (
            "require(bool(data) == flag);",
            "cannot cast 'bytes' to 'bool'",
        ),
    ] {
        let error = compile_error(&format!(
            "contract E() {{ function spend(bytes data, int n, bool flag) {{ {source} require(data == data && n == n && flag == flag); }} }}"
        ));
        assert!(error.contains(message), "{source}: {error}");
    }
    let error = compile_error(
        "contract F() { function spend(int n) { require(n == n); } private function int(int a) int { return a; } }",
    );
    assert!(error.contains("function name 'int' is reserved"), "{error}");
    let error = compile_error(
        "contract G() { const int TOO_BIG = int(0x8000000000000000); function spend(int n) { require(n < TOO_BIG); } }",
    );
    assert!(
        error.contains("expected a signed 64-bit integer"),
        "{error}"
    );
}

#[test]
fn same_type_casts_are_no_ops() {
    let output = compile_ok(
        r#"
contract SameType(pubkey owner) {
    function spend(signature sig, int n, bool flag, bytes20 h) {
        let x = int(42);
        require(int(n) + x == 43);
        require(bool(flag) && bool(2));
        require(bytes20(h) == h);
        require(checkSig(sig, owner));
    }
}"#,
    );
    let asm = crate::common::arkade_asm(&output, "spend");
    assert_eq!(
        asm.matches("OP_0NOTEQUAL").count(),
        1,
        "only bool(2) converts: {asm}"
    );
    assert!(
        !asm.contains("OP_SIZE"),
        "bytes20(bytes20) is unchecked: {asm}"
    );
}

#[test]
fn pubkeys_and_signatures_widen_to_bytes_in_bindings_and_arguments() {
    compile_ok(
        "contract Widen(pubkey owner) { function spend(signature sig, bytes data) { bytes key = owner; require(same(sig, data) || key == data || owner + sig == data); require(checkSig(sig, owner)); } private function same(bytes a, bytes b) bool { return a == b; } }",
    );
}

// ─── Hash widths, builtin operands, and diagnostics ─────────────────────────

#[test]
fn hash_comparisons_expect_the_digest_width() {
    for (hash_fn, digest, wrong) in [
        ("sha256", "bytes32", "bytes20"),
        ("hash256", "bytes32", "bytes20"),
        ("hash160", "bytes20", "bytes32"),
        ("ripemd160", "bytes20", "bytes32"),
    ] {
        let covenant = |ty: &str| {
            format!("contract H({ty} h, pubkey k) {{ function spend(bytes p, signature s) {{ require({hash_fn}(p) == h); require(checkSig(s, k)); }} }}")
        };
        compile_ok(&covenant(digest));
        compile_ok(&covenant("bytes"));
        let error = compile_error(&covenant(wrong));
        assert!(
            error.contains(&format!(
                "{hash_fn} comparison: 'h' has type '{wrong}', expected {digest}"
            )),
            "{error}"
        );
    }
    let tapscript = |ty: &str| {
        format!("contract H({ty} h, pubkey k) {{ function spend() {{ require(h == h); }} function claim(bytes p, signature s, signature ss) tapscript {{ require(hash160(p) == h); require(checkMultisig([k, server], [s, ss])); }} }}")
    };
    compile_ok(&tapscript("bytes20"));
    let error = compile_error(&tapscript("bytes32"));
    assert!(
        error.contains("hash160 value `h` has type 'bytes32', expected bytes20"),
        "{error}"
    );
}

#[test]
fn tapscript_timelocks_must_be_int() {
    for (ty, ok) in [("int", true), ("bytes", false), ("bytes32", false)] {
        let source = format!("contract T(pubkey owner, {ty} delay) {{ function spend() {{ require(delay == delay); }} function exit(signature sig) tapscript {{ require(older(delay)); require(checkSig(sig, owner)); }} }}");
        match compile(&source) {
            Ok(_) => assert!(ok, "{ty} timelock accepted"),
            Err(error) => assert!(
                !ok && error
                    .to_string()
                    .contains(&format!("timelock `delay` has type '{ty}', expected 'int'")),
                "{ty}: {error}"
            ),
        }
    }
}

#[test]
fn builtin_operands_are_type_checked() {
    for (expression, expected) in [
        (
            "substr(i, 0, 1) == d",
            "substr operand has type 'int', expected 'bytes'",
        ),
        (
            "substr(d, k, 1) == d",
            "substr operand has type 'bytes', expected 'int'",
        ),
        (
            "cat(i, d) == d",
            "cat operand has type 'int', expected 'bytes'",
        ),
        (
            "bin2num(i) == 1",
            "bin2num operand has type 'int', expected 'bytes'",
        ),
        (
            "num2bin(d, 4) == d",
            "num2bin operand has type 'bytes', expected 'int'",
        ),
        (
            "reverseBytes(i) == d",
            "reverseBytes operand has type 'int', expected 'bytes'",
        ),
        (
            "size(i) == 1",
            "size operand has type 'int', expected 'bytes'",
        ),
        (
            "sighash(k) == m",
            "sighash operand has type 'bytes', expected 'int'",
        ),
        (
            "digest(i, 0) == d",
            "digest operand has type 'int', expected 'bytes'",
        ),
        (
            "size(tx.packet(k)) > 0",
            "tx.packet operand has type 'bytes', expected 'int'",
        ),
        (
            "tx.inputs[k].value > 0",
            "tx.inputs[] operand has type 'bytes', expected 'int'",
        ),
        (
            "tx.outputs[d].value > 0",
            "tx.outputs[] operand has type 'bytes', expected 'int'",
        ),
        (
            "checkSigFromStack(s, k, i)",
            "message 'i' has type 'int', expected 'bytes'",
        ),
    ] {
        let source = |condition: &str| {
            format!("contract T(pubkey k) {{ function f(signature s, int i, bytes d, bytes32 m) {{ require(i == i && d == d && m == m); require({condition}); require(checkSig(s, k)); }} }}")
        };
        let error = compile_error(&source(expression));
        assert!(error.contains(expected), "{expression}: {error}");
    }
    compile_ok("contract T(pubkey k) { function f(signature s, int i, bytes d, bytes32 m) { require(substr(tx.packet(16), i, 4) == d && cat(d, m) == d && bin2num(d) == i && num2bin(i, 4) == d && reverseBytes(k) == d && size(m) == 32 && sighash(0) == m && digest(d, 1) == d && tx.inputs[i].value > 0); require(checkSigFromStack(s, k, m)); require(checkSig(s, k)); } }");
}

#[test]
fn casts_accept_byte_expressions() {
    let output = compile_ok(
        "contract T(pubkey k) { function f(signature s, bytes a, bytes b, bytes32 m) { bytes32 x = bytes32(a + b); require(x == m); require(checkSig(s, k)); } }",
    );
    let asm = crate::common::arkade_asm(&output, "f");
    assert!(asm.contains("OP_CAT OP_SIZE 32 OP_EQUALVERIFY"), "{asm}");
}

#[test]
fn unused_locals_are_checked_per_declaration() {
    let source = |else_read: &str| {
        format!("contract T(pubkey k) {{ function f(signature s, int i) {{ if (i > 0) {{ int x = 1; require(x == 1); }} else {{ int x = 2; require({else_read}); }} require(checkSig(s, k)); }} }}")
    };
    compile_ok(&source("x == 2"));
    let error = compile_error(&source("true"));
    assert!(
        error.contains("variable 'x' in function 'f' is never used"),
        "{error}"
    );
}

#[test]
fn parse_errors_name_tokens_not_grammar_rules() {
    let error = compile_error(
        "contract T(pubkey k) { function f(signature s) { require(checkSig(s, k)) } }",
    );
    assert!(
        error.contains("expected ';'") && !error.contains("_op"),
        "{error}"
    );
}
