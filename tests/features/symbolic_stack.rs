use crate::common::compile_unoptimized as compile;
use arkade_compiler::opcodes::{
    OP_ADD, OP_DUP, OP_ELSE, OP_ENDIF, OP_GREATERTHAN, OP_GREATERTHANOREQUAL, OP_IF, OP_LESSTHAN,
    OP_MUL, OP_PICK, OP_PUT, OP_ROLL, OP_VERIFY,
};

fn covenant(source: &str, function: &str) -> arkade_compiler::models::ArkadeCovenant {
    let output = compile(source).unwrap_or_else(|error| panic!("compile failed: {error}"));
    crate::common::group(&output, function)
        .arkade
        .clone()
        .expect("function must have a covenant")
}

fn contains_tokens(asm: &[String], expected: &[&str]) -> bool {
    asm.windows(expected.len()).any(|window| {
        window
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied())
    })
}

#[test]
fn optimization_can_be_disabled_for_assembly_checks() {
    let source = r#"
contract Shape(int limit) {
    function read() { require(limit == limit); }
    function write(int amount) {
        int[2] weights = [1, 2];
        weights[0] = 4;
        require(amount >= weights[0]);
    }
}
"#;
    let raw = compile(source).unwrap();
    let raw_read = crate::common::arkade_asm_tokens(&raw, "read");
    assert!(contains_tokens(&raw_read, &["OP_0", OP_PICK]));
    assert!(raw_read.ends_with(&[OP_VERIFY.to_string(), "OP_1".to_string()]));
    assert!(contains_tokens(
        &crate::common::arkade_asm_tokens(&raw, "write"),
        &["4", "OP_0", OP_PUT]
    ));

    let optimized = arkade_compiler::compile(source).unwrap();
    assert_eq!(
        crate::common::arkade_asm(&optimized, "read"),
        "<limit> OP_DUP OP_SWAP OP_EQUAL"
    );
    assert_eq!(
        crate::common::arkade_asm(&optimized, "write"),
        "2 1 4 OP_NIP OP_ROT OP_OVER OP_GREATERTHANOREQUAL OP_NIP OP_NIP"
    );
}

#[test]
fn constructor_prologue_and_function_inputs_have_explicit_positions() {
    let covenant = covenant(
        r#"
contract Frame(int left, int right) {
    function spend(int x, int y) {
        require((left + x) == (right + y));
    }
}
"#,
        "spend",
    );

    assert_eq!(
        covenant
            .inputs
            .iter()
            .map(|input| input.name.as_str())
            .collect::<Vec<_>>(),
        ["x", "y"]
    );
    assert_eq!(&covenant.asm[..2], ["<right>", "<left>"]);
    assert!(
        contains_tokens(&covenant.asm, &["OP_0", OP_ROLL, "OP_2", OP_ROLL, OP_ADD]),
        "constructor and function inputs must be read by depth: {:?}",
        covenant.asm
    );
}

#[test]
fn nested_expression_reads_bindings_without_consuming_them() {
    let covenant = covenant(
        r#"
contract Nested() {
    function spend(int x, int y, int z) {
        let w = (bin2num(num2bin(x, 8)) + y) * z;
        require(w > x);
    }
}
"#,
        "spend",
    );

    assert!(covenant.asm.iter().any(|token| token == OP_MUL));
    assert!(covenant.asm.iter().any(|token| token == OP_GREATERTHAN));
    assert!(
        covenant
            .asm
            .iter()
            .filter(|token| token.as_str() == OP_PICK)
            .count()
            == 1,
        "only the first x read must use OP_PICK: {:?}",
        covenant.asm
    );
}

#[test]
fn reassignment_replaces_the_existing_slot_and_scopes_clean_up() {
    let output = compile(
        r#"
contract Mutate() {
    function spend(int value, bool choose) {
        let total = value + 1;
        total = total + 2;
        if (choose) {
            let branch = total * 3;
            total = total + branch;
        } else {
            let branch = total * 4;
            total = total + branch;
        }
        require(total > value);
    }
}
"#,
    )
    .expect("compile");

    assert_eq!(output.functions.len(), 1);
    let group = crate::common::group(&output, "spend");
    assert_eq!(group.leaves.len(), 1);
    assert_eq!(group.leaves[0].name, "spend");
    assert_eq!(
        crate::common::witness_names(&output, "spend", "spend"),
        ["serverSig", "emulatorSig"]
    );
    assert!(group.leaves[0]
        .witness
        .iter()
        .all(|w| w.elem_type == "signature" && w.injected));
    assert_eq!(
        crate::common::leaf_asm(&output, "spend", "spend"),
        "<SERVER_KEY> OP_CHECKSIGVERIFY <EMULATOR_KEY:spend> OP_CHECKSIG"
    );
    let covenant = group.arkade.as_ref().expect("spend covenant");
    assert_eq!(
        crate::common::arkade_inputs(&output, "spend"),
        ["value", "choose"]
    );

    assert_eq!(
        covenant
            .asm
            .iter()
            .filter(|token| token.as_str() == OP_PUT)
            .count(),
        2,
        "deep branch assignments still need {OP_PUT}: {:?}",
        covenant.asm
    );
    let if_index = covenant
        .asm
        .iter()
        .position(|token| token == OP_IF)
        .expect("if");
    let else_index = covenant
        .asm
        .iter()
        .position(|token| token == OP_ELSE)
        .expect("else");
    let end_index = covenant
        .asm
        .iter()
        .position(|token| token == OP_ENDIF)
        .expect("endif");
    assert!(covenant.asm[if_index..else_index]
        .iter()
        .any(|token| token == OP_ROLL));
    assert!(covenant.asm[else_index..end_index]
        .iter()
        .any(|token| token == OP_ROLL));
}

#[test]
fn array_loop_values_remain_runtime_group_indices() {
    let covenant = covenant(
        r#"
contract GroupIndices() {
    function spend(int[3] groups) {
        let total = 0;
        for (i, group) in groups {
            total = total + group.sumInputs + i;
        }
        require(total >= 0);
    }
}
"#,
        "spend",
    );

    assert_eq!(
        covenant
            .asm
            .iter()
            .filter(|token| token.as_str() == "OP_INSPECTASSETGROUPSUM")
            .count(),
        3
    );
    assert!(
        covenant.asm.iter().any(|token| token == OP_PICK),
        "each unrolled group value must read its flattened input binding"
    );
    assert!(covenant.asm.iter().all(|token| !token.contains("$array:")));
}

#[test]
fn runtime_array_indices_are_bounded_and_pick_by_computed_depth() {
    let output = compile(
        r#"
contract RuntimeIndex() {
    function spend(int[3] values, int index) {
        require(values[index] >= 0);
    }
}
"#,
    )
    .expect("compile");

    assert_eq!(output.functions.len(), 1);
    let group = crate::common::group(&output, "spend");
    assert_eq!(group.leaves.len(), 1);
    assert_eq!(group.leaves[0].name, "spend");
    assert_eq!(
        crate::common::witness_names(&output, "spend", "spend"),
        ["serverSig", "emulatorSig"]
    );
    assert!(group.leaves[0]
        .witness
        .iter()
        .all(|w| w.elem_type == "signature" && w.injected));
    assert_eq!(
        crate::common::leaf_asm(&output, "spend", "spend"),
        "<SERVER_KEY> OP_CHECKSIGVERIFY <EMULATOR_KEY:spend> OP_CHECKSIG"
    );
    let covenant = group.arkade.as_ref().expect("spend covenant");
    assert_eq!(
        crate::common::arkade_inputs(&output, "spend"),
        ["values", "index"]
    );

    for opcode in [OP_GREATERTHANOREQUAL, OP_LESSTHAN, OP_DUP, OP_PICK] {
        assert!(
            covenant.asm.iter().any(|token| token == opcode),
            "runtime index must emit {opcode}: {:?}",
            covenant.asm
        );
    }
    assert!(contains_tokens(
        &covenant.asm,
        &[
            "OP_3",
            OP_ROLL,
            OP_DUP,
            "OP_0",
            OP_GREATERTHANOREQUAL,
            "OP_VERIFY",
            OP_DUP,
            "OP_3",
            OP_LESSTHAN,
            "OP_VERIFY",
            OP_PICK,
        ],
    ));
}

#[test]
fn array_index_accepts_integer_expressions() {
    let covenant = covenant(
        r#"
contract ExpressionIndex() {
    function spend(int[3] values, int x, int y) {
        require(values[x * y + 3] >= 0);
    }
}
"#,
        "spend",
    );

    assert!(contains_tokens(&covenant.asm, &[OP_MUL, "3", OP_ADD]));
    assert!(contains_tokens(
        &covenant.asm,
        &[OP_GREATERTHANOREQUAL, "OP_VERIFY"]
    ));
    assert!(contains_tokens(&covenant.asm, &[OP_LESSTHAN, "OP_VERIFY"]));
}

#[test]
fn literal_array_indices_remain_static() {
    let covenant = covenant(
        r#"
contract StaticIndex() {
    function spend(int[3] values, int expected) {
        require(values[2] == expected);
    }
}
"#,
        "spend",
    );

    assert!(!covenant.asm.iter().any(|token| token == OP_LESSTHAN));
    assert!(!covenant
        .asm
        .iter()
        .any(|token| token == OP_GREATERTHANOREQUAL));
}

#[test]
fn leading_zero_array_indices_are_rejected() {
    let source = r#"
contract StaticIndex() {
    function spend(int[3] values, int expected) {
        require(values[01] == expected);
    }
}
"#;

    assert!(compile(source).is_err());
}

#[test]
fn runtime_array_indices_work_in_named_crypto_operands_and_loop_values() {
    let cases = [
        r#"
contract RuntimeIndex(pubkey[3] keys) {
    function spend(signature sig, bytes32 msg, int index) {
        require(checkSigFromStack(sig, keys[index], msg));
    }
}
"#,
        r#"
contract LoopValueIndex() {
    function spend(int[3] indices, int[3] values) {
        for (i, index) in indices {
            require(values[index] >= 0);
        }
    }
}
"#,
    ];

    for source in cases {
        compile(source).expect("runtime array index must compile");
    }
}

#[test]
fn runtime_array_index_must_be_an_integer() {
    let source = r#"
contract RuntimeIndex() {
    function spend(int[3] values, bytes index) {
        require(values[index] >= 0);
    }
}
"#;

    let error = compile(source)
        .expect_err("non-integer array index must be rejected")
        .to_string();
    assert!(
        error.contains("expected 'int'"),
        "unexpected error: {error}"
    );
}

#[test]
fn constructor_parameters_are_filtered_per_spending_path() {
    let output = compile(
        r#"
contract Paths(int unused, int left, int right, pubkey exitKey, int delay) {
    function first(int value) { require(value == left); }
    function second(int value) { require(value == right); }
    function neither() { require(true); }
    function exit(signature ownerSig) tapscript {
        require(older(delay));
        require(checkSig(ownerSig, exitKey));
    }
}
"#,
    )
    .expect("compile");
    assert_eq!(output.parameters.len(), 5);
    assert_eq!(output.functions.len(), 4);
    for (name, parameter) in [("first", "left"), ("second", "right")] {
        let group = crate::common::group(&output, name);
        let covenant = group.arkade.as_ref().unwrap();
        assert_eq!(
            covenant.asm,
            format!("<{parameter}> OP_1 OP_ROLL OP_1 OP_ROLL OP_EQUAL OP_VERIFY OP_1")
                .split_whitespace()
                .map(String::from)
                .collect::<Vec<_>>()
        );
        assert_eq!(crate::common::arkade_inputs(&output, name), ["value"]);
        assert_eq!(group.leaves.len(), 1);
        assert_eq!(
            crate::common::witness_names(&output, name, name),
            ["serverSig", "emulatorSig"]
        );
        assert_eq!(
            crate::common::leaf_asm(&output, name, name),
            format!("<SERVER_KEY> OP_CHECKSIGVERIFY <EMULATOR_KEY:{name}> OP_CHECKSIG")
        );
    }
    assert_eq!(
        crate::common::arkade_asm_tokens(&output, "neither"),
        ["OP_1", "OP_VERIFY", "OP_1"]
    );
    assert!(crate::common::group(&output, "exit").arkade.is_none());
    assert_eq!(
        crate::common::witness_names(&output, "exit", "exit"),
        ["ownerSig"]
    );
    assert_eq!(
        crate::common::leaf_asm(&output, "exit", "exit"),
        "<delay> OP_CHECKSEQUENCEVERIFY OP_DROP <exitKey> OP_CHECKSIG"
    );
}

#[test]
fn constructor_references_cover_nested_bodies_and_named_operands() {
    let covenant = |source: &str, name: &str| {
        let output = arkade_compiler::compile_sources(
            "main.ark",
            &[
                ("main.ark".into(), source.into()),
                (
                    "policy.ark".into(),
                    "struct Policy { pubkey key; int[2] limits; }".into(),
                ),
                (
                    "child.ark".into(),
                    "import \"policy.ark\"; contract Child(Policy policy) {}".into(),
                ),
            ]
            .into_iter()
            .collect(),
        )
        .unwrap();
        crate::common::group(&output, name).arkade.clone().unwrap()
    };
    for (parameters, inputs, body, expected) in [
        ("int limit, int alternate, bool choose", "int value",
         "let total = 0; if (choose) { total = limit; } else { total = alternate; } require(total > value);",
         vec!["<choose>", "<alternate>", "<limit>"]),
        ("int[2] values, int limit", "",
         "for (i, value) in values { require(value > limit); }",
         vec!["<limit>", "<values.1>", "<values.0>"]),
        ("int index, int amount", "",
         "int[2] values = [0, 0]; values[index] = amount; require(values[0] >= 0);",
         vec!["<amount>", "<index>"]),
        ("Policy policy", "int index",
         "require(policy.limits[index] > 0); require(policy.limits.length == 2);",
         vec!["<policy.limits.1>", "<policy.limits.0>", "<policy.key>"]),
        ("pubkey[2] keys, int index, bytes32 message", "signature sig",
         "require(checkSigFromStack(sig, keys[index], message));",
         vec!["<message>", "<index>", "<keys.1>", "<keys.0>"]),
        ("pubkey key", "signature sig",
         "if (checkSig(sig, key)) { require(true); } else { require(false); }",
         vec!["<key>"]),
        ("bytes32 digest, int deadline", "bytes preimage",
         "require(sha256(preimage) == digest); require(tx.time >= deadline);",
         vec!["<deadline>", "<digest>"]),
        ("int groupIndex, bytes32 txid, int gidx", "",
         "require(groupIndex.sumInputs >= 0); require(groupIndex.controlIs(txid, gidx));",
         vec!["<gidx>", "<txid>", "<groupIndex>"]),
        ("Policy policy", "",
         "require(tx.outputs[0].scriptPubKey == new Child(policy));",
         vec!["<policy.limits.1>", "<policy.limits.0>", "<policy.key>"]),
    ] {
        let source = format!(
            "import \"policy.ark\"; import \"child.ark\"; contract C(int unused, Policy unusedPolicy, {parameters}, int unusedTail) {{ function spend({inputs}) {{ {body} }} }}"
        );
        let actual = covenant(&source, "spend");
        let prologue = actual.asm.iter().take_while(|token| token.starts_with('<')).map(String::as_str).collect::<Vec<_>>();
        assert_eq!(prologue, expected, "{body}");
        let baseline = covenant(&source.replace("int unused, Policy unusedPolicy, ", "").replace(", int unusedTail", ""), "spend");
        assert_eq!(actual.asm, baseline.asm, "{body}");
        if body.contains("new Child") {
            assert!(actual.asm.contains(&"<VTXO:Child(<policy.key>,<policy.limits.0>,<policy.limits.1>)>".to_string()));
        }
    }
}

#[test]
fn final_use_liveness_keeps_repeated_reads_and_assignment_targets() {
    for (body, expected) in [
        (
            "require(x + x == y);",
            "OP_0 OP_PICK OP_1 OP_ROLL OP_ADD OP_1 OP_ROLL OP_EQUAL OP_VERIFY OP_1",
        ),
        (
            "require(x == y); x = 7; require(true);",
            "OP_0 OP_PICK OP_2 OP_ROLL OP_EQUAL OP_VERIFY 7 OP_NIP OP_1 OP_VERIFY OP_1 OP_NIP",
        ),
        (
            "x = x + 1; require(x == y);",
            "OP_0 OP_ROLL 1 OP_ADD OP_0 OP_ROLL OP_1 OP_ROLL OP_EQUAL OP_VERIFY OP_1",
        ),
    ] {
        let source = format!("contract FinalUse() {{ function spend(int x, int y) {{ {body} }} }}");
        assert_eq!(covenant(&source, "spend").asm.join(" "), expected, "{body}");
    }
}

#[test]
fn top_binding_reassignment_keeps_branch_layouts() {
    let covenant = covenant(
        r#"
contract BranchReplace() {
    function spend(int x, bool choose) {
        if (choose) {
            x = x + 1;
        } else {
            x = 7;
        }
        require(x > 0);
    }
}
"#,
        "spend",
    );

    let if_index = covenant
        .asm
        .iter()
        .position(|token| token == OP_IF)
        .unwrap();
    let else_index = covenant
        .asm
        .iter()
        .position(|token| token == OP_ELSE)
        .unwrap();
    let end_index = covenant
        .asm
        .iter()
        .position(|token| token == OP_ENDIF)
        .unwrap();
    assert!(contains_tokens(
        &covenant.asm[if_index..else_index],
        &["OP_0", OP_ROLL, "1", OP_ADD]
    ));
    assert!(contains_tokens(
        &covenant.asm[else_index..end_index],
        &["7", "OP_NIP"]
    ));
    assert!(!covenant.asm.iter().any(|token| token == OP_PUT));
    assert!(contains_tokens(
        &covenant.asm[end_index..],
        &["OP_0", OP_ROLL, "0", OP_GREATERTHAN]
    ));
}

#[test]
fn final_use_after_a_private_call_consumes_the_caller_binding() {
    let covenant = covenant(
        r#"
contract Framed() {
    public function spend(int x, int y) {
        require(double(x) > 0);
        require(double(x) == y);
        require(x >= 1);
    }
    private function double(int v) int {
        return v * 2;
    }
}
"#,
        "spend",
    );

    assert_eq!(
        covenant
            .asm
            .windows(4)
            .filter(|tokens| *tokens == ["OP_0", OP_PICK, "2", OP_MUL])
            .count(),
        2,
        "each helper invocation should read the caller slot directly: {:?}",
        covenant.asm,
    );
    assert!(covenant
        .asm
        .iter()
        .all(|token| token != OP_PUT && token != "OP_NIP"));
    assert!(
        contains_tokens(
            &covenant.asm,
            &["OP_0", OP_ROLL, "1", OP_GREATERTHANOREQUAL]
        ),
        "the caller's final read after a call must consume the slot: {:?}",
        covenant.asm
    );
}

#[test]
fn readonly_private_arguments_alias_caller_slots_but_mutated_arguments_copy() {
    let covenant = covenant(
        r#"
contract C() {
    function spend(int x) {
        let earlier = x + 1;
        require(outer(x) == earlier + x - 1);
        require(bump(x) == x + 1);
    }
    private function outer(int v) int { return inner(v); }
    private function inner(int w) int { return w * 2; }
    private function bump(int v) int { if (v > 0) { v = v + 1; } return v; }
}
"#,
        "spend",
    );

    assert_eq!(&covenant.asm[..4], ["OP_0", OP_PICK, "1", OP_ADD]);
    assert!(contains_tokens(
        &covenant.asm,
        &["OP_1", OP_PICK, "2", OP_MUL]
    ));
    assert!(contains_tokens(
        &covenant.asm,
        &["OP_0", OP_PICK, "OP_0", OP_PICK, "0", OP_GREATERTHAN, OP_IF]
    ));
}

#[test]
fn readonly_constructor_argument_preserves_constructor_access() {
    let covenant = covenant(
        r#"
contract C(int base) {
    function spend() { require(sum(base) == base * 2); }
    private function sum(int value) int { return value + base; }
}
"#,
        "spend",
    );

    assert_eq!(
        &covenant.asm[..6],
        ["<base>", "OP_0", OP_PICK, "OP_1", OP_PICK, OP_ADD]
    );
}

#[test]
fn caller_top_slot_rebinding_ignores_same_named_helper_locals() {
    let covenant = covenant(
        r#"
contract C() {
    function spend(int y, bool c) {
        let x = y;
        x = helper(y, c);
        require(x > 0);
    }
    private function helper(int y, bool c) int {
        let x = y + 1;
        if (c) { require(x > 0); }
        return 5;
    }
}
"#,
        "spend",
    );

    assert!(contains_tokens(
        &covenant.asm,
        &[
            OP_IF,
            "OP_0",
            OP_PICK,
            "0",
            OP_GREATERTHAN,
            OP_VERIFY,
            OP_ENDIF
        ]
    ));
    let end = covenant
        .asm
        .iter()
        .rposition(|token| token == OP_ENDIF)
        .unwrap();
    assert_eq!(
        &covenant.asm[end + 1..],
        [
            "5",
            "OP_NIP",
            "OP_NIP",
            "OP_0",
            OP_ROLL,
            "0",
            OP_GREATERTHAN,
            OP_VERIFY,
            "OP_1",
            "OP_NIP",
            "OP_NIP"
        ]
    );
}
