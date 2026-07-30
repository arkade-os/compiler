use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_ADD, OP_DROP, OP_ELSE, OP_ENDIF, OP_GREATERTHAN, OP_IF, OP_MUL, OP_PICK, OP_ROLL,
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
fn constructor_prologue_and_function_witness_have_explicit_positions() {
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

    assert_eq!(covenant.witness_order, ["y", "x"]);
    assert_eq!(&covenant.asm[..2], ["<right>", "<left>"]);
    assert!(
        contains_tokens(&covenant.asm, &["OP_0", OP_PICK, "OP_3", OP_PICK, OP_ADD]),
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
            >= 4,
        "nested reads and the later x reuse must use OP_PICK: {:?}",
        covenant.asm
    );
}

#[test]
fn reassignment_replaces_the_existing_slot_and_scopes_clean_up() {
    let covenant = covenant(
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
        "spend",
    );

    assert!(
        covenant.asm.iter().any(|token| token == OP_ROLL),
        "in-place reassignment must roll the old slot into position: {:?}",
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
        .any(|token| token == OP_DROP));
    assert!(covenant.asm[else_index..end_index]
        .iter()
        .any(|token| token == OP_DROP));
}

#[test]
fn array_loop_values_remain_runtime_group_indices() {
    let covenant = covenant(
        r#"
contract GroupIndices() {
    function spend(int[] groups) {
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
}
