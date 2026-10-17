use crate::common::*;
use arkade_compiler::compile;

fn asm(source: &str) -> Vec<String> {
    arkade_asm_tokens(&compile(source).unwrap(), "spend")
}

#[test]
fn loop_indexes_encoding_requirements_and_branches_match_static_code() {
    let source = |body: &str| {
        format!("contract C() {{ function spend(ECPoint[11] batchIC, int[10] rounds, int input, bytes encoded) {{ require(rounds.length == 10); {body} }} }}")
    };
    let looped = source(
        r#"
        for (i, unused) in rounds {
            require(i + 1 < 11);
            require(batchIC[i + 1].x == input);
            require(num2bin(i + 1, 1) == encoded);
            if (i == 0) { require(batchIC[i + 1].y == input); }
            else { require(batchIC[i + 1].y > input); }
        }
    "#,
    );
    let expanded = (1..=10).map(|index| format!(
        "for (1) {{ require(batchIC[{index}].x == input); require(0x{index:02x} == encoded); require(batchIC[{index}].y {} input); }}",
        if index == 1 { "==" } else { ">" },
    )).collect::<String>();
    let output = compile(&looped).unwrap();
    let expected = compile(&source(&expanded)).unwrap();
    assert_eq!(
        arkade_asm_tokens(&output, "spend"),
        arkade_asm_tokens(&expected, "spend")
    );
    let raw = compile_unoptimized(&looped).unwrap();
    let optimized = arkade_asm_tokens(&output, "spend");
    for opcode in [
        "OP_NUM2BIN",
        "OP_IF",
        "OP_MUL",
        "OP_LESSTHAN",
        "OP_GREATERTHANOREQUAL",
    ] {
        assert!(
            !optimized.iter().any(|token| token == opcode),
            "{opcode}: {optimized:?}"
        );
        assert!(
            arkade_asm_tokens(&raw, "spend")
                .iter()
                .any(|token| token == opcode),
            "{opcode}"
        );
    }
    assert_eq!(
        arkade_inputs(&output, "spend"),
        ["batchIC", "rounds", "input", "encoded"]
    );
    assert_eq!(group(&output, "spend").leaves.len(), 1);
    assert_eq!(
        leaf_asm(&output, "spend", "spend"),
        leaf_asm(&raw, "spend", "spend")
    );
    assert_eq!(
        witness_names(&output, "spend", "spend"),
        ["serverSig", "emulatorSig"]
    );
}

#[test]
fn literal_arithmetic_and_comparisons_fold_without_propagating_locals() {
    for (expression, literal) in [
        ("(2 + 3) * 4 - 1", "19"),
        ("-7 / 2", "-3"),
        ("-7 % 2", "-1"),
        ("-7 >> 1", "-4"),
        ("3 << 4", "48"),
        ("-(-9)", "9"),
        ("-0", "0"),
        ("9223372036854775807 + 1", "9223372036854775808"),
    ] {
        let source = |value: &str| {
            format!("contract C() {{ function spend(int input) {{ require(input == {value}); }} }}")
        };
        assert_eq!(
            asm(&source(expression)),
            asm(&source(literal)),
            "{expression}"
        );
    }
    for condition in [
        "1 + 2 == 3",
        "0 == -0",
        "!(3 < 2)",
        "0xAb == 0xab",
        "false || true",
    ] {
        let source = format!("contract C() {{ function spend() {{ require({condition}); }} }}");
        assert_eq!(asm(&source), ["OP_1"], "{condition}");
    }
    let source = "contract C() { function spend(int[3] values, int input) { let k = 1 + 1; require(values[k] == input); } }";
    assert!(asm(source).iter().any(|token| token == "OP_LESSTHAN"));
}

#[test]
fn num2bin_preserves_sign_padding_and_boundaries() {
    for (value, width, bytes) in [
        ("0", 0, ""),
        ("0", 2, "0000"),
        ("1", 1, "01"),
        ("127", 1, "7f"),
        ("128", 2, "8000"),
        ("255", 2, "ff00"),
        ("-1", 1, "81"),
        ("-1", 2, "0180"),
        ("-127", 1, "ff"),
        ("-128", 2, "8080"),
        ("-255", 3, "ff0080"),
        ("-0", 1, "00"),
        (
            "-170141183460469231731687303715884105728",
            17,
            "0000000000000000000000000000008080",
        ),
    ] {
        let source = |value: &str| {
            format!("contract C() {{ function spend(bytes expected) {{ require({value} == expected); }} }}")
        };
        assert_eq!(
            asm(&source(&format!("num2bin({value}, {width})"))),
            asm(&source(&if bytes.is_empty() {
                "\"\"".to_string()
            } else {
                format!("0x{bytes}")
            })),
            "{value}, {width}"
        );
    }
    let source = "contract C() { function spend(bytes expected) { require(num2bin(-1, 520) == expected); } }";
    let tokens = asm(source);
    let literal = tokens.iter().find(|token| token.starts_with("0x")).unwrap();
    assert_eq!(literal.len(), 1042);
    assert!(literal.starts_with("0x01"));
    assert!(literal.ends_with("80"));
}

#[test]
fn invalid_or_unrepresentable_arithmetic_and_encoding_stays_at_runtime() {
    for (expression, opcode) in [
        ("170141183460469231731687303715884105727 + 1", "OP_1ADD"),
        ("num2bin(128, 1)", "OP_NUM2BIN"),
        ("num2bin(-128, 1)", "OP_NUM2BIN"),
        ("num2bin(1, 0)", "OP_NUM2BIN"),
        ("num2bin(0, -1)", "OP_NUM2BIN"),
        ("num2bin(0, 521)", "OP_NUM2BIN"),
    ] {
        let ty = if expression.starts_with("num2bin") {
            "bytes"
        } else {
            "int"
        };
        let source = format!("contract C() {{ function spend({ty} expected) {{ require({expression} == expected); }} }}");
        assert!(
            asm(&source).iter().any(|token| token == opcode),
            "{expression}"
        );
    }
    for (expression, opcode) in [
        ("1 / (i - i)", "OP_DIV"),
        ("1 % (i - i)", "OP_MOD"),
        ("1 << (i - 1)", "OP_LSHIFT"),
    ] {
        let source = format!("contract C() {{ function spend(int[1] rounds, int expected) {{ for (i, unused) in rounds {{ require({expression} == expected); }} }} }}");
        assert!(
            asm(&source).iter().any(|token| token == opcode),
            "{expression}"
        );
    }
    for expression in ["1 / 0", "1 % 0", "1 << -1"] {
        let source = format!("contract C() {{ function spend(int expected) {{ require({expression} == expected); }} }}");
        assert!(compile(&source).is_err());
        assert!(compile_unoptimized(&source).is_err());
    }
    for condition in ["1 + 1 == 3", "num2bin(1, 1) == 0x02"] {
        let source = format!("contract C() {{ function spend() {{ require({condition}); }} }}");
        assert_eq!(asm(&source), ["OP_0"], "false requirement must still fail");
    }
}

#[test]
fn static_indexes_cover_reads_writes_nested_arrays_and_helper_arguments() {
    for (body, expected) in [
        (
            "require(values[1 + 1] == input);",
            "require(values[2] == input);",
        ),
        (
            "values[1 + 1] = input; require(values[2] == input);",
            "values[2] = input; require(values[2] == input);",
        ),
        (
            "require(value.points[1 + 1].x == input);",
            "require(value.points[2].x == input);",
        ),
        (
            "value.points[1 + 1].y = input; require(value.points[2].y == input);",
            "value.points[2].y = input; require(value.points[2].y == input);",
        ),
        (
            "require(identity(values[1 + 1]) == input);",
            "require(identity(values[2]) == input);",
        ),
        (
            "require(values[values.length - 1] == input);",
            "require(values[2] == input);",
        ),
    ] {
        let source = |body: &str| {
            format!("struct Data {{ ECPoint[3] points; }} contract C() {{ private function identity(int n) int {{ return n; }} function spend(int[3] values, Data value, int input) {{ require(values[0] == input); require(value.points[0].x == input); {body} }} }}")
        };
        assert_eq!(asm(&source(body)), asm(&source(expected)), "{body}");
    }
    let runtime = asm("contract C() { function spend(int[3] values, int index, int input) { require(values[index + 1] == input); } }");
    assert!(runtime.iter().any(|token| token == "OP_LESSTHAN"));
    assert!(runtime.iter().any(|token| token == "OP_GREATERTHANOREQUAL"));
}

#[test]
fn mixed_nested_indexes_and_length_fields_keep_their_layout() {
    for (body, expected) in [
        ("require(rows[1 + 1].values[1 + 1] == input);", "require(rows[2].values[2] == input);"),
        ("require(rows[index].values[1 + 1] == input);", "require(rows[index].values[2] == input);"),
        ("rows[1 + 1].values[index] = input; require(rows[2].values[index] == input);", "rows[2].values[index] = input; require(rows[2].values[index] == input);"),
        ("require(rows[1 + 1].length == input);", "require(rows[2].length == input);"),
        ("rows[1 + 1] = {length: input, values: [1, 2, input]}; require(rows[2].length == input);", "rows[2] = {length: input, values: [1, 2, input]}; require(rows[2].length == input);"),
    ] {
        let source = |body: &str| format!("struct Row {{ int length; int[3] values; }} contract C() {{ function spend(Row[3] rows, int index, int input) {{ require(index >= 0); {body} }} }}");
        assert_eq!(asm(&source(body)), asm(&source(expected)), "{body}");
    }
    let source = "struct Row { int length; int[2] values; } contract C(Row state) { function spend(int expected) { require(state.length == expected); require(state.values.length - 1 == expected); } }";
    let tokens = asm(source);
    assert!(tokens.iter().any(|token| token == "<state.length>"));
    assert!(!tokens.iter().any(|token| token == "OP_SUB"));
}

#[test]
fn computed_out_of_range_indexes_fail_for_reads_and_writes() {
    for body in [
        "require(values[1 + 2] == input);",
        "values[1 + 2] = input; require(true);",
        "require(values[1 - 2] == input);",
        "values[1 - 2] = input; require(true);",
        "require(value.points[1 + 2].x == input);",
        "value.points[1 - 2].y = input; require(true);",
        "for (i, x) in values { require(values[i + 1] == input); }",
        "require(identity(values[1 + 2]) == input);",
    ] {
        let source = format!("struct Data {{ ECPoint[3] points; }} contract C() {{ private function identity(int n) int {{ return n; }} function spend(int[3] values, Data value, int input) {{ require(values[0] == input); require(value.points[0].x == input); {body} }} }}");
        let error = compile(&source).unwrap_err().to_string();
        assert!(error.contains("out of range"), "{body}: {error}");
        let raw_error = compile_unoptimized(&source).unwrap_err().to_string();
        assert!(raw_error.contains("out of range"), "{body}: {raw_error}");
    }
}

#[test]
fn constant_index_diagnostics_are_independent_of_optimization() {
    for index in [
        "1 + 2",
        "1 - 2",
        "values.length",
        "-(1 + 1)",
        "(1 << 2) - 1",
    ] {
        let source = format!("contract C() {{ function spend(int[3] values, int input) {{ require(values[{index}] == input); }} }}");
        let optimized = compile(&source).unwrap_err().to_string();
        let raw = compile_unoptimized(&source).unwrap_err().to_string();
        assert_eq!(optimized, raw, "{index}");
        let files = [("main.ark".to_string(), source.clone())].into();
        let diagnostics = arkade_compiler::check("main.ark", &files);
        let diagnostic = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.message.contains("out of range"))
            .unwrap();
        let span = diagnostic.span.unwrap();
        assert_eq!(&source[span.start..span.end], index);
    }
    let source = "contract C() { function spend(int[3] values, int input) { require(values[1 + 1] == input); } }";
    let raw = arkade_asm_tokens(&compile_unoptimized(source).unwrap(), "spend");
    assert!(raw.iter().any(|token| token == "OP_ADD"));
    assert!(raw.iter().any(|token| token == "OP_LESSTHAN"));
}

#[test]
fn unrolled_index_validation_skips_dead_branches_and_returned_iterations_in_both_modes() {
    for body in [
        "for (i, unused) in values { if (i < 3) { require(true); } else { require(values[i + 1] == input); } }",
        "for (i, unused) in values { if (i >= 3) { require(values[i + 1] == input); } else { require(true); } }",
        "require(helper(values, input) == input);",
        "require(true || bad(values, input));",
    ] {
        let source = format!("contract C() {{ private function helper(int[3] values, int input) int {{ for (i, unused) in values {{ if (i == 0) {{ return input; }} require(values[i + 1] == input); }} return 0; }} private function bad(int[3] values, int input) bool {{ for (i, unused) in values {{ require(values[i + 1] == input); }} return true; }} function spend(int[3] values, int input) {{ {body} }} }}");
        compile(&source).unwrap();
        compile_unoptimized(&source).unwrap();
    }
}

#[test]
fn static_branches_preserve_scopes_and_deferred_initialization() {
    for (body, expected) in [
        (
            "if (1 < 2) { let n = input; require(n > 0); } else { require(false); }",
            "for (1) { let n = input; require(n > 0); }",
        ),
        (
            "if (1 > 2) { require(false); } else { let n = input; require(n > 0); }",
            "for (1) { let n = input; require(n > 0); }",
        ),
        (
            "int n; if (1 < 2) { n = input; } else { n = 9; } require(n > 0);",
            "int n; for (1) { n = input; } require(n > 0);",
        ),
        (
            "int n; if (1 > 2) { n = 9; } else { n = input; } require(n > 0);",
            "int n; for (1) { n = input; } require(n > 0);",
        ),
        (
            "if (false) { require(input == 0); } require(input > 0);",
            "require(input > 0);",
        ),
    ] {
        let source =
            |body: &str| format!("contract C() {{ function spend(int input) {{ {body} }} }}");
        assert_eq!(asm(&source(body)), asm(&source(expected)), "{body}");
    }
}

#[test]
fn short_circuit_folding_preserves_executed_helpers() {
    for (condition, called) in [
        ("false && verify(input)", false),
        ("true || verify(input)", false),
        ("true && verify(input)", true),
        ("false || verify(input)", true),
        ("verify(input) || true", true),
        ("verify(input) && false", true),
    ] {
        let source = format!("contract C() {{ private function verify(int input) bool {{ require(input > 0); return true; }} function spend(int input) {{ require({condition}); }} }}");
        let tokens = asm(&source);
        assert_eq!(
            tokens.iter().any(|token| token == "OP_GREATERTHAN"),
            called,
            "{condition}: {tokens:?}"
        );
    }
    for source in [
        "contract C() { function spend() { if (true) { require(true); } else { require(missing == 0); } } }",
        "contract C() { function spend() { require(true || (1 + false == 0)); } }",
    ] {
        assert!(compile(source).is_err(), "invalid dead code must still be validated");
    }
}

#[test]
fn short_circuit_skips_indexes_that_become_invalid_after_unrolling() {
    for condition in [
        "i < 2 || values[i + 2] == input",
        "!(i >= 2 && values[i + 2] == input)",
        "true && (i < 2 || values[i + 2] == input)",
        "false || !(i >= 2 && values[i + 2] == input)",
    ] {
        let source = format!("contract C() {{ function spend(int[2] values, int input) {{ for (i, unused) in values {{ require({condition}); }} }} }}");
        compile_unoptimized(&source).unwrap();
        let tokens = asm(&source);
        assert!(
            !tokens
                .iter()
                .any(|token| token == "OP_IF" || token == "OP_PICK"),
            "{condition}: {tokens:?}"
        );
    }
    for condition in [
        "i < 2 && values[i + 2] == input",
        "i >= 2 || values[i + 2] == input",
    ] {
        let source = format!("contract C() {{ function spend(int[2] values, int input) {{ for (i, unused) in values {{ require({condition}); }} }} }}");
        assert!(
            compile(&source)
                .unwrap_err()
                .to_string()
                .contains("out of range"),
            "{condition}"
        );
    }
}

#[test]
fn static_conditions_in_helpers_and_nested_loops_keep_return_bookkeeping() {
    for body in [
        "if (1 < 2) { return input; } else { return 9; }",
        "if (1 > 2) { return 9; } return input;",
        "int[2] values = [7, 9]; for (i, v) in values { if (i == 1) { return input; } } return 0;",
        "int[2] values = [7, 9]; for (i, v) in values { for (j, w) in values { if (i + j == 2) { return input; } } } return 0;",
        "int n; if (true) { n = input; } else { return 9; } return n;",
    ] {
        let source = format!("contract C() {{ private function helper(int input) int {{ {body} }} function spend(int input) {{ require(helper(input) == input); }} }}");
        compile(&source).unwrap();
        compile_unoptimized(&source).unwrap();
    }
}

#[test]
fn optimization_preserves_numeric_execution_across_scopes_and_returns() {
    // Execute the numeric subset used here to compare both lowering paths on real stacks.
    fn execute(tokens: &[String], mut stack: Vec<i128>) -> bool {
        let mut branches = Vec::new();
        let mut active = true;
        for token in tokens {
            match token.as_str() {
                "OP_IF" => {
                    let condition = active && stack.pop().unwrap() != 0;
                    branches.push((active, condition));
                    active = condition;
                }
                "OP_ELSE" => {
                    let (parent, condition) = branches.last().unwrap();
                    active = *parent && !condition;
                }
                "OP_ENDIF" => active = branches.pop().unwrap().0,
                _ if !active => {}
                "OP_VERIFY" => {
                    if stack.pop().unwrap() == 0 {
                        return false;
                    }
                }
                "OP_DUP" => stack.push(*stack.last().unwrap()),
                "OP_OVER" => stack.push(stack[stack.len() - 2]),
                "OP_DROP" => {
                    stack.pop().unwrap();
                }
                "OP_2DROP" => {
                    stack.pop().unwrap();
                    stack.pop().unwrap();
                }
                "OP_NIP" => {
                    stack.remove(stack.len() - 2);
                }
                "OP_2DUP" | "OP_3DUP" | "OP_2OVER" => {
                    let (from, count) = match token.as_str() {
                        "OP_2DUP" => (2, 2),
                        "OP_3DUP" => (3, 3),
                        _ => (4, 2),
                    };
                    let start = stack.len() - from;
                    stack.extend_from_within(start..start + count);
                }
                "OP_2SWAP" | "OP_2ROT" => {
                    let start = stack.len() - if token == "OP_2SWAP" { 4 } else { 6 };
                    let moved = stack.drain(start..start + 2).collect::<Vec<_>>();
                    stack.extend(moved);
                }
                "OP_SWAP" => {
                    let length = stack.len();
                    stack.swap(length - 1, length - 2);
                }
                "OP_ROT" => {
                    let value = stack.remove(stack.len() - 3);
                    stack.push(value);
                }
                "OP_PICK" | "OP_ROLL" | "OP_PUT" => {
                    let depth = usize::try_from(stack.pop().unwrap()).unwrap();
                    let value = (token == "OP_PUT").then(|| stack.pop().unwrap());
                    let slot = stack.len() - depth - 1;
                    if let Some(value) = value {
                        stack[slot] = value;
                    } else {
                        let value = if token == "OP_ROLL" {
                            stack.remove(slot)
                        } else {
                            stack[slot]
                        };
                        stack.push(value);
                    }
                }
                "OP_NOT" | "OP_0NOTEQUAL" | "OP_NEGATE" | "OP_1ADD" => {
                    let value = stack.pop().unwrap();
                    stack.push(match token.as_str() {
                        "OP_NOT" => i128::from(value == 0),
                        "OP_0NOTEQUAL" => i128::from(value != 0),
                        "OP_NEGATE" => -value,
                        _ => value + 1,
                    });
                }
                "OP_ADD"
                | "OP_SUB"
                | "OP_MUL"
                | "OP_MOD"
                | "OP_EQUAL"
                | "OP_EQUALVERIFY"
                | "OP_NUMEQUAL"
                | "OP_NUMEQUALVERIFY"
                | "OP_GREATERTHAN"
                | "OP_GREATERTHANOREQUAL"
                | "OP_LESSTHAN"
                | "OP_LESSTHANOREQUAL" => {
                    let right = stack.pop().unwrap();
                    let left = stack.pop().unwrap();
                    let value = match token.as_str() {
                        "OP_ADD" => left + right,
                        "OP_SUB" => left - right,
                        "OP_MUL" => left * right,
                        "OP_MOD" => left % right,
                        "OP_GREATERTHAN" => i128::from(left > right),
                        "OP_GREATERTHANOREQUAL" => i128::from(left >= right),
                        "OP_LESSTHAN" => i128::from(left < right),
                        "OP_LESSTHANOREQUAL" => i128::from(left <= right),
                        _ => i128::from(left == right),
                    };
                    if token.ends_with("VERIFY") {
                        if value == 0 {
                            return false;
                        }
                    } else {
                        stack.push(value);
                    }
                }
                _ => stack.push(
                    token
                        .strip_prefix("OP_")
                        .unwrap_or(token)
                        .parse()
                        .unwrap_or_else(|_| panic!("unsupported opcode {token}")),
                ),
            }
        }
        assert!(branches.is_empty());
        stack == [1]
    }
    for (body, helper) in [
        "int n; if (1 < 2) { n = input; } else { n = 9; } require(n == input);",
        "let n = input; if (true) { let scoped = n + 1; n = scoped; } else { n = 0; } require(n == input + 1);",
        "int[3] values = [7, 9, 11]; values[1 + 1] = input; require(values[2] == input);",
        "int[3] values = [7, 9, 11]; require(values[input % 3] > 0);",
        "int total = 0; int[3] values = [1, 2, 3]; for (i, v) in values { for (j, unused) in values { if (i == 0) { total = total + input; } else { total = total + v; } require(j + 1 < 4); } } require(total == 3 * input + 15);",
        "if (choose) { require(helper(input, choose) == input + 1); } else { require(helper(input, choose) == input + 2); }",
    ].map(|body| (body, r#"
                int[2] values = [7, 9];
                for (i, v) in values { for (j, w) in values {
                    if (i + j == 1) { if (choose) { return input + 1; } else { return input + 2; } }
                } }
                return 0;
    "#)).into_iter().chain([
        ("require(helper(input, choose) == input);", "int n; if (choose) { if (true) { return input; } else { n = 9; } } else { n = input; } return n;"),
        ("require(helper(input, choose) == input);", "int n; if (choose) { n = input; } else { if (false) { n = 9; } else { return input; } } return n;"),
        ("require(helper(input, choose) == input);", "int n; if (choose) { for (2) { if (true) { return input; } else { n = 9; } } } else { n = input; } return n;"),
        ("require(helper(input, choose) == input);", "int n; int[2] values = [7, 9]; if (choose) { for (i, v) in values { if (i == 1) { return input; } else { n = input; } } } else { n = input; } return n;"),
        ("require(helper(input, choose) == input);", "ECPoint n; if (choose) { if (true) { return input; } else { n = {x: input, y: 9}; } } else { n = {x: input, y: 9}; } return n.x;"),
    ]) {
        let source = format!(r#"contract C() {{
            private function helper(int input, bool choose) int {{
                {helper}
            }}
            function spend(int input, bool choose) {{
                require(choose == choose);
                {body}
                if (choose) {{ require(input > 0); }} else {{ require(input <= 0); }}
            }}
        }}"#);
        let optimized = asm(&source);
        let raw = arkade_asm_tokens(&compile_unoptimized(&source).unwrap(), "spend");
        for input in -3..=3 {
            for choose in [0, 1] {
                let witness = vec![choose, input];
                let expected = choose == i128::from(input > 0)
                    && (!body.contains("values[input % 3]") || input % 3 >= 0);
                assert_eq!(execute(&optimized, witness.clone()), expected, "optimized: input={input}, choose={choose}: {body}");
                assert_eq!(execute(&raw, witness), expected, "unoptimized: input={input}, choose={choose}: {body}");
            }
        }
    }
}

#[test]
fn folding_keeps_byte_size_failures_and_concatenation() {
    let source = "contract C() { function spend(bytes expected) { require(bytes32(num2bin(1, 1)) == expected); } }";
    assert!(asm(source).iter().any(|token| token == "OP_SIZE"));
    let oversized = "00".repeat(521);
    let source = format!(
        "contract C() {{ function spend() {{ require(0x{oversized} == 0x{oversized}); }} }}"
    );
    assert!(asm(&source).iter().any(|token| token == "OP_EQUAL"));
    let source =
        "contract C() { function spend(bytes expected) { require(0x01 + 0x02 == expected); } }";
    assert!(asm(source).iter().any(|token| token == "OP_CAT"));
}

#[test]
fn a_covenant_that_only_checks_its_witness_keeps_the_final_verify() {
    for body in ["require(b);", "require(1 < 2); require((0 < 1 || b) && b);"] {
        let source = format!("contract C() {{ function spend(bool b) {{ {body} }} }}");
        assert_eq!(asm(&source), ["OP_VERIFY", "OP_1"], "{body}");
    }
}
