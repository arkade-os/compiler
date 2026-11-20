use crate::common::{
    arkade_asm, arkade_asm_tokens, compile_unoptimized as compile, group, leaf_asm,
    opcode_count_in_arkade, witness_names,
};
use arkade_compiler::opcodes::{OP_GREATERTHAN, OP_MUL, OP_PUT};

fn contains_tokens(asm: &[String], expected: &[&str]) -> bool {
    asm.windows(expected.len()).any(|window| {
        window
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied())
    })
}

#[test]
fn artifact_types_list_sizes_outermost_first_and_leaves_flatten_row_by_row() {
    let output = compile(
        r#"
struct Board { int[2][3] cells; }
contract Nested(pubkey[2][2] keys, Board board) {
    function spend(int[2][3] grid, signature sig) {
        require(grid[1][2] == board.cells[0][1]);
        require(checkSig(sig, keys[0][1]));
    }

    function exit(signature sig) tapscript {
        require(older(blocks(144)));
        require(checkSig(sig, keys[1][0]));
    }
}
"#,
    )
    .expect("nested arrays compile");

    let types = |parameters: &[arkade_compiler::models::Parameter]| {
        parameters
            .iter()
            .map(|p| (p.name.clone(), p.param_type.to_string()))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        types(&output.parameters),
        [
            ("keys".to_string(), "pubkey[2][2]".to_string()),
            ("board".to_string(), "Board".to_string())
        ]
    );
    assert_eq!(
        types(&output.structs[0].fields),
        [("cells".to_string(), "int[2][3]".to_string())]
    );
    let inputs = &group(&output, "spend").arkade.as_ref().unwrap().inputs;
    assert_eq!(
        inputs
            .iter()
            .map(|input| (input.name.as_str(), input.param_type.as_str()))
            .collect::<Vec<_>>(),
        [("grid", "int[2][3]"), ("sig", "signature")]
    );

    // The leaf name walks the indexes outermost first, so row 0, column 1 of `board.cells`.
    let asm = arkade_asm(&output, "spend");
    for placeholder in ["<board.cells.0.1>", "<keys.0.1>"] {
        assert!(asm.contains(placeholder), "{placeholder}: {asm}");
    }
    assert!(!asm.contains("<keys.1.0>"), "{asm}");
    assert_eq!(
        leaf_asm(&output, "spend", "spend"),
        "<OPERATOR_KEY:spend> OP_CHECKSIG"
    );
    assert_eq!(witness_names(&output, "spend", "spend"), ["operatorSig"]);
    assert_eq!(
        leaf_asm(&output, "exit", "exit"),
        "144 OP_CHECKSEQUENCEVERIFY OP_DROP <keys.1.0> OP_CHECKSIG"
    );
    assert_eq!(witness_names(&output, "exit", "exit"), ["sig"]);
}

#[test]
fn runtime_indexes_scale_by_the_width_of_each_level_and_check_its_bound() {
    for (declaration, read, windows) in [
        // Two rows of three: the row index is below 2 and scales by 3.
        (
            "int[2][3] values",
            "values[i][j] == 7",
            &[
                &["OP_0", "OP_2", "OP_WITHIN", "OP_VERIFY", "OP_3", OP_MUL][..],
                &["OP_0", "OP_3", "OP_WITHIN", "OP_VERIFY", "OP_ADD"],
            ][..],
        ),
        (
            "int[2][3][4] values",
            "values[i][j][k] == 7",
            &[
                &["OP_0", "OP_2", "OP_WITHIN", "OP_VERIFY", "OP_12", OP_MUL][..],
                &[
                    "OP_0",
                    "OP_3",
                    "OP_WITHIN",
                    "OP_VERIFY",
                    "OP_4",
                    OP_MUL,
                    "OP_ADD",
                ],
                &["OP_0", "OP_4", "OP_WITHIN", "OP_VERIFY", "OP_ADD"],
            ],
        ),
        // A point is two leaves, so a row of three is six.
        (
            "Point[2][3] values",
            "values[i][j].y == 7",
            &[
                &["OP_0", "OP_2", "OP_WITHIN", "OP_VERIFY", "OP_6", OP_MUL][..],
                &[
                    "OP_0",
                    "OP_3",
                    "OP_WITHIN",
                    "OP_VERIFY",
                    "OP_2",
                    OP_MUL,
                    "OP_ADD",
                ],
            ],
        ),
    ] {
        let output = compile(&format!(
            "struct Point {{ int x; int y; }}
            contract C() {{
                function spend(int i, int j, int k, {declaration}) {{ require(k >= 0); require({read}); }}
            }}"
        ))
        .expect(declaration);
        let asm = arkade_asm_tokens(&output, "spend");
        for window in windows {
            assert!(
                contains_tokens(&asm, window),
                "{declaration}: {window:?} in {asm:?}"
            );
        }
    }
}

#[test]
fn rows_assign_compare_and_pass_as_values_with_runtime_indexes() {
    let output = compile(
        r#"
contract C() {
    private function sum(int[3] row) int { return row[0] + row[1] + row[2]; }
    private function grid(int v) int[2][3] { return [[v, v, v], [v, v, v]]; }
    function spend(int i, int j, int v, int[2][3] values, int[3] row) {
        int[2][3] local = grid(v);
        local[i] = row;
        local[i][j] = v;
        require(local[i] == values[1 - i]);
        require(sum(values[i]) == v);
        require(local != values);
    }
}
"#,
    )
    .expect("rows are values");
    // The row write puts three leaves and the element write one.
    assert_eq!(opcode_count_in_arkade(&output, "spend", OP_PUT), 4);
}

#[test]
fn loops_iterate_nested_arrays_rows_and_literals_of_arrays() {
    let output = compile(
        r#"
contract C() {
    const int ROWS = 2;
    const int COLUMNS = 3;
    function spend(int v, int[ROWS][COLUMNS] values) {
        for (r, row) in values {
            for (c, cell) in row {
                require(cell > r + c);
            }
        }
        for (r, pair) in [[v, 1], [2, v]] {
            require(pair[0] + pair[1] > r);
        }
    }
}
"#,
    )
    .expect("nested loops unroll");
    assert_eq!(
        group(&output, "spend").arkade.as_ref().unwrap().inputs[1].param_type,
        "int[2][3]"
    );
    assert_eq!(opcode_count_in_arkade(&output, "spend", OP_GREATERTHAN), 8);
}

#[test]
fn diagnostics_spell_nested_types_outermost_first() {
    for (body, expected) in [
        (
            "int[2][3] m = [[1, 2, 3], [4, 5, 6]]; int[3][2] n = m; require(n[0][0] == v);",
            "binding 'n' declares type 'int[3][2]' but initializer has type 'int[2][3]'",
        ),
        (
            "int[2][3] m = [[1, 2], [3, 4, 5]]; require(m[0][0] == v);",
            "element 0: expected 3 array elements, got 2",
        ),
        (
            "int[2][3] m = [[1, 2, 3], [4, 5, 6]]; require(m[0][3] == v);",
            "array index '3' is out of range for 'm[0][3]'",
        ),
        (
            "int[3] ks = [0, 1, 2]; for (k, x) in ks { require(grid(v)[k][0] == x); }",
            "array index '2' is out of range for 'int[2][3]'",
        ),
    ] {
        let error = compile(&format!(
            "contract C() {{
                private function grid(int v) int[2][3] {{ return [[v, v, v], [v, v, v]]; }}
                function spend(int v) {{ {body} }}
            }}"
        ))
        .expect_err(body)
        .to_string();
        assert!(error.contains(expected), "{body}: {error}");
    }
}
