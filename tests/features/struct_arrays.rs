use crate::common::{
    arkade_asm, arkade_asm_tokens, arkade_inputs, compile_unoptimized as compile, group, leaf_asm,
    witness_names,
};

#[test]
fn struct_array_inputs_flatten_and_runtime_fields_select_the_right_slot() {
    let output = compile(
        r#"
struct Point { int x; int y; }
contract C() {
    function spend(Point[2] points, int index, int expected) {
        require(points[index + 0].y == expected);
    }
}
"#,
    )
    .unwrap();
    assert_eq!(
        arkade_inputs(&output, "spend"),
        ["points", "index", "expected"]
    );
    assert_eq!(group(&output, "spend").leaves.len(), 1);
    assert_eq!(
        witness_names(&output, "spend", "spend"),
        ["serverSig", "emulatorSig"]
    );
    assert_eq!(
        leaf_asm(&output, "spend", "spend"),
        "<SERVER_KEY> OP_CHECKSIGVERIFY <EMULATOR_KEY:spend> OP_CHECKSIG"
    );
    let asm = arkade_asm_tokens(&output, "spend");
    assert!(asm.iter().any(|op| op == "OP_MUL"));
}

#[test]
fn nested_array_fields_support_local_literals_mutation_and_composite_helpers() {
    let output = compile(
        r#"
struct Point { int x; int y; }
struct Row { Point[2] points; int marker; }
contract C() {
    private function sum(Point point) int { return point.x + point.y; }
    function spend(int row, int column, int next) {
        Row[2] rows = [
            { points: [{ x: 11, y: 12 }, { x: 13, y: 14 }], marker: 15 },
            { points: [{ x: 21, y: 22 }, { x: 23, y: 24 }], marker: 25 }
        ];
        rows[row].points[column].y = next;
        require(rows[row].points[column].y == next);
        require(sum(rows[row].points[column]) == rows[row].points[column].x + next);
        let selected = rows[row].points[column];
        require(selected.y == next);
        require(rows[0].marker == 15);
        require(rows[1].marker == 25);
        require(rows[row].points.length == 2);
    }
}
"#,
    )
    .unwrap();
    let asm = arkade_asm_tokens(&output, "spend");
    assert!(asm.iter().any(|op| op == "OP_PUT"));
}

#[test]
fn loops_comparisons_native_structs_and_constructor_arrays_compile() {
    let output = compile(
        r#"
struct Item { int value; Outpoint position; }
struct State { Item[2] items; }
contract C(State state) {
    private function copy(Item[2] items) Item[2] { return items; }
    function spend(Item[2] provided) {
        require(state.items == provided);
        Item[2] local = copy(provided);
        for (index, item) in local {
            require(item.value == state.items[index].value);
            require(item.position == provided[index].position);
        }
        require(tx.outputs[0].scriptPubKey == new C(state));
    }
}
"#,
    )
    .unwrap();
    let asm = arkade_asm_tokens(&output, "spend");
    assert!(asm.contains(&"<state.items.1.position.vout>".to_string()));
    assert!(asm.iter().any(|token| token.starts_with("<CONTRACT:C(")
        && token.contains("<state.items.0.position.txid>")));
    assert!(!asm
        .iter()
        .any(|token| token.contains("<item") || token.contains("<index")));

    compile(
        r#"
contract C(Outpoint[2] positions) {
    function spend(int index, int vout) { require(positions[index].vout == vout); }
}
"#,
    )
    .unwrap();
}

#[test]
fn indexed_crypto_operands_and_constructor_tapleaf_fields_compile() {
    let output = compile(r#"
struct Signer { pubkey key; signature sig; int delay; }
contract C(Signer[2] owners) {
    function spend(int index, Signer[2] signers) {
        require(checkSig(signers[index].sig, owners[index].key));
    }
    function exit(signature sig) tapscript { require(older(owners[1].delay)); require(checkSig(sig, owners[1].key)); }
}
"#).unwrap();
    assert!(arkade_asm_tokens(&output, "spend")
        .iter()
        .any(|op| op == "OP_CHECKSIG"));
    assert!(leaf_asm(&output, "exit", "exit").contains("<owners.1.key>"));
}

#[test]
fn struct_array_errors_are_rejected_before_emission() {
    for (body, expected) in [
        (
            "Point[2] points = [{ x: 1, y: 2 }]; require(true);",
            "expected 2 array elements",
        ),
        (
            "Point[1] points = [{ x: 1 }]; require(true);",
            "missing field 'y'",
        ),
        (
            "Point[1] points = [{ x: true, y: 2 }]; require(true);",
            "expected 'int'",
        ),
        (
            "Point[1] points = [{ x: 1, y: 2 }]; require(points[1].x == 1);",
            "out of range",
        ),
        (
            "Point[1] points = [{ x: 1, y: 2 }]; require(points[-1].x == 1);",
            "out of range",
        ),
        (
            "Point[1] points = [{ x: 1, y: 2 }]; require(points[true].x == 1);",
            "expected 'int'",
        ),
        (
            "Point[1] points = [{ x: 1, y: 2 }]; require(points[0].missing == 1);",
            "undefined",
        ),
        (
            "Point[1] points = [{ x: 1, y: 2 }]; points[0].x = true; require(true);",
            "changes its type",
        ),
    ] {
        let source = format!(
            "struct Point {{ int x; int y; }} contract C() {{ function spend() {{ {body} }} }}"
        );
        let error = compile(&source).expect_err(&source).to_string();
        assert!(error.contains(expected), "{source}: {error}");
    }
    let error = compile("struct Row { int[2] values; } contract C() { function spend() { Row[1] rows = [{ values: [1, 2] }]; rows[0].values.length = 1; require(true); } }").unwrap_err().to_string();
    assert!(
        error.contains("assignment target is not a binding"),
        "{error}"
    );
    let error = compile("struct Point { int x; } contract C(Point[2] points) { function spend(int index) { points[index].x = 1; require(true); } }").unwrap_err().to_string();
    assert!(
        error.contains("cannot assign to constructor parameter"),
        "{error}"
    );
}

#[test]
fn struct_array_loops_preserve_nested_scalar_arrays_and_field_types() {
    let output = compile(
        r#"
struct Row { int[2] values; int[1] length; }
contract C() {
    function spend(int index) {
        Row[2] rows = [{ values: [11, 12], length: [101] }, { values: [21, 22], length: [102] }];
        require(rows[index].length.length == 1);
        for (i, row) in rows {
            require(row.length.length == 1);
            require(row.values[index] == rows[i].values[index]);
            for (j, value) in row.values { require(value == rows[i].values[j]); }
        }
    }
}
"#,
    )
    .unwrap();
    let asm = arkade_asm_tokens(&output, "spend");
    assert!(asm.iter().any(|op| op == "OP_LESSTHAN"));

    compile(
        r#"
struct Signer { pubkey key; }
contract C(Signer[2] owners) {
    const int FIRST = 0;
    const int LAST = 1;
    function spend(signature sig) {
        for (index, owner) in owners {
            require(checkSig(sig, owners[index].key));
        }
        require(checkSig(sig, owners[FIRST].key));
        require(checkSig(sig, owners[LAST].key));
    }
}
"#,
    )
    .unwrap();
}

#[test]
fn native_struct_array_elements_support_tunnel_exceptions() {
    let output = compile(r#"
contract C() {
    function spend(AssetId[2] ids, int index) {
        require(this.tunnel(0, { scriptPubKey: true, value: true, assets: true }, [ids[index], ids[0]]));
    }
}
"#).unwrap();
    let asm = arkade_asm_tokens(&output, "spend");
    assert!(asm.windows(2).any(|tokens| tokens == ["2", "OP_TUNNEL"]));
    assert_eq!(asm.iter().filter(|token| *token == "OP_SWAP").count(), 2);
}

#[test]
fn loop_values_resolve_inside_named_operands_and_nested_iterables() {
    let output = compile(
        r#"
struct Signer { pubkey[2] keys; }
contract C(Signer[2] signers) {
    function spend(signature sig) {
        for (i, s) in signers { require(checkSig(sig, s.keys[i])); }
    }
}
"#,
    )
    .unwrap();
    // Iteration k checks signers[k].keys[k].
    assert_eq!(
        arkade_asm(&output, "spend"),
        "<signers.1.keys.1> <signers.1.keys.0> <signers.0.keys.1> <signers.0.keys.0> \
         OP_4 OP_PICK OP_1 OP_PICK OP_CHECKSIG OP_VERIFY \
         OP_4 OP_PICK OP_4 OP_PICK OP_CHECKSIG OP_VERIFY OP_1 OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP"
    );

    for body in [
        "for (i, x) in idx { for (j, s) in signers { require(checkSig(sig, s.keys[i])); } }",
        "for (i, item) in items { for (j, w) in item.idx { require(checkSig(sig, signers[0].keys[w])); } }",
        "for (j, w) in items[1].idx { require(checkSig(sig, signers[w].keys[j])); }",
        "for (i, item) in items { for (j, w) in items[i].idx { require(w > j); } } require(checkSig(sig, signers[0].keys[0]));",
    ] {
        let source = format!(
            "struct Signer {{ pubkey[2] keys; }} struct It {{ int[2] idx; }} \
             contract C(Signer[2] signers, It[2] items, int[2] idx) {{ function spend(signature sig) {{ {body} }} }}"
        );
        compile(&source).unwrap_or_else(|error| panic!("{body}: {error}"));
    }
}

#[test]
fn access_diagnostics_report_the_written_path_once() {
    for (body, expected) in [
        (
            "require(rows[5].points[t].x == 1);",
            "array index '5' is out of range for 'rows[2]'",
        ),
        (
            "require(rows[t].points[5].x == 1);",
            "array index '5' is out of range for 'rows[t].points[2]'",
        ),
        (
            "require(rows[t].points[0].z == 1);",
            "field 'rows[t].points[0].z' is undefined",
        ),
        (
            "P p = rows[t].points; require(p.x == 1);",
            "binding 'p' declares type 'P'",
        ),
    ] {
        let source = format!(
            "struct P {{ int x; }} struct Row {{ P[2] points; }} \
             contract C(Row[2] rows) {{ function spend(int t) {{ {body} }} }}"
        );
        let error = compile(&source).unwrap_err().to_string();
        assert!(error.contains(expected), "{body}: {error}");
        assert_eq!(
            error.matches("validation error").count(),
            1,
            "{body}: {error}"
        );
    }
}

#[test]
fn loop_values_alias_scalar_helper_arguments() {
    let output = compile(
        r#"
contract C() {
    private function positive(int value) { require(value > 0); }
    function spend(int[2] xs) {
        for (i, x) in xs { positive(x); }
    }
}
"#,
    )
    .unwrap();
    // The helper reads each element in place instead of copying it into an argument slot.
    assert_eq!(
        arkade_asm(&output, "spend"),
        "OP_0 OP_PICK 0 OP_GREATERTHAN OP_VERIFY OP_1 OP_PICK 0 OP_GREATERTHAN OP_VERIFY OP_1 OP_NIP OP_NIP"
    );
}
