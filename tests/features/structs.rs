use crate::common::compile_unoptimized as compile;
use arkade_compiler::opcodes::{
    OP_ADD, OP_BOOLAND, OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_DUP, OP_ENDIF, OP_EQUAL,
    OP_EQUALVERIFY, OP_GREATERTHANOREQUAL, OP_INSPECTASSETGROUPASSETID, OP_INSPECTINPUTOUTPOINT,
    OP_LESSTHAN, OP_NOT, OP_PICK, OP_PUT, OP_ROLL, OP_SWAP, OP_VERIFY,
};

#[test]
fn struct_definitions_are_preserved_in_the_artifact() {
    let output = compile(
        r#"
struct Signer {
    pubkey key;
    int weight;
}

struct Policy {
    Signer primary;
    int[2] limits;
}

contract Vault(Policy policy) {
    function spend() {
        require(true);
    }
}
"#,
    )
    .expect("struct declarations should compile");

    assert_eq!(output.structs.len(), 2);
    assert_eq!(output.structs[0].name, "Signer");
    assert_eq!(output.structs[0].fields[0].name, "key");
    assert_eq!(output.structs[1].fields[0].param_type.to_string(), "Signer");
    assert_eq!(output.parameters[0].param_type.to_string(), "Policy");
}

#[test]
fn forward_struct_references_are_allowed() {
    compile(
        r#"
struct Outer {
    Inner inner;
}

struct Inner {
    int value;
}

contract Forward(Outer value) {
    function spend() {
        require(true);
    }
}
"#,
    )
    .expect("struct layouts are resolved after parsing all definitions");
}

#[test]
fn invalid_struct_layouts_are_rejected() {
    let cases = [
        (
            r#"
struct Bad { Missing value; }
contract C(Bad value) { function spend() { require(true); } }
"#,
            "unknown type 'Missing'",
        ),
        (
            r#"
struct Node { Node child; }
contract C(Node value) { function spend() { require(true); } }
"#,
            "recursive struct layout",
        ),
        (
            r#"
struct Item { Item[2] values; }
contract C(Item item) { function spend() { require(true); } }
"#,
            "recursive struct layout",
        ),
        (
            r#"
struct Pair { int value; bool value; }
contract C(Pair pair) { function spend() { require(true); } }
"#,
            "duplicate field 'value'",
        ),
        (
            r#"
struct AssetId { bytes32 txid; int gidx; }
contract C() { function spend() { require(true); } }
"#,
            "collides with a built-in type",
        ),
    ];

    for (source, expected) in cases {
        let error = compile(source).expect_err(expected).to_string();
        assert!(error.contains(expected), "unexpected error: {error}");
    }
}

#[test]
fn struct_tapscript_inputs_are_rejected() {
    let error = compile(
        r#"
struct Proof { bytes preimage; }
contract C(pubkey owner) {
    function exit(Proof proof, signature sig) tapscript {
        require(checkSig(sig, owner));
    }
}
"#,
    )
    .expect_err("struct tapscript witness")
    .to_string();

    assert!(error.contains("struct witnesses are not supported"));
}

#[test]
fn nested_struct_parameters_flatten_and_fields_read_by_stack_depth() {
    let output = compile(
        r#"
struct Signer {
    pubkey key;
    int weight;
}

struct Policy {
    Signer primary;
    int[2] limits;
}

contract Vault(Policy policy) {
    function spend(Policy candidate, signature sig, bytes32 message) {
        require(checkSigFromStack(sig, policy.primary.key, message));
        require(candidate.limits[1] >= policy.primary.weight);
        require(policy.limits.length == 2);
    }
}
"#,
    )
    .expect("nested struct fields should compile");

    assert_eq!(output.parameters[0].param_type.to_string(), "Policy");
    let arkade = output.functions[0].arkade.as_ref().expect("covenant");
    assert_eq!(arkade.inputs[0].name, "candidate");
    assert_eq!(arkade.inputs[0].param_type, "Policy");
    // Constructor leaves are pushed at their only read; `limits` is only measured.
    let asm = arkade.asm.join(" ");
    assert!(
        asm.contains(&format!(
            "OP_4 OP_ROLL <policy.primary.key> OP_6 OP_ROLL OP_SWAP {OP_CHECKSIGFROMSTACK}"
        )),
        "{asm}"
    );
    assert!(
        asm.contains("OP_3 OP_PICK <policy.primary.weight> OP_GREATERTHANOREQUAL"),
        "{asm}"
    );
    assert!(!asm.contains("policy.limits"), "{asm}");
}

#[test]
fn unknown_fields_and_bare_struct_values_are_rejected() {
    let unknown = compile(
        r#"
struct Point { int x; int y; }
contract C(Point point) {
    function spend() { require(point.z == 0); }
}
"#,
    )
    .expect_err("unknown field")
    .to_string();
    assert!(
        unknown.contains("field 'point.z' is undefined"),
        "{unknown}"
    );

    let composite = compile(
        r#"
struct Point { int x; int y; }
contract C(Point point) {
    function spend() { require(point); }
}
"#,
    )
    .expect_err("bare struct")
    .to_string();
    assert!(
        composite.contains("struct expressions are composite values"),
        "{composite}"
    );
}

#[test]
fn struct_equality_compares_every_field() {
    let output = compile(
        r#"
struct Point { int x; int y; }
struct Pair { Point a; Point b; }
contract C(Pair left) {
    function spend(Pair right) { require(left == right); }
}
"#,
    )
    .expect("struct equality compares leaf by leaf");
    let asm = crate::common::arkade_asm_tokens(&output, "spend");
    assert_eq!(
        asm.iter().filter(|token| *token == OP_EQUALVERIFY).count(),
        4,
        "every leaf of the nested struct is verified: {asm:?}"
    );

    let mismatch = compile(
        r#"
struct Point { int x; int y; }
struct Pair { Point a; Point b; }
contract C(Point point) {
    function spend(Pair pair) { require(point == pair); }
}
"#,
    )
    .expect_err("structs with different layouts")
    .to_string();
    assert!(
        mismatch.contains("comparison '==' is not defined between 'Point' and 'Pair'"),
        "{mismatch}"
    );

    let widened = compile(
        r#"
contract C(bytes[1] a) {
    function spend(bytes20[1] b) { require(a == b); }
}
"#,
    )
    .expect_err("element types must match exactly")
    .to_string();
    assert!(
        widened.contains("comparison '==' is not defined between 'bytes[1]' and 'bytes20[1]'"),
        "{widened}"
    );
}

#[test]
fn struct_inequality_checks_the_final_leaf() {
    let output = compile(
        "struct Point { int x; int y; }
         struct Pair { Point a; Point b; }
         contract C() {
             function spend() {
                 Pair left = {a: {x: 1, y: 2}, b: {x: 3, y: 4}};
                 Pair right = {a: {x: 1, y: 2}, b: {x: 3, y: 5}};
                 require(left != right);
             }
         }",
    )
    .expect("only the final leaf differs");
    let asm = crate::common::arkade_asm_tokens(&output, "spend");
    assert_eq!(asm.iter().filter(|token| *token == OP_EQUAL).count(), 4);
    assert_eq!(asm.iter().filter(|token| *token == OP_BOOLAND).count(), 3);
    assert!(
        asm.windows(4)
            .any(|tokens| tokens == [OP_EQUAL, OP_BOOLAND, OP_NOT, OP_VERIFY]),
        "{asm:?}"
    );
}

#[test]
fn composite_types_do_not_outlive_their_bindings() {
    let after_call = compile(
        r#"
struct Res { int selected; int other; }
contract C() {
    private function same(Res left, Res right) { require(left == right); }
    function spend(Res a, Res b, int left) {
        same(a, b);
        require(left == 1);
    }
}
"#,
    )
    .expect("helper parameter types stay inside the helper");
    assert!(crate::common::arkade_asm(&after_call, "spend").contains(OP_EQUALVERIFY));

    let after_block = compile(
        r#"
struct Point { int x; int y; }
contract C() {
    function spend(int flag) {
        if (flag == 1) {
            Point q = { x: 1, y: 2 };
            require(q.x == 1);
        }
        let q = 5;
        require(q == 5);
    }
}
"#,
    )
    .expect("block-local struct types end with the block");
    assert!(crate::common::arkade_asm(&after_block, "spend").contains(OP_ENDIF));
}

#[test]
fn constructor_struct_arguments_expand_recursively() {
    let output = compile(
        r#"
struct Point { int x; int y; }
contract C(Point point) {
    function renew() {
        require(tx.outputs[0].script == new C(point));
    }
}
"#,
    )
    .expect("whole constructor struct argument");

    assert!(output.functions[0]
        .arkade
        .as_ref()
        .expect("covenant")
        .asm
        .contains(&"<CONTRACT:C(<point.x>,<point.y>)>".to_string()));
}

#[test]
fn constructor_struct_fields_are_available_to_tapscripts() {
    let output = compile(
        r#"
struct Owner { pubkey key; int exit; }
contract C(Owner owner) {
    function exit(signature sig) tapscript {
        require(older(owner.exit));
        require(checkSig(sig, owner.key));
    }
}
"#,
    )
    .expect("scalar constructor fields in tapscript");

    let asm = &output.functions[0].leaves[0].asm;
    assert!(asm.contains(&"<owner.exit>".to_string()));
    assert!(asm.contains(&"<owner.key>".to_string()));
    assert!(asm.contains(&OP_CHECKSIG.to_string()));
}

#[test]
fn composite_constructor_values_are_rejected_in_tapscripts() {
    let error = compile(
        r#"
struct Delay { int blocks; }
struct Policy { Delay exit; }
contract C(Policy policy, pubkey owner) {
    function exit(signature sig) tapscript {
        require(older(policy.exit));
        require(checkSig(sig, owner));
    }
}
"#,
    )
    .expect_err("intermediate struct values are not tapscript operands")
    .to_string();

    assert!(
        error.contains("timelock `policy.exit` is not a literal"),
        "{error}"
    );
}

#[test]
fn array_fields_support_runtime_indexing_and_loop_unrolling() {
    let output = compile(
        r#"
struct Values { int[3] items; }
contract C(Values values) {
    function spend(int index, int expected) {
        int total = 0;
        for (i, value) in values.items {
            total = total + value;
        }
        require(values.items[index] + total == expected);
    }
}
"#,
    )
    .expect("array fields should retain array behavior");

    let asm = &output.functions[0].arkade.as_ref().expect("covenant").asm;
    assert!(asm.windows(2).any(|tokens| tokens == ["OP_3", OP_LESSTHAN]));
    assert!(asm.iter().filter(|token| token.as_str() == OP_ADD).count() >= 4);
}

#[test]
fn local_struct_array_field_supports_expression_index_assignment() {
    let output = compile(
        r#"
struct State { int[3] values; }
contract C() {
    function spend(int index, int next) {
        State state = { values: [1, 2, 3] };
        state.values[index + 1] = next;
        require(state.values[index + 1] == next);
    }
}
"#,
    )
    .expect("local struct array fields should support expression-indexed assignment");

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
        ["index", "next"]
    );
    let asm = &covenant.asm;
    assert!(asm.iter().any(|token| token == OP_PUT), "{asm:?}");
    assert!(
        asm.windows(4)
            .any(|tokens| { tokens == [OP_DUP, "OP_0", OP_GREATERTHANOREQUAL, OP_VERIFY] }),
        "missing lower-bound check: {asm:?}"
    );
    assert!(
        asm.windows(4)
            .any(|tokens| { tokens == [OP_DUP, "OP_3", OP_LESSTHAN, OP_VERIFY] }),
        "missing upper-bound check: {asm:?}"
    );
}

#[test]
fn dotted_paths_distinguish_underscores_from_nesting() {
    let output = compile(
        r#"
struct Inner { int b; }
struct Ambiguous { int a_b; Inner a; }
contract C(Ambiguous value) {
    function spend() { require(value.a_b == value.a.b); }
}
"#,
    )
    .expect("dotted field paths are unambiguous");

    assert_eq!(
        &output.functions[0].arkade.as_ref().expect("covenant").asm[..2],
        ["<value.a_b>", "<value.a.b>"]
    );
}

#[test]
fn group_property_names_are_valid_struct_fields() {
    let output = compile(
        r#"
struct Token { int assetId; }
contract C(Token token) {
    function spend() { require(token.assetId >= 0); }
}
"#,
    )
    .expect("asset-group property names should remain valid struct fields");

    let asm = &output.functions[0].arkade.as_ref().expect("covenant").asm;
    assert!(asm.iter().all(|token| token != OP_INSPECTASSETGROUPASSETID));
    assert_eq!(asm[0], "<token.assetId>");
}

#[test]
fn local_struct_literals_bind_and_assign_scalar_leaves() {
    let output = compile(
        r#"
struct Signer { pubkey key; int weight; }
struct Policy { Signer primary; int[2] limits; }
contract C() {
    function spend(pubkey key, int replacement) {
        Policy policy = {
            limits: [1, 2],
            primary: { weight: 3, key: key }
        };
        policy.primary.weight = replacement;
        policy.limits[1] = replacement;
        require(policy.primary.weight == policy.limits[1]);
    }
}
"#,
    )
    .expect("local struct leaves should behave like scalar locals");

    let asm = &output.functions[0].arkade.as_ref().expect("covenant").asm;
    assert!(asm.iter().all(|token| !token.contains("policy.")));
    assert!(asm.iter().filter(|token| *token == OP_PICK).count() >= 2);
    assert!(asm.iter().any(|token| token == OP_EQUAL));
}

#[test]
fn native_results_can_initialize_nested_struct_fields() {
    let output = compile(
        r#"
struct Snapshot { Outpoint outpoint; int minimumVout; }
contract C(Snapshot expected) {
    function spend(int inputIndex) {
        Snapshot snapshot = {
            outpoint: tx.inputs[inputIndex].outpoint,
            minimumVout: expected.minimumVout
        };
        require(snapshot.outpoint.vout >= expected.outpoint.vout);
    }
}
"#,
    )
    .expect("native struct result nested in a user struct");

    let asm = &output.functions[0].arkade.as_ref().expect("covenant").asm;
    assert_eq!(asm[0], "<expected.minimumVout>");
    assert!(asm
        .windows(2)
        .any(|tokens| tokens == ["<expected.outpoint.vout>", "OP_GREATERTHANOREQUAL"]));
    assert!(asm.iter().all(|token| token != "<expected.outpoint.txid>"));
    assert!(asm.iter().any(|token| token == OP_INSPECTINPUTOUTPOINT));
    assert!(asm.iter().any(|token| token == OP_SWAP));
    assert!(asm.iter().filter(|token| *token == OP_ROLL).count() >= 2);
}

#[test]
fn struct_literals_require_the_exact_declared_shape() {
    let cases = [
        (
            r#"
struct Point { int x; int y; }
contract C() { function spend() { Point point = { x: 1 }; require(true); } }
"#,
            "missing field 'y'",
        ),
        (
            r#"
struct Point { int x; int y; }
contract C() { function spend() { Point point = { x: 1, y: 2, z: 3 }; require(true); } }
"#,
            "unknown field 'z'",
        ),
        (
            r#"
struct Point { int x; int y; }
contract C() { function spend() { Point point = { x: 1, x: 2, y: 3 }; require(true); } }
"#,
            "duplicate field 'x'",
        ),
        (
            r#"
struct Values { int[2] items; }
contract C() { function spend() { Values values = { items: [1] }; require(true); } }
"#,
            "expected 2 array elements",
        ),
        (
            r#"
struct Point { int x; int y; }
contract C() { function spend() { Point point = { x: true, y: 2 }; require(true); } }
"#,
            "expected 'int', got 'bool'",
        ),
        (
            r#"
struct Point { int x; int y; }
contract C() { function spend() { let point = { x: 1, y: 2 }; require(true); } }
"#,
            "needs a declared struct type",
        ),
    ];

    for (source, expected) in cases {
        let error = compile(source).expect_err(expected).to_string();
        assert!(error.contains(expected), "unexpected error: {error}");
    }
}

#[test]
fn whole_struct_copy_and_constructor_field_assignment_are_rejected() {
    let copy = compile(
        r#"
struct Point { int x; int y; }
contract C(Point initial) {
    function spend() {
        Point copied = initial;
        require(copied.x == 1);
    }
}
"#,
    )
    .expect_err("whole struct copy")
    .to_string();
    assert!(copy.contains("matching struct value"), "{copy}");

    let mutation = compile(
        r#"
struct Point { int x; int y; }
contract C(Point point) {
    function spend(int next) {
        point.x = next;
        require(point.x == next);
    }
}
"#,
    )
    .expect_err("constructor field mutation")
    .to_string();
    assert!(
        mutation.contains("cannot assign to constructor parameter 'point.x'"),
        "{mutation}"
    );
}

#[test]
fn shared_nested_structs_are_validated_once() {
    let mut source = String::from("struct S0 { Missing m; }\n");
    for level in 1..=12 {
        source.push_str(&format!(
            "struct S{level} {{ S{prev} a; S{prev} b; }}\n",
            prev = level - 1
        ));
    }
    source.push_str("contract C(S12 q) { function f() { require(true); } }\n");

    let error = compile(&source)
        .expect_err("an unknown field type must be rejected")
        .to_string();
    assert_eq!(
        error.matches("unknown type 'Missing'").count(),
        1,
        "expected one diagnostic per bad field, got: {error}"
    );
}

#[test]
fn whitespace_around_field_separators_is_ignored() {
    compile(
        r#"
struct Policy { pubkey key; int weight; bytes32 txid; int gidx; }
contract C(Policy policy) {
    function spend(int amount) {
        require(amount == policy . weight);
        require(tx.outputs[0].assets.lookup(policy . txid, policy . gidx) >= 0);
    }
}
"#,
    )
    .expect("interior whitespace in a field path is insignificant");
}

#[test]
fn struct_fields_are_accepted_as_hash_and_timelock_operands() {
    compile(
        r#"
struct Terms { bytes32 digest; int deadline; }
contract C(Terms terms) {
    function claim(bytes preimage) {
        require(tx.locktime >= terms.deadline);
        require(sha256(preimage) == terms.digest);
    }
}
"#,
    )
    .expect("struct fields are valid hash and timelock operands");
}

#[test]
fn native_result_structs_are_valid_parameter_types() {
    let output = compile(
        r#"
contract C(AssetId expected) {
    function spend(Outpoint previous, int vout) {
        require(previous.vout == vout);
        require(previous.txid == expected.txid);
    }
}
"#,
    )
    .expect("native result structs flatten like any other struct");

    assert_eq!(output.parameters[0].param_type.to_string(), "AssetId");
    let covenant = output.functions[0].arkade.as_ref().expect("covenant");
    assert_eq!(covenant.inputs[0].param_type, "Outpoint");
    assert!(
        covenant
            .asm
            .windows(2)
            .any(|tokens| tokens == ["<expected.txid>", "OP_EQUAL"]),
        "{:?}",
        covenant.asm
    );
    assert!(covenant.asm.iter().all(|token| token != "<expected.gidx>"));
}

#[test]
fn a_field_named_length_outranks_the_array_length_form() {
    let output = compile(
        r#"
struct Packet { int length; int[3] payload; }
struct Wrapper { Packet length; }
struct ArrayField { int[2] length; }
contract C(Packet packet, Wrapper wrapper, ArrayField array) {
    function spend(int expected) {
        require(packet.length == expected);
        require(packet.payload.length == 3);
        require(packet.payload[0] == expected);
        require(wrapper.length.length == expected);
        require(array.length[0] == expected);
    }
}
"#,
    )
    .expect("a scalar field named `length` is a binding, not an array length");

    let asm = &output.functions[0].arkade.as_ref().expect("covenant").asm;
    assert!(
        asm.iter().any(|token| token == "<packet.length>"),
        "the field must be read from its own stack leaf: {asm:?}"
    );
}

#[test]
fn whole_composite_assignments_preserve_the_covenant_and_witness_shape() {
    let output = compile(
        r#"
struct Point { int x; int y; }
struct State { Point point; int[2] values; }
contract C() {
    private function advance(State state) State {
        state = { point: { x: state.point.y, y: state.point.x }, values: state.values };
        return state;
    }
    function spend(ECPoint base, State next, int index, bool condition) {
        ECPoint sc = { x: 0, y: 0 };
        sc = ecAdd(sc, base, 0);
        sc = ecMul(sc, 2, 0);
        require(sc == ecMul(base, 2, 0));
        State state = { point: { x: 1, y: 2 }, values: [3, 4] };
        state = next;
        state = state;
        if (condition) { state = advance(state); } else { state = next; }
        for (2) { state = advance(state); }
        State[2] states = [state, next];
        states[index] = state;
        states[0] = states[index];
        states = states;
        states = [states[1], states[0]];
        states = [{ point: { x: 1, y: 2 }, values: [3, 4] }, state];
        state.values = next.values;
        state.values = [state.values[1], state.values[0]];
        states[index].values = state.values;
        states[index].point = { x: state.point.y, y: state.point.x };
        state.point = states[index].point;
        require(state.point == states[index].point);
    }
}
"#,
    )
    .expect("whole struct reassignment uses the existing flattened layout");

    assert_eq!(
        crate::common::arkade_inputs(&output, "spend"),
        ["base", "next", "index", "condition"]
    );
    assert_eq!(crate::common::group(&output, "spend").leaves.len(), 1);
    assert_eq!(
        crate::common::witness_names(&output, "spend", "spend"),
        ["serverSig", "emulatorSig"]
    );
    assert_eq!(
        crate::common::leaf_asm(&output, "spend", "spend"),
        "<SERVER_KEY> OP_CHECKSIGVERIFY <EMULATOR_KEY:spend> OP_CHECKSIG"
    );
    let asm = crate::common::arkade_asm_tokens(&output, "spend");
    assert!(asm.iter().any(|op| op == "OP_ECADD"));
    assert!(asm.iter().any(|op| op == "OP_ECMUL"));
    assert!(asm.iter().any(|op| op == OP_PUT));
}

#[test]
fn whole_composite_assignments_validate_types_shapes_and_mutability() {
    let cases = [
        ("point = true;", "changes its type from 'Point' to 'bool'"),
        (
            "point = ecAdd(base, base, 0);",
            "changes its type from 'Point' to 'ECPoint'",
        ),
        ("point = { x: 1 };", "missing field 'y'"),
        ("point = { x: 1, y: 2, z: 3 };", "unknown field 'z'"),
        ("point = { x: 1, y: 2, y: 3 };", "duplicate field 'y'"),
        ("point = { x: true, y: 2 };", "expected 'int', got 'bool'"),
        (
            "initial = point;",
            "cannot assign to constructor parameter 'initial'",
        ),
        (
            "initials[index] = point;",
            "cannot assign to constructor parameter 'initials'",
        ),
        ("points[2] = point;", "out of range"),
        ("points[true] = point;", "expected 'int'"),
        ("points[index] = { x: 1 };", "missing field 'y'"),
        (
            "points[index] = base;",
            "changes its type from 'Point' to 'ECPoint'",
        ),
        ("points = [{ x: 1, y: 2 }];", "expected 2 array elements"),
        ("points = [{ x: 1, y: 2 }, { x: 3 }];", "missing field 'y'"),
        ("values = [1];", "expected 2 array elements"),
        ("values = [1, 2, 3];", "expected 2 array elements"),
        ("values = [true, 2];", "expected 'int', got 'bool'"),
        (
            "values = points;",
            "changes its type from 'int[2]' to 'Point[2]'",
        ),
        (
            "initials = points;",
            "cannot assign to constructor parameter 'initials'",
        ),
        (
            "values = shorter;",
            "changes its type from 'int[2]' to 'int[1]'",
        ),
    ];
    for (statement, expected) in cases {
        let source = format!(
            r#"
struct Point {{ int x; int y; }}
contract C(Point initial, Point[2] initials) {{
    function spend(ECPoint base, int index) {{
        Point point = {{ x: 1, y: 2 }};
        Point[2] points = [{{ x: 3, y: 4 }}, {{ x: 5, y: 6 }}];
        int[2] values = [1, 2];
        int[1] shorter = [3];
        {statement}
        require(true);
    }}
}}
"#
        );
        let error = compile(&source).expect_err(expected).to_string();
        assert!(error.contains(expected), "{statement}: {error}");
    }
}
