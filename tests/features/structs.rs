use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_ADD, OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_DUP, OP_EQUAL, OP_GREATERTHANOREQUAL,
    OP_INSPECTASSETGROUPASSETID, OP_INSPECTINPUTOUTPOINT, OP_LESSTHAN, OP_PICK, OP_PUT, OP_SWAP,
    OP_VERIFY,
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
    assert_eq!(output.structs[1].fields[0].param_type, "Signer");
    assert_eq!(output.parameters[0].param_type, "Policy");
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
struct Item { int value; }
contract C(Item[2] values) { function spend() { require(true); } }
"#,
            "arrays of structs are not supported",
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

    assert_eq!(output.parameters[0].param_type, "Policy");
    let arkade = output.functions[0].arkade.as_ref().expect("covenant");
    assert_eq!(arkade.inputs[0].name, "candidate");
    assert_eq!(arkade.inputs[0].param_type, "Policy");
    assert_eq!(
        &arkade.asm[..4],
        [
            "<policy.limits.1>",
            "<policy.limits.0>",
            "<policy.primary.weight>",
            "<policy.primary.key>",
        ]
    );
    assert!(arkade.asm.iter().any(|token| token == OP_CHECKSIGFROMSTACK));
    assert!(arkade.asm[4..]
        .iter()
        .all(|token| !token.contains("policy.")));
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
    function spend() { require(point == point); }
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
fn constructor_struct_arguments_expand_recursively() {
    let output = compile(
        r#"
struct Point { int x; int y; }
contract C(Point point) {
    function renew() {
        require(tx.outputs[0].scriptPubKey == new C(point));
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
        .contains(&"<VTXO:C(<point.x>,<point.y>)>".to_string()));
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

    let asm = &output.functions[0].arkade.as_ref().expect("covenant").asm;
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
    function spend() { require(true); }
}
"#,
    )
    .expect("dotted field paths are unambiguous");

    assert_eq!(
        &output.functions[0].arkade.as_ref().expect("covenant").asm[..2],
        ["<value.a.b>", "<value.a_b>"]
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
    assert!(asm.iter().any(|token| token == OP_PICK));
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
    assert_eq!(
        &asm[..3],
        [
            "<expected.minimumVout>",
            "<expected.outpoint.vout>",
            "<expected.outpoint.txid>",
        ]
    );
    assert!(asm.iter().any(|token| token == OP_INSPECTINPUTOUTPOINT));
    assert!(asm.iter().any(|token| token == OP_SWAP));
    assert!(asm.iter().filter(|token| *token == OP_PICK).count() >= 2);
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
            "more than once",
        ),
        (
            r#"
struct Values { int[2] items; }
contract C() { function spend() { Values values = { items: [1] }; require(true); } }
"#,
            "declares 2 elements",
        ),
        (
            r#"
struct Point { int x; int y; }
contract C() { function spend() { Point point = { x: true, y: 2 }; require(true); } }
"#,
            "has type 'bool', expected 'int'",
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
        require(tx.time >= terms.deadline);
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

    assert_eq!(output.parameters[0].param_type, "AssetId");
    let covenant = output.functions[0].arkade.as_ref().expect("covenant");
    assert_eq!(covenant.inputs[0].param_type, "Outpoint");
    assert_eq!(
        &covenant.asm[..2],
        ["<expected.gidx>", "<expected.txid>"],
        "constructor leaves push in reverse flattened order"
    );
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
