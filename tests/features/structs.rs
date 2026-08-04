use arkade_compiler::compile;
use arkade_compiler::opcodes::{OP_ADD, OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_LESSTHAN};

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
    assert!(
        copy.contains("must be initialized with a struct literal"),
        "{copy}"
    );

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
