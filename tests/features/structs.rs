use arkade_compiler::compile;

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
