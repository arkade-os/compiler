use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_ADD, OP_CAT, OP_CHECKSIGFROMSTACK, OP_DROP, OP_LESSTHAN, OP_ROLL, OP_SWAP,
};

fn contains_tokens(asm: &[String], expected: &[&str]) -> bool {
    asm.windows(expected.len()).any(|window| {
        window
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied())
    })
}

#[test]
fn declared_sizes_drive_input_expansion_per_array() {
    let output = compile(
        r#"
contract Sized(pubkey[2] owners) {
    function spend(signature[4] sigs, bytes32 msg) {
        require(checkSigFromStack(sigs[0], owners[1], msg));
    }
}
"#,
    )
    .expect("sized arrays must compile");

    assert_eq!(
        output
            .parameters
            .iter()
            .map(|p| (p.name.as_str(), p.param_type.as_str()))
            .collect::<Vec<_>>(),
        vec![("owners", "pubkey[2]")],
        "constructor inputs keep one entry per source parameter, sized"
    );

    let inputs = crate::common::arkade_inputs(&output, "spend");
    assert_eq!(
        inputs,
        vec!["sigs", "msg"],
        "covenant inputs keep one entry per source parameter"
    );

    let asm = crate::common::arkade_asm(&output, "spend");
    for placeholder in ["<owners.0>", "<owners.1>"] {
        assert!(
            asm.contains(placeholder),
            "constructor array expands to its declared size: {asm}"
        );
    }
    assert!(
        !asm.contains("<owners.2>"),
        "constructor array must not expand past its declared size: {asm}"
    );
}

#[test]
fn loops_unroll_once_per_declared_element() {
    let output = compile(
        r#"
contract Quorum(pubkey[5] oracles) {
    function attest(signature[5] sigs, bytes32 msg) {
        int valid = 0;
        for (i, sig) in sigs {
            if (checkSigFromStack(sig, oracles[i], msg)) {
                valid = valid + 1;
            }
        }
        require(valid >= 3);
    }
}
"#,
    )
    .expect("loop over a sized array must compile");

    let asm = crate::common::arkade_asm_tokens(&output, "attest");
    assert_eq!(
        asm.iter()
            .filter(|token| token.as_str() == OP_CHECKSIGFROMSTACK)
            .count(),
        5,
        "loop unrolls once per declared element"
    );
}

#[test]
fn runtime_index_bound_check_uses_the_arrays_own_size() {
    let output = compile(
        r#"
contract Bounds() {
    function spend(int[7] values, int index) {
        require(values[index] >= 0);
    }
}
"#,
    )
    .expect("runtime index must compile");

    let asm = crate::common::arkade_asm_tokens(&output, "spend");
    assert!(
        contains_tokens(&asm, &["OP_7", OP_LESSTHAN]),
        "bound check must compare against the declared size: {asm:?}"
    );
}

#[test]
fn literal_index_past_the_declared_size_is_rejected() {
    let error = compile(
        r#"
contract Bounds() {
    function spend(int[2] values, int expected) {
        require(values[2] == expected);
    }
}
"#,
    )
    .expect_err("index at the declared size must be rejected")
    .to_string();

    assert!(error.contains("out of range"), "unexpected error: {error}");
}

#[test]
fn unsized_array_types_are_rejected() {
    let error = compile(
        r#"
contract Unsized(pubkey[] owners) {
    function spend(signature sig) {
        require(checkSig(sig, owners[0]));
    }
}
"#,
    )
    .expect_err("unsized array types must be rejected")
    .to_string();

    assert!(
        error.to_lowercase().contains("parse"),
        "unexpected error: {error}"
    );
}

#[test]
fn array_length_folds_to_a_literal() {
    let output = compile(
        r#"
contract Quorum(pubkey[5] oracles) {
    function spend(int[4] weights, int total) {
        require(total >= oracles.length + weights.length);
    }
}
"#,
    )
    .expect("arr.length must compile");

    let asm = crate::common::arkade_asm_tokens(&output, "spend");
    assert!(
        contains_tokens(&asm, &["OP_5", "OP_4", OP_ADD]),
        "each .length folds to its declared size: {asm:?}"
    );
}

#[test]
fn length_on_a_non_array_is_rejected() {
    let error = compile(
        r#"
contract Scalar(int limit) {
    function spend(int amount) {
        require(amount >= limit.length);
    }
}
"#,
    )
    .expect_err("'.length' on a scalar must be rejected")
    .to_string();

    assert!(error.contains(".length"), "unexpected error: {error}");
}

#[test]
fn local_arrays_bind_one_element_per_declared_slot() {
    let output = compile(
        r#"
contract Local(int limit) {
    function spend(int amount, int index) {
        int[3] weights = [1, 2, 5];
        require(amount * weights[index] >= limit + weights.length);
    }
}
"#,
    )
    .expect("local array must compile");

    let asm = crate::common::arkade_asm_tokens(&output, "spend");
    assert!(
        contains_tokens(&asm, &["5", "2", "1"]),
        "elements are pushed deepest-last so element 0 sits closest to the top: {asm:?}"
    );
    assert!(
        contains_tokens(&asm, &["OP_3", OP_LESSTHAN]),
        "runtime index into a local array is bounded by its declared size: {asm:?}"
    );
}

#[test]
fn local_array_elements_are_assignable_at_a_literal_index() {
    let output = compile(
        r#"
contract Local() {
    function spend(int amount) {
        int[2] weights = [1, 2];
        weights[0] = 4;
        require(amount >= weights[0]);
    }
}
"#,
    )
    .expect("element assignment must compile");

    let asm = crate::common::arkade_asm_tokens(&output, "spend");
    assert!(
        contains_tokens(&asm, &["4", "OP_1", OP_ROLL, OP_DROP]),
        "assignment overwrites the element in place: {asm:?}"
    );
}

#[test]
fn assignment_at_a_runtime_index_is_rejected() {
    let error = compile(
        r#"
contract Local() {
    function spend(int amount, int index) {
        int[2] weights = [1, 2];
        weights[index] = 4;
        require(amount >= weights[0]);
    }
}
"#,
    )
    .expect_err("runtime-index assignment must be rejected")
    .to_string();

    assert!(error.contains("runtime index"), "unexpected error: {error}");
}

#[test]
fn array_literal_size_must_match_the_declaration() {
    let error = compile(
        r#"
contract Local() {
    function spend(int amount) {
        int[3] weights = [1, 2];
        require(amount >= weights[0]);
    }
}
"#,
    )
    .expect_err("element count mismatch must be rejected")
    .to_string();

    assert!(
        error.contains("int[3]") && error.contains("int[2]"),
        "unexpected error: {error}"
    );
}

#[test]
fn array_literals_are_rejected_outside_array_declarations() {
    let error = compile(
        r#"
contract Local() {
    function spend(int amount) {
        let weights = [1, 2];
        require(amount >= weights);
    }
}
"#,
    )
    .expect_err("array literal outside an array declaration must be rejected")
    .to_string();

    assert!(error.contains("array literal"), "unexpected error: {error}");
}

#[test]
fn iterating_tx_asset_groups_is_rejected() {
    let error = compile(
        r#"
contract Groups() {
    function spend() {
        for (k, group) in tx.assetGroups {
            require(group.sumOutputs >= group.sumInputs, "drained");
        }
    }
}
"#,
    )
    .expect_err("the asset group count is not known at compile time")
    .to_string();

    assert!(
        error.contains("cannot iterate 'tx.assetGroups'"),
        "unexpected error: {error}"
    );
}

#[test]
fn array_inputs_are_rejected_in_tapscript_functions() {
    let error = compile(
        r#"
contract Demo(pubkey owner) {
    function spend(signature sig) {
        require(checkSig(sig, owner));
    }

    function leaf(signature sig, signature[3] extras) tapscript {
        require(checkSig(sig, owner));
    }
}
"#,
    )
    .expect_err("array witnesses are not supported in tapscript functions")
    .to_string();

    assert!(
        error.contains("array witnesses are not supported"),
        "unexpected error: {error}"
    );
}

#[test]
fn array_literal_elements_are_substituted_inside_loops() {
    let output = compile(
        r#"
contract Local(int limit) {
    function spend(int[2] xs) {
        for (i, v) in xs {
            int[2] pair = [v, i];
            require(pair[0] + pair[1] >= limit);
        }
    }
}
"#,
    )
    .expect("loop variables inside an array literal must be unrolled");

    let asm = crate::common::arkade_asm_tokens(&output, "spend");
    assert!(
        asm.iter().all(|token| !token.contains("$array:")),
        "internal bindings must not leak: {asm:?}"
    );
}

#[test]
fn array_literal_elements_are_rewritten_by_the_concat_pass() {
    let output = compile(
        r#"
contract Parts(bytes32 a, bytes32 b, bytes expected) {
    function spend(int amount) {
        bytes[2] parts = [a + b, a];
        require(parts[0] == expected);
        require(amount > 0);
    }
}
"#,
    )
    .expect("byte concatenation inside an array literal must compile");

    let asm = crate::common::arkade_asm_tokens(&output, "spend");
    assert!(
        asm.iter().any(|token| token == OP_CAT),
        "adding two byte operands must emit {OP_CAT}, not arithmetic: {asm:?}"
    );
    assert!(
        !asm.iter().any(|token| token == OP_ADD),
        "byte concatenation must not emit {OP_ADD}: {asm:?}"
    );
}

#[test]
fn array_literal_element_types_must_match_the_declared_element_type() {
    let error = compile(
        r#"
contract Local(bytes32 h) {
    function spend(int amount, bytes32 other) {
        bytes32[2] xs = [h, 5];
        require(xs[1] == other);
        require(amount > 0);
    }
}
"#,
    )
    .expect_err("a heterogeneous array literal must be rejected")
    .to_string();

    assert!(
        error.contains("element 1 of array 'xs' has type 'int', expected 'bytes32'"),
        "unexpected error: {error}"
    );
}

#[test]
fn local_array_elements_are_assignable_at_a_nonzero_literal_index() {
    let output = compile(
        r#"
contract Local() {
    function spend(int amount) {
        int[3] weights = [1, 2, 3];
        weights[1] = 9;
        require(amount >= (weights[0] + weights[1]) + weights[2]);
    }
}
"#,
    )
    .expect("element assignment at a non-zero index must compile");

    let asm = crate::common::arkade_asm_tokens(&output, "spend");
    // Index 0 sits directly under the pushed value (depth 1, no walk-back);
    // index 1 is one deeper and must be swapped back into place.
    assert!(
        contains_tokens(&asm, &["9", "OP_2", OP_ROLL, OP_DROP, OP_SWAP]),
        "the write must roll the element at its own depth, not index 0's: {asm:?}"
    );
}
