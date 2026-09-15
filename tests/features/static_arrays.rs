use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_ADD, OP_CAT, OP_CHECKSIGFROMSTACK, OP_DUP, OP_GREATERTHANOREQUAL, OP_LESSTHAN, OP_PUT,
    OP_VERIFY,
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
fn counted_loops_unroll_the_compile_time_constant_number_of_times() {
    let output = compile(
        r#"
contract Counted(pubkey owner) {
    const int ROUNDS = 2;

    function spend(signature sig) {
        for (ROUNDS + 1) {
            require(checkSig(sig, owner));
        }
        for (1 + 2) {
            require(checkSig(sig, owner));
        }
    }
}
"#,
    )
    .expect("counted loop must compile");

    let asm = crate::common::arkade_asm_tokens(&output, "spend");
    assert_eq!(
        asm.iter()
            .filter(|token| token.as_str() == arkade_compiler::opcodes::OP_CHECKSIG)
            .count(),
        6,
        "counted loop unrolls its body once per iteration"
    );
}

#[test]
fn zero_counted_loop_emits_no_body() {
    let counted = compile(
        r#"
contract Counted(pubkey owner) {
    function spend(signature sig) {
        for (0) {
            require(false);
        }
        require(checkSig(sig, owner));
    }
}
"#,
    )
    .expect("zero-count loop must compile");
    let direct = compile(
        r#"
contract Counted(pubkey owner) {
    function spend(signature sig) {
        require(checkSig(sig, owner));
    }
}
"#,
    )
    .expect("direct body must compile");

    assert_eq!(
        crate::common::arkade_asm_tokens(&counted, "spend"),
        crate::common::arkade_asm_tokens(&direct, "spend")
    );

    let error = compile(
        r#"
contract Counted() {
    function spend() {
        for (0) {
            require(true);
        }
    }
}
"#,
    )
    .expect_err("a zero-count loop cannot enforce a spend condition")
    .to_string();
    assert!(
        error.contains("spend path with no require"),
        "unexpected error: {error}"
    );
}

#[test]
fn counted_loop_rejects_non_constant_or_negative_counts() {
    for count in ["rounds", "-1"] {
        let error = compile(&format!(
            r#"
contract Counted() {{
    function spend(int rounds) {{
        for ({count}) {{
            require(true);
        }}
        require(true);
    }}
}}
"#
        ))
        .expect_err("invalid loop count must be rejected")
        .to_string();

        assert!(
            error.contains("loop count must be a non-negative integer compile-time constant"),
            "unexpected error: {error}"
        );
    }
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
        contains_tokens(&asm, &["4", "OP_0", OP_PUT]),
        "assignment overwrites the element in place: {asm:?}"
    );
}

#[test]
fn array_element_assignment_accepts_runtime_index_expressions() {
    let output = compile(
        r#"
contract Local() {
    function spend(int amount, int index) {
        int[2] weights = [1, 2];
        weights[index + 1] = 4;
        require(amount >= weights[0]);
    }
}
"#,
    )
    .expect("runtime expression-index assignment must compile");

    let asm = crate::common::arkade_asm_tokens(&output, "spend");
    assert!(
        contains_tokens(
            &asm,
            &[OP_ADD, OP_DUP, "OP_0", OP_GREATERTHANOREQUAL, OP_VERIFY]
        ),
        "assignment must check the computed index's lower bound: {asm:?}"
    );
    assert!(
        contains_tokens(&asm, &[OP_DUP, "OP_2", OP_LESSTHAN, OP_VERIFY, OP_PUT]),
        "assignment must check the computed index against the array size: {asm:?}"
    );
    assert!(
        asm.iter().any(|token| token == OP_PUT),
        "assignment must write the computed stack depth with {OP_PUT}: {asm:?}"
    );
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
fn array_elements_use_scalar_type_widening() {
    compile(
        r#"
contract Local(bytes32 first, bytes32 second) {
    function spend(bytes expected) {
        bytes[2] values = [first, second];
        require(values[0] == expected);
    }
}
"#,
    )
    .expect("bytes32 array elements must widen to bytes");
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
    assert!(
        contains_tokens(&asm, &["9", "OP_1", OP_PUT]),
        "the write must replace the element at its own depth, not index 0's: {asm:?}"
    );
}
