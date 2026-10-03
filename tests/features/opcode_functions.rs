use crate::common::compile_unoptimized as compile;
use arkade_compiler::opcodes::{
    OP_0, OP_1, OP_ADD, OP_CAT, OP_CHECKSIGFROMSTACK, OP_DIGEST, OP_ECADD, OP_ECMUL,
    OP_ECMULSCALARVERIFY, OP_ECPAIRING, OP_MODEXP, OP_NEGATE, OP_PICK, OP_ROLL, OP_SHA256FINALIZE,
    OP_SHA256INITIALIZE, OP_SHA256UPDATE, OP_SIGHASH, OP_SUB, OP_SWAP, OP_TWEAKVERIFY,
};

fn contains_tokens(asm: &[String], expected: &[&str]) -> bool {
    asm.windows(expected.len()).any(|window| {
        window
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied())
    })
}
// ─── Streaming SHA256 ──────────────────────────────────────────────────

#[test]
fn test_sha256_initialize() {
    let code = r#"
        contract StreamingHasher(pubkey owner) {
            function initHash(signature ownerSig, bytes32 initialData) {
                require(checkSig(ownerSig, owner));
                let ctx = sha256Initialize(initialData);
                require(ctx == ctx);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse sha256Initialize: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let asm_str = crate::common::arkade_asm(&output, "initHash");
    assert!(
        asm_str.contains(OP_SHA256INITIALIZE),
        "Expected {OP_SHA256INITIALIZE} in ASM: {}",
        asm_str
    );
}

#[test]
fn test_sha256_update() {
    let code = r#"
        contract StreamingHasher(pubkey owner) {
            function updateHash(signature ownerSig, bytes32 ctx, bytes32 chunk) {
                require(checkSig(ownerSig, owner));
                let newCtx = sha256Update(ctx, chunk);
                require(newCtx == newCtx);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse sha256Update: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let asm_str = crate::common::arkade_asm(&output, "updateHash");
    assert!(
        asm_str.contains(OP_SHA256UPDATE),
        "Expected {OP_SHA256UPDATE} in ASM: {}",
        asm_str
    );
}

#[test]
fn test_sha256_finalize() {
    let code = r#"
        contract StreamingHasher(pubkey owner) {
            function finalizeHash(signature ownerSig, bytes32 ctx, bytes32 lastChunk) {
                require(checkSig(ownerSig, owner));
                let hash = sha256Finalize(ctx, lastChunk);
                require(hash == hash);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse sha256Finalize: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let asm_str = crate::common::arkade_asm(&output, "finalizeHash");
    assert!(
        asm_str.contains(OP_SHA256FINALIZE),
        "Expected {OP_SHA256FINALIZE} in ASM: {}",
        asm_str
    );
}

#[test]
fn test_digest() {
    let code = r#"
        contract RuntimeDigest(int hashType) {
            function hash(bytes data) {
                let hash = digest(data, hashType);
                require(hash == hash);
            }
        }
    "#;

    let output = compile(code).expect("compile digest");
    let asm = crate::common::arkade_asm_tokens(&output, "hash");
    assert!(
        contains_tokens(&asm, &[OP_1, OP_ROLL, OP_1, OP_ROLL, OP_DIGEST]),
        "Expected ordered {OP_DIGEST} operand reads in ASM: {asm:?}"
    );
}

// digest's data operand is parsed as an additive expression, so a `+` under it
// is byte concatenation and must not fall through to arithmetic.
#[test]
fn test_digest_concatenates_bytes_operands() {
    let code = r#"
        contract DigestConcat(bytes32 a, bytes32 b, int hashType) {
            function hash() {
                let h = digest(a + b, hashType);
                require(h == a);
            }
        }
    "#;

    let output = compile(code).expect("compile digest over a concatenation");
    let asm = crate::common::arkade_asm_tokens(&output, "hash");
    assert!(
        contains_tokens(
            &asm,
            &[OP_0, OP_PICK, "OP_2", OP_ROLL, OP_CAT, "OP_2", OP_ROLL, OP_DIGEST]
        ),
        "Expected digest operands to be concatenated; asm: {asm:?}"
    );
    assert!(
        !asm.iter().any(|token| token == OP_ADD),
        "bytes32 + bytes32 must not compile to arithmetic; asm: {asm:?}"
    );
}

// ─── Arithmetic ────────────────────────────────────────────────────────

#[test]
fn test_unary_minus_negates() {
    let code = r#"
        contract ArithmeticOps(pubkey owner) {
            function negateValue(signature ownerSig, int value) {
                require(checkSig(ownerSig, owner));
                let negated = -value;
                require(negated == negated);
            }
        }
    "#;

    let output = compile(code).expect("compile unary minus");
    let asm = crate::common::arkade_asm_tokens(&output, "negateValue");
    assert!(
        contains_tokens(&asm, &[OP_0, OP_ROLL, OP_NEGATE]),
        "Expected unary `-` to read its operand and emit {OP_NEGATE}; asm: {asm:?}"
    );
}

// A loop body is unrolled by substituting the index into every operand, so the
// negation has to carry the substitution through rather than keep `<i>`.
#[test]
fn test_unary_minus_substitutes_loop_index() {
    let code = r#"
        contract LoopNeg(pubkey owner) {
            function f(int[3] amounts) {
                for (i, amt) in amounts {
                    let d = -i;
                    require(d <= 0);
                }
            }
        }
    "#;

    let output = compile(code).expect("compile negated loop index");
    let asm = crate::common::arkade_asm(&output, "f");
    for k in 0..3 {
        assert!(
            asm.contains(&format!("{k} {OP_NEGATE}")),
            "Expected iteration {k} to negate the literal index; asm: {asm}"
        );
    }
}

// `a - b` must stay a subtraction: the leading-minus rule is optional, so the
// binary operator has to win when an operand precedes it.
#[test]
fn test_binary_minus_still_subtracts() {
    let code = r#"
        contract ArithmeticOps(int a, int b) {
            function diff() {
                let d = a - b;
                require(d >= 0);
            }
        }
    "#;

    let output = compile(code).expect("compile subtraction");
    let asm = crate::common::arkade_asm_tokens(&output, "diff");
    assert!(
        contains_tokens(&asm, &[OP_0, OP_ROLL, OP_1, OP_ROLL, OP_SUB]),
        "Expected a binary subtraction; asm: {asm:?}"
    );
    assert!(
        !asm.iter().any(|token| token == OP_NEGATE),
        "Binary `-` must not emit {OP_NEGATE}; asm: {asm:?}"
    );
}

#[test]
fn test_mod_exp() {
    let code = r#"
        contract ArithmeticOps(int modulus) {
            function calculate(int base, int exponent) {
                let result = modExp(base, exponent, modulus);
                require(result >= 0);
            }
        }
    "#;

    let output = compile(code).expect("compile modExp");
    let asm = crate::common::arkade_asm_tokens(&output, "calculate");
    assert!(
        contains_tokens(
            &asm,
            &[OP_1, OP_ROLL, "OP_2", OP_ROLL, "OP_2", OP_ROLL, OP_MODEXP]
        ),
        "Expected ordered {OP_MODEXP} operand reads in ASM: {asm:?}"
    );
}

// ─── Elliptic Curve ────────────────────────────────────────────────────

#[test]
fn test_ec_add_returns_typed_point() {
    let code = r#"
        contract EllipticCurve(int curveId) {
            function add(ECPoint p, ECPoint q) {
                ECPoint result = ecAdd(p, q, curveId);
                require(result.x >= 0);
                require(result.y >= 0);
            }
        }
    "#;

    let output = compile(code).expect("ecAdd returns ECPoint");
    let asm = crate::common::arkade_asm_tokens(&output, "add");
    assert!(
        contains_tokens(&asm, &[OP_ECADD, OP_SWAP, OP_0, OP_ROLL]),
        "EC point output must be normalized to struct field order: {asm:?}"
    );
}

#[test]
fn test_ec_operands_are_type_checked() {
    let compile_spend = |statement: &str| {
        compile(&format!(
            "struct Other {{ int x; int y; }}
            contract EllipticCurve() {{
                function spend(
                    ECPoint p, ECPoint q, Other other, int x, bytes data, bytes32 scalar, pubkey key,
                    ECPoint[2] g1, G2Point[2] g2
                ) {{
                    {statement}
                }}
            }}"
        ))
    };
    for (statement, message) in [
        (
            "require(ecAdd(x, q, 0) == p);",
            "ecAdd operand has type 'int', expected 'ECPoint'",
        ),
        (
            "require(ecAdd(p, other, 0) == p);",
            "ecAdd operand has type 'Other', expected 'ECPoint'",
        ),
        (
            "require(ecAdd(p, q, data) == p);",
            "ecAdd operand has type 'bytes', expected 'int'",
        ),
        (
            "require(ecMul(x, 1, 0) == p);",
            "ecMul operand has type 'int', expected 'ECPoint'",
        ),
        (
            "require(ecMul(p, data, 0) == p);",
            "ecMul operand has type 'bytes', expected 'int'",
        ),
        (
            "require(ecMul(p, 1, data) == p);",
            "ecMul operand has type 'bytes', expected 'int'",
        ),
        (
            "require(ecPairing(p, g2, 2));",
            "ecPairing operand has type 'ECPoint', expected 'ECPoint[1]'",
        ),
        (
            "require(ecPairing(g1, p, 2));",
            "ecPairing operand has type 'ECPoint', expected 'G2Point[2]'",
        ),
        (
            "require(ecPairing(g1, g2, key));",
            "ecPairing operand has type 'bytes', expected 'int'",
        ),
        (
            "require(ecMulScalarVerify(x, key, key));",
            "ecMulScalarVerify operand has type 'int', expected 'bytes32'",
        ),
        (
            "require(ecMulScalarVerify(scalar, x, key));",
            "ecMulScalarVerify operand has type 'int', expected 'bytes'",
        ),
        (
            "require(tweakVerify(key, scalar, key));",
            "tweakVerify operand has type 'bytes', expected 'bytes32'",
        ),
        (
            "require(tweakVerify(scalar, x, key));",
            "tweakVerify operand has type 'int', expected 'bytes32'",
        ),
        (
            "require(tweakVerify(scalar, scalar, x));",
            "tweakVerify operand has type 'int', expected 'bytes'",
        ),
    ] {
        let error = compile_spend(statement)
            .expect_err(&format!("{statement} must be rejected"))
            .to_string();
        assert!(
            error.contains(message),
            "{statement}: unexpected error: {error}"
        );
    }
    compile_spend(
        "require(ecAdd(p, q, 0) == ecMul(p, 2, 0));
        require(other.x == x);
        require(ecPairing(g1, g2, 2));
        require(ecMulScalarVerify(scalar, key, key));
        require(tweakVerify(scalar, scalar, key));
        require(ecMulScalarVerify(scalar, data, scalar));
        require(tweakVerify((bytes32(data)), scalar, data));",
    )
    .expect("well-typed EC operands compile");
}

#[test]
fn test_ec_operands_accept_point_values() {
    let output = compile(
        r#"
        struct Keys { ECPoint base; int scalar; }
        contract EllipticCurve(ECPoint generator) {
            private function double(ECPoint p) ECPoint { return ecAdd(p, p, 0); }
            function spend(Keys keys) {
                let sum = ecAdd((double(keys.base)), (ecMul(generator, keys.scalar, 0)), 0);
                require(sum.x >= 0);
            }
        }
    "#,
    )
    .expect("ECPoint bindings, fields, helper results, and native results are points");
    let asm = crate::common::arkade_asm_tokens(&output, "spend");
    assert!(
        contains_tokens(&asm, &[OP_ECADD, OP_SWAP, OP_SWAP]),
        "helper point must return to native field order: {asm:?}"
    );
    assert!(
        contains_tokens(&asm, &[OP_ECMUL, "0", OP_ECADD]),
        "nested native point must feed ecAdd unswapped: {asm:?}"
    );
}

#[test]
fn test_native_result_type_must_match_declaration() {
    let error = compile(
        r#"
        contract EllipticCurve(int curveId) {
            function add(ECPoint p, ECPoint q) {
                AssetId result = ecAdd(p, q, curveId);
                require(result.gidx >= 0);
            }
        }
    "#,
    )
    .expect_err("ECPoint cannot initialize AssetId")
    .to_string();

    assert!(
        error.contains("declares type 'AssetId' but initializer has type 'ECPoint'"),
        "unexpected error: {error}"
    );
}

#[test]
fn test_ec_mul_infers_point_type() {
    let code = r#"
        contract EllipticCurve(int curveId) {
            function multiply(ECPoint p, int scalar) {
                let result = ecMul(p, scalar, curveId);
                require(result.x >= 0);
                require(result.y >= 0);
            }
        }
    "#;

    let output = compile(code).expect("ecMul infers ECPoint");
    let asm = crate::common::arkade_asm_tokens(&output, "multiply");
    assert!(
        contains_tokens(&asm, &[OP_ECMUL, OP_SWAP]),
        "EC point output must be normalized to struct field order: {asm:?}"
    );
}

#[test]
fn test_inferred_point_fields_keep_their_types_during_concat_rewrite() {
    let error = compile(
        r#"
        contract EllipticCurve(int curveId) {
            function multiply(ECPoint p, int scalar, bytes suffix) {
                let result = ecMul(p, scalar, curveId);
                require(result.x + suffix == suffix);
            }
        }
    "#,
    )
    .expect_err("numeric ECPoint field needs an explicit byte width")
    .to_string();

    assert!(
        error.contains("cannot concatenate bytes with the left `int` operand"),
        "unexpected error: {error}"
    );
}

#[test]
fn test_ec_pairing_takes_aligned_point_arrays() {
    let output = compile(
        r#"
        struct Proof { ECPoint[2] g1; G2Point[2] g2; }
        contract EllipticCurve() {
            function pair(ECPoint[2] g1, G2Point[2] g2, Proof[2] proofs, int index) {
                require(ecPairing(g1, g2, 2));
                require(ecPairing(proofs[index].g1, proofs[index].g2, 2));
            }
        }
    "#,
    )
    .expect("ecPairing accepts bindings and struct-array fields");
    let asm = crate::common::arkade_asm_tokens(&output, "pair");
    assert_eq!(
        asm.iter().filter(|token| *token == OP_ECPAIRING).count(),
        2,
        "{asm:?}"
    );
    assert!(
        contains_tokens(&asm, &["OP_2", "2", OP_ECPAIRING]),
        "pair count must precede the curve id: {asm:?}"
    );

    let error = compile(
        r#"
        contract EllipticCurve() {
            function mismatched(ECPoint[2] g1, G2Point[3] g2) { require(ecPairing(g1, g2, 2)); }
            function many(ECPoint[17] g1, G2Point[17] g2) { require(ecPairing(g1, g2, 2)); }
        }
    "#,
    )
    .expect_err("misaligned and oversized pairings are rejected")
    .to_string();
    assert!(
        error.contains("ecPairing operand has type 'G2Point[3]', expected 'G2Point[2]'"),
        "{error}"
    );
    assert!(
        error.contains("ecPairing supports at most 16 pairs, got 17"),
        "{error}"
    );
}

#[test]
fn modexp_group_index_and_sha256_builtins_reject_mistyped_operands() {
    for (params, statement, expected) in [
        (
            "pubkey owner",
            "let r = modExp(owner, 2, 3);",
            "modExp operand has type 'bytes', expected 'int'",
        ),
        (
            "pubkey owner",
            "let r = tx.assetGroups[owner].sumInputs;",
            "assetGroups[].sum operand has type 'bytes', expected 'int'",
        ),
        (
            "pubkey owner",
            "let r = tx.assetGroups[owner].numInputs;",
            "assetGroups[].numIO operand has type 'bytes', expected 'int'",
        ),
        (
            "pubkey owner",
            "let r = tx.assetGroups[0].outputs[owner].amount;",
            "assetGroups[].io operand has type 'bytes', expected 'int'",
        ),
        (
            "int x",
            "let r = sha256(x);",
            "sha256 operand has type 'int', expected 'bytes'",
        ),
        (
            "int x",
            "let r = sha256Initialize(x);",
            "sha256Initialize operand has type 'int', expected 'bytes'",
        ),
        (
            "bytes32 ctx, int x",
            "let r = sha256Update(ctx, x);",
            "sha256Update operand has type 'int', expected 'bytes'",
        ),
        (
            "bytes32 ctx, int x",
            "let r = sha256Finalize(ctx, x);",
            "sha256Finalize operand has type 'int', expected 'bytes'",
        ),
    ] {
        let source = format!("contract Grouped({params}) {{ function spend() {{ {statement} }} }}");
        let error = compile(&source).expect_err(&source).to_string();
        assert!(error.contains(expected), "{statement}: {error}");
    }
}

#[test]
fn bytes32_operands_accept_only_32_byte_literals() {
    let word = format!("0x{}", "01".repeat(32));
    let short = format!("0x{}", "01".repeat(31));
    for (params, statement) in [
        ("bytes d", "let r = sha256Update(LIT, d); require(r == r);"),
        (
            "bytes d",
            "let r = sha256Finalize(LIT, d); require(r == r);",
        ),
        (
            "pubkey p, pubkey q",
            "require(ecMulScalarVerify(LIT, p, q));",
        ),
        ("bytes32 p, pubkey q", "require(tweakVerify(p, LIT, q));"),
    ] {
        let source = |literal: &str| {
            let statement = statement.replace("LIT", literal);
            format!("contract Grouped({params}) {{ function spend() {{ {statement} }} }}")
        };
        compile(&source(&word)).unwrap_or_else(|error| panic!("{statement}: {error}"));
        let error = compile(&source(&short)).expect_err(statement).to_string();
        assert!(
            error.contains("operand has type 'bytes', expected 'bytes32'"),
            "{statement}: {error}"
        );
    }
}

#[test]
fn test_ec_mul_scalar_verify_cannot_be_value_bound() {
    let code = r#"
        contract CryptoOps(pubkey owner) {
            function verifyScalarMul(signature ownerSig, bytes32 scalar, pubkey P, pubkey Q) {
                require(checkSig(ownerSig, owner));
                let result = ecMulScalarVerify(scalar, P, Q);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result
            .expect_err("verify opcode produces no bindable value")
            .to_string()
            .contains("expression does not produce one stack item"),
        "{OP_ECMULSCALARVERIFY} must not be accepted as a value"
    );
}

#[test]
fn test_tweak_verify_cannot_be_value_bound() {
    let code = r#"
        contract CryptoOps(pubkey owner) {
            function verifyTweak(signature ownerSig, bytes32 P, bytes32 tweak, pubkey Q) {
                require(checkSig(ownerSig, owner));
                let result = tweakVerify(P, tweak, Q);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result
            .expect_err("verify opcode produces no bindable value")
            .to_string()
            .contains("expression does not produce one stack item"),
        "{OP_TWEAKVERIFY} must not be accepted as a value"
    );
}

// ─── Signatures ────────────────────────────────────────────────────────

#[test]
fn test_sighash() {
    let code = r#"
        contract SignatureHash(int hashType) {
            function hashCurrentInput() {
                let hash = sighash(hashType);
                require(hash == hash);
            }
        }
    "#;

    let output = compile(code).expect("compile sighash");
    let asm = crate::common::arkade_asm_tokens(&output, "hashCurrentInput");
    assert!(
        contains_tokens(&asm, &[OP_0, OP_ROLL, OP_SIGHASH]),
        "Expected ordered {OP_SIGHASH} operand read in ASM: {asm:?}"
    );
}

#[test]
fn test_check_sig_from_stack_verify() {
    let code = r#"
        contract CryptoOps(pubkey owner) {
            function verifyMessageSig(signature ownerSig, signature msgSig, pubkey signer, bytes32 message) {
                require(checkSig(ownerSig, owner));
                require(checkSigFromStackVerify(msgSig, signer, message));
            }
        }
    "#;

    let output =
        compile(code).expect("checkSigFromStackVerify is a valid self-verifying requirement");
    let asm = crate::common::arkade_asm(&output, "verifyMessageSig");
    assert!(
        asm.contains(OP_CHECKSIGFROMSTACK),
        "expected {OP_CHECKSIGFROMSTACK} in covenant ASM: {asm}"
    );
}

// ─── Workflows ─────────────────────────────────────────────────────────

#[test]
fn test_streaming_hash_full_workflow() {
    let code = r#"
        contract StreamingHashWorkflow(pubkey owner, bytes32 expectedHash) {
            function computeHash(signature ownerSig, bytes32 chunk1, bytes32 chunk2, bytes32 chunk3) {
                require(checkSig(ownerSig, owner));
                let ctx = sha256Initialize(chunk1);
                let ctx2 = sha256Update(ctx, chunk2);
                let hash = sha256Finalize(ctx2, chunk3);
                require(hash == expectedHash);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse streaming hash workflow: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let asm_str = crate::common::arkade_asm(&output, "computeHash");
    assert!(
        asm_str.contains(OP_SHA256INITIALIZE),
        "Expected {OP_SHA256INITIALIZE} in ASM: {}",
        asm_str
    );
    assert!(
        asm_str.contains(OP_SHA256UPDATE),
        "Expected {OP_SHA256UPDATE} in ASM: {}",
        asm_str
    );
    assert!(
        asm_str.contains(OP_SHA256FINALIZE),
        "Expected {OP_SHA256FINALIZE} in ASM: {}",
        asm_str
    );
}

#[test]
fn unary_negation_precedence_and_spend_shape() {
    for (expression, expected) in [
        ("--1", "1 OP_NEGATE OP_NEGATE"),
        ("-(-1)", "1 OP_NEGATE OP_NEGATE"),
        ("1 - -2 * 3", "1 2 OP_NEGATE 3 OP_MUL OP_SUB"),
        ("-(1 + 2) * 3", "1 2 OP_ADD OP_NEGATE 3 OP_MUL"),
        ("!true", "OP_1 OP_NOT"),
        ("!false", "OP_0 OP_NOT"),
        ("!!true", "OP_1 OP_NOT OP_NOT"),
        ("!!false", "OP_0 OP_NOT OP_NOT"),
        ("!(1 < 2)", "1 2 OP_LESSTHAN OP_NOT"),
        ("!true != false", "OP_1 OP_NOT OP_0 OP_EQUAL OP_NOT"),
        ("num2bin(-1, 4)", "1 OP_NEGATE 4 OP_NUM2BIN"),
        ("modExp(-2, 3, 5)", "2 OP_NEGATE 3 5 OP_MODEXP"),
    ] {
        let source = format!(
            "contract Unary() {{ function spend() {{ let result = {expression}; require(result == result); }} }}"
        );
        let output = compile(&source).unwrap_or_else(|error| panic!("{expression}: {error}"));
        assert!(
            output.warnings.is_empty(),
            "{expression}: {:?}",
            output.warnings
        );
        let asm = crate::common::arkade_asm_tokens(&output, "spend");
        assert!(
            contains_tokens(&asm, &expected.split_whitespace().collect::<Vec<_>>()),
            "{expression}: {asm:?}"
        );
        assert_eq!(output.functions.len(), 1);
        assert_eq!(crate::common::group(&output, "spend").leaves.len(), 1);
        assert!(crate::common::arkade_inputs(&output, "spend").is_empty());
        assert_eq!(
            crate::common::witness_names(&output, "spend", "spend"),
            ["serverSig", "emulatorSig"]
        );
        assert_eq!(
            crate::common::leaf_asm(&output, "spend", "spend"),
            "<SERVER_KEY> OP_CHECKSIGVERIFY <EMULATOR_KEY:spend> OP_CHECKSIG"
        );
    }
}

#[test]
fn unary_negation_in_loops_and_conditions() {
    let output = compile(
        r#"
        contract Unary() {
            function spend(bool[2] flags) {
                for (i, flag) in flags {
                    if (!flag) { require(!!flag == false); }
                    let encoded = num2bin(-(i + 1), 4);
                    require(size(encoded) == 4);
                }
            }
        }
    "#,
    )
    .expect("negated loop operands compile");
    assert!(output.warnings.is_empty(), "{:?}", output.warnings);
    let asm = crate::common::arkade_asm(&output, "spend");
    for index in 0..2 {
        assert!(
            asm.contains(&format!("{index} 1 OP_ADD OP_NEGATE 4 OP_NUM2BIN")),
            "{asm}"
        );
    }
    assert_eq!(
        crate::common::opcode_count_in_arkade(&output, "spend", "OP_NOT"),
        6
    );
    assert!(!asm.contains("<flag>") && !asm.contains("<i>"), "{asm}");
}

#[test]
fn unary_negation_rejects_invalid_operand_types() {
    for (params, expression, expected) in [
        ("bool value", "-value", "expected 'int'"),
        ("bytes value", "-value", "expected 'int'"),
        ("int value", "!value", "expected 'bool'"),
        ("bytes value", "!value", "expected 'bool'"),
        ("bool value", "num2bin(-value, 4)", "expected 'int'"),
        ("int value", "num2bin(-(value == 1), 4)", "expected 'int'"),
        ("bool value", "modExp(-value, 2, 3)", "expected 'int'"),
        ("bool value", "!-value", "expected 'int'"),
        ("int value", "-!value", "expected 'bool'"),
        ("bool[2] value", "-value[0]", "expected 'int'"),
        ("int[2] value", "!value[0]", "expected 'bool'"),
    ] {
        let source = format!("contract Unary() {{ function spend({params}) {{ let result = {expression}; require(true); }} }}");
        let error = compile(&source).expect_err(&source).to_string();
        assert!(
            error.contains("unary '") && error.contains(expected),
            "{expression}: {error}"
        );
    }
}

#[test]
fn unary_negation_preserves_literal_index_bounds() {
    for (index, valid) in [
        ("--1", true),
        ("---0", true),
        ("---1", false),
        ("--2", false),
    ] {
        let source = format!("contract Unary() {{ function spend(int[2] values) {{ require(values[{index}] == 0); }} }}");
        let result = compile(&source);
        if valid {
            result.expect(&source);
        } else {
            assert!(
                result.unwrap_err().to_string().contains("out of range"),
                "{index}"
            );
        }
    }
}

#[test]
fn unary_negation_remains_unsupported_in_l1_tapscripts() {
    for condition in [
        "!checkSig(sig, owner)",
        "-checkSig(sig, owner)",
        "!!checkSig(sig, owner)",
    ] {
        let source = format!("contract Unary(pubkey owner) {{ function spend(signature sig) tapscript {{ require({condition}); }} }}");
        let error = compile(&source).expect_err(&source).to_string();
        assert!(
            error.contains("unsupported compound expression in tapscript"),
            "{error}"
        );
    }
}

#[test]
fn unary_negation_in_builtin_atom_arguments() {
    for (statement, expected) in [
        (
            "let result = num2bin(-(-1), 4);",
            "1 OP_NEGATE OP_NEGATE 4 OP_NUM2BIN",
        ),
        (
            "let result = num2bin(-value, 4);",
            "OP_0 OP_ROLL OP_NEGATE 4 OP_NUM2BIN",
        ),
        (
            "let result = modExp(--value, 2, 3);",
            "OP_0 OP_ROLL OP_NEGATE OP_NEGATE 2 3 OP_MODEXP",
        ),
        (
            "let result = ecAdd(point, point, -1);",
            "1 OP_NEGATE OP_ECADD",
        ),
        (
            "let result = ecMul(point, -3, 0);",
            "3 OP_NEGATE 0 OP_ECMUL",
        ),
        (
            "let result = ecPairing(g1s, g2s, -2);",
            "OP_1 2 OP_NEGATE OP_ECPAIRING",
        ),
        ("let result = sighash(-1);", "1 OP_NEGATE OP_SIGHASH"),
        ("let result = digest(data, -1);", "1 OP_NEGATE OP_DIGEST"),
        (
            "let result = substr(data, -(value + 1), (2 * 3));",
            "1 OP_ADD OP_NEGATE 2 3 OP_MUL OP_SUBSTR",
        ),
        (
            "let result = num2bin(-(value + 1), (2 + 2));",
            "1 OP_ADD OP_NEGATE 2 2 OP_ADD OP_NUM2BIN",
        ),
        (
            "require(tweakVerify(scalar, scalar, (pubkey(data + data))));",
            "OP_CAT",
        ),
        (
            "let result = substr(data, --0, 1);",
            "0 OP_NEGATE OP_NEGATE 1 OP_SUBSTR",
        ),
        (
            "let result = tx.packet(--1);",
            "1 OP_NEGATE OP_NEGATE OP_INSPECTPACKET",
        ),
        (
            "let result = tx.inputs[0].packet(--1);",
            "1 OP_NEGATE OP_NEGATE 0 OP_INSPECTINPUTPACKET",
        ),
    ] {
        let params = [
            ("value", "int value"),
            ("data", "bytes data"),
            ("point", "ECPoint point"),
            ("scalar", "bytes32 scalar"),
            ("g1s", "ECPoint[1] g1s"),
            ("g2s", "G2Point[1] g2s"),
        ]
        .iter()
        .filter(|(name, _)| statement.contains(name))
        .map(|(_, param)| *param)
        .collect::<Vec<_>>()
        .join(", ");
        let read = if statement.starts_with("let") {
            "require(result == result);"
        } else {
            ""
        };
        let source =
            format!("contract Unary() {{ function spend({params}) {{ {statement} {read} }} }}");
        let output = compile(&source).unwrap_or_else(|error| panic!("{statement}: {error}"));
        let asm = crate::common::arkade_asm_tokens(&output, "spend");
        assert!(
            contains_tokens(&asm, &expected.split_whitespace().collect::<Vec<_>>()),
            "{statement}: {asm:?}"
        );
    }
}

#[test]
fn logical_negation_preserves_nested_expressions() {
    let output = compile(
        r#"
        struct State { bool enabled; }
        contract Unary(pubkey owner) {
            function spend(State state, signature sig, bytes left, bytes right) {
                require(!state.enabled);
                require(!(left + right == left));
                require(!checkSig(sig, owner));
            }
        }
    "#,
    )
    .expect("nested logical operands compile");
    assert!(output.warnings.is_empty(), "{:?}", output.warnings);
    let asm = crate::common::arkade_asm_tokens(&output, "spend");
    assert!(asm.iter().any(|token| token == "OP_CAT"), "{asm:?}");
    assert!(
        contains_tokens(&asm, &["OP_EQUAL", "OP_NOT", "OP_VERIFY"]),
        "{asm:?}"
    );
    assert!(
        contains_tokens(&asm, &["OP_CHECKSIG", "OP_NOT", "OP_VERIFY"]),
        "{asm:?}"
    );
}

#[test]
fn grouped_builtin_operands_reject_implicit_byte_conversion() {
    let error = compile("contract Grouped() { function spend(bytes data, bytes32 k, pubkey q) { require(ecMulScalarVerify(k, (pubkey(data + 1)), q)); } }")
        .expect_err("grouped operands must validate concatenation types")
        .to_string();
    assert!(error.contains("cannot concatenate bytes"), "{error}");
}

#[test]
fn builtin_arguments_are_general_expressions() {
    for (statement, expected) in [
        (
            "require(cat(sha256(a), b) == b);",
            &["OP_SHA256", "OP_CAT"][..],
        ),
        (
            "require(bin2num(reverseBytes(substr(a, 0, 4))) == 7);",
            &["OP_SUBSTR", "OP_REVERSEBYTES", "OP_BIN2NUM"],
        ),
        (
            "require(substr(a, n + 1, 2) == a);",
            &["OP_ADD", "OP_SUBSTR"],
        ),
    ] {
        let source = format!(
            "contract Calls(bytes a, bytes b, int n) {{ function spend() {{ {statement} }} }}"
        );
        let output = compile(&source).unwrap_or_else(|error| panic!("{statement}: {error}"));
        let asm = crate::common::arkade_asm_tokens(&output, "spend");
        let mut rest = asm.iter();
        assert!(
            expected.iter().all(|op| rest.any(|token| token == op)),
            "{statement}: expected {expected:?} in order in {asm:?}"
        );
    }
}
