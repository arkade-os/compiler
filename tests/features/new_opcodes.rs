use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CAT, OP_CHECKSIGFROMSTACKVERIFY, OP_ECMULSCALARVERIFY, OP_HASH256, OP_LE32TOLE64,
    OP_LE64TOSCRIPTNUM, OP_NEG64, OP_REVERSEBYTES, OP_SHA256, OP_SHA256FINALIZE,
    OP_SHA256INITIALIZE, OP_SHA256UPDATE, OP_TWEAKVERIFY,
};

// ─── hash256 / reverseBytes as first-class expressions ─────────────────
// These primitives previously only parsed inside `require(hash256(x) == y)`.
// Exposing them in let/assignment/expression position is what makes an
// on-chain SPV merkle fold and PoW check expressible (see examples/bridge).

#[test]
fn test_hash256_in_let_and_merkle_step() {
    // hash256() must work in assignment position and accept a `+` concat
    // argument (a merkle step), lowering the inner `+` to OP_CAT.
    let code = r#"
        contract MerkleStep(bytes32 root, int exit) {
            function step(bytes32 leaf, bytes32 sibling) {
                let parent = hash256(leaf + sibling);
                require(parent == root, "mismatch");
            }
        }
    "#;
    let output = compile(code).expect("hash256 in let should compile");
    let asm = crate::common::arkade_asm(&output, "step");
    assert!(asm.contains(OP_HASH256), "expected {OP_HASH256}: {asm}");
    assert!(
        asm.contains(OP_CAT),
        "hash256(a + b) must lower `+` to {OP_CAT}: {asm}"
    );
    // Double-SHA256, not single.
    assert!(
        !asm.contains(OP_SHA256) || asm.contains(OP_HASH256),
        "hash256 must map to {OP_HASH256}, not {OP_SHA256}"
    );
}

#[test]
fn test_reverse_bytes_expression() {
    let code = r#"
        contract Rev(bytes32 target, int exit) {
            function chk(bytes header) {
                let be = reverseBytes(hash256(header));
                require(be == target, "nope");
            }
        }
    "#;
    let output = compile(code).expect("reverseBytes should compile");
    let asm = crate::common::arkade_asm(&output, "chk");
    assert!(
        asm.contains(OP_REVERSEBYTES),
        "expected {OP_REVERSEBYTES}: {asm}"
    );
    assert!(asm.contains(OP_HASH256), "expected {OP_HASH256}: {asm}");
}

#[test]
fn test_hash256_loop_accumulator_merkle_fold() {
    // The merkle-fold idiom used by the SPV bridge: reassign an accumulator
    // across an unrolled loop, choosing sibling order by a direction bit.
    let code = r#"
        contract MerkleFold(bytes32 root, int exit) {
            function verify(bytes32 txid, bytes32[] branch, int[] dirs) {
                bytes32 node = txid;
                for (i, sibling) in branch {
                    if (dirs[i] == 0) {
                        node = hash256(node + sibling);
                    } else {
                        node = hash256(sibling + node);
                    }
                }
                require(node == root, "bad merkle proof");
            }
        }
    "#;
    let output = compile(code).expect("merkle fold should compile");
    let tokens = crate::common::arkade_asm_tokens(&output, "verify");
    // 3-level default unroll: 2 hash256 per level (both branches emitted).
    let h = tokens.iter().filter(|s| *s == OP_HASH256).count();
    assert_eq!(
        h, 6,
        "expected 6 {OP_HASH256} for 3 unrolled levels, got {h}"
    );
    let c = tokens.iter().filter(|s| *s == OP_CAT).count();
    assert_eq!(c, 6, "expected 6 {OP_CAT} for 3 unrolled levels, got {c}");
}

// ─── Streaming SHA256 Tests ────────────────────────────────────────────

#[test]
fn test_sha256_initialize() {
    let code = r#"
        contract StreamingHasher(pubkey owner) {
            function initHash(signature ownerSig, bytes32 initialData) {
                require(checkSig(ownerSig, owner));
                let ctx = sha256Initialize(initialData);
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

// ─── Conversion & Arithmetic Tests ─────────────────────────────────────

#[test]
fn test_neg64() {
    let code = r#"
        contract ArithmeticOps(pubkey owner) {
            function negateValue(signature ownerSig, int value) {
                require(checkSig(ownerSig, owner));
                let negated = neg64(value);
            }
        }
    "#;

    let result = compile(code);
    assert!(result.is_ok(), "Failed to parse neg64: {:?}", result.err());

    let output = result.unwrap();
    let asm_str = crate::common::arkade_asm(&output, "negateValue");
    assert!(
        asm_str.contains(OP_NEG64),
        "Expected {OP_NEG64} in ASM: {}",
        asm_str
    );
}

#[test]
fn test_le64_to_script_num() {
    let code = r#"
        contract ConversionOps(pubkey owner) {
            function convertToScriptNum(signature ownerSig, int value) {
                require(checkSig(ownerSig, owner));
                let converted = le64ToScriptNum(value);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse le64ToScriptNum: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let asm_str = crate::common::arkade_asm(&output, "convertToScriptNum");
    assert!(
        asm_str.contains(OP_LE64TOSCRIPTNUM),
        "Expected {OP_LE64TOSCRIPTNUM} in ASM: {}",
        asm_str
    );
}

#[test]
fn test_le32_to_le64() {
    let code = r#"
        contract ConversionOps(pubkey owner) {
            function extendTo64Bit(signature ownerSig, int value) {
                require(checkSig(ownerSig, owner));
                let extended = le32ToLe64(value);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse le32ToLe64: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let asm_str = crate::common::arkade_asm(&output, "extendTo64Bit");
    assert!(
        asm_str.contains(OP_LE32TOLE64),
        "Expected {OP_LE32TOLE64} in ASM: {}",
        asm_str
    );
}

// ─── Crypto Opcodes Tests ──────────────────────────────────────────────

#[test]
fn test_ec_mul_scalar_verify() {
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
        result.is_ok(),
        "Failed to parse ecMulScalarVerify: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let asm_str = crate::common::arkade_asm(&output, "verifyScalarMul");
    assert!(
        asm_str.contains(OP_ECMULSCALARVERIFY),
        "Expected {OP_ECMULSCALARVERIFY} in ASM: {}",
        asm_str
    );
}

#[test]
fn test_tweak_verify() {
    let code = r#"
        contract CryptoOps(pubkey owner) {
            function verifyTweak(signature ownerSig, pubkey P, bytes32 tweak, pubkey Q) {
                require(checkSig(ownerSig, owner));
                let result = tweakVerify(P, tweak, Q);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse tweakVerify: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let asm_str = crate::common::arkade_asm(&output, "verifyTweak");
    assert!(
        asm_str.contains(OP_TWEAKVERIFY),
        "Expected {OP_TWEAKVERIFY} in ASM: {}",
        asm_str
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

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse checkSigFromStackVerify: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let asm_str = crate::common::arkade_asm(&output, "verifyMessageSig");
    assert!(
        asm_str.contains(OP_CHECKSIGFROMSTACKVERIFY),
        "Expected {OP_CHECKSIGFROMSTACKVERIFY} in ASM: {}",
        asm_str
    );
}

// ─── Combined Usage Tests ───────────────────────────────────────────────────────

#[test]
fn test_streaming_hash_full_workflow() {
    let code = r#"
        contract StreamingHashWorkflow(pubkey owner, bytes32 expectedHash) {
            function computeHash(signature ownerSig, bytes32 chunk1, bytes32 chunk2, bytes32 chunk3) {
                require(checkSig(ownerSig, owner));
                let ctx = sha256Initialize(chunk1);
                let ctx2 = sha256Update(ctx, chunk2);
                let hash = sha256Finalize(ctx2, chunk3);
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
fn test_conversion_chain() {
    let code = r#"
        contract ConversionChain(pubkey owner) {
            function convertAndNegate(signature ownerSig, int value) {
                require(checkSig(ownerSig, owner));
                let extended = le32ToLe64(value);
                let negated = neg64(extended);
                let scriptNum = le64ToScriptNum(negated);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse conversion chain: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let asm_str = crate::common::arkade_asm(&output, "convertAndNegate");
    assert!(
        asm_str.contains(OP_LE32TOLE64),
        "Expected {OP_LE32TOLE64} in ASM: {}",
        asm_str
    );
    assert!(
        asm_str.contains(OP_NEG64),
        "Expected {OP_NEG64} in ASM: {}",
        asm_str
    );
    assert!(
        asm_str.contains(OP_LE64TOSCRIPTNUM),
        "Expected {OP_LE64TOSCRIPTNUM} in ASM: {}",
        asm_str
    );
}
