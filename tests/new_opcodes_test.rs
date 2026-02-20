use arkade_compiler::compile;

// ─── Streaming SHA256 Tests ────────────────────────────────────────────

#[test]
fn test_sha256_initialize() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract StreamingHasher(pubkey serverKey, pubkey owner) {
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
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "initHash" && f.server_variant)
        .expect("Should have initHash server variant");

    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains("OP_SHA256INITIALIZE"),
        "Expected OP_SHA256INITIALIZE in ASM: {}",
        asm_str
    );
}

#[test]
fn test_sha256_update() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract StreamingHasher(pubkey serverKey, pubkey owner) {
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
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "updateHash" && f.server_variant)
        .expect("Should have updateHash server variant");

    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains("OP_SHA256UPDATE"),
        "Expected OP_SHA256UPDATE in ASM: {}",
        asm_str
    );
}

#[test]
fn test_sha256_finalize() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract StreamingHasher(pubkey serverKey, pubkey owner) {
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
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "finalizeHash" && f.server_variant)
        .expect("Should have finalizeHash server variant");

    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains("OP_SHA256FINALIZE"),
        "Expected OP_SHA256FINALIZE in ASM: {}",
        asm_str
    );
}

// ─── Conversion & Arithmetic Tests ─────────────────────────────────────

#[test]
fn test_neg64() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract ArithmeticOps(pubkey serverKey, pubkey owner) {
            function negateValue(signature ownerSig, int value) {
                require(checkSig(ownerSig, owner));
                let negated = neg64(value);
            }
        }
    "#;

    let result = compile(code);
    assert!(result.is_ok(), "Failed to parse neg64: {:?}", result.err());

    let output = result.unwrap();
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "negateValue" && f.server_variant)
        .expect("Should have negateValue server variant");

    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains("OP_NEG64"),
        "Expected OP_NEG64 in ASM: {}",
        asm_str
    );
}

#[test]
fn test_le64_to_script_num() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract ConversionOps(pubkey serverKey, pubkey owner) {
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
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "convertToScriptNum" && f.server_variant)
        .expect("Should have convertToScriptNum server variant");

    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains("OP_LE64TOSCRIPTNUM"),
        "Expected OP_LE64TOSCRIPTNUM in ASM: {}",
        asm_str
    );
}

#[test]
fn test_le32_to_le64() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract ConversionOps(pubkey serverKey, pubkey owner) {
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
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "extendTo64Bit" && f.server_variant)
        .expect("Should have extendTo64Bit server variant");

    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains("OP_LE32TOLE64"),
        "Expected OP_LE32TOLE64 in ASM: {}",
        asm_str
    );
}

// ─── Crypto Opcodes Tests ──────────────────────────────────────────────

#[test]
fn test_ec_mul_scalar_verify() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract CryptoOps(pubkey serverKey, pubkey owner) {
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
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "verifyScalarMul" && f.server_variant)
        .expect("Should have verifyScalarMul server variant");

    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains("OP_ECMULSCALARVERIFY"),
        "Expected OP_ECMULSCALARVERIFY in ASM: {}",
        asm_str
    );
}

#[test]
fn test_tweak_verify() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract CryptoOps(pubkey serverKey, pubkey owner) {
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
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "verifyTweak" && f.server_variant)
        .expect("Should have verifyTweak server variant");

    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains("OP_TWEAKVERIFY"),
        "Expected OP_TWEAKVERIFY in ASM: {}",
        asm_str
    );
}

#[test]
fn test_check_sig_from_stack_verify() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract CryptoOps(pubkey serverKey, pubkey owner) {
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
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "verifyMessageSig" && f.server_variant)
        .expect("Should have verifyMessageSig server variant");

    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains("OP_CHECKSIGFROMSTACKVERIFY"),
        "Expected OP_CHECKSIGFROMSTACKVERIFY in ASM: {}",
        asm_str
    );
}

// ─── Combined Usage Tests ───────────────────────────────────────────────────────

#[test]
fn test_streaming_hash_full_workflow() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract StreamingHashWorkflow(pubkey serverKey, pubkey owner, bytes32 expectedHash) {
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
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "computeHash" && f.server_variant)
        .expect("Should have computeHash server variant");

    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains("OP_SHA256INITIALIZE"),
        "Expected OP_SHA256INITIALIZE in ASM: {}",
        asm_str
    );
    assert!(
        asm_str.contains("OP_SHA256UPDATE"),
        "Expected OP_SHA256UPDATE in ASM: {}",
        asm_str
    );
    assert!(
        asm_str.contains("OP_SHA256FINALIZE"),
        "Expected OP_SHA256FINALIZE in ASM: {}",
        asm_str
    );
}

#[test]
fn test_conversion_chain() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract ConversionChain(pubkey serverKey, pubkey owner) {
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
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "convertAndNegate" && f.server_variant)
        .expect("Should have convertAndNegate server variant");

    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains("OP_LE32TOLE64"),
        "Expected OP_LE32TOLE64 in ASM: {}",
        asm_str
    );
    assert!(
        asm_str.contains("OP_NEG64"),
        "Expected OP_NEG64 in ASM: {}",
        asm_str
    );
    assert!(
        asm_str.contains("OP_LE64TOSCRIPTNUM"),
        "Expected OP_LE64TOSCRIPTNUM in ASM: {}",
        asm_str
    );
}
