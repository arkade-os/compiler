use arkade_compiler::compile;

use crate::common::{arkade_asm_tokens, arkade_inputs, group};

#[test]
fn bytes_literals_encode_exact_bytes() {
    for (literal, expected) in [
        (r#""hello""#, "0x68656c6c6f"),
        (r#""ž🙂""#, "0xc5bef09f9982"),
        (
            r#""\"\\\/\b\f\n\r\t\u0000\u017e\uD83D\uDE42""#,
            "0x225c2f080c0a0d0900c5bef09f9982",
        ),
        (r#""""#, "OP_0"),
        (
            r#""// <injected> OP_DROP""#,
            "0x2f2f203c696e6a65637465643e204f505f44524f50",
        ),
        ("0xdeadbeef", "0xdeadbeef"),
        ("0xDEADBEEF", "0xDEADBEEF"),
        ("0x000180", "0x000180"),
    ] {
        let out = compile(&format!(
            "contract Demo() {{ function spend(bytes expected) {{ bytes x = {literal}; require(x == expected); }} }}"
        )).unwrap_or_else(|error| panic!("{literal}: {error}"));
        let asm = arkade_asm_tokens(&out, "spend");
        assert_eq!(asm[0], expected, "{literal}: {asm:?}");
        assert!(asm.iter().any(|token| token == "OP_EQUAL"));
        assert_eq!(arkade_inputs(&out, "spend"), ["expected"]);
        assert_eq!(group(&out, "spend").leaves.len(), 1);
    }
}

#[test]
fn bytes_literals_work_through_expressions_and_named_operands() {
    let out = compile(
        r#"
        struct Pair { bytes first; bytes second; }
        contract Demo(pubkey key, bytes32 hash) {
            const bytes MESSAGE = "hello";
            private function echo(bytes data) bytes { return data; }
            function spend(signature sig) {
                bytes x = "hello";
                x = 0xDEADBEEF;
                let y = "he" + 0x6c6c6f;
                bytes[2] values = ["hello", 0xDEADBEEF];
                Pair pair = { first: "hello", second: 0xDEADBEEF };
                require(values[0] == pair.first);
                require(echo("hello") == y);
                require(x != "hello");
                require("hello" == MESSAGE);
                require(size("") == 0);
                require(substr("hello", 0, 2) == 0x6865);
                require(cat("he", 0x6c6c6f) == y);
                require(bin2num(0x01) == 1);
                require(reverseBytes(0x0001) == 0x0100);
                require(sha256("hello") == hash);
                require(sha256(y) == 0x00);
                require(sha256(y + "!") == 0x00);
                require(hash160("hello") == 0x00);
                require(hash256(MESSAGE) == 0x00);
                require(ripemd160("hello") == "digest");
                let ctx = sha256Initialize("he");
                ctx = sha256Update(ctx, "ll");
                require(sha256Finalize(ctx, 0x6f) == hash);
                require(digest("hello", 0) == hash);
                require(checkSigFromStack(sig, key, "hello"));
                let valid = checkSigFromStack(sig, key, 0x68656c6c6f);
                require(valid);
                require(checkSigFromStackVerify(sig, key, MESSAGE));
            }
        }
    "#,
    )
    .expect("byte expressions compile");
    let asm = arkade_asm_tokens(&out, "spend");
    for opcode in [
        "OP_CAT",
        "OP_SUBSTR",
        "OP_BIN2NUM",
        "OP_REVERSEBYTES",
        "OP_SHA256",
        "OP_HASH160",
        "OP_HASH256",
        "OP_RIPEMD160",
        "OP_SHA256INITIALIZE",
        "OP_SHA256UPDATE",
        "OP_SHA256FINALIZE",
        "OP_DIGEST",
        "OP_CHECKSIGFROMSTACK",
    ] {
        assert!(asm.iter().any(|token| token == opcode), "missing {opcode}");
    }
    assert!(!asm
        .iter()
        .any(|token| token.contains("MESSAGE") || token.contains("hello")));
}

#[test]
fn bytes_literals_reject_malformed_syntax_and_wrong_types() {
    for literal in [
        "0x",
        "0x0",
        "0xabc",
        "0xgg",
        "0x001g",
        "0x00_ff",
        "0x00 11",
        "0XFF",
        r#""\q""#,
        r#""\uD800""#,
        r#""\uDC00""#,
        r#""unterminated"#,
    ] {
        assert!(compile(&format!("contract Demo() {{ function spend() {{ bytes x = {literal}; require(x == x); }} }}")).is_err(), "accepted {literal}");
    }
    for statement in [
        "int x = 0x01;",
        "bool x = \"true\";",
        "bytes32 x = 0x00;",
        "let x = -0x01;",
        "let x = !\"hello\";",
        "let x = \"a\" + 1;",
        "require(checkSigFromStack(0x00, key, \"message\"));",
    ] {
        assert!(
            compile(&format!(
                "contract Demo(pubkey key) {{ function spend() {{ {statement} require(true); }} }}"
            ))
            .is_err(),
            "accepted {statement}"
        );
    }
    for condition in ["0x01 == 1", r#""a" < "b""#] {
        let out = compile(&format!(
            "contract Demo() {{ function spend() {{ require({condition}); }} }}"
        ))
        .unwrap();
        assert!(
            out.warnings
                .iter()
                .any(|warning| warning.contains("comparison") && warning.contains("bytes")),
            "{:?}",
            out.warnings
        );
    }
}

#[test]
fn bytes_literals_in_tapscript_hash_keep_witness_shape() {
    let out = compile(
        r#"
        contract Demo(pubkey owner) {
            function claim(bytes preimage, signature sig) tapscript {
                require(hash160(preimage) == 0x0000000000000000000000000000000000000000);
                require(older(512));
                require(checkSig(sig, owner));
            }
        }
    "#,
    )
    .expect("literal hash in tapleaf");
    let group = group(&out, "claim");
    assert!(group.arkade.is_none());
    assert_eq!(group.leaves.len(), 1);
    let leaf = &group.leaves[0];
    assert_eq!(
        &leaf.asm[..4],
        [
            "OP_HASH160",
            "0x0000000000000000000000000000000000000000",
            "OP_EQUAL",
            "OP_VERIFY"
        ]
    );
    assert_eq!(
        leaf.witness
            .iter()
            .map(|input| input.name.as_str())
            .collect::<Vec<_>>(),
        ["preimage", "sig"]
    );
}

#[test]
fn bytes_literals_compound_hash_comparisons() {
    for rhs in [r#""he" + 0x6c6c6f"#, "0x6865 + suffix", "sha256(suffix)"] {
        let out = compile(&format!(
            "contract Demo() {{ function spend(bytes suffix) {{ require(sha256(\"hello\") == {rhs}); }} }}"
        )).unwrap_or_else(|error| panic!("{rhs}: {error}"));
        assert!(out.warnings.is_empty(), "{:?}", out.warnings);
        assert!(arkade_asm_tokens(&out, "spend")
            .iter()
            .any(|token| token == "OP_EQUAL"));
    }
}

#[test]
fn bytes_literals_validate_escapes_in_all_string_contexts() {
    for source in [
        r#"import "\uD800.ark"; contract Demo() { function spend() { require(true); } }"#,
        r#"contract Demo() { function spend() { require(true, "\uD800"); } }"#,
        r#"contract Demo(pubkey owner) { function exit(signature sig) tapscript {
            require(older(144), "\uD800"); require(checkSig(sig, owner));
        } }"#,
    ] {
        let error = compile(source).expect_err("unpaired surrogate must fail");
        assert!(
            error.to_string().contains("Invalid string literal"),
            "{error}"
        );
    }
}
