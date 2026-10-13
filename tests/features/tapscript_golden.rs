//! Golden-parity: the §6.1 HTLC tapscript leaves must assemble to the exact
//! closures arkd recognizes (`../arkd/pkg/ark-lib/script/closure.go`) and the
//! introspector funds (`../introspector/test/htlc_test.go`):
//!   claim    → ConditionMultisigClosure{ HASH160 <h> EQUAL, [server, emulator(claim)] }
//!   refund   → CLTVMultisigClosure{ refundTime, [server, emulator(refund)] }
//!   unilateral → CSVMultisigClosure{ exit, [sender] }
//!
//! These assert the LEAF asm only; the covenant bodies just need to compile
//! (the grammar accepts numeric subscripts, not `this.activeInputIndex`, so the
//! covenants use `tx.outputs[0]` / `tx.inputs[0]` — irrelevant to leaf parity).
use arkade_compiler::compile;

const HTLC: &str = r#"
contract HTLC(pubkey receiver, pubkey sender, bytes20 preimageHash, int refundTime, int exit) {
    function claim() {
        require(tx.outputs[0].value >= tx.inputs[0].value);
    }
    function refund() {
        require(tx.outputs[0].value >= tx.inputs[0].value);
    }
    function claim(bytes preimage, signature serverSig, signature emulatorSig) tapscript {
        require(hash160(preimage) == preimageHash);
        require(checkMultisig([server, emulator], [serverSig, emulatorSig], 2));
    }
    function refund(signature serverSig, signature emulatorSig) tapscript {
        require(after(refundTime));
        require(checkMultisig([server, emulator], [serverSig, emulatorSig], 2));
    }
    function unilateral(signature senderSig) tapscript {
        require(older(exit));
        require(checkSig(senderSig, sender));
    }
}
"#;

#[test]
fn claim_matches_condition_multisig_closure() {
    let out = compile(HTLC).unwrap();
    assert_eq!(
        crate::common::leaf_asm(&out, "claim", "claim"),
        "OP_HASH160 <preimageHash> OP_EQUAL OP_VERIFY \
         <SERVER_KEY> OP_CHECKSIGVERIFY <EMULATOR_KEY:claim> OP_CHECKSIG"
    );
}

#[test]
fn refund_matches_cltv_multisig_closure() {
    let out = compile(HTLC).unwrap();
    assert_eq!(
        crate::common::leaf_asm(&out, "refund", "refund"),
        "<refundTime> OP_CHECKLOCKTIMEVERIFY OP_DROP \
         <SERVER_KEY> OP_CHECKSIGVERIFY <EMULATOR_KEY:refund> OP_CHECKSIG"
    );
}

#[test]
fn unilateral_matches_csv_multisig_closure() {
    let out = compile(HTLC).unwrap();
    assert_eq!(
        crate::common::leaf_asm(&out, "unilateral", "unilateral"),
        "<exit> OP_CHECKSEQUENCEVERIFY OP_DROP <sender> OP_CHECKSIG"
    );
}

const SERVER_EXIT: &str = r#"
contract Exit(pubkey owner) {
    function exit(signature ownerSig) tapscript {
        require(older(serverExitDelay));
        require(checkSig(ownerSig, owner));
    }
}
"#;

#[test]
fn server_exit_delay_lowers_to_reserved_placeholder() {
    let out = compile(SERVER_EXIT).unwrap();
    assert_eq!(
        crate::common::leaf_asm(&out, "exit", "exit"),
        "<SERVER_EXIT_DELAY> OP_CHECKSEQUENCEVERIFY OP_DROP <owner> OP_CHECKSIG"
    );
    let inputs: Vec<_> = out.parameters.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(inputs, ["owner"]);
}

#[test]
fn server_exit_delay_is_not_an_absolute_locktime() {
    let source = SERVER_EXIT.replace("older(serverExitDelay)", "after(serverExitDelay)");
    let error = compile(&source).unwrap_err().to_string();
    assert!(error.contains("serverExitDelay"), "got: {error}");
}

#[test]
fn timelock_units_encode_literals_and_constants() {
    let leaf = |timelock: &str| {
        let source = format!(
            "contract C(pubkey owner) {{ const int DELAY = 1024; function exit(signature serverSig, signature sig) tapscript {{ require({timelock}); require(checkMultisig([server, owner], [serverSig, sig], 2)); }} }}"
        );
        let out = compile(&source).unwrap();
        (crate::common::leaf_asm(&out, "exit", "exit"), out.warnings)
    };
    for (timelock, operand) in [
        ("older(seconds(DELAY))", "4194306 OP_CHECKSEQUENCEVERIFY"),
        ("older(blocks(144))", "144 OP_CHECKSEQUENCEVERIFY"),
        ("after(blocks(800000))", "800000 OP_CHECKLOCKTIMEVERIFY"),
        (
            "after(seconds(1700000000))",
            "1700000000 OP_CHECKLOCKTIMEVERIFY",
        ),
    ] {
        let (asm, warnings) = leaf(timelock);
        assert!(asm.starts_with(operand), "{timelock}: {asm}");
        assert!(warnings.is_empty(), "{timelock}: {warnings:?}");
    }
    let (asm, warnings) = leaf("older(DELAY)");
    assert!(asm.starts_with("1024 OP_CHECKSEQUENCEVERIFY"), "{asm}");
    assert!(
        warnings[0].contains("older(1024) is a raw BIP68 sequence"),
        "{warnings:?}"
    );
}

#[test]
fn sized_hashlock_preimages_emit_runtime_width_checks() {
    for (preimage_type, width) in [("bytes20", 20), ("bytes32", 32)] {
        for (hash, digest_type, opcode) in [
            ("hash160", "bytes20", "OP_HASH160"),
            ("ripemd160", "bytes20", "OP_RIPEMD160"),
            ("sha256", "bytes32", "OP_SHA256"),
            ("hash256", "bytes32", "OP_HASH256"),
        ] {
            for (covenant, timelock, keys, signatures) in [
                ("", "", "server, owner", "serverSig, sig"),
                (
                    "",
                    "require(older(144));",
                    "server, owner",
                    "serverSig, sig",
                ),
                (
                    "function claim() { require(tx.outputs[0].value >= 1); }",
                    "",
                    "server, emulator",
                    "serverSig, sig",
                ),
            ] {
                let source = format!(
                    "contract C(pubkey owner, {digest_type} digest) {{ {covenant} function claim({preimage_type} preimage, signature serverSig, signature sig) tapscript {{ require({hash}(preimage) == digest); {timelock} require(checkMultisig([{keys}], [{signatures}], 2)); }} }}"
                );
                for optimize in [false, true] {
                    let output = arkade_compiler::compile_sources_with_options(
                        "main.ark",
                        &std::collections::BTreeMap::from([("main.ark".into(), source.clone())]),
                        arkade_compiler::CompileOptions { optimize },
                    )
                    .unwrap();
                    let leaf = &crate::common::group(&output, "claim").leaves[0];
                    assert_eq!(
                        leaf.asm[..4],
                        ["OP_SIZE", &width.to_string(), "OP_EQUALVERIFY", opcode],
                        "{preimage_type}/{hash}/optimize={optimize}: {:?}",
                        leaf.asm
                    );
                    assert_eq!(leaf.witness[0].name, "preimage");
                    assert_eq!(leaf.witness[0].elem_type, preimage_type);
                }
            }
        }
    }
}

#[test]
fn unsized_hashlock_preimage_preserves_existing_leaf() {
    for optimize in [false, true] {
        let output = arkade_compiler::compile_sources_with_options(
            "main.ark",
            &std::collections::BTreeMap::from([("main.ark".into(), HTLC.into())]),
            arkade_compiler::CompileOptions { optimize },
        )
        .unwrap();
        assert_eq!(
            crate::common::leaf_asm(&output, "claim", "claim"),
            "OP_HASH160 <preimageHash> OP_EQUAL OP_VERIFY <SERVER_KEY> OP_CHECKSIGVERIFY <EMULATOR_KEY:claim> OP_CHECKSIG"
        );
    }
}
