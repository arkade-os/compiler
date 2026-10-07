//! Golden-parity: the §6.1 HTLC tapscript leaves must assemble to the exact
//! closures arkd recognizes (`../arkd/pkg/ark-lib/script/closure.go`) and the
//! introspector funds (`../introspector/test/htlc_test.go`):
//!   claim    → ConditionMultisigClosure{ HASH160 <h> EQUAL, [server, emulator(claim)] }
//!   refund   → CLTVMultisigClosure{ refundTime, [server, emulator(refund)] }
//!   unilateral → CSVMultisigClosure{ 512 seconds, [sender] }
//!
//! These assert the LEAF asm only; the covenant bodies just need to compile
//! (the grammar accepts numeric subscripts, not `this.activeInputIndex`, so the
//! covenants use `tx.outputs[0]` / `tx.inputs[0]` — irrelevant to leaf parity).
use arkade_compiler::compile;

const HTLC: &str = r#"
contract HTLC(pubkey receiver, pubkey sender, bytes20 preimageHash, int refundTime) {
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
        require(older(512));
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
        "4194305 OP_CHECKSEQUENCEVERIFY OP_DROP <sender> OP_CHECKSIG"
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
