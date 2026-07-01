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

mod common;

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
        require(tx.time >= refundTime);
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
        common::leaf_asm(&out, "claim", "claim"),
        "OP_HASH160 <preimageHash> OP_EQUAL OP_VERIFY \
         <SERVER_KEY> OP_CHECKSIGVERIFY <EMULATOR_KEY:claim> OP_CHECKSIG"
    );
}

#[test]
fn refund_matches_cltv_multisig_closure() {
    let out = compile(HTLC).unwrap();
    assert_eq!(
        common::leaf_asm(&out, "refund", "refund"),
        "<refundTime> OP_CHECKLOCKTIMEVERIFY OP_DROP \
         <SERVER_KEY> OP_CHECKSIGVERIFY <EMULATOR_KEY:refund> OP_CHECKSIG"
    );
}

#[test]
fn unilateral_matches_csv_multisig_closure() {
    let out = compile(HTLC).unwrap();
    assert_eq!(
        common::leaf_asm(&out, "unilateral", "unilateral"),
        "<exit> OP_CHECKSEQUENCEVERIFY OP_DROP <sender> OP_CHECKSIG"
    );
}
