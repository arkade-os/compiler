//! StabilityPayout tests — the stability-vault + LVGA-payout fusion.
//!
//! `seekerPayout` settles an oracle-priced CHF claim as a merchant LVGA
//! payment: the seeker's BTC entitlement goes to the LP, and an OP_RETURN
//! commitment authorizes the SwissLedger pool release.

use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CAT, OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_NUM2BIN, OP_SHA256,
};

use crate::common::{arkade_asm, arkade_asm_tokens};

const CODE: &str = include_str!("../../examples/stability/stability_lvga_payout.ark");

#[test]
fn test_structure() {
    let output = compile(CODE).unwrap();
    assert_eq!(output.name, "StabilityPayout");
    // seekerPayout (function-backed) + unilateral (standalone tapscript).
    assert_eq!(output.functions.len(), 2);
    let names: Vec<&str> = output.functions.iter().map(|f| f.name.as_str()).collect();
    assert!(names.contains(&"seekerPayout"), "Got: {names:?}");
    assert!(names.contains(&"unilateral"), "Got: {names:?}");
}

#[test]
fn test_two_signature_checks_oracle_and_merchant() {
    // Oracle price feed AND merchant invoice are both verified with
    // checkSigFromStack; the seeker authorizes the spend with a plain checkSig.
    let output = compile(CODE).unwrap();
    let tokens = arkade_asm_tokens(&output, "seekerPayout");
    let csfs = tokens.iter().filter(|s| *s == OP_CHECKSIGFROMSTACK).count();
    assert_eq!(csfs, 2, "expected oracle + merchant CSFS, got {csfs}");
    let asm = arkade_asm(&output, "seekerPayout");
    assert!(
        asm.contains(OP_CHECKSIG),
        "seeker must authorize with checkSig: {asm}"
    );
    assert!(
        asm.contains(OP_SHA256),
        "oracle + invoice messages are hashed: {asm}"
    );
}

#[test]
fn test_seeker_btc_goes_to_lp() {
    // The settled BTC is pinned to the LP (compensation), not to the seeker.
    let output = compile(CODE).unwrap();
    let asm = arkade_asm(&output, "seekerPayout");
    assert!(
        asm.contains("<VTXO:SingleSig(<lpPk>"),
        "seeker's settled BTC must be pinned to the LP: {asm}"
    );
    assert!(
        asm.contains("<VTXO:SingleSig(<providerPk>"),
        "collateral remainder must be pinned to the provider: {asm}"
    );
    assert!(
        !asm.contains("<VTXO:SingleSig(<seekerPk>"),
        "the seeker is paying out, not receiving BTC here: {asm}"
    );
}

#[test]
fn test_pins_opreturn_commitment() {
    let output = compile(CODE).unwrap();
    let asm = arkade_asm(&output, "seekerPayout");
    assert!(
        asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY) && asm.contains(OP_NUM2BIN),
        "the LVGA payout commitment must be pinned with a fixed-width CHF amount: {asm}"
    );
    // Oracle message (2 CATs) + invoice message (3) + commitment (2) = 7.
    let cats = arkade_asm_tokens(&output, "seekerPayout")
        .iter()
        .filter(|s| *s == OP_CAT)
        .count();
    assert_eq!(
        cats, 7,
        "expected 7 {OP_CAT} across oracle/invoice/commitment, got {cats}"
    );
}
