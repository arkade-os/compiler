//! WlvgaPayout tests — bridge-out (two-party transfer + same-party burn).
//!
//! `payOut` transfers the BTC-backed wLVGA claim to the LVGA liquidity
//! provider (two distinct parties); `burnOut` destroys it (integrated
//! market maker). Both authorize the payee with a merchant secp256k1 key via
//! checkSigFromStack (mirrored by ecrecover on the SwissLedger pool) and pin
//! an OP_RETURN commitment the pool reads.

use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CAT, OP_CHECKSIGFROMSTACK, OP_FINDASSETGROUPBYASSETID, OP_INSPECTASSETGROUPSUM,
    OP_INSPECTOUTASSETLOOKUP, OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_NUM2BIN, OP_SHA256,
};

use crate::common::{arkade_asm, arkade_asm_tokens};

const CODE: &str = include_str!("../../examples/bridge/wlvga_payout.ark");

#[test]
fn test_structure() {
    let output = compile(CODE).unwrap();
    assert_eq!(output.name, "WlvgaPayout");
    // Two covenant modes: payOut (two parties) + burnOut (integrated).
    assert_eq!(output.functions.len(), 2);
    let names: Vec<&str> = output.functions.iter().map(|f| f.name.as_str()).collect();
    assert!(names.contains(&"payOut"), "Got: {names:?}");
    assert!(names.contains(&"burnOut"), "Got: {names:?}");
}

#[test]
fn test_payout_transfers_claim_to_lp() {
    // Two-party mode: the BTC-backed wLVGA claim is transferred to the LP
    // (compensation), NOT burned — so no supply-shrinking burn accounting.
    let output = compile(CODE).unwrap();
    let asm = arkade_asm(&output, "payOut");
    assert!(
        asm.contains("<VTXO:SingleSig(<lpPk>"),
        "wLVGA claim must be transferred to the LP: {asm}"
    );
    assert!(
        asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "LP output must carry the wLVGA amount: {asm}"
    );
    assert!(
        !asm.contains(OP_INSPECTASSETGROUPSUM),
        "payOut transfers (not burns), so no supply-shrink accounting: {asm}"
    );
}

#[test]
fn test_burnout_shrinks_supply() {
    // Same-party option: the wLVGA is burned (supply shrinks).
    let output = compile(CODE).unwrap();
    let asm = arkade_asm(&output, "burnOut");
    assert!(
        asm.contains(OP_FINDASSETGROUPBYASSETID) && asm.contains(OP_INSPECTASSETGROUPSUM),
        "burn must be accounted via asset-group sums: {asm}"
    );
    assert!(
        !asm.contains("<VTXO:SingleSig(<lpPk>"),
        "burnOut destroys the claim; it does not transfer to the LP: {asm}"
    );
}

#[test]
fn test_merchant_csfs_and_concat() {
    // Both modes authorize the payee with CSFS over a byte-CONCATENATED
    // message (OP_CAT, not arithmetic OP_ADD), so the digest matches the
    // merchant's off-chain signature and the EVM ecrecover reconstruction.
    let output = compile(CODE).unwrap();
    for mode in ["payOut", "burnOut"] {
        let asm = arkade_asm(&output, mode);
        assert!(
            asm.contains(OP_CHECKSIGFROMSTACK) && asm.contains(OP_SHA256),
            "{mode}: merchant authorization must be CSFS over a hash: {asm}"
        );
        let cats = arkade_asm_tokens(&output, mode)
            .iter()
            .filter(|s| *s == OP_CAT)
            .count();
        assert_eq!(
            cats, 5,
            "{mode}: expected 5 {OP_CAT} (message + commitment), got {cats}"
        );
    }
}

#[test]
fn test_pins_opreturn_commitment() {
    // Both modes pin the commitment the SwissLedger pool reads, built as
    // protocolTag || evmAddr || num2bin(amount, 8).
    let output = compile(CODE).unwrap();
    for mode in ["payOut", "burnOut"] {
        let asm = arkade_asm(&output, mode);
        assert!(
            asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY) && asm.contains(OP_NUM2BIN),
            "{mode}: commitment output must be pinned with a fixed-width amount: {asm}"
        );
    }
}
