use arkade_compiler::compile_file;
use arkade_compiler::models::ContractJson;
use arkade_compiler::opcodes::{
    OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_CHECKTIME, OP_INSPECTLOCKTIME,
    OP_INSPECTNUMINPUTS, OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_SHA256,
};
use std::path::Path;

use crate::common::{arkade_asm, arkade_inputs, group, leaf_asm, opcode_count_in_arkade};

fn escrow() -> ContractJson {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/escrow/escrow.ark");
    compile_file(&path).expect("escrow.ark should compile")
}

#[test]
fn test_escrow_spend_groups() {
    let output = escrow();

    assert_eq!(output.name, "Escrow");
    let names: Vec<&str> = output.functions.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, ["complete", "cancel", "unilateral"]);
}

#[test]
fn test_no_path_requires_a_party_signature() {
    let output = escrow();

    for name in ["complete", "cancel"] {
        assert_eq!(
            opcode_count_in_arkade(&output, name, OP_CHECKSIG),
            0,
            "{name} must not check a transaction signature"
        );
    }
    assert!(
        arkade_inputs(&output, "cancel").is_empty(),
        "the timeout refund must take no covenant inputs"
    );
    assert_eq!(
        arkade_inputs(&output, "complete"),
        ["oracleMsg", "oracleSig"],
        "complete takes the attestation and nothing else"
    );
}

#[test]
fn test_attestation_is_committed_and_verified() {
    let output = escrow();
    let asm = arkade_asm(&output, "complete");

    assert!(
        asm.contains(OP_SHA256),
        "the attestation must be hashed before comparison: {asm}"
    );
    assert!(
        asm.contains("<oracleMessageHash>"),
        "the attested message must be pinned to committed state: {asm}"
    );
    assert_eq!(
        opcode_count_in_arkade(&output, "complete", OP_CHECKSIGFROMSTACK),
        1,
        "exactly one oracle attestation is verified"
    );
    assert!(
        asm.contains("<oraclePk>"),
        "the attestation is checked against the committed oracle key: {asm}"
    );
}

#[test]
fn test_payouts_are_pinned_to_committed_destinations() {
    let output = escrow();

    let complete = arkade_asm(&output, "complete");
    assert!(
        complete.contains(OP_INSPECTNUMINPUTS),
        "complete must refuse a multi-input drain: {complete}"
    );
    for destination in ["<partyBScript>", "<partyAScript>"] {
        assert!(
            complete.contains(destination),
            "complete must pin a payout to {destination}: {complete}"
        );
    }
    assert!(
        complete.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "complete must inspect the payout scripts: {complete}"
    );

    let cancel = arkade_asm(&output, "cancel");
    assert!(
        cancel.contains(OP_INSPECTNUMINPUTS),
        "cancel must refuse a multi-input drain: {cancel}"
    );
    assert!(
        cancel.contains(OP_CHECKTIME) && cancel.contains("<timeoutAt>"),
        "cancel must gate on the committed timeout: {cancel}"
    );
    assert!(
        !cancel.contains(OP_INSPECTLOCKTIME),
        "arkd rebuilds this spend with nLockTime 0, so tx.time cannot gate cancel: {cancel}"
    );
    assert!(
        cancel.contains("<partyAScript>") && !cancel.contains("<partyBScript>"),
        "a timeout refund may only reach party A: {cancel}"
    );
}

#[test]
fn test_unilateral_exit_is_two_of_two() {
    let output = escrow();

    assert!(
        group(&output, "unilateral").arkade.is_none(),
        "unilateral is a standalone L1 leaf"
    );
    let leaf = leaf_asm(&output, "unilateral", "unilateral");
    assert!(
        leaf.contains(OP_CHECKSEQUENCEVERIFY)
            && leaf.contains("<partyAPk>")
            && leaf.contains("<partyBPk>")
            && !leaf.contains("<oraclePk>"),
        "the exit requires both parties after the CSV delay: {leaf}"
    );
}
