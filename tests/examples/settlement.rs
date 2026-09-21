use arkade_compiler::compile_file;
use arkade_compiler::models::ContractJson;
use arkade_compiler::opcodes::{
    OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_INSPECTLOCKTIME,
    OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_SHA256,
};
use std::path::Path;

use crate::common::{arkade_asm, arkade_inputs, group, leaf_asm, opcode_count_in_arkade};

/// Arkade port of a Liquid/SimplicityHL bilateral settlement. See
/// `examples/settlement/settlement.md` for the construct-by-construct mapping.
fn settlement() -> ContractJson {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/settlement/settlement.ark");
    compile_file(&path).expect("settlement.ark should compile")
}

#[test]
fn test_settlement_spend_groups() {
    let output = settlement();

    assert_eq!(output.name, "Settlement");
    let names: Vec<&str> = output.functions.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, ["complete", "cancel", "fallback", "unilateral"]);
}

/// The port's headline change: the original needs party B to co-sign the
/// settlement, because there only the destinations are fixed. Pinning the
/// amounts removes that signature, so no covenant path checks one.
#[test]
fn test_no_path_requires_a_party_signature() {
    let output = settlement();

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

/// The oracle asserts one pre-committed message, so a compromised oracle key
/// cannot name a different outcome: the covenant hashes what it is given and
/// compares it against committed state before verifying the signature.
#[test]
fn test_attestation_is_committed_and_verified() {
    let output = settlement();
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

/// Both payouts go to destinations committed at construction, never to a
/// script the spender supplies.
#[test]
fn test_payouts_are_pinned_to_committed_destinations() {
    let output = settlement();

    let complete = arkade_asm(&output, "complete");
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
        cancel.contains(OP_INSPECTLOCKTIME) && cancel.contains("<timeoutHeight>"),
        "cancel must gate on the committed timeout: {cancel}"
    );
    assert!(
        cancel.contains("<partyAScript>") && !cancel.contains("<partyBScript>"),
        "a timeout refund may only reach party A: {cancel}"
    );
}

/// Two CSV leaves. The agent spends alone after the shorter delay; the parties
/// spend 2-of-2 after the longer one. The oracle key is in neither leaf.
#[test]
fn test_layered_csv_exit() {
    let output = settlement();

    for name in ["fallback", "unilateral"] {
        assert!(
            group(&output, name).arkade.is_none(),
            "{name} is a standalone L1 leaf"
        );
    }

    let fallback = leaf_asm(&output, "fallback", "fallback");
    assert!(
        fallback.contains(OP_CHECKSEQUENCEVERIFY) && fallback.contains("<agentPk>"),
        "the first exit is the agent key after agentExit: {fallback}"
    );
    assert!(
        !fallback.contains("<partyAPk>") && !fallback.contains("<oraclePk>"),
        "the agent leaf carries neither a party nor the oracle: {fallback}"
    );

    let unilateral = leaf_asm(&output, "unilateral", "unilateral");
    assert!(
        unilateral.contains(OP_CHECKSEQUENCEVERIFY)
            && unilateral.contains("<partyAPk>")
            && unilateral.contains("<partyBPk>"),
        "the second exit requires both parties after the longer CSV: {unilateral}"
    );
    assert!(
        !unilateral.contains("<agentPk>") && !unilateral.contains("<oraclePk>"),
        "the party leaf carries neither the agent nor the oracle: {unilateral}"
    );
}
