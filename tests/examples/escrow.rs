use arkade_compiler::compile_file;
use arkade_compiler::models::ContractJson;
use arkade_compiler::opcodes::{
    OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_CHECKSIGVERIFY, OP_CHECKTIME,
    OP_INSPECTLOCKTIME, OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_INSPECTOUTPUTVALUE, OP_NUM2BIN, OP_SHA256,
};
use std::path::Path;

use crate::common::{
    arkade_asm, arkade_inputs, group, leaf_asm, opcode_count_in_arkade, witness_names,
};

/// Escrow upgraded from the 2-of-3 multisig shape: payouts are pinned by
/// introspection and the mediator speaks through a signed verdict, so no path
/// depends on a counterparty signing the settlement transaction.
fn escrow() -> ContractJson {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/escrow/escrow.ark");
    compile_file(&path).expect("escrow.ark should compile")
}

#[test]
fn test_escrow_spend_groups() {
    let output = escrow();

    assert_eq!(output.name, "Escrow");
    let names: Vec<&str> = output.functions.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "release",
            "refund",
            "resolve",
            "exitBuyerSeller",
            "exitBuyerMediator",
            "exitSellerMediator"
        ]
    );

    let params: Vec<(&str, &str)> = output
        .parameters
        .iter()
        .map(|p| (p.name.as_str(), p.param_type.as_str()))
        .collect();
    assert_eq!(
        params,
        [
            ("buyerPk", "pubkey"),
            ("sellerPk", "pubkey"),
            ("oraclePk", "pubkey"),
            ("mediatorPk", "pubkey"),
            ("dealId", "bytes32"),
            ("mediationFee", "int"),
            ("refundLocktime", "int"),
            ("exit", "int"),
        ]
    );
}

/// The upgrade on the cooperative path: the seller's signature is replaced by a
/// covenant that can only pay the seller, so exactly one key still signs.
#[test]
fn test_release_drops_the_seller_signature() {
    let output = escrow();

    assert_eq!(
        arkade_inputs(&output, "release"),
        ["buyerSig"],
        "release must collect the buyer's signature and nothing else"
    );
    assert_eq!(
        opcode_count_in_arkade(&output, "release", OP_CHECKSIG),
        1,
        "release must check exactly one transaction signature"
    );

    let asm = arkade_asm(&output, "release");
    assert!(
        asm.contains(&format!(
            "{OP_INSPECTOUTPUTSCRIPTPUBKEY} OP_DROP <VTXO:SingleSig(<sellerPk>,<exit>)>"
        )),
        "release must pin output 0 to the seller: {asm}"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTVALUE),
        "release must pin the payout amount: {asm}"
    );
}

/// The strongest form of the upgrade: past the locktime the refund is fully
/// determined, so it carries no witness and needs nobody online.
#[test]
fn test_refund_needs_no_signature() {
    let output = escrow();

    assert!(
        arkade_inputs(&output, "refund").is_empty(),
        "refund must take no covenant inputs"
    );
    assert_eq!(
        opcode_count_in_arkade(&output, "refund", OP_CHECKSIG),
        0,
        "refund must not check a transaction signature"
    );
    assert_eq!(
        opcode_count_in_arkade(&output, "refund", OP_CHECKSIGFROMSTACK),
        0,
        "refund must not check a message signature either"
    );

    let asm = arkade_asm(&output, "refund");
    assert!(
        asm.contains(OP_INSPECTLOCKTIME),
        "refund must gate on the transaction locktime: {asm}"
    );
    assert!(
        asm.contains("<refundLocktime>"),
        "refund must compare against the committed locktime: {asm}"
    );
    assert!(
        asm.contains(&format!(
            "{OP_INSPECTOUTPUTSCRIPTPUBKEY} OP_DROP <VTXO:SingleSig(<buyerPk>,<exit>)>"
        )),
        "refund must pin output 0 to the buyer: {asm}"
    );
}

/// The mediator authorizes with an attestation, not a transaction signature:
/// the covenant reconstructs sha256(dealId || share || stamp) and verifies it
/// from the stack.
#[test]
fn test_resolve_verifies_an_oracle_attestation() {
    let output = escrow();

    assert_eq!(
        arkade_inputs(&output, "resolve"),
        ["sellerShareBps", "attestedAt", "oracleSig"],
        "resolve takes the verdict and its signature, and no destination"
    );
    assert_eq!(
        opcode_count_in_arkade(&output, "resolve", OP_CHECKSIG),
        0,
        "resolve must not require any party to sign the transaction"
    );
    assert_eq!(
        opcode_count_in_arkade(&output, "resolve", OP_CHECKSIGFROMSTACK),
        1,
        "resolve must verify exactly one attestation"
    );

    let asm = arkade_asm(&output, "resolve");
    assert!(
        asm.contains("<dealId>"),
        "the verdict must be bound to this deal: {asm}"
    );
    assert_eq!(
        opcode_count_in_arkade(&output, "resolve", OP_NUM2BIN),
        2,
        "the attested share and timestamp are both width-fixed before hashing"
    );
    assert!(
        asm.contains(OP_SHA256),
        "the attestation message is hashed before verification: {asm}"
    );
    assert!(
        asm.contains("<oraclePk>"),
        "the attestation is checked against the committed oracle key: {asm}"
    );
    assert!(
        asm.contains(OP_CHECKTIME),
        "a post-dated verdict must be rejected: {asm}"
    );
}

/// A verdict names a share; the covenant turns it into destinations. All three
/// payouts are committed contract state, never spender-supplied scripts.
#[test]
fn test_resolve_pins_every_payout() {
    let output = escrow();
    let asm = arkade_asm(&output, "resolve");

    for owner in ["sellerPk", "buyerPk", "mediatorPk"] {
        assert!(
            asm.contains(&format!(
                "{OP_INSPECTOUTPUTSCRIPTPUBKEY} OP_DROP <VTXO:SingleSig(<{owner}>,<exit>)>"
            )),
            "resolve must pin a payout to {owner}: {asm}"
        );
    }

    // Seller-takes-all, buyer-takes-all, and the split: two payouts each in the
    // first two, three in the split.
    assert_eq!(
        opcode_count_in_arkade(&output, "resolve", OP_INSPECTOUTPUTVALUE),
        7,
        "every branch must pin every output amount it emits: {asm}"
    );
}

/// The emulator-down fallback is the 2-of-3 the escrow always was, enumerated
/// as pairs because arkd recognizes only N-of-N closures. A single-key leaf
/// would hand that party the escrow outright; buyer-and-seller alone would
/// strand a disputed deal, which is the case that matters.
#[test]
fn test_exit_is_a_two_of_three_over_csv() {
    let output = escrow();

    let pairs = [
        (
            "exitBuyerSeller",
            "buyerPk",
            "sellerPk",
            ["buyerSig", "sellerSig"],
        ),
        (
            "exitBuyerMediator",
            "buyerPk",
            "mediatorPk",
            ["buyerSig", "mediatorSig"],
        ),
        (
            "exitSellerMediator",
            "sellerPk",
            "mediatorPk",
            ["sellerSig", "mediatorSig"],
        ),
    ];

    for (name, first, second, witness) in pairs {
        assert!(
            group(&output, name).arkade.is_none(),
            "{name} is a standalone L1 leaf"
        );
        assert_eq!(
            witness_names(&output, name, name),
            witness,
            "{name} witness"
        );
        assert_eq!(
            leaf_asm(&output, name, name),
            format!(
                "<exit> {OP_CHECKSEQUENCEVERIFY} OP_DROP <{first}> {OP_CHECKSIGVERIFY} <{second}> {OP_CHECKSIG}"
            ),
            "{name} must require both keys after the CSV delay"
        );
    }
}
