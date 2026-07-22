//! Advanced Bridge contract tests.
//!
//! `bridge_mint.ark` — custodian-quorum-attested mint of a wrapped foreign
//! asset (deposit leg). `bridge_withdrawal.ark` — escrowed burn with
//! attested release and timeout refund (withdrawal leg).
//! `bridge_spv.ark` — trustless deposit leg: on-chain SPV proof (merkle
//! inclusion + PoW + confirmation depth) replaces the custodian quorum.

use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_BIN2NUM, OP_CAT, OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG,
    OP_CHECKSIGFROMSTACK, OP_FINDASSETGROUPBYASSETID, OP_GREATERTHANOREQUAL, OP_HASH256,
    OP_INSPECTOUTASSETLOOKUP, OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_SCRIPTNUMTOLE64, OP_SHA256,
    OP_SUBSTR,
};

use crate::common::{arkade_asm, arkade_inputs, leaf_asm};

const BRIDGE_MINT_CODE: &str = include_str!("../../examples/bridge/bridge_mint.ark");
const BRIDGE_WITHDRAWAL_CODE: &str = include_str!("../../examples/bridge/bridge_withdrawal.ark");
const BRIDGE_SPV_CODE: &str = include_str!("../../examples/bridge/bridge_spv.ark");
const SWAP_HTLC_CODE: &str = include_str!("../../examples/bridge/swap_htlc.ark");

// ─── BridgeMint ───────────────────────────────────────────────────────────────

#[test]
fn test_bridge_mint_structure() {
    let output = compile(BRIDGE_MINT_CODE).unwrap();

    assert_eq!(output.name, "BridgeMint");
    // Single function-backed spend group (mint); the synthesized default
    // collaborative leaf carries cooperative signing.
    assert_eq!(output.functions.len(), 1);
    assert_eq!(output.functions[0].name, "mint");
}

#[test]
fn test_bridge_mint_custodian_array_flattening() {
    let output = compile(BRIDGE_MINT_CODE).unwrap();

    let param_names: Vec<&str> = output.parameters.iter().map(|p| p.name.as_str()).collect();
    for name in ["custodians_0", "custodians_1", "custodians_2"] {
        assert!(
            param_names.contains(&name),
            "Missing {name} in constructor params. Got: {:?}",
            param_names
        );
    }

    let input_names = arkade_inputs(&output, "mint");
    for name in ["custodianSigs_0", "custodianSigs_1", "custodianSigs_2"] {
        assert!(
            input_names.contains(&name.to_string()),
            "Missing {name} in covenant inputs. Got: {:?}",
            input_names
        );
    }
}

#[test]
fn test_bridge_mint_attestation_reconstruction() {
    let output = compile(BRIDGE_MINT_CODE).unwrap();
    let asm = arkade_asm(&output, "mint");
    let tokens = crate::common::arkade_asm_tokens(&output, "mint");

    // sha256(depositId + recipientSpk + amount + nonce): three concats, one
    // hash, int operands coerced to LE64 before concatenation.
    let cat_count = tokens.iter().filter(|s| *s == OP_CAT).count();
    assert_eq!(cat_count, 3, "Expected 3 {OP_CAT} for 4-operand concat");
    assert!(asm.contains(OP_SHA256), "Missing {OP_SHA256}");
    assert!(
        asm.contains(OP_SCRIPTNUMTOLE64),
        "Missing {OP_SCRIPTNUMTOLE64} int coercion for concat"
    );

    // Quorum: loop unrolled to one checkSigFromStack per custodian slot,
    // compared against the threshold.
    let csfs_count = tokens.iter().filter(|s| *s == OP_CHECKSIGFROMSTACK).count();
    assert_eq!(
        csfs_count, 3,
        "Expected 3 {OP_CHECKSIGFROMSTACK} (one per custodian)"
    );
    assert!(
        asm.contains(OP_GREATERTHANOREQUAL),
        "Missing {OP_GREATERTHANOREQUAL} quorum comparison"
    );
}

#[test]
fn test_bridge_mint_supply_and_recipient_checks() {
    let output = compile(BRIDGE_MINT_CODE).unwrap();
    let asm = arkade_asm(&output, "mint");

    // Asset-group delta / control checks.
    assert!(
        asm.contains(OP_FINDASSETGROUPBYASSETID),
        "Missing {OP_FINDASSETGROUPBYASSETID}"
    );
    // Recipient output pinned to the attested script pubkey, and its token
    // balance inspected.
    assert!(
        asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "Missing {OP_INSPECTOUTPUTSCRIPTPUBKEY}"
    );
    assert!(
        asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "Missing {OP_INSPECTOUTASSETLOOKUP}"
    );
}

#[test]
fn test_bridge_mint_state_continuation_placeholder() {
    let output = compile(BRIDGE_MINT_CODE).unwrap();
    let asm = arkade_asm(&output, "mint");

    // The continuation output is asserted against a fresh BridgeMint
    // instance; the constructor placeholders must reference the flattened
    // custodian set so the next state keeps the same quorum.
    assert!(
        asm.contains("<custodians_0>"),
        "Missing <custodians_0> in continuation constructor. ASM: {}",
        asm
    );
}

// ─── BridgeWithdrawal ─────────────────────────────────────────────────────────

#[test]
fn test_bridge_withdrawal_structure() {
    let output = compile(BRIDGE_WITHDRAWAL_CODE).unwrap();

    assert_eq!(output.name, "BridgeWithdrawal");
    // release + refund (function-backed) + unilateral (standalone tapscript).
    assert_eq!(output.functions.len(), 3);
    let names: Vec<&str> = output.functions.iter().map(|f| f.name.as_str()).collect();
    assert!(names.contains(&"release"), "Got: {:?}", names);
    assert!(names.contains(&"refund"), "Got: {:?}", names);
    assert!(names.contains(&"unilateral"), "Got: {:?}", names);
}

#[test]
fn test_bridge_withdrawal_release_quorum_and_burn() {
    let output = compile(BRIDGE_WITHDRAWAL_CODE).unwrap();
    let asm = arkade_asm(&output, "release");
    let tokens = crate::common::arkade_asm_tokens(&output, "release");

    // Quorum over sha256(withdrawalId + destHash + amount): two concats.
    let cat_count = tokens.iter().filter(|s| *s == OP_CAT).count();
    assert_eq!(cat_count, 2, "Expected 2 {OP_CAT} for 3-operand concat");
    assert!(asm.contains(OP_SHA256), "Missing {OP_SHA256}");
    let csfs_count = tokens.iter().filter(|s| *s == OP_CHECKSIGFROMSTACK).count();
    assert_eq!(
        csfs_count, 3,
        "Expected 3 {OP_CHECKSIGFROMSTACK} (one per custodian)"
    );

    // Burn accounting via asset-group sums.
    assert!(
        asm.contains(OP_FINDASSETGROUPBYASSETID),
        "Missing {OP_FINDASSETGROUPBYASSETID} for burn check"
    );
}

#[test]
fn test_bridge_withdrawal_refund_is_timelocked() {
    let output = compile(BRIDGE_WITHDRAWAL_CODE).unwrap();
    let asm = arkade_asm(&output, "refund");

    // tx.time >= refundTime lowers to a CLTV-style check in the covenant.
    assert!(
        asm.contains(OP_CHECKLOCKTIMEVERIFY),
        "Missing {OP_CHECKLOCKTIMEVERIFY} in refund. ASM: {}",
        asm
    );
    assert!(
        asm.contains("<refundTime>"),
        "Missing <refundTime>. ASM: {asm}"
    );
}

// ─── BridgeSpv (trustless SPV deposit leg) ─────────────────────────────────────

#[test]
fn test_bridge_spv_structure() {
    let output = compile(BRIDGE_SPV_CODE).unwrap();
    assert_eq!(output.name, "BridgeSpv");
    // Single covenant spend group; no quorum, no signers on the proof path.
    assert_eq!(output.functions.len(), 1);
    assert_eq!(output.functions[0].name, "mintFromDeposit");
}

#[test]
fn test_bridge_spv_no_signature_on_proof_path() {
    // The whole point: a deposit is credited by proof, not by a signer.
    // No checkSigFromStack (quorum attestation) appears in the covenant.
    let output = compile(BRIDGE_SPV_CODE).unwrap();
    let asm = arkade_asm(&output, "mintFromDeposit");
    assert!(
        !asm.contains(OP_CHECKSIGFROMSTACK),
        "SPV proof path must not verify any attestation signature: {asm}"
    );
}

#[test]
fn test_bridge_spv_merkle_and_pow_primitives() {
    let output = compile(BRIDGE_SPV_CODE).unwrap();
    let asm = arkade_asm(&output, "mintFromDeposit");
    let tokens = crate::common::arkade_asm_tokens(&output, "mintFromDeposit");

    // Merkle fold + block hashing use Bitcoin double-SHA256 (OP_HASH256),
    // never a tagged-hash merkle opcode.
    let h256 = tokens.iter().filter(|s| *s == OP_HASH256).count();
    assert!(
        h256 >= 6,
        "expected merkle+header double-SHA256s, got {h256}"
    );
    assert!(asm.contains(OP_CAT), "merkle concatenation missing");
    // Header/tx field extraction by byte offset.
    assert!(asm.contains(OP_SUBSTR), "header/tx slicing missing");
    // PoW compare interprets the block hash as a BigNum.
    assert!(asm.contains(OP_BIN2NUM), "PoW magnitude conversion missing");
    // Never uses the tagged-hash merkle opcode (wrong tree for Bitcoin).
    assert!(
        !asm.contains("OP_MERKLEBRANCHVERIFY"),
        "must hand-roll Bitcoin merkle, not use tagged OP_MERKLEBRANCHVERIFY"
    );
}

#[test]
fn test_bridge_spv_mint_under_control_asset() {
    let output = compile(BRIDGE_SPV_CODE).unwrap();
    let asm = arkade_asm(&output, "mintFromDeposit");
    // Supply is gated by the control asset and pinned to a continuation state.
    assert!(
        asm.contains(OP_FINDASSETGROUPBYASSETID),
        "mint must be gated by asset-group control"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "recipient + continuation outputs must be pinned"
    );
    assert!(
        asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "minted token amount must be inspected"
    );
}

#[test]
fn test_bridge_spv_witness_arrays_flattened() {
    let output = compile(BRIDGE_SPV_CODE).unwrap();
    let inputs = arkade_inputs(&output, "mintFromDeposit");
    for name in [
        "merkleSiblings_0",
        "dirs_0",
        "confHeaders_0",
        "depositHeader",
        "txid",
    ] {
        assert!(
            inputs.contains(&name.to_string()),
            "missing witness {name} in covenant inputs: {inputs:?}"
        );
    }
}

// ─── SwapHtlc (introspection-gated fast-transfer swap leg) ─────────────────────

#[test]
fn test_swap_htlc_structure() {
    let output = compile(SWAP_HTLC_CODE).unwrap();
    assert_eq!(output.name, "SwapHtlc");
    // claim + refund (function-backed) + unilateral (standalone) = 3 groups.
    assert_eq!(output.functions.len(), 3);
    let names: Vec<&str> = output.functions.iter().map(|f| f.name.as_str()).collect();
    assert!(names.contains(&"claim"), "Got: {names:?}");
    assert!(names.contains(&"refund"), "Got: {names:?}");
    assert!(names.contains(&"unilateral"), "Got: {names:?}");
}

#[test]
fn test_swap_htlc_claim_is_hashlocked_and_solver_pinned() {
    let output = compile(SWAP_HTLC_CODE).unwrap();
    let asm = arkade_asm(&output, "claim");
    // SHA256 hashlock (matches Lightning payment hash) — completing the claim
    // forces `s` on-chain.
    assert!(
        asm.contains(OP_SHA256),
        "claim must be SHA256-hashlocked: {asm}"
    );
    // Payout pinned to the solver via introspection.
    assert!(
        asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "claim must pin the payout output: {asm}"
    );
    assert!(
        asm.contains("<VTXO:SingleSig(<solverPk>"),
        "claim payout must be pinned to solverPk: {asm}"
    );
}

#[test]
fn test_swap_htlc_claim_needs_no_beneficiary_signature() {
    // The whole point of introspection-gating: the cooperative claim path
    // carries no beneficiary signature, so any relayer/watchtower/operator can
    // complete it once `s` is public.
    let output = compile(SWAP_HTLC_CODE).unwrap();
    let covenant = arkade_asm(&output, "claim");
    assert!(
        !covenant.contains(OP_CHECKSIG),
        "claim covenant must not require a beneficiary signature: {covenant}"
    );
}

#[test]
fn test_swap_htlc_refund_is_timelocked_and_user_pinned() {
    let output = compile(SWAP_HTLC_CODE).unwrap();
    let asm = arkade_asm(&output, "refund");
    assert!(
        asm.contains(OP_CHECKLOCKTIMEVERIFY),
        "refund must be timelocked to refundTime: {asm}"
    );
    assert!(
        asm.contains("<VTXO:SingleSig(<userPk>"),
        "refund must be pinned to userPk: {asm}"
    );
}

#[test]
fn test_swap_htlc_claim_leaf_reenforces_hashlock() {
    // The L1 claim leaf keeps the hashlock so the unilateral path also forces
    // revealing `s`, co-signed by the infra keys.
    let output = compile(SWAP_HTLC_CODE).unwrap();
    let leaf = leaf_asm(&output, "claim", "claim");
    assert!(
        leaf.contains(OP_SHA256),
        "claim leaf must keep the hashlock: {leaf}"
    );
    assert!(
        leaf.contains("<SERVER_KEY>"),
        "claim leaf must co-sign with the server key: {leaf}"
    );
}

#[test]
fn test_swap_htlc_unilateral_is_csv_to_user() {
    let output = compile(SWAP_HTLC_CODE).unwrap();
    let leaf = leaf_asm(&output, "unilateral", "unilateral");
    assert!(
        leaf.contains(OP_CHECKSEQUENCEVERIFY),
        "unilateral exit must be CSV-timelocked: {leaf}"
    );
    assert!(
        leaf.contains("<userPk>") && leaf.contains(OP_CHECKSIG),
        "unilateral exit must be the user's signature: {leaf}"
    );
}
