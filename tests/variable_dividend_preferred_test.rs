//! Behavioral tests for `examples/variable_dividend_preferred.ark` — a Bitcoin-native
//! perpetual preferred share paying a variable cash dividend.
//!
//! These assert the load-bearing semantics, not byte-for-byte ASM:
//!   - oracle-verifying functions reconstruct sha256(ticker||price||time),
//!   - pure key-swaps (transfer/topUp) touch no oracle,
//!   - `pokeArrears` is permissionless (no issuer/holder signature gate),
//!   - every function exposes a timelock-gated unilateral exit variant.

mod common;

use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CAT, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_SHA256,
};
use common::*;
use std::fs;
use std::path::PathBuf;

fn vdp() -> arkade_compiler::models::ContractJson {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join("variable_dividend_preferred.ark");
    let source = fs::read_to_string(&path).expect("read variable_dividend_preferred.ark");
    compile(&source).expect("variable_dividend_preferred compiles")
}

#[test]
fn compiles_with_14_tapleaves() {
    let out = vdp();
    assert_eq!(out.name, "VariableDividendPreferred");
    // 7 functions × 2 variants (server + exit).
    assert_eq!(out.functions.len(), 14);
}

#[test]
fn oracle_functions_verify_full_signed_message() {
    // Every function that consumes an oracle price must reconstruct
    // sha256(ticker || price || time) on stack (>=2 OP_CAT: ticker+price,
    // +time) and verify it with OP_CHECKSIGFROMSTACK.
    let out = vdp();
    for name in &["accrueAndRepeg", "pokeArrears", "claim", "redeem"] {
        let asm = asm_of(&out, name);
        let cat = opcode_count(&out, name, OP_CAT);
        assert!(
            cat >= 2,
            "{name}: expected >=2 OP_CAT for ticker+price+time, found {cat}"
        );
        assert!(asm.contains(OP_SHA256), "{name}: missing OP_SHA256");
        assert!(
            asm.contains(OP_CHECKSIGFROMSTACK),
            "{name}: missing oracle sig verification"
        );
    }
}

#[test]
fn holder_and_issuer_actions_carry_their_signature() {
    let out = vdp();
    // accrueAndRepeg & redeem are issuer-gated; claim & transfer are holder-gated.
    for name in &[
        "accrueAndRepeg",
        "redeem",
        "claim",
        "transfer",
        "topUp",
        "forceRedeem",
    ] {
        assert!(
            asm_of(&out, name).contains(OP_CHECKSIG),
            "{name}: must verify an owner signature with OP_CHECKSIG"
        );
    }
}

#[test]
fn transfer_and_topup_touch_no_oracle() {
    // State-preserving key operations must not invoke the oracle or hash.
    let out = vdp();
    for name in &["transfer", "topUp"] {
        let asm = asm_of(&out, name);
        assert!(
            !asm.contains(OP_CHECKSIGFROMSTACK),
            "{name}: must not call the oracle"
        );
        assert!(
            !asm.contains(OP_SHA256),
            "{name}: must not hash an oracle message"
        );
        assert!(
            opcode_count(&out, name, OP_CAT) == 0,
            "{name}: must not concatenate an oracle message"
        );
    }
}

#[test]
fn poke_arrears_is_permissionless() {
    // The arrears clock must be startable by anyone (holder, watchtower, …) so
    // the issuer cannot dodge the penalty by staying idle: no issuer/holder
    // signature in the witness schema, but the oracle witness is required.
    let out = vdp();
    let witness = witness_names(&out, "pokeArrears");
    assert!(
        !witness.iter().any(|w| w == "issuerSig" || w == "holderSig"),
        "pokeArrears must not be gated on issuer/holder signatures, got {witness:?}"
    );
    assert!(
        witness.iter().any(|w| w == "oracleSig"),
        "pokeArrears must still require the oracle witness, got {witness:?}"
    );
    assert!(
        witness.iter().any(|w| w == "nextArrearsSince"),
        "pokeArrears must take the declared next arrears timestamp, got {witness:?}"
    );
    // The only user-trust signature on the cooperative path is the oracle's.
    assert_eq!(
        user_signatures(&out, "pokeArrears"),
        vec!["oracleSig".to_string()],
        "pokeArrears cooperative path should carry only the oracle signature"
    );
}

#[test]
fn force_redeem_needs_only_the_holder() {
    // The teeth: holder-gated and oracle-free.
    let out = vdp();
    let asm = asm_of(&out, "forceRedeem");
    assert!(
        !asm.contains(OP_CHECKSIGFROMSTACK),
        "forceRedeem must not depend on the oracle"
    );
    assert!(
        asm.contains(OP_CHECKSIG),
        "forceRedeem must verify the holder signature"
    );
}

#[test]
fn every_function_has_a_timelocked_exit_variant() {
    // Non-internal functions must emit a unilateral-exit (serverVariant=false)
    // tapleaf: an N-of-N CHECKSIG fallback gated by the `<exit>` relative
    // timelock (OP_CHECKSEQUENCEVERIFY).
    let out = vdp();
    for name in &[
        "accrueAndRepeg",
        "pokeArrears",
        "claim",
        "topUp",
        "transfer",
        "redeem",
        "forceRedeem",
    ] {
        let exit_asm = asm_variant(&out, name, false);
        assert!(
            exit_asm.contains(OP_CHECKSEQUENCEVERIFY),
            "{name}: exit variant must be gated by the exit timelock"
        );
    }
}
