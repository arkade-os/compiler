//! CoveredCallVault — pooled, fully-collateralized two-token BTC covered call.
//!
//! Issuance mints a LONG + SHORT share pair 1:1:1 against BTC (control-gated by
//! the vault identity singleton); burn returns a pair for BTC; settle splits the
//! pot via an oracle price attested within ±60s of maturity; redemption drains
//! each side's pot pro-rata (order-invariant). No compiler exit leaf — the
//! short-side unilateral exit is the PULSE lattice (docs/recurrent-exit-pulse.md).

use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKSIGFROMSTACK, OP_FINDASSETGROUPBYASSETID, OP_INSPECTASSETGROUPCTRL,
    OP_INSPECTASSETGROUPSUM, OP_INSPECTOUTASSETLOOKUP,
};

mod common;
use common::{arkade_asm, arkade_inputs, user_signatures};

const CODE: &str = include_str!("../examples/options/covered_call_vault.ark");

#[test]
fn test_compiles_to_five_cooperative_groups() {
    // issue, burnPair, settle, redeemLong, redeemShort — all cooperative, NO
    // tapscript exit leaf (the short-side unilateral exit is the PULSE lattice,
    // SDK/ceremony surface, not a compiler leaf — same as the bonds pool).
    let out = compile(CODE).expect("compile");
    assert_eq!(out.name, "CoveredCallVault");
    let mut names: Vec<&str> = out.functions.iter().map(|g| g.name.as_str()).collect();
    names.sort();
    assert_eq!(
        names,
        ["burnPair", "issue", "redeemLong", "redeemShort", "settle"]
    );
}

#[test]
fn test_share_and_identity_ids_are_two_params() {
    // LONG, SHORT, and the identity singleton are each two explicit params
    // (bytes32 txid, int gidx), never a raw bytes32.
    let out = compile(CODE).unwrap();
    for (base, txty) in [
        ("longId", "bytes32"),
        ("shortId", "bytes32"),
        ("contractId", "bytes32"),
    ] {
        let txid = out
            .parameters
            .iter()
            .find(|p| p.name == format!("{base}Txid"))
            .unwrap_or_else(|| panic!("missing {base}Txid"));
        assert_eq!(txid.param_type, txty);
        assert!(
            out.parameters
                .iter()
                .any(|p| p.name == format!("{base}Gidx")),
            "missing {base}Gidx"
        );
    }
}

#[test]
fn test_issue_mints_both_legs_control_gated_and_permissionless() {
    // issue finds both share groups, asserts controlIs(identity) + exact supply
    // delta, and delivers both legs to an output. No contract-level signature.
    let out = compile(CODE).unwrap();
    let asm = arkade_asm(&out, "issue");
    assert!(
        asm.contains(OP_FINDASSETGROUPBYASSETID),
        "issue locates share groups"
    );
    assert!(
        asm.contains(OP_INSPECTASSETGROUPCTRL),
        "issue control-gates the mint"
    );
    assert!(
        asm.contains(OP_INSPECTASSETGROUPSUM),
        "issue pins the minted supply delta"
    );
    assert!(
        asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "issue delivers the minted legs to output"
    );
    assert!(
        user_signatures(&out, "issue").is_empty(),
        "issue is permissionless"
    );
    assert!(
        arkade_inputs(&out, "issue").contains(&"amount".to_string()),
        "issue takes an amount"
    );
}

#[test]
fn test_burn_pair_burns_both_legs_without_control_gate() {
    // burnPair burns via the group supply delta (both legs) and needs no mint
    // authority, so no control-gate opcode. Permissionless (burn authenticates).
    let out = compile(CODE).unwrap();
    let asm = arkade_asm(&out, "burnPair");
    assert!(
        asm.contains(OP_INSPECTASSETGROUPSUM),
        "burnPair burns via supply delta"
    );
    assert!(
        !asm.contains(OP_INSPECTASSETGROUPCTRL),
        "burnPair must not control-gate a burn"
    );
    assert!(
        user_signatures(&out, "burnPair").is_empty(),
        "burnPair is authenticated by the share burn, no signature"
    );
}

#[test]
fn test_settle_uses_oracle_attestation() {
    // Settlement is oracle-driven (checkSigFromStack over the signed price) and
    // takes the price/time/signature witnesses.
    let out = compile(CODE).unwrap();
    assert!(
        arkade_asm(&out, "settle").contains(OP_CHECKSIGFROMSTACK),
        "settle verifies the oracle signature"
    );
    let inputs = arkade_inputs(&out, "settle");
    for field in ["oraclePrice", "oracleTime", "oracleSig"] {
        assert!(
            inputs.contains(&field.to_string()),
            "settle missing {field}"
        );
    }
}

#[test]
fn test_only_settle_consults_the_oracle() {
    // The oracle is confined to settlement; issue/burn/redeem never call it.
    let out = compile(CODE).unwrap();
    for name in ["issue", "burnPair", "redeemLong", "redeemShort"] {
        assert!(
            !arkade_asm(&out, name).contains(OP_CHECKSIGFROMSTACK),
            "{name} must not consult the oracle"
        );
    }
}

#[test]
fn test_redeem_sides_are_symmetric_and_gated() {
    // Each redeem burns one leg (supply delta) and pins the other unchanged; both
    // are permissionless (burn authenticates) and post-settlement only.
    let out = compile(CODE).unwrap();
    for name in ["redeemLong", "redeemShort"] {
        let asm = arkade_asm(&out, name);
        assert!(
            asm.contains(OP_INSPECTASSETGROUPSUM),
            "{name} burns via supply delta"
        );
        assert!(
            user_signatures(&out, name).is_empty(),
            "{name} is authenticated by the share burn"
        );
        assert!(
            arkade_inputs(&out, name).contains(&"amount".to_string()),
            "{name} takes an amount"
        );
    }
}

#[test]
fn test_identity_retained_in_every_function() {
    // Every function re-creates the vault holding the identity singleton (an
    // output asset lookup), so mint authority never leaves the vault.
    let out = compile(CODE).unwrap();
    for name in ["issue", "burnPair", "settle", "redeemLong", "redeemShort"] {
        assert!(
            arkade_asm(&out, name).contains(OP_INSPECTOUTASSETLOOKUP),
            "{name} must re-assert the vault retains its identity singleton"
        );
    }
}
