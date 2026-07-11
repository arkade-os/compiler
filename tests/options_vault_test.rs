//! OptionsVault — pooled, cash-settled covered-call writing vault.
//!
//! Pattern-A pooling: LP shares are a fungible Arkade Asset, minted on deposit
//! and burned on withdraw (the burn is the authentication). Premium accrues to
//! the pool (PPS up). One covered call per epoch, cash-settled via the Fuji
//! oracle. The unilateral exit is a custodial curator-gated placeholder;
//! passive-LP recurrent exit is deferred to PULSE (docs/recurrent-exit-pulse.md).

use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_CHECKSIGFROMSTACK,
    OP_INSPECTINASSETLOOKUP, OP_INSPECTOUTASSETLOOKUP,
};

mod common;
use common::{arkade_asm, arkade_inputs, group, user_signatures};

const CODE: &str = include_str!("../examples/options/options_vault.ark");

#[test]
fn test_compiles_with_5_groups() {
    // 4 covenant functions (deposit, withdraw, writeOption, settle) + 1
    // standalone unilateral tapscript = 5 groups.
    let out = compile(CODE).expect("compile");
    assert_eq!(out.name, "OptionsVault");
    assert_eq!(out.functions.len(), 5);
}

#[test]
fn test_lp_asset_id_is_two_explicit_params() {
    // The LP share token is an Arkade Asset; its id is two explicit params
    // (bytes32 txid, int gidx), never a single raw bytes32.
    let out = compile(CODE).unwrap();
    let txid = out
        .parameters
        .iter()
        .find(|p| p.name == "lpAssetIdTxid")
        .expect("constructorInputs must include lpAssetIdTxid");
    assert_eq!(txid.param_type, "bytes32");
    let gidx = out
        .parameters
        .iter()
        .find(|p| p.name == "lpAssetIdGidx")
        .expect("constructorInputs must include lpAssetIdGidx");
    assert_eq!(gidx.param_type, "int");
    assert!(
        !out.parameters.iter().any(|p| p.name == "lpAssetId"),
        "raw bytes32 lpAssetId should not appear in the ABI"
    );
}

#[test]
fn test_deposit_mints_shares_and_is_permissionless() {
    // Deposit mints LP shares to output[1] (asset lookup on an OUTPUT) and takes
    // NO user signature — the depositor's own funding input authorizes the tx.
    let out = compile(CODE).unwrap();
    let asm = arkade_asm(&out, "deposit");
    assert!(
        asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "deposit must look up minted LP shares on an output"
    );
    assert!(
        user_signatures(&out, "deposit").is_empty(),
        "deposit is permissionless — no contract-level signature"
    );
    let inputs = arkade_inputs(&out, "deposit");
    for field in ["depositSats", "sharesIssued"] {
        assert!(
            inputs.contains(&field.to_string()),
            "deposit missing {field}"
        );
    }
}

#[test]
fn test_withdraw_burns_shares_as_authentication() {
    // Withdraw burns LP shares from input[1] (asset lookup on an INPUT) and,
    // like deposit, requires no contract-level signature: spending the share
    // UTXO is itself the LP's authorization.
    let out = compile(CODE).unwrap();
    let asm = arkade_asm(&out, "withdraw");
    assert!(
        asm.contains(OP_INSPECTINASSETLOOKUP),
        "withdraw must look up burned LP shares on an input"
    );
    assert!(
        user_signatures(&out, "withdraw").is_empty(),
        "withdraw auth is the share burn — no separate signature"
    );
}

#[test]
fn test_write_option_is_curator_gated_no_oracle() {
    // The curator picks strike/expiry and writes the option; premium is
    // collected upfront with no oracle involved at write time.
    let out = compile(CODE).unwrap();
    assert_eq!(
        user_signatures(&out, "writeOption"),
        vec!["curatorSig".to_string()],
        "writeOption must be gated by exactly the curator signature"
    );
    assert!(
        !arkade_asm(&out, "writeOption").contains(OP_CHECKSIGFROMSTACK),
        "writeOption must not touch the oracle"
    );
    let inputs = arkade_inputs(&out, "writeOption");
    for field in [
        "newBuyerPk",
        "newStrikePrice",
        "newExpiryHeight",
        "premiumSats",
    ] {
        assert!(
            inputs.contains(&field.to_string()),
            "writeOption missing {field}"
        );
    }
}

#[test]
fn test_settle_uses_oracle_and_expiry_gate() {
    // Cash settlement is oracle-driven (checkSigFromStack over the Fuji message)
    // and only opens at/after expiry (CLTV on expiryHeight).
    let out = compile(CODE).unwrap();
    let asm = arkade_asm(&out, "settle");
    assert!(
        asm.contains(OP_CHECKSIGFROMSTACK),
        "settle must verify the oracle signature"
    );
    assert!(
        asm.contains(OP_CHECKLOCKTIMEVERIFY),
        "settle must enforce tx.time >= expiryHeight"
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
    // The oracle is confined to settlement; deposit/withdraw/writeOption never
    // invoke checkSigFromStack.
    let out = compile(CODE).unwrap();
    for name in ["deposit", "withdraw", "writeOption"] {
        assert!(
            !arkade_asm(&out, name).contains(OP_CHECKSIGFROMSTACK),
            "{name} must not consult the oracle"
        );
    }
}

#[test]
fn test_unilateral_is_csv_placeholder_no_introspection() {
    // EXIT MODEL: the unilateral tapscript is pure Bitcoin script — a CSV
    // (`older(exit)`) gating a single curator checkSig, with NO introspection.
    // It cannot check per-LP share burns, which is exactly why passive LPs get
    // no standing unilateral exit here — the gap PULSE closes
    // (docs/recurrent-exit-pulse.md). This placeholder is deliberately custodial.
    let out = compile(CODE).unwrap();
    let g = group(&out, "unilateral");
    assert_eq!(
        g.leaves.len(),
        1,
        "unilateral must be a single tapscript leaf"
    );
    let leaf = g.leaves[0].asm.join(" ");
    assert!(
        !leaf.contains("OP_INSPECT"),
        "unilateral leaf must carry no introspection: {leaf}"
    );
    assert!(
        leaf.contains(OP_CHECKSEQUENCEVERIFY),
        "unilateral must enforce the exit CSV via older(exit)"
    );
    assert!(
        leaf.contains(OP_CHECKSIG),
        "unilateral must require the curator signature"
    );
    assert!(
        !leaf.contains(OP_CHECKLOCKTIMEVERIFY),
        "unilateral is a CSV exit, not a CLTV gate"
    );
}
