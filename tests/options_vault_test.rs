//! OptionsVault — pooled, cash-settled covered-call writing vault.
//!
//! Pattern-A pooling: LP shares are a fungible Arkade Asset whose MINT is gated
//! by the vault's contract-identity singleton (the share group is
//! `controlIs(contractId)`, and the identity singleton lives only in the vault).
//! Minted on deposit, burned on withdraw (the burn is the auth).
//! Premium accrues to the pool (value per share up). One covered call per epoch,
//! cash-settled against an oracle-signed price. The unilateral exit lets the
//! curator recover pool collateral after the timelock; a per-provider recurrent
//! exit is next work under PULSE (docs/recurrent-exit-pulse.md).

use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_CHECKSIGFROMSTACK,
    OP_FINDASSETGROUPBYASSETID, OP_INSPECTASSETGROUPCTRL, OP_INSPECTASSETGROUPSUM,
    OP_INSPECTOUTASSETLOOKUP,
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
fn test_asset_ids_are_two_explicit_params() {
    // The LP share asset and the vault's identity singleton are Arkade Assets;
    // each id is two explicit params (bytes32 txid, int gidx), never a raw bytes32.
    let out = compile(CODE).unwrap();
    for base in ["lpAssetId", "contractId"] {
        let txid = out
            .parameters
            .iter()
            .find(|p| p.name == format!("{base}Txid"))
            .unwrap_or_else(|| panic!("constructorInputs must include {base}Txid"));
        assert_eq!(txid.param_type, "bytes32");
        let gidx = out
            .parameters
            .iter()
            .find(|p| p.name == format!("{base}Gidx"))
            .unwrap_or_else(|| panic!("constructorInputs must include {base}Gidx"));
        assert_eq!(gidx.param_type, "int");
        assert!(
            !out.parameters.iter().any(|p| p.name == base),
            "raw bytes32 {base} should not appear in the ABI"
        );
    }
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
fn test_mint_is_control_gated() {
    // The mint is gated by the vault's identity singleton: deposit finds the
    // share group and asserts controlIs(contractId) plus the exact supply delta.
    // Only a spend holding the identity singleton (i.e. the vault) can mint.
    let out = compile(CODE).unwrap();
    let asm = arkade_asm(&out, "deposit");
    assert!(
        asm.contains(OP_FINDASSETGROUPBYASSETID),
        "deposit must locate the share asset group"
    );
    assert!(
        asm.contains(OP_INSPECTASSETGROUPCTRL),
        "deposit must assert the share group is controlIs(contractId)"
    );
    assert!(
        asm.contains(OP_INSPECTASSETGROUPSUM),
        "deposit must pin the minted share supply delta"
    );
}

#[test]
fn test_withdraw_burns_via_group_no_control_gate() {
    // Withdraw burns shares via the asset-group supply delta (sumInputs ==
    // sumOutputs + sharesBurned), NOT a control-gated mint — burning needs no
    // mint authority. The burn (spending the share output) is the authentication,
    // so no contract-level signature is required.
    let out = compile(CODE).unwrap();
    let asm = arkade_asm(&out, "withdraw");
    assert!(
        asm.contains(OP_INSPECTASSETGROUPSUM),
        "withdraw must burn via the share asset-group supply delta"
    );
    assert!(
        !asm.contains(OP_INSPECTASSETGROUPCTRL),
        "withdraw must NOT control-gate the burn (only mint is gated)"
    );
    assert!(
        user_signatures(&out, "withdraw").is_empty(),
        "withdraw auth is the share burn — no separate signature"
    );
}

#[test]
fn test_control_retained_in_every_covenant_function() {
    // The identity-retention invariant: every covenant function re-creates the
    // vault holding >= 1 identity singleton (an output asset lookup). writeOption
    // and settle touch no shares, so their only output asset lookup IS this check.
    let out = compile(CODE).unwrap();
    for name in ["deposit", "withdraw", "writeOption", "settle"] {
        assert!(
            arkade_asm(&out, name).contains(OP_INSPECTOUTASSETLOOKUP),
            "{name} must re-assert the vault retains its identity singleton"
        );
    }
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
    // Cash settlement is oracle-driven (checkSigFromStack over the signed price
    // message) and only opens at/after expiry (CLTV on expiryHeight).
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
fn test_unilateral_is_csv_exit_no_introspection() {
    // EXIT MODEL: the unilateral exit is pure Bitcoin script — a CSV
    // (`older(exit)`) gating a single curator checkSig, with NO introspection.
    // After the timelock the curator recovers pool collateral on-chain; PULSE
    // (next work) extends this to a per-provider exit (docs/recurrent-exit-pulse.md).
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
