use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKSIGFROMSTACK, OP_DIV, OP_FINDASSETGROUPBYASSETID, OP_INSPECTASSETGROUPCTRL,
    OP_INSPECTOUTASSETLOOKUP, OP_MUL,
};

use crate::common::{arkade_asm, arkade_asm_tokens, arkade_inputs};

const VAULT_CODE: &str = include_str!("../../examples/mining_margin/mining_margin_vault.ark");

#[test]
fn test_disabled_vault_compiles_with_stateful_schema() {
    // State transitions are commented out pending dynamic taproot
    // reconstruction; only the `disabled` placeholder compiles today, but the
    // stateful constructor schema is the contract's public interface.
    let out = compile(VAULT_CODE).expect("compile");
    assert_eq!(out.name, "MiningMarginVault");
    assert_eq!(out.functions.len(), 1);
    assert_eq!(out.functions[0].name, "disabled");

    let names: Vec<&str> = out.parameters.iter().map(|p| p.name.as_str()).collect();
    for param in [
        "oraclePk",
        "hashTicker",
        "powerTicker",
        "cap",
        "maturity",
        "settleWindow",
        "settled",
        "rigShares",
        "gridShares",
        "rigPot",
        "gridPot",
        "exit",
    ] {
        assert!(names.contains(&param), "missing {param}, got: {names:?}");
    }
    for id in ["rigId", "gridId", "contractId"] {
        assert!(
            names.contains(&format!("{id}Txid").as_str())
                && names.contains(&format!("{id}Gidx").as_str()),
            "{id} not present as explicit Txid/Gidx params, got: {names:?}"
        );
    }
}

#[test]
#[ignore = "dynamic contract reconstruction is temporarily disabled"]
fn test_compiles_with_5_groups() {
    // issue, burnPair, settle, redeemRig, redeemGrid — each with a
    // synthesized cooperative leaf.
    let out = compile(VAULT_CODE).expect("compile");
    assert_eq!(out.functions.len(), 5);
}

#[test]
#[ignore = "dynamic contract reconstruction is temporarily disabled"]
fn test_issue_and_burn_are_amount_only() {
    // Collateral operations are permissionless and carry no oracle material.
    let out = compile(VAULT_CODE).unwrap();
    for fn_name in ["issue", "burnPair"] {
        assert_eq!(
            arkade_inputs(&out, fn_name),
            vec!["amount"],
            "{fn_name} must take only amount"
        );
        assert!(
            !arkade_asm(&out, fn_name).contains(OP_CHECKSIGFROMSTACK),
            "{fn_name} must not invoke the oracle"
        );
    }
}

#[test]
#[ignore = "dynamic contract reconstruction is temporarily disabled"]
fn test_settle_verifies_both_fixings() {
    // The margin is fixed once from two windowed attestations.
    let out = compile(VAULT_CODE).unwrap();
    assert_eq!(
        arkade_inputs(&out, "settle"),
        vec![
            "hashPrice",
            "hashTime",
            "hashSig",
            "powerCost",
            "powerTime",
            "powerSig"
        ],
        "settle witness shape"
    );
    let csfs = arkade_asm_tokens(&out, "settle")
        .iter()
        .filter(|t| t.as_str() == OP_CHECKSIGFROMSTACK)
        .count();
    assert_eq!(csfs, 2, "settle must verify exactly 2 attestations");
    assert!(
        !arkade_asm(&out, "settle").contains(OP_DIV),
        "settle split is exact — no division"
    );
}

#[test]
#[ignore = "dynamic contract reconstruction is temporarily disabled"]
fn test_redeems_are_pro_rata_without_oracle() {
    // Post-settlement redemption drains pot and supply together.
    let out = compile(VAULT_CODE).unwrap();
    for fn_name in ["redeemRig", "redeemGrid"] {
        let asm = arkade_asm(&out, fn_name);
        assert_eq!(arkade_inputs(&out, fn_name), vec!["amount"]);
        assert!(
            asm.contains(OP_MUL) && asm.contains(OP_DIV),
            "{fn_name} must compute amount × pot / shares"
        );
        assert!(
            !asm.contains(OP_CHECKSIGFROMSTACK),
            "{fn_name} must not invoke the oracle"
        );
    }
}

#[test]
#[ignore = "dynamic contract reconstruction is temporarily disabled"]
fn test_paired_mint_is_identity_gated() {
    let out = compile(VAULT_CODE).unwrap();
    let asm = arkade_asm(&out, "issue");
    assert!(
        asm.contains(OP_FINDASSETGROUPBYASSETID),
        "issue must inspect asset groups"
    );
    assert!(
        asm.contains(OP_INSPECTASSETGROUPCTRL),
        "issue mint must be identity-controlled"
    );
    assert!(
        asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "issue must check leg delivery and identity retention"
    );
}
