use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKSIGFROMSTACK, OP_DIV, OP_FINDASSETGROUPBYASSETID, OP_INSPECTASSETGROUPCTRL,
    OP_INSPECTOUTASSETLOOKUP, OP_MUL,
};

use crate::common::{arkade_asm, arkade_asm_tokens, arkade_inputs};

const VAULT_CODE: &str = include_str!("../../examples/mining_margin/mining_margin_vault.ark");

#[test]
fn test_compiles_with_4_groups() {
    // 4 covenant functions, each with a synthesized cooperative leaf.
    let out = compile(VAULT_CODE).expect("compile");
    assert_eq!(out.name, "MiningMarginVault");
    assert_eq!(out.functions.len(), 4);
}

#[test]
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
fn test_redeems_verify_both_fixings() {
    // Settlement is per-redemption: hashprice + power fixings, both checked.
    let out = compile(VAULT_CODE).unwrap();
    for fn_name in ["redeemRig", "redeemGrid"] {
        assert_eq!(
            arkade_inputs(&out, fn_name),
            vec!["amount", "hashPrice", "hashSig", "powerCost", "powerSig"],
            "{fn_name} witness shape"
        );
        let csfs = arkade_asm_tokens(&out, fn_name)
            .iter()
            .filter(|t| t.as_str() == OP_CHECKSIGFROMSTACK)
            .count();
        assert_eq!(csfs, 2, "{fn_name} must verify exactly 2 attestations");
    }
}

#[test]
fn test_settlement_is_exact_no_division() {
    // Payouts are amount × margin — no pro-rata pots, so no OP_DIV outside
    // the issue-time overflow guard.
    let out = compile(VAULT_CODE).unwrap();
    for fn_name in ["burnPair", "redeemRig", "redeemGrid"] {
        let asm = arkade_asm(&out, fn_name);
        assert!(!asm.contains(OP_DIV), "{fn_name} must not divide");
        assert!(asm.contains(OP_MUL), "{fn_name} must scale by amount");
    }
    assert!(
        arkade_asm(&out, "issue").contains(OP_DIV),
        "issue must bound amount by 2.1e15 / cap"
    );
}

#[test]
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
