use arkade_compiler::compile;
use arkade_compiler::opcodes::{OP_CAT, OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_SHA256};

use crate::common::arkade_asm;

const VAULT_CODE: &str = include_str!("../../examples/stability/stability_vault.ark");
const OFFER_CODE: &str = include_str!("../../examples/stability/stability_offer.ark");

#[test]
#[ignore = "dynamic contract reconstruction is temporarily disabled"]
fn test_vault_compiles_with_9_groups() {
    // 8 covenant functions + 1 unilateral tapscript = 9 groups
    let out = compile(VAULT_CODE).expect("vault compile");
    assert_eq!(out.name, "StabilityVault");
    assert_eq!(out.functions.len(), 9);
}

#[test]
#[ignore = "dynamic contract reconstruction is temporarily disabled"]
fn test_merge_emits_active_input_index_opcode() {
    use arkade_compiler::opcodes::OP_PUSHCURRENTINPUTINDEX;
    let out = compile(VAULT_CODE).unwrap();
    let asm = arkade_asm(&out, "merge");
    assert!(
        asm.contains(OP_PUSHCURRENTINPUTINDEX),
        "merge must emit OP_PUSHCURRENTINPUTINDEX for this.activeInputIndex"
    );
    assert!(
        asm.contains("OP_INSPECTINPUTSCRIPTPUBKEY"),
        "merge must inspect the other input's scriptPubKey"
    );
}

#[test]
#[ignore = "dynamic contract reconstruction is temporarily disabled"]
fn test_vault_settlement_verifies_full_oracle_message() {
    // seekerExit and providerExit must reconstruct sha256(ticker || price || time)
    // via OP_CAT + OP_SHA256 and verify the oracle sig against it.
    // Oracle logic lives in the covenant (arkade) ASM.
    let out = compile(VAULT_CODE).unwrap();
    for name in &["seekerExit", "providerExit"] {
        let asm_tokens: Vec<String> = crate::common::arkade_asm_tokens(&out, name);
        let asm = asm_tokens.join(" ");
        let cat_count = asm_tokens.iter().filter(|s| s.as_str() == OP_CAT).count();
        assert!(
            cat_count >= 2,
            "{name}: expected >=2 OP_CAT (ticker+price, +time), found {cat_count}"
        );
        assert!(asm.contains(OP_SHA256), "{name}: missing OP_SHA256");
        assert!(
            asm.contains(OP_CHECKSIGFROMSTACK),
            "{name}: missing oracle sig verify"
        );
        assert!(asm.contains(OP_CHECKSIG), "{name}: missing user checksig");
    }
}

#[test]
#[ignore = "dynamic contract reconstruction is temporarily disabled"]
fn test_vault_transfer_is_pure_keyswap() {
    let out = compile(VAULT_CODE).unwrap();
    let asm = arkade_asm(&out, "transfer");
    assert!(
        !asm.contains(OP_CHECKSIGFROMSTACK),
        "transfer must not call oracle"
    );
    assert!(!asm.contains(OP_CAT), "transfer must not concatenate");
    assert!(!asm.contains(OP_SHA256), "transfer must not hash");
    assert!(asm.contains(OP_CHECKSIG));
}

#[test]
#[ignore = "dynamic contract reconstruction is temporarily disabled"]
fn test_vault_split_is_pure_keyswap() {
    let out = compile(VAULT_CODE).unwrap();
    let asm = arkade_asm(&out, "split");
    assert!(
        !asm.contains(OP_CHECKSIGFROMSTACK),
        "split must not call oracle"
    );
    assert!(!asm.contains(OP_CAT), "split must not concatenate");
    assert!(!asm.contains(OP_SHA256), "split must not hash");
    assert!(asm.contains(OP_CHECKSIG), "split must keep user checksig");
}

#[test]
#[ignore = "dynamic contract reconstruction is temporarily disabled"]
fn test_settle_and_update_funding_does_no_oracle_call() {
    // Funding update is purely time-driven; no oracle witness involved.
    let out = compile(VAULT_CODE).unwrap();
    let asm = arkade_asm(&out, "settleAndUpdateFunding");
    assert!(
        !asm.contains(OP_CHECKSIGFROMSTACK),
        "settleAndUpdateFunding must not call oracle"
    );
    assert!(
        asm.contains(OP_CHECKSIG),
        "settleAndUpdateFunding must verify provider"
    );
}

#[test]
#[ignore = "dynamic contract reconstruction is temporarily disabled"]
fn test_add_capital_does_no_oracle_call() {
    let out = compile(VAULT_CODE).unwrap();
    let asm = arkade_asm(&out, "addCapital");
    assert!(
        !asm.contains(OP_CHECKSIGFROMSTACK),
        "addCapital must not call oracle"
    );
}

#[test]
#[ignore = "dynamic contract reconstruction is temporarily disabled"]
fn test_remove_capital_verifies_oracle() {
    let out = compile(VAULT_CODE).unwrap();
    let asm = arkade_asm(&out, "removeCapital");
    assert!(
        asm.contains(OP_CHECKSIGFROMSTACK),
        "removeCapital must verify oracle"
    );
    assert!(
        asm.contains(OP_SHA256),
        "removeCapital must hash oracle msg"
    );
}

#[test]
#[ignore = "dynamic contract reconstruction is temporarily disabled"]
fn test_offer_compiles_with_3_groups() {
    // 2 covenant functions + 1 unilateral tapscript = 3 groups
    let out = compile(OFFER_CODE).expect("offer compile");
    assert_eq!(out.name, "StabilityOffer");
    assert_eq!(out.functions.len(), 3);
}

#[test]
#[ignore = "dynamic contract reconstruction is temporarily disabled"]
fn test_offer_take_verifies_full_oracle_message() {
    let out = compile(OFFER_CODE).unwrap();
    let asm_tokens = crate::common::arkade_asm_tokens(&out, "take");
    let asm = asm_tokens.join(" ");
    let cat_count = asm_tokens.iter().filter(|s| s.as_str() == OP_CAT).count();
    assert!(
        cat_count >= 2,
        "take: expected >=2 OP_CAT for ticker+price+time, found {cat_count}"
    );
    assert!(asm.contains(OP_SHA256), "take: missing OP_SHA256");
    assert!(
        asm.contains(OP_CHECKSIGFROMSTACK),
        "take: missing oracle sig verify"
    );
}
