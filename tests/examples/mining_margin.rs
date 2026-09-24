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
    // stateful constructor schema is the contract's public interface. The
    // assertion is order-sensitive: the commented recreations hard-code this
    // positional order, so a reorder must fail here, not at restoration.
    let out = compile(VAULT_CODE).expect("compile");
    assert_eq!(out.name, "MiningMarginVault");
    assert_eq!(out.functions.len(), 1);
    assert_eq!(out.functions[0].name, "disabled");

    let names: Vec<&str> = out.parameters.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "oraclePk",
            "hashTicker",
            "powerTicker",
            "cap",
            "maturity",
            "rigIdTxid",
            "rigIdGidx",
            "gridIdTxid",
            "gridIdGidx",
            "contractIdTxid",
            "contractIdGidx",
            "settled",
            "rigShares",
            "gridShares",
            "rigPot",
            "gridPot",
            "exit",
        ],
        "constructor schema must match the commented recreations positionally"
    );
}

/// CI guard over the commented design: mechanically uncomment the five
/// state-transition functions, drop the placeholder, and compile. The result
/// must fail with EXACTLY the dynamic-recreation validation errors — nothing
/// else — proving the commented bodies stay valid code as the file evolves.
/// The day dynamic contract transitions are restored, the compile succeeds
/// and this test fails loudly: that is the restoration tripwire.
#[test]
fn test_commented_design_fails_only_on_dynamic_recreation() {
    let mut in_body = false;
    let mut uncommented = String::new();
    for line in VAULT_CODE.lines() {
        if line.starts_with("contract MiningMarginVault(") {
            in_body = true;
        }
        // Commented-out code sits at column 0; prose comments in the body are
        // indented, so this transformation touches only the design code.
        if in_body && line.starts_with("//") {
            uncommented.push_str("  ");
            uncommented.push_str(&line[2..]);
        } else {
            uncommented.push_str(line);
        }
        uncommented.push('\n');
    }
    let placeholder =
        "  function disabled() {\n    require(0 == 1, \"temporarily disabled\");\n  }\n";
    assert!(
        uncommented.contains(placeholder),
        "disabled() placeholder not found in expected form"
    );
    let uncommented = uncommented.replace(placeholder, "");

    let err = match compile(&uncommented) {
        Err(e) => e.to_string(),
        Ok(_) => panic!(
            "uncommented design COMPILED: dynamic contract transitions are back. \
             Restore the design now: uncomment the functions in the .ark, delete \
             the disabled() placeholder, un-ignore the five design tests, and \
             delete this guard test."
        ),
    };

    let runtime_value_errors = err.matches("is a runtime value").count();
    assert_eq!(
        runtime_value_errors, 10,
        "expected exactly 10 dynamic-recreation errors, got {runtime_value_errors}: {err}"
    );
    for fn_name in ["issue", "burnPair", "settle", "redeemRig", "redeemGrid"] {
        assert!(
            err.contains(&format!("function '{fn_name}'")),
            "no dynamic-recreation error for {fn_name}: {err}"
        );
    }
    for other in [
        "Parse error",
        "computed contract arguments",
        "type mismatch",
    ] {
        assert!(
            !err.contains(other),
            "commented design has rotted beyond the dynamic-recreation gate ({other}): {err}"
        );
    }
}

#[test]
#[ignore = "dynamic contract reconstruction is temporarily disabled"]
fn test_compiles_with_5_groups() {
    // issue, burnPair, settle, redeemRig, redeemGrid — each with a
    // synthesized cooperative leaf (the disabled() placeholder is deleted at
    // restoration).
    let out = compile(VAULT_CODE).expect("compile");
    assert_eq!(out.functions.len(), 5);
    let names: Vec<&str> = out.functions.iter().map(|g| g.name.as_str()).collect();
    for f in ["issue", "burnPair", "settle", "redeemRig", "redeemGrid"] {
        assert!(names.contains(&f), "missing group {f}, got {names:?}");
    }
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
fn test_settle_verifies_two_maturity_stamped_fixings() {
    // The margin is fixed once from two attestations signed over exactly
    // `maturity` — no timestamp witnesses, no window to shop in.
    let out = compile(VAULT_CODE).unwrap();
    assert_eq!(
        arkade_inputs(&out, "settle"),
        vec!["hashPrice", "hashSig", "powerCost", "powerSig"],
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
