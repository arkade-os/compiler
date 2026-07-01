use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKLOCKTIMEVERIFY, OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_INSPECTOUTASSETLOOKUP,
};

mod common;
use common::{arkade_asm, arkade_inputs, group};

const CALL_CODE: &str = include_str!("../examples/options/covered_call.ark");

#[test]
fn test_compiles_with_5_groups() {
    // 4 covenant functions + 1 standalone unilateral tapscript = 5 groups
    let out = compile(CALL_CODE).expect("compile");
    assert_eq!(out.name, "CoveredCall");
    assert_eq!(out.functions.len(), 5);
}

#[test]
fn test_exercise_takes_only_buyer_signature() {
    // Single-locked design: exercise is buyer-gated. No oracle, no seller.
    let out = compile(CALL_CODE).unwrap();
    let names = arkade_inputs(&out, "exercise");
    assert!(
        names.contains(&"buyerSig".to_string()),
        "exercise must take buyerSig"
    );
    for forbidden in [
        "sellerSig",
        "oracleSig",
        "oraclePrice",
        "oracleTime",
        "oraclePk",
    ] {
        assert!(
            !names.contains(&forbidden.to_string()),
            "exercise must not require {forbidden}"
        );
    }
}

#[test]
fn test_exercise_has_no_oracle() {
    // No checkSigFromStack — there is no oracle dependency in this design.
    let out = compile(CALL_CODE).unwrap();
    for fn_name in ["exercise", "reclaim", "transferSeller", "transferBuyer"] {
        let asm = arkade_asm(&out, fn_name);
        assert!(
            !asm.contains(OP_CHECKSIGFROMSTACK),
            "{fn_name}: must not invoke oracle"
        );
    }
}

#[test]
fn test_exercise_verifies_strike_payment() {
    let out = compile(CALL_CODE).unwrap();
    let asm = arkade_asm(&out, "exercise");
    assert!(
        asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "exercise must look up stablecoin balance on output 0"
    );
    assert!(
        asm.contains("OP_INSPECTOUTPUTVALUE"),
        "exercise must verify output 1's BTC value"
    );
    // CLTV on expiryHeight = exercise window opens
    assert!(
        asm.contains(OP_CHECKLOCKTIMEVERIFY),
        "exercise must enforce tx.time >= expiryHeight"
    );
}

#[test]
fn test_reclaim_is_seller_only_with_cltv() {
    let out = compile(CALL_CODE).unwrap();
    let names = arkade_inputs(&out, "reclaim");
    assert!(
        names.contains(&"sellerSig".to_string()),
        "reclaim must take sellerSig"
    );
    assert!(
        !names.contains(&"buyerSig".to_string()),
        "reclaim must not require buyerSig"
    );
    let asm = arkade_asm(&out, "reclaim");
    assert!(
        asm.contains(OP_CHECKLOCKTIMEVERIFY),
        "reclaim must enforce timelock"
    );
    assert!(
        !asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "reclaim should not need asset introspection"
    );
}

#[test]
fn test_asset_id_is_two_explicit_params() {
    let out = compile(CALL_CODE).unwrap();
    let txid = out
        .parameters
        .iter()
        .find(|p| p.name == "stableAssetIdTxid")
        .expect("constructorInputs must include explicit stableAssetIdTxid");
    assert_eq!(txid.param_type, "bytes32");
    let gidx = out
        .parameters
        .iter()
        .find(|p| p.name == "stableAssetIdGidx")
        .expect("constructorInputs must include explicit stableAssetIdGidx");
    assert_eq!(gidx.param_type, "int");
}

#[test]
fn test_transfers_guarded_by_expiry() {
    // Cooperative covenant carries the `tx.time < expiryHeight` guard.
    let out = compile(CALL_CODE).unwrap();
    for name in ["transferSeller", "transferBuyer"] {
        let asm = arkade_asm(&out, name);
        assert!(
            asm.contains("<expiryHeight>"),
            "{name}: covenant must reference <expiryHeight>"
        );
    }
}

#[test]
fn test_transfers_preserve_btc_collateral() {
    // CoveredCall vault holds BTC only — transfers must check the
    // continuation's BTC value, not asset balance.
    let out = compile(CALL_CODE).unwrap();
    for name in ["transferSeller", "transferBuyer"] {
        let asm = arkade_asm(&out, name);
        assert!(
            !asm.contains(OP_INSPECTOUTASSETLOOKUP),
            "{name}: CoveredCall transfers should not need asset lookup (vault is BTC-only)"
        );
        assert!(
            asm.contains("OP_INSPECTOUTPUTVALUE"),
            "{name}: must verify BTC value preserved on continuation"
        );
        assert!(
            asm.contains(OP_CHECKSIG),
            "{name}: must require party signature"
        );
    }
}

#[test]
fn test_unilateral_leaf_has_no_introspection() {
    // The unilateral tapscript (CSV exit) must carry no introspection opcodes.
    let out = compile(CALL_CODE).unwrap();
    let g = group(&out, "unilateral");
    assert_eq!(g.leaves.len(), 1);
    let leaf_asm = g.leaves[0].asm.join(" ");
    assert!(
        !leaf_asm.contains("OP_INSPECT"),
        "unilateral leaf must not use introspection: {}",
        leaf_asm
    );
    assert!(
        !leaf_asm.contains(OP_CHECKLOCKTIMEVERIFY),
        "unilateral must use CSV (CHECKSEQUENCEVERIFY), not CLTV"
    );
}
