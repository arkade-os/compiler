use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CAT, OP_CHECKSIGFROMSTACK, OP_DIV64, OP_FINDASSETGROUPBYASSETID, OP_INSPECTOUTASSETLOOKUP,
    OP_MUL64, OP_SHA256,
};

use crate::common::{arkade_asm, arkade_asm_tokens, arkade_inputs, group};

const BTC_CODE: &str = include_str!("../../examples/hashprice/hashprice_btc_vault.ark");
const USD_CODE: &str = include_str!("../../examples/hashprice/hashprice_usd_vault.ark");

#[test]
fn test_btc_vault_compiles_with_5_groups() {
    // 5 covenant functions, no author tapscript (pooled exit lives off-chain)
    let out = compile(BTC_CODE).expect("btc vault compile");
    assert_eq!(out.name, "HashpriceBtcVault");
    assert_eq!(out.functions.len(), 5);
}

#[test]
fn test_usd_vault_compiles_with_5_groups() {
    let out = compile(USD_CODE).expect("usd vault compile");
    assert_eq!(out.name, "HashpriceUsdVault");
    assert_eq!(out.functions.len(), 5);
}

#[test]
fn test_all_paths_are_permissionless() {
    // Every function authenticates via asset burns / oracle attestations, not
    // user signatures: the only signature witnesses are oracle sigs on settle.
    for code in [BTC_CODE, USD_CODE] {
        let out = compile(code).unwrap();
        for name in ["issue", "burnPair", "redeemUp", "redeemDown"] {
            let names = arkade_inputs(&out, name);
            assert_eq!(
                names,
                vec!["amount".to_string()],
                "{name} must take only `amount`"
            );
        }
    }
}

#[test]
fn test_btc_settle_verifies_single_oracle_fixing() {
    // settle must reconstruct sha256(ticker || price || time) via OP_CAT +
    // OP_SHA256 and verify exactly one oracle signature against it.
    let out = compile(BTC_CODE).unwrap();
    let tokens = arkade_asm_tokens(&out, "settle");
    let csfs = tokens
        .iter()
        .filter(|t| t.as_str() == OP_CHECKSIGFROMSTACK)
        .count();
    let cats = tokens.iter().filter(|t| t.as_str() == OP_CAT).count();
    let shas = tokens.iter().filter(|t| t.as_str() == OP_SHA256).count();
    assert_eq!(csfs, 1, "btc settle: exactly one oracle verification");
    assert_eq!(cats, 2, "btc settle: ticker||price||time needs two OP_CAT");
    assert_eq!(shas, 1, "btc settle: one message digest");
    assert_eq!(
        arkade_inputs(&out, "settle"),
        vec!["spotPrice", "spotTime", "oracleSig"],
        "btc settle witness"
    );
}

#[test]
fn test_usd_settle_verifies_both_fixings_and_converts() {
    // The USD vault needs the hashprice fixing AND the BTC/USD fixing, both
    // signed, and a division for the USD→sats conversion.
    let out = compile(USD_CODE).unwrap();
    let tokens = arkade_asm_tokens(&out, "settle");
    let csfs = tokens
        .iter()
        .filter(|t| t.as_str() == OP_CHECKSIGFROMSTACK)
        .count();
    let cats = tokens.iter().filter(|t| t.as_str() == OP_CAT).count();
    let shas = tokens.iter().filter(|t| t.as_str() == OP_SHA256).count();
    assert_eq!(csfs, 2, "usd settle: two oracle verifications");
    assert_eq!(cats, 4, "usd settle: two messages, two OP_CAT each");
    assert_eq!(shas, 2, "usd settle: two message digests");
    let asm = tokens.join(" ");
    assert!(
        asm.contains(OP_DIV64),
        "usd settle: must divide by btcUsdPrice"
    );
    assert_eq!(
        arkade_inputs(&out, "settle"),
        vec![
            "spotPrice",
            "spotTime",
            "spotSig",
            "btcUsdPrice",
            "btcUsdTime",
            "btcUsdSig"
        ],
        "usd settle witness"
    );
}

#[test]
fn test_btc_settle_splits_without_division() {
    // Sats-quoted payoffs split the pot exactly — no division, so no
    // truncation dust in settlement (division only appears in redemption).
    let out = compile(BTC_CODE).unwrap();
    let asm = arkade_asm(&out, "settle");
    assert!(!asm.contains(OP_DIV64), "btc settle must not divide: {asm}");
}

#[test]
fn test_oracle_only_consulted_at_settlement() {
    for code in [BTC_CODE, USD_CODE] {
        let out = compile(code).unwrap();
        for name in ["issue", "burnPair", "redeemUp", "redeemDown"] {
            let asm = arkade_asm(&out, name);
            assert!(
                !asm.contains(OP_CHECKSIGFROMSTACK),
                "{name}: must not invoke oracle"
            );
        }
    }
}

#[test]
fn test_issue_mints_both_legs_to_depositor() {
    // issue must find all three asset groups (UP, DOWN, identity) and verify
    // delivery of both legs on output[1].
    for code in [BTC_CODE, USD_CODE] {
        let out = compile(code).unwrap();
        let tokens = arkade_asm_tokens(&out, "issue");
        let finds = tokens
            .iter()
            .filter(|t| t.as_str() == OP_FINDASSETGROUPBYASSETID)
            .count();
        assert!(
            finds >= 3,
            "issue must inspect UP, DOWN and identity groups; got {finds}"
        );
        let lookups = tokens
            .iter()
            .filter(|t| t.as_str() == OP_INSPECTOUTASSETLOOKUP)
            .count();
        // two leg deliveries on output[1] + identity retention on output[0]
        assert!(
            lookups >= 3,
            "issue must look up both legs and the identity on outputs; got {lookups}"
        );
    }
}

#[test]
fn test_redeem_is_pro_rata() {
    // redemption pays amount × pot / shares — multiplication AND division.
    for code in [BTC_CODE, USD_CODE] {
        let out = compile(code).unwrap();
        for name in ["redeemUp", "redeemDown"] {
            let asm = arkade_asm(&out, name);
            assert!(asm.contains(OP_MUL64), "{name}: pro-rata multiply missing");
            assert!(asm.contains(OP_DIV64), "{name}: pro-rata divide missing");
        }
    }
}

#[test]
fn test_all_groups_use_synthesized_cooperative_leaf() {
    // No author tapscripts: every group's single leaf is the synthesized
    // collaborative leaf with injected server + emulator signatures.
    for code in [BTC_CODE, USD_CODE] {
        let out = compile(code).unwrap();
        for g in &out.functions {
            assert_eq!(g.leaves.len(), 1, "{}: one leaf expected", g.name);
            let leaf = &g.leaves[0];
            assert!(
                leaf.witness.iter().all(|w| w.injected),
                "{}: cooperative leaf witnesses must all be injected",
                g.name
            );
            let asm = leaf.asm.join(" ");
            assert!(
                asm.contains("<SERVER_KEY>"),
                "{}: leaf must include server key",
                g.name
            );
            assert!(
                asm.contains(&format!("<EMULATOR_KEY:{}>", g.name)),
                "{}: leaf must include function-tweaked emulator key",
                g.name
            );
        }
    }
}

#[test]
fn test_asset_ids_are_two_explicit_params() {
    for code in [BTC_CODE, USD_CODE] {
        let out = compile(code).unwrap();
        for (txid_name, gidx_name) in [
            ("upIdTxid", "upIdGidx"),
            ("downIdTxid", "downIdGidx"),
            ("contractIdTxid", "contractIdGidx"),
        ] {
            let txid = out
                .parameters
                .iter()
                .find(|p| p.name == txid_name)
                .unwrap_or_else(|| panic!("missing constructor input {txid_name}"));
            assert_eq!(txid.param_type, "bytes32");
            let gidx = out
                .parameters
                .iter()
                .find(|p| p.name == gidx_name)
                .unwrap_or_else(|| panic!("missing constructor input {gidx_name}"));
            assert_eq!(gidx.param_type, "int");
        }
    }
}

#[test]
fn test_usd_vault_has_conversion_feed_and_escrow_cap() {
    // The USD vault must carry the second feed id and the per-pair sats
    // escrow that caps the UP payout; the BTC vault must carry neither.
    let usd = compile(USD_CODE).unwrap();
    for (name, ty) in [("btcUsdTicker", "bytes32"), ("pairCollateral", "int")] {
        let p = usd
            .parameters
            .iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("usd vault missing {name}"));
        assert_eq!(p.param_type, ty);
    }
    let btc = compile(BTC_CODE).unwrap();
    for name in ["btcUsdTicker", "pairCollateral"] {
        assert!(
            !btc.parameters.iter().any(|p| p.name == name),
            "btc vault must not carry {name}"
        );
    }
}

#[test]
fn test_settle_flips_state_via_recreation() {
    // Every settle branch recreates the vault with settled=1; the recreation
    // placeholder embeds the constructor call.
    for code in [BTC_CODE, USD_CODE] {
        let out = compile(code).unwrap();
        let g = group(&out, "settle");
        let asm = g.arkade.as_ref().expect("settle covenant").asm.join(" ");
        assert!(
            asm.contains("<VTXO:"),
            "settle must recreate the vault via constructor placeholder"
        );
    }
}
