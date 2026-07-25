//! Streaming-dividend program: DividendTreasury (reserve hub) + StreamingShare
//! (per-holder position). Dividends accrue per second in USD cents and pay in
//! sats at an oracle-attested BTC/USD price; a claim co-spends both contracts.

use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CAT, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIGFROMSTACK, OP_DIV64, OP_MUL64,
    OP_PUSHCURRENTINPUTINDEX, OP_SHA256,
};

use crate::common::{arkade_asm, arkade_asm_tokens, arkade_inputs, group, user_signatures};

const TREASURY_CODE: &str = include_str!("../../examples/dividend_stream/dividend_treasury.ark");
const SHARE_CODE: &str = include_str!("../../examples/dividend_stream/streaming_share.ark");

const SECONDS_PER_YEAR: &str = "31536000";

#[test]
fn test_treasury_compiles_with_4_groups() {
    // topUp, service, recall (covenants) + unilateral (standalone tapscript)
    let out = compile(TREASURY_CODE).expect("treasury compile");
    assert_eq!(out.name, "DividendTreasury");
    assert_eq!(out.functions.len(), 4);
}

#[test]
fn test_share_compiles_with_4_groups() {
    // claim, transfer, split (covenants) + unilateral (standalone tapscript)
    let out = compile(SHARE_CODE).expect("share compile");
    assert_eq!(out.name, "StreamingShare");
    assert_eq!(out.functions.len(), 4);
}

#[test]
fn test_claim_paths_verify_oracle_and_cross_input() {
    // Both halves of the claim tx must verify exactly one oracle attestation
    // (sha256(ticker || price || time) via 2×OP_CAT + OP_SHA256) and inspect
    // the sibling input's scriptPubKey via the current-input-index opcode.
    for (code, fn_name) in [(TREASURY_CODE, "service"), (SHARE_CODE, "claim")] {
        let out = compile(code).unwrap();
        let tokens = arkade_asm_tokens(&out, fn_name);
        let csfs = tokens
            .iter()
            .filter(|t| t.as_str() == OP_CHECKSIGFROMSTACK)
            .count();
        let cats = tokens.iter().filter(|t| t.as_str() == OP_CAT).count();
        let shas = tokens.iter().filter(|t| t.as_str() == OP_SHA256).count();
        assert_eq!(csfs, 1, "{fn_name}: exactly one oracle verification");
        assert_eq!(cats, 2, "{fn_name}: ticker||price||time needs two OP_CAT");
        assert_eq!(shas, 1, "{fn_name}: one message digest");
        let asm = tokens.join(" ");
        assert!(
            asm.contains(OP_PUSHCURRENTINPUTINDEX),
            "{fn_name}: must emit OP_PUSHCURRENTINPUTINDEX for the sibling check"
        );
        assert!(
            asm.contains("OP_INSPECTINPUTSCRIPTPUBKEY"),
            "{fn_name}: must inspect the co-spent input's scriptPubKey"
        );
    }
}

#[test]
fn test_accrual_math_normalizes_per_second_and_converts_to_sats() {
    // accruedCents = units × annualDividendCents × elapsed / 31536000, then
    // payoutSats = accruedCents × 1e8 / price: at least one multiply and two
    // divides, with the seconds-per-year constant pushed literally.
    for (code, fn_name) in [(TREASURY_CODE, "service"), (SHARE_CODE, "claim")] {
        let out = compile(code).unwrap();
        let tokens = arkade_asm_tokens(&out, fn_name);
        let divs = tokens.iter().filter(|t| t.as_str() == OP_DIV64).count();
        let muls = tokens.iter().filter(|t| t.as_str() == OP_MUL64).count();
        assert!(divs >= 2, "{fn_name}: year + price divides expected");
        assert!(muls >= 2, "{fn_name}: units×rate and cents×1e8 expected");
        assert!(
            tokens.iter().any(|t| t.as_str() == SECONDS_PER_YEAR),
            "{fn_name}: must normalize by 31536000 seconds/year"
        );
    }
}

#[test]
fn test_topup_and_service_are_permissionless() {
    // topUp takes only `amount`; service authenticates via the co-spent
    // position (whose claim carries the holder sig) plus the oracle — no
    // user signature of its own.
    let out = compile(TREASURY_CODE).unwrap();
    assert_eq!(
        arkade_inputs(&out, "topUp"),
        vec!["amount".to_string()],
        "topUp must take only `amount`"
    );
    assert_eq!(
        user_signatures(&out, "service"),
        vec!["oracleSig".to_string()],
        "service must carry no user signature besides the oracle attestation"
    );
}

#[test]
fn test_recall_is_issuer_gated_and_oracle_free() {
    let out = compile(TREASURY_CODE).unwrap();
    assert_eq!(
        user_signatures(&out, "recall"),
        vec!["issuerSig".to_string()],
        "recall must require exactly the issuer signature"
    );
    let asm = arkade_asm(&out, "recall");
    assert!(
        !asm.contains(OP_CHECKSIGFROMSTACK),
        "recall must not consult the oracle"
    );
}

#[test]
fn test_claim_requires_holder_sig() {
    let out = compile(SHARE_CODE).unwrap();
    assert_eq!(
        user_signatures(&out, "claim"),
        vec!["holderSig".to_string(), "oracleSig".to_string()],
        "claim must carry the holder signature and the oracle attestation"
    );
}

#[test]
fn test_transfer_and_split_are_pure_key_operations() {
    // No oracle, no cross-input introspection: accrual state carries over
    // unchanged, which is what makes record dates unnecessary.
    let out = compile(SHARE_CODE).unwrap();
    for fn_name in ["transfer", "split"] {
        let asm = arkade_asm(&out, fn_name);
        assert!(
            !asm.contains(OP_CHECKSIGFROMSTACK),
            "{fn_name}: must not consult the oracle"
        );
        assert!(
            !asm.contains(OP_PUSHCURRENTINPUTINDEX),
            "{fn_name}: must not inspect sibling inputs"
        );
        assert!(
            !asm.contains(SECONDS_PER_YEAR),
            "{fn_name}: must not touch accrual math"
        );
    }
}

#[test]
fn test_service_advances_position_basis_to_now() {
    // The treasury may only release reserve against a position re-created
    // with lastClaim = tx.offchainTime — the recreation placeholder must
    // carry the wallclock, not the stale basis.
    let out = compile(TREASURY_CODE).unwrap();
    let asm = arkade_asm(&out, "service");
    assert!(
        asm.contains("<VTXO:StreamingShare(<posHolderPk>,<issuerPk>,<oraclePk>,<ticker>,<annualDividendCents>,<posUnits>,<tx.offchainTime>,<exit>)>"),
        "service must re-create the position with lastClaim advanced to tx.offchainTime"
    );
}

#[test]
fn test_claim_recreates_position_and_pays_holder() {
    let out = compile(SHARE_CODE).unwrap();
    let asm = arkade_asm(&out, "claim");
    assert!(
        asm.contains("<VTXO:StreamingShare(<holderPk>,<issuerPk>,<oraclePk>,<ticker>,<annualDividendCents>,<units>,<tx.offchainTime>,<exit>)>"),
        "claim must re-create the position with lastClaim advanced"
    );
    assert!(
        asm.contains("<VTXO:SingleSig(<holderPk>,<exit>)>"),
        "claim must route the payout to the holder"
    );
    assert!(
        asm.contains("<VTXO:DividendTreasury("),
        "claim must bind the co-spent input to the genuine treasury"
    );
}

#[test]
fn test_dust_floor_present_in_claim_paths() {
    for (code, fn_name) in [(TREASURY_CODE, "service"), (SHARE_CODE, "claim")] {
        let out = compile(code).unwrap();
        let tokens = arkade_asm_tokens(&out, fn_name);
        assert!(
            tokens.iter().any(|t| t.as_str() == "330"),
            "{fn_name}: 330-sat dust floor must be enforced"
        );
    }
}

#[test]
fn test_unilateral_exits_are_pure_csv_tapscripts() {
    for (code, key) in [(TREASURY_CODE, "<issuerPk>"), (SHARE_CODE, "<holderPk>")] {
        let out = compile(code).unwrap();
        let g = group(&out, "unilateral");
        assert!(
            g.arkade.is_none(),
            "unilateral must be a standalone tapscript, no covenant"
        );
        assert_eq!(g.leaves.len(), 1);
        let asm = g.leaves[0].asm.join(" ");
        assert!(
            asm.contains(OP_CHECKSEQUENCEVERIFY),
            "unilateral must be CSV-gated"
        );
        assert!(asm.contains(key), "unilateral must check the owner key");
        assert!(
            !asm.contains("OP_INSPECT"),
            "unilateral must carry no introspection"
        );
    }
}

#[test]
fn test_covenant_groups_get_synthesized_cooperative_leaf() {
    for code in [TREASURY_CODE, SHARE_CODE] {
        let out = compile(code).unwrap();
        for g in out.functions.iter().filter(|g| g.arkade.is_some()) {
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
fn test_constructor_schemas_share_program_parameters() {
    // Both contracts must agree on the program-defining fields so the
    // cross-input scriptPubKey reconstructions can bind them.
    let treasury = compile(TREASURY_CODE).unwrap();
    let share = compile(SHARE_CODE).unwrap();
    for (name, ty) in [
        ("issuerPk", "pubkey"),
        ("oraclePk", "pubkey"),
        ("ticker", "bytes32"),
        ("annualDividendCents", "int"),
        ("exit", "int"),
    ] {
        for (label, out) in [("treasury", &treasury), ("share", &share)] {
            let p = out
                .parameters
                .iter()
                .find(|p| p.name == name)
                .unwrap_or_else(|| panic!("{label} missing constructor input {name}"));
            assert_eq!(p.param_type, ty, "{label}.{name}");
        }
    }
    // Role-specific state
    for name in ["totalUnits", "reserveSats"] {
        assert!(
            treasury.parameters.iter().any(|p| p.name == name),
            "treasury missing {name}"
        );
    }
    for name in ["holderPk", "units", "lastClaim"] {
        assert!(
            share.parameters.iter().any(|p| p.name == name),
            "share missing {name}"
        );
    }
}
