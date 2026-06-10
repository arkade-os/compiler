// InventoryHedge: perpetual, BTC-settled, fully-collateralized MM inventory
// hedge (docs/mm-residual-hedge.md). A generalization of stability_vault.ark.
//
// These tests pin the compilation roundtrip (both tapleaf variants per
// function, non-empty witness schemas) and the behavioral invariants:
// oracle-gated settlement, the redeem clamp branches, and the auto-injected
// <SERVER_KEY> on the cooperative path.

use arkade_compiler::compile;
use arkade_compiler::opcodes::{OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_DIV64};

const HEDGE_CODE: &str = include_str!("../examples/hedging/inventory_hedge.ark");

const FUNCTIONS: &[&str] = &[
    "transfer",
    "updateFunding",
    "addCapital",
    "removeCapital",
    "redeem",
    "withdraw",
];

// Functions that settle against the oracle-attested price.
const ORACLE_FUNCTIONS: &[&str] = &["removeCapital", "redeem", "withdraw"];

#[test]
fn test_compiles_with_12_tapleaves() {
    let out = compile(HEDGE_CODE).expect("inventory hedge compile");
    assert_eq!(out.name, "InventoryHedge");
    // 6 functions × 2 variants (cooperative + exit).
    assert_eq!(out.functions.len(), 12);
}

#[test]
fn test_both_variants_emit_with_nonempty_witness_schema() {
    let out = compile(HEDGE_CODE).unwrap();
    for name in FUNCTIONS {
        for server_variant in [true, false] {
            let f = out
                .functions
                .iter()
                .find(|f| &f.name == name && f.server_variant == server_variant)
                .unwrap_or_else(|| panic!("missing {name} (serverVariant={server_variant})"));
            assert!(
                !f.asm.is_empty(),
                "{name} (serverVariant={server_variant}): empty asm"
            );
            assert!(
                !f.witness_schema.is_empty(),
                "{name} (serverVariant={server_variant}): empty witness schema"
            );
        }
    }
}

#[test]
fn test_cooperative_path_injects_server_key() {
    // options { server = server } must auto-inject <SERVER_KEY> on every
    // cooperative (serverVariant=true) leaf; it is never a constructor param.
    let out = compile(HEDGE_CODE).unwrap();
    for name in FUNCTIONS {
        let f = out
            .functions
            .iter()
            .find(|f| &f.name == name && f.server_variant)
            .unwrap();
        assert!(
            f.asm.iter().any(|s| s.contains("SERVER_KEY")),
            "{name}: cooperative leaf must carry the auto-injected <SERVER_KEY>"
        );
    }
    // And SERVER_KEY must never appear as a constructor input.
    assert!(
        !out.parameters
            .iter()
            .any(|p| p.name.to_uppercase().contains("SERVER")),
        "server key must not be a constructor parameter"
    );
}

#[test]
fn test_oracle_paths_verify_price_and_divide() {
    // Each settling path reconstructs the oracle message, verifies it via
    // checkSigFromStack, and converts fiat->sats with a 64-bit division.
    let out = compile(HEDGE_CODE).unwrap();
    for name in ORACLE_FUNCTIONS {
        let f = out
            .functions
            .iter()
            .find(|f| &f.name == name && f.server_variant)
            .unwrap();
        let asm = f.asm.join(" ");
        assert!(
            asm.contains(OP_CHECKSIGFROMSTACK),
            "{name}: missing oracle sig verify"
        );
        assert!(
            asm.contains(OP_DIV64),
            "{name}: missing OP_DIV64 conversion"
        );
        assert!(
            f.asm.iter().any(|s| s == OP_CHECKSIG),
            "{name}: missing user checksig"
        );
    }
}

#[test]
fn test_update_funding_is_offchain_rate_no_oracle() {
    // The imbalance-driven rate is supplied off-chain; on-chain updateFunding is
    // just the >=0 guard + accrual. It must NOT call the oracle.
    let out = compile(HEDGE_CODE).unwrap();
    let f = out
        .functions
        .iter()
        .find(|f| f.name == "updateFunding" && f.server_variant)
        .unwrap();
    let asm = f.asm.join(" ");
    assert!(
        !asm.contains(OP_CHECKSIGFROMSTACK),
        "updateFunding must not call the oracle"
    );
    assert!(
        f.asm.iter().any(|s| s == OP_CHECKSIG),
        "updateFunding must verify the long-leg key"
    );
}

#[test]
fn test_transfer_is_pure_keyswap() {
    let out = compile(HEDGE_CODE).unwrap();
    let f = out
        .functions
        .iter()
        .find(|f| f.name == "transfer" && f.server_variant)
        .unwrap();
    let asm = f.asm.join(" ");
    assert!(
        !asm.contains(OP_CHECKSIGFROMSTACK),
        "transfer must not call the oracle"
    );
    assert!(
        f.asm.iter().any(|s| s == OP_CHECKSIG),
        "transfer must verify the claim key"
    );
}

#[test]
fn test_redeem_has_clamp_branches() {
    // claimRaw is clamped into [0, totalCollateral]: claimRaw<=0 (all to long),
    // claimRaw>=collateral (all to claim), else split. That is three OP_IF
    // branches plus the long-leg dust guard.
    let out = compile(HEDGE_CODE).unwrap();
    let f = out
        .functions
        .iter()
        .find(|f| f.name == "redeem" && f.server_variant)
        .unwrap();
    let if_count = f.asm.iter().filter(|s| s.as_str() == "OP_IF").count();
    assert!(
        if_count >= 3,
        "redeem must encode the clamp branches, found {if_count} OP_IF"
    );
}

#[test]
fn test_compile_is_deterministic_ignoring_updated_at() {
    // updatedAt is a timestamp and must be stripped before any JSON comparison.
    let a = compile(HEDGE_CODE).unwrap();
    let b = compile(HEDGE_CODE).unwrap();
    let mut va = serde_json::to_value(&a).unwrap();
    let mut vb = serde_json::to_value(&b).unwrap();
    for v in [&mut va, &mut vb] {
        if let Some(obj) = v.as_object_mut() {
            obj.remove("updatedAt");
        }
    }
    assert_eq!(
        va, vb,
        "compilation must be deterministic once updatedAt is removed"
    );
}
