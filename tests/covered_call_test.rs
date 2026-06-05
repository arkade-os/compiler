use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKLOCKTIMEVERIFY, OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_INSPECTOUTASSETLOOKUP,
};

// CoveredCall: single-locked, no-oracle, physically-settled European call
// matching Rysk v12's mechanics. Only the seller's BTC is escrowed. Buyer
// brings the strike payment at exercise time IF they choose to exercise.
const CALL_CODE: &str = r#"
import "single_sig.ark";

options {
  server = server;
  exit = exit;
}

contract CoveredCall(
  pubkey  sellerPk,
  pubkey  buyerPk,
  bytes32 stableAssetId,
  int     btcSats,
  int     strikeAmount,
  int     expiryHeight,
  int     graceBlocks,
  int     exit
) {
  function exercise(signature buyerSig) {
    require(tx.time >= expiryHeight, "before expiry");
    require(checkSig(buyerSig, buyerPk), "invalid buyer sig");

    require(
      tx.outputs[0].assets.lookup(stableAssetId) >= strikeAmount,
      "seller underpaid"
    );
    require(
      tx.outputs[0].scriptPubKey == new SingleSig(sellerPk),
      "output 0 not seller"
    );

    require(tx.outputs[1].value >= btcSats, "buyer underpaid");
    require(
      tx.outputs[1].scriptPubKey == new SingleSig(buyerPk),
      "output 1 not buyer"
    );
  }

  function reclaim(signature sellerSig) {
    int reclaimHeight = expiryHeight + graceBlocks;
    require(tx.time >= reclaimHeight, "reclaim window not open");
    require(checkSig(sellerSig, sellerPk), "invalid seller sig");
  }

  function transferSeller(signature sellerSig, pubkey newSellerPk) {
    require(tx.time < expiryHeight, "no transfers after expiry");
    require(checkSig(sellerSig, sellerPk), "invalid seller sig");
    require(
      tx.outputs[0].scriptPubKey == new CoveredCall(
        newSellerPk, buyerPk, stableAssetId,
        btcSats, strikeAmount, expiryHeight, graceBlocks, exit
      ),
      "invalid transfer output"
    );
    require(tx.outputs[0].value >= btcSats, "collateral not preserved");
  }

  function transferBuyer(signature buyerSig, pubkey newBuyerPk) {
    require(tx.time < expiryHeight, "no transfers after expiry");
    require(checkSig(buyerSig, buyerPk), "invalid buyer sig");
    require(
      tx.outputs[0].scriptPubKey == new CoveredCall(
        sellerPk, newBuyerPk, stableAssetId,
        btcSats, strikeAmount, expiryHeight, graceBlocks, exit
      ),
      "invalid transfer output"
    );
    require(tx.outputs[0].value >= btcSats, "collateral not preserved");
  }
}
"#;

#[test]
fn test_compiles_with_8_tapleaves() {
    // 4 functions x 2 variants (cooperative + exit) = 8 leaves
    let out = compile(CALL_CODE).expect("compile");
    assert_eq!(out.name, "CoveredCall");
    assert_eq!(out.functions.len(), 8);
}

#[test]
fn test_exercise_takes_only_buyer_signature() {
    // Single-locked design: exercise is buyer-gated. No oracle, no seller.
    let out = compile(CALL_CODE).unwrap();
    let ex = out
        .functions
        .iter()
        .find(|f| f.name == "exercise" && f.server_variant)
        .unwrap();
    let names: Vec<&str> = ex.function_inputs.iter().map(|i| i.name.as_str()).collect();
    assert!(names.contains(&"buyerSig"), "exercise must take buyerSig");
    for forbidden in [
        "sellerSig",
        "oracleSig",
        "oraclePrice",
        "oracleTime",
        "oraclePk",
    ] {
        assert!(
            !names.contains(&forbidden),
            "exercise must not require {forbidden}"
        );
    }
}

#[test]
fn test_exercise_has_no_oracle() {
    // No checkSigFromStack — there is no oracle dependency in this design.
    let out = compile(CALL_CODE).unwrap();
    for fn_name in ["exercise", "reclaim", "transferSeller", "transferBuyer"] {
        for &sv in &[true, false] {
            let f = out
                .functions
                .iter()
                .find(|f| f.name == fn_name && f.server_variant == sv)
                .unwrap();
            let asm = f.asm.join(" ");
            assert!(
                !asm.contains(OP_CHECKSIGFROMSTACK),
                "{fn_name} ({}): must not invoke oracle",
                if sv { "coop" } else { "exit" }
            );
        }
    }
}

#[test]
fn test_exercise_verifies_strike_payment() {
    // Output 0 must hold strikeAmount of stableAssetId, output 1 must hold
    // btcSats of BTC value. Both checks emitted in the cooperative ASM.
    let out = compile(CALL_CODE).unwrap();
    let ex = out
        .functions
        .iter()
        .find(|f| f.name == "exercise" && f.server_variant)
        .unwrap();
    let asm = ex.asm.join(" ");
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
    let r = out
        .functions
        .iter()
        .find(|f| f.name == "reclaim" && f.server_variant)
        .unwrap();
    let names: Vec<&str> = r.function_inputs.iter().map(|i| i.name.as_str()).collect();
    assert!(names.contains(&"sellerSig"), "reclaim must take sellerSig");
    assert!(
        !names.contains(&"buyerSig"),
        "reclaim must not require buyerSig"
    );
    let asm = r.asm.join(" ");
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
fn test_asset_id_decomposes_to_txid_and_gidx() {
    let out = compile(CALL_CODE).unwrap();
    let names: Vec<&str> = out.parameters.iter().map(|p| p.name.as_str()).collect();
    assert!(
        names.contains(&"stableAssetId_txid"),
        "constructorInputs must include stableAssetId_txid"
    );
    assert!(
        names.contains(&"stableAssetId_gidx"),
        "constructorInputs must include stableAssetId_gidx"
    );
    assert!(
        !names.contains(&"stableAssetId"),
        "raw bytes32 stableAssetId should not appear in ABI"
    );
}

#[test]
fn test_transfers_guarded_by_expiry() {
    // Cooperative variant carries the `tx.time < expiryHeight` guard. The
    // exit variant strips introspection (Arkade-wide constraint) and falls
    // back to N-of-N consent, which provides equivalent protection.
    let out = compile(CALL_CODE).unwrap();
    for name in ["transferSeller", "transferBuyer"] {
        let t = out
            .functions
            .iter()
            .find(|f| f.name == name && f.server_variant)
            .unwrap();
        assert!(
            t.asm.iter().any(|op| op.as_str() == "<expiryHeight>"),
            "{name}: cooperative variant must reference <expiryHeight>"
        );
    }
}

#[test]
fn test_transfers_preserve_btc_collateral() {
    // CoveredCall vault holds BTC only — transfers must check the
    // continuation's BTC value, not asset balance.
    let out = compile(CALL_CODE).unwrap();
    for name in ["transferSeller", "transferBuyer"] {
        let t = out
            .functions
            .iter()
            .find(|f| f.name == name && f.server_variant)
            .unwrap();
        let asm = t.asm.join(" ");
        assert!(
            !asm.contains(OP_INSPECTOUTASSETLOOKUP),
            "{name}: CoveredCall transfers should not need asset lookup (vault is BTC-only)"
        );
        assert!(
            asm.contains("OP_INSPECTOUTPUTVALUE"),
            "{name}: must verify BTC value preserved on continuation"
        );
        assert!(
            t.asm.iter().any(|s| s == OP_CHECKSIG),
            "{name}: must require party signature"
        );
    }
}

#[test]
fn test_exit_leaves_have_no_introspection() {
    // Exit variants are pure Bitcoin script: N-of-N CHECKSIG + CSV.
    // No introspection opcodes (OP_INSPECT*, OP_CHECKLOCKTIMEVERIFY).
    let out = compile(CALL_CODE).unwrap();
    for fn_name in ["exercise", "reclaim", "transferSeller", "transferBuyer"] {
        let exit = out
            .functions
            .iter()
            .find(|f| f.name == fn_name && !f.server_variant)
            .unwrap();
        let asm = exit.asm.join(" ");
        assert!(
            !asm.contains("OP_INSPECT"),
            "{fn_name} exit must not use introspection opcodes"
        );
        // reclaim's exit DOES legitimately have CLTV (because reclaim's
        // cooperative path also has it, and CLTV is pure Bitcoin script).
        // The other functions should not.
        if fn_name != "reclaim" {
            assert!(
                !asm.contains(OP_CHECKLOCKTIMEVERIFY),
                "{fn_name} exit must not use OP_CHECKLOCKTIMEVERIFY"
            );
        }
    }
}
