use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKLOCKTIMEVERIFY, OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_INSPECTOUTASSETLOOKUP,
};

// CashSecuredPut: single-locked mirror of CoveredCall. Only the seller's
// stablecoin is escrowed. Buyer brings BTC at exercise IF they choose to.
const PUT_CODE: &str = r#"
import "single_sig.ark";

options {
  server = server;
  exit = exit;
}

contract CashSecuredPut(
  pubkey  sellerPk,
  pubkey  buyerPk,
  bytes32 stableAssetId,
  int     stableAmount,
  int     btcSats,
  int     expiryHeight,
  int     graceBlocks,
  int     exit
) {
  function exercise(signature buyerSig) {
    require(tx.time >= expiryHeight, "before expiry");
    require(checkSig(buyerSig, buyerPk), "invalid buyer sig");

    require(tx.outputs[0].value >= btcSats, "seller underpaid");
    require(
      tx.outputs[0].scriptPubKey == new SingleSig(sellerPk),
      "output 0 not seller"
    );

    require(
      tx.outputs[1].assets.lookup(stableAssetId) >= stableAmount,
      "buyer underpaid"
    );
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
      tx.outputs[0].scriptPubKey == new CashSecuredPut(
        newSellerPk, buyerPk, stableAssetId,
        stableAmount, btcSats, expiryHeight, graceBlocks, exit
      ),
      "invalid transfer output"
    );
    require(
      tx.outputs[0].assets.lookup(stableAssetId) >= stableAmount,
      "collateral not preserved"
    );
  }

  function transferBuyer(signature buyerSig, pubkey newBuyerPk) {
    require(tx.time < expiryHeight, "no transfers after expiry");
    require(checkSig(buyerSig, buyerPk), "invalid buyer sig");
    require(
      tx.outputs[0].scriptPubKey == new CashSecuredPut(
        sellerPk, newBuyerPk, stableAssetId,
        stableAmount, btcSats, expiryHeight, graceBlocks, exit
      ),
      "invalid transfer output"
    );
    require(
      tx.outputs[0].assets.lookup(stableAssetId) >= stableAmount,
      "collateral not preserved"
    );
  }
}
"#;

#[test]
fn test_compiles_with_8_tapleaves() {
    let out = compile(PUT_CODE).expect("compile");
    assert_eq!(out.name, "CashSecuredPut");
    assert_eq!(out.functions.len(), 8);
}

#[test]
fn test_exercise_takes_only_buyer_signature() {
    let out = compile(PUT_CODE).unwrap();
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
fn test_no_oracle_anywhere() {
    let out = compile(PUT_CODE).unwrap();
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
fn test_exercise_verifies_btc_delivery_and_stable_payout() {
    // Mirror of the call: output 0 takes BTC from buyer, output 1 takes
    // stablecoin from the vault.
    let out = compile(PUT_CODE).unwrap();
    let ex = out
        .functions
        .iter()
        .find(|f| f.name == "exercise" && f.server_variant)
        .unwrap();
    let asm = ex.asm.join(" ");
    assert!(
        asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "exercise must look up stablecoin balance on output 1"
    );
    assert!(
        asm.contains("OP_INSPECTOUTPUTVALUE"),
        "exercise must verify output 0's BTC value"
    );
    assert!(
        asm.contains(OP_CHECKLOCKTIMEVERIFY),
        "exercise must enforce tx.time >= expiryHeight"
    );
}

#[test]
fn test_reclaim_is_seller_only_with_cltv() {
    let out = compile(PUT_CODE).unwrap();
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
    let out = compile(PUT_CODE).unwrap();
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
    let out = compile(PUT_CODE).unwrap();
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
fn test_transfers_preserve_stablecoin_collateral() {
    // CashSecuredPut vault holds stablecoin (asset), not BTC. Transfers
    // must check the asset balance is preserved on the continuation.
    let out = compile(PUT_CODE).unwrap();
    for name in ["transferSeller", "transferBuyer"] {
        let t = out
            .functions
            .iter()
            .find(|f| f.name == name && f.server_variant)
            .unwrap();
        let asm = t.asm.join(" ");
        assert!(
            asm.contains(OP_INSPECTOUTASSETLOOKUP),
            "{name}: must verify stablecoin balance on continuation"
        );
        assert!(
            t.asm.iter().any(|s| s == OP_CHECKSIG),
            "{name}: must require party signature"
        );
    }
}

#[test]
fn test_exit_leaves_have_no_introspection() {
    let out = compile(PUT_CODE).unwrap();
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
        if fn_name != "reclaim" {
            assert!(
                !asm.contains(OP_CHECKLOCKTIMEVERIFY),
                "{fn_name} exit must not use OP_CHECKLOCKTIMEVERIFY"
            );
        }
    }
}
