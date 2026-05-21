use arkade_compiler::compile;
use arkade_compiler::opcodes::{OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_INSPECTOUTASSETLOOKUP};

// CashSecuredPut: physically-settled European cash-secured put. No oracle.
// Buyer exercises within [expiryHeight, expiryHeight + graceBlocks) by
// delivering `btcSats` BTC to the seller and receiving the locked
// stablecoin. After the window, seller reclaims the cash.
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
    int windowClose = expiryHeight + graceBlocks;
    require(tx.time >= expiryHeight, "before expiry");
    require(tx.time < windowClose, "exercise window closed");
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
    // 4 functions × 2 variants (cooperative + exit) = 8 leaves
    let out = compile(PUT_CODE).expect("compile");
    assert_eq!(out.name, "CashSecuredPut");
    assert_eq!(out.functions.len(), 8);
}

#[test]
fn test_exercise_uses_asset_lookup_no_oracle() {
    // exercise checks the stablecoin payout to buyer via asset lookup, and
    // the BTC payout to seller via tx.outputs[0].value. No oracle.
    let out = compile(PUT_CODE).unwrap();
    let ex = out
        .functions
        .iter()
        .find(|f| f.name == "exercise" && f.server_variant)
        .unwrap();
    let asm = ex.asm.join(" ");
    assert!(
        asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "exercise must look up output 1 asset balance for the cash payout"
    );
    assert!(
        !asm.contains(OP_CHECKSIGFROMSTACK),
        "exercise must not invoke an oracle"
    );
    assert!(
        ex.asm.iter().any(|s| s == OP_CHECKSIG),
        "exercise must require the buyer's signature"
    );
}

#[test]
fn test_exercise_is_buyer_gated() {
    let out = compile(PUT_CODE).unwrap();
    let ex = out
        .functions
        .iter()
        .find(|f| f.name == "exercise" && f.server_variant)
        .unwrap();
    let names: Vec<&str> = ex.function_inputs.iter().map(|i| i.name.as_str()).collect();
    assert!(names.contains(&"buyerSig"), "exercise must take buyerSig");
    assert!(
        !names.contains(&"sellerSig"),
        "exercise must not require sellerSig"
    );
}

#[test]
fn test_reclaim_is_seller_only() {
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
        !asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "reclaim should not need asset introspection"
    );
}

#[test]
fn test_transfers_preserve_stablecoin_collateral() {
    // Unlike the call (which preserves BTC value), the put preserves the
    // stablecoin asset balance — that's the collateral.
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
            "{name}: must verify stablecoin balance on continuation output"
        );
        assert!(
            t.asm.iter().any(|s| s == OP_CHECKSIG),
            "{name}: must require party signature"
        );
    }
}
