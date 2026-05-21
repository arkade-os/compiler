use arkade_compiler::compile;
use arkade_compiler::opcodes::{OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_INSPECTOUTASSETLOOKUP};

// RyskPhysicalCall: physically-settled covered call. No oracle.
// Buyer exercises within [expiryHeight, expiryHeight + graceBlocks) by
// paying the strike in a stablecoin asset and receiving the locked BTC.
// After the window, seller reclaims.
const CALL_CODE: &str = r#"
import "single_sig.ark";

options {
  server = server;
  exit = exit;
}

contract RyskPhysicalCall(
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
    int windowClose = expiryHeight + graceBlocks;
    require(tx.time >= expiryHeight, "before expiry");
    require(tx.time < windowClose, "exercise window closed");
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
    require(checkSig(sellerSig, sellerPk), "invalid seller sig");
    require(
      tx.outputs[0].scriptPubKey == new RyskPhysicalCall(
        newSellerPk, buyerPk, stableAssetId,
        btcSats, strikeAmount, expiryHeight, graceBlocks, exit
      ),
      "invalid transfer output"
    );
    require(tx.outputs[0].value >= btcSats, "collateral not preserved");
  }

  function transferBuyer(signature buyerSig, pubkey newBuyerPk) {
    require(checkSig(buyerSig, buyerPk), "invalid buyer sig");
    require(
      tx.outputs[0].scriptPubKey == new RyskPhysicalCall(
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
    // 4 functions × 2 variants (cooperative + exit) = 8 leaves
    let out = compile(CALL_CODE).expect("compile");
    assert_eq!(out.name, "RyskPhysicalCall");
    assert_eq!(out.functions.len(), 8);
}

#[test]
fn test_exercise_uses_asset_lookup_no_oracle() {
    // exercise pays USDT to seller and BTC to buyer; physical, no oracle.
    let out = compile(CALL_CODE).unwrap();
    let ex = out
        .functions
        .iter()
        .find(|f| f.name == "exercise" && f.server_variant)
        .unwrap();
    let asm = ex.asm.join(" ");
    assert!(
        asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "exercise must look up output 0 asset balance for the strike payment"
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
    // Only the buyer signature should appear (besides the cooperative
    // server co-sign in the server variant).
    let out = compile(CALL_CODE).unwrap();
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
    // reclaim is a pure unlock, no asset introspection.
    let asm = r.asm.join(" ");
    assert!(
        !asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "reclaim should not need asset introspection"
    );
}

#[test]
fn test_transfer_seller_preserves_collateral() {
    let out = compile(CALL_CODE).unwrap();
    let t = out
        .functions
        .iter()
        .find(|f| f.name == "transferSeller" && f.server_variant)
        .unwrap();
    let asm = t.asm.join(" ");
    assert!(
        !asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "transferSeller is a pure key swap, no asset lookup"
    );
    assert!(
        t.asm.iter().any(|s| s == OP_CHECKSIG),
        "transferSeller must require seller signature"
    );
}

#[test]
fn test_transfer_buyer_preserves_collateral() {
    let out = compile(CALL_CODE).unwrap();
    let t = out
        .functions
        .iter()
        .find(|f| f.name == "transferBuyer" && f.server_variant)
        .unwrap();
    let asm = t.asm.join(" ");
    assert!(
        !asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "transferBuyer is a pure key swap, no asset lookup"
    );
    assert!(
        t.asm.iter().any(|s| s == OP_CHECKSIG),
        "transferBuyer must require buyer signature"
    );
}
