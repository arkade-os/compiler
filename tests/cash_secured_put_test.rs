use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CAT, OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_INSPECTOUTASSETLOOKUP, OP_SHA256,
};

// CashSecuredPut: mirror of CoveredCall. Both parties' collateral lives in
// the same vault; settle() is permissionless and oracle-triggered. ITM if
// oracle price < strike (buyer puts BTC to seller at strike).
const PUT_CODE: &str = r#"
import "single_sig.ark";

options {
  server = server;
  exit = exit;
}

contract CashSecuredPut(
  pubkey  sellerPk,
  pubkey  buyerPk,
  pubkey  oraclePk,
  bytes32 ticker,
  bytes32 stableAssetId,
  int     stableAmount,
  int     btcSats,
  int     strikePrice,
  int     expiryHeight,
  int     exit
) {
  function settle(
    int       oraclePrice,
    int       oracleTime,
    signature oracleSig
  ) {
    require(tx.time >= expiryHeight, "before expiry");
    require(oraclePrice > 0, "invalid oracle price");
    require(strikePrice > 0, "invalid strike price");

    int oracleAge = tx.time - oracleTime;
    require(oracleAge >= 0, "future-dated oracle");
    require(oracleAge <= 6, "stale oracle");
    require(oracleTime >= expiryHeight, "oracle predates expiry");

    let oracleMsg = sha256(ticker + oraclePrice + oracleTime);
    require(checkSigFromStack(oracleSig, oraclePk, oracleMsg), "invalid oracle signature");

    if (oraclePrice < strikePrice) {
      require(tx.outputs[0].value >= btcSats, "seller underpaid");
      require(tx.outputs[0].scriptPubKey == new SingleSig(sellerPk), "output 0 not seller");
      require(tx.outputs[1].assets.lookup(stableAssetId) >= stableAmount, "buyer underpaid");
      require(tx.outputs[1].scriptPubKey == new SingleSig(buyerPk), "output 1 not buyer");
    } else {
      require(tx.outputs[0].assets.lookup(stableAssetId) >= stableAmount, "seller underpaid");
      require(tx.outputs[0].scriptPubKey == new SingleSig(sellerPk), "output 0 not seller");
      require(tx.outputs[1].value >= btcSats, "buyer underpaid");
      require(tx.outputs[1].scriptPubKey == new SingleSig(buyerPk), "output 1 not buyer");
    }
  }

  function transferSeller(signature sellerSig, pubkey newSellerPk) {
    require(checkSig(sellerSig, sellerPk), "invalid seller sig");
    require(
      tx.outputs[0].scriptPubKey == new CashSecuredPut(
        newSellerPk, buyerPk, oraclePk, ticker, stableAssetId,
        stableAmount, btcSats, strikePrice, expiryHeight, exit
      ),
      "invalid transfer output"
    );
    require(tx.outputs[0].value >= btcSats, "BTC not preserved");
    require(tx.outputs[0].assets.lookup(stableAssetId) >= stableAmount, "stable not preserved");
  }

  function transferBuyer(signature buyerSig, pubkey newBuyerPk) {
    require(checkSig(buyerSig, buyerPk), "invalid buyer sig");
    require(
      tx.outputs[0].scriptPubKey == new CashSecuredPut(
        sellerPk, newBuyerPk, oraclePk, ticker, stableAssetId,
        stableAmount, btcSats, strikePrice, expiryHeight, exit
      ),
      "invalid transfer output"
    );
    require(tx.outputs[0].value >= btcSats, "BTC not preserved");
    require(tx.outputs[0].assets.lookup(stableAssetId) >= stableAmount, "stable not preserved");
  }
}
"#;

#[test]
fn test_compiles_with_6_tapleaves() {
    let out = compile(PUT_CODE).expect("compile");
    assert_eq!(out.name, "CashSecuredPut");
    assert_eq!(out.functions.len(), 6);
}

#[test]
fn test_settle_takes_no_party_signature() {
    let out = compile(PUT_CODE).unwrap();
    let s = out
        .functions
        .iter()
        .find(|f| f.name == "settle" && f.server_variant)
        .unwrap();
    let names: Vec<&str> = s.function_inputs.iter().map(|i| i.name.as_str()).collect();
    for forbidden in ["sellerSig", "buyerSig"] {
        assert!(
            !names.contains(&forbidden),
            "settle must not require {forbidden}"
        );
    }
    for required in ["oraclePrice", "oracleTime", "oracleSig"] {
        assert!(names.contains(&required), "settle must take {required}");
    }
}

#[test]
fn test_settle_reconstructs_oracle_message() {
    let out = compile(PUT_CODE).unwrap();
    let s = out
        .functions
        .iter()
        .find(|f| f.name == "settle" && f.server_variant)
        .unwrap();
    let asm = s.asm.join(" ");
    let cats = s.asm.iter().filter(|x| x.as_str() == OP_CAT).count();
    assert!(
        cats >= 2,
        "settle: expected >=2 OP_CAT for ticker+price+time, found {cats}"
    );
    assert!(asm.contains(OP_SHA256), "settle: missing OP_SHA256");
    assert!(
        asm.contains(OP_CHECKSIGFROMSTACK),
        "settle: missing oracle CHECKSIGFROMSTACK"
    );
}

#[test]
fn test_settle_has_both_itm_and_otm_branches() {
    let out = compile(PUT_CODE).unwrap();
    let s = out
        .functions
        .iter()
        .find(|f| f.name == "settle" && f.server_variant)
        .unwrap();
    let lookups = s
        .asm
        .iter()
        .filter(|x| x.as_str() == OP_INSPECTOUTASSETLOOKUP)
        .count();
    assert!(
        lookups >= 2,
        "settle: expected an asset lookup in each branch, found {lookups}"
    );
}

#[test]
fn test_transfers_preserve_both_legs() {
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
            "{name}: must check stablecoin preservation"
        );
        assert!(
            t.asm.iter().any(|s| s == OP_CHECKSIG),
            "{name}: must require party signature"
        );
    }
}
