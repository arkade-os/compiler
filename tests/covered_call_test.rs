use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CAT, OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_INSPECTOUTASSETLOOKUP, OP_SHA256,
};

// CoveredCall: dual-locked, oracle-triggered, physically-settled European
// covered call. Both parties' collateral lives in the same vault from
// funding until expiry. settle() takes no party signature - the outcome
// is fully determined by a fresh oracle-signed price.
const CALL_CODE: &str = r#"
import "single_sig.ark";

options {
  server = server;
  exit = exit;
}

contract CoveredCall(
  pubkey  sellerPk,
  pubkey  buyerPk,
  pubkey  oraclePk,
  bytes32 ticker,
  bytes32 stableAssetId,
  int     btcSats,
  int     strikeAmount,
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

    int oracleAge = tx.time - oracleTime;
    require(oracleAge >= 0, "future-dated oracle");
    require(oracleAge <= 144, "stale oracle");

    let oracleMsg = sha256(ticker + oraclePrice + oracleTime);
    require(checkSigFromStack(oracleSig, oraclePk, oracleMsg), "invalid oracle signature");

    if (oraclePrice > strikePrice) {
      require(tx.outputs[0].assets.lookup(stableAssetId) >= strikeAmount, "seller underpaid");
      require(tx.outputs[0].scriptPubKey == new SingleSig(sellerPk), "output 0 not seller");
      require(tx.outputs[1].value >= btcSats, "buyer underpaid");
      require(tx.outputs[1].scriptPubKey == new SingleSig(buyerPk), "output 1 not buyer");
    } else {
      require(tx.outputs[0].value >= btcSats, "seller underpaid");
      require(tx.outputs[0].scriptPubKey == new SingleSig(sellerPk), "output 0 not seller");
      require(tx.outputs[1].assets.lookup(stableAssetId) >= strikeAmount, "buyer underpaid");
      require(tx.outputs[1].scriptPubKey == new SingleSig(buyerPk), "output 1 not buyer");
    }
  }

  function transferSeller(signature sellerSig, pubkey newSellerPk) {
    require(checkSig(sellerSig, sellerPk), "invalid seller sig");
    require(
      tx.outputs[0].scriptPubKey == new CoveredCall(
        newSellerPk, buyerPk, oraclePk, ticker, stableAssetId,
        btcSats, strikeAmount, strikePrice, expiryHeight, exit
      ),
      "invalid transfer output"
    );
    require(tx.outputs[0].value >= btcSats, "BTC not preserved");
    require(tx.outputs[0].assets.lookup(stableAssetId) >= strikeAmount, "stable not preserved");
  }

  function transferBuyer(signature buyerSig, pubkey newBuyerPk) {
    require(checkSig(buyerSig, buyerPk), "invalid buyer sig");
    require(
      tx.outputs[0].scriptPubKey == new CoveredCall(
        sellerPk, newBuyerPk, oraclePk, ticker, stableAssetId,
        btcSats, strikeAmount, strikePrice, expiryHeight, exit
      ),
      "invalid transfer output"
    );
    require(tx.outputs[0].value >= btcSats, "BTC not preserved");
    require(tx.outputs[0].assets.lookup(stableAssetId) >= strikeAmount, "stable not preserved");
  }
}
"#;

#[test]
fn test_compiles_with_6_tapleaves() {
    // 3 functions x 2 variants (cooperative + exit) = 6 leaves
    let out = compile(CALL_CODE).expect("compile");
    assert_eq!(out.name, "CoveredCall");
    assert_eq!(out.functions.len(), 6);
}

#[test]
fn test_settle_takes_no_party_signature() {
    // settle is permissionless: anyone with a fresh oracle sig can trigger.
    let out = compile(CALL_CODE).unwrap();
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
    // Must rebuild sha256(ticker || price || time) on stack and verify
    // the oracle signature against it.
    let out = compile(CALL_CODE).unwrap();
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
    // Both branches use asset introspection: one to pay the seller in stable
    // (ITM), the other to pay the buyer in stable (OTM). Each branch is
    // emitted, so two asset lookups should appear in settle's ASM.
    let out = compile(CALL_CODE).unwrap();
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
    // Each transfer continuation output must keep both BTC value and the
    // stablecoin asset balance.
    let out = compile(CALL_CODE).unwrap();
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
