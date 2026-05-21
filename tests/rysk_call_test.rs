use arkade_compiler::compile;
use arkade_compiler::opcodes::{OP_CAT, OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_SHA256};

// RyskCall: Bitcoin-native, BTC-collateralized, cash-settled covered call.
// Mirrors the inverse-call payoff from Rysk Finance v12. Settlement uses the
// same Fuji-style signed price feed as StabilityVault: the oracle signs
//   msg = sha256(ticker || price || time)
// and the contract reconstructs that hash on-stack to verify the signature.
const CALL_CODE: &str = r#"
import "single_sig.ark";

options {
  server = server;
  exit = exit;
}

contract RyskCall(
  pubkey  sellerPk,
  pubkey  buyerPk,
  pubkey  oraclePk,
  bytes32 ticker,
  int     notionalSats,
  int     strikeUSDCents,
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

    if (oraclePrice <= strikeUSDCents) {
      require(tx.outputs[0].value >= notionalSats, "seller underpaid");
      require(tx.outputs[0].scriptPubKey == new SingleSig(sellerPk), "output 0 not seller");
    } else {
      int sellerPayout = notionalSats * strikeUSDCents / oraclePrice;
      int buyerPayout  = notionalSats - sellerPayout;
      if (sellerPayout >= 330) {
        require(tx.outputs[0].value >= sellerPayout, "seller underpaid");
        require(tx.outputs[0].scriptPubKey == new SingleSig(sellerPk), "output 0 not seller");
        if (buyerPayout > 330) {
          require(tx.outputs[1].value >= buyerPayout, "buyer underpaid");
          require(tx.outputs[1].scriptPubKey == new SingleSig(buyerPk), "output 1 not buyer");
        }
      } else {
        require(tx.outputs[0].value >= notionalSats, "buyer underpaid");
        require(tx.outputs[0].scriptPubKey == new SingleSig(buyerPk), "output 0 not buyer");
      }
    }
  }

  function transferSeller(signature sellerSig, pubkey newSellerPk) {
    require(checkSig(sellerSig, sellerPk), "invalid seller sig");
    require(
      tx.outputs[0].scriptPubKey == new RyskCall(
        newSellerPk, buyerPk, oraclePk, ticker,
        notionalSats, strikeUSDCents, expiryHeight, exit
      ),
      "invalid transfer output"
    );
    require(tx.outputs[0].value >= notionalSats, "collateral not preserved");
  }

  function transferBuyer(signature buyerSig, pubkey newBuyerPk) {
    require(checkSig(buyerSig, buyerPk), "invalid buyer sig");
    require(
      tx.outputs[0].scriptPubKey == new RyskCall(
        sellerPk, newBuyerPk, oraclePk, ticker,
        notionalSats, strikeUSDCents, expiryHeight, exit
      ),
      "invalid transfer output"
    );
    require(tx.outputs[0].value >= notionalSats, "collateral not preserved");
  }
}
"#;

#[test]
fn test_call_compiles_with_6_tapleaves() {
    // 3 functions x 2 variants (server + exit)
    let out = compile(CALL_CODE).expect("call compile");
    assert_eq!(out.name, "RyskCall");
    assert_eq!(out.functions.len(), 6);
}

#[test]
fn test_settle_verifies_full_oracle_message() {
    // settle must reconstruct sha256(ticker || price || time) via OP_CAT +
    // OP_SHA256 and verify the oracle signature on it. No party signature is
    // required — settlement is a pure function of the attested price.
    let out = compile(CALL_CODE).unwrap();
    let settle = out
        .functions
        .iter()
        .find(|f| f.name == "settle" && f.server_variant)
        .unwrap();
    let asm = settle.asm.join(" ");
    let cat_count = settle.asm.iter().filter(|s| s.as_str() == OP_CAT).count();
    assert!(
        cat_count >= 2,
        "settle: expected >=2 OP_CAT for ticker+price+time, found {cat_count}"
    );
    assert!(asm.contains(OP_SHA256), "settle: missing OP_SHA256");
    assert!(
        asm.contains(OP_CHECKSIGFROMSTACK),
        "settle: missing oracle sig verify"
    );
}

#[test]
fn test_settle_takes_no_party_signature() {
    // settle is non-interactive past expiry: it requires only the oracle
    // signature, not seller/buyer signatures. Confirm via the ABI inputs.
    let out = compile(CALL_CODE).unwrap();
    let settle = out
        .functions
        .iter()
        .find(|f| f.name == "settle" && f.server_variant)
        .unwrap();
    for name in ["sellerSig", "buyerSig"] {
        assert!(
            !settle.function_inputs.iter().any(|i| i.name == name),
            "settle must not require {name}"
        );
    }
}

#[test]
fn test_transfer_seller_is_pure_keyswap() {
    // transferSeller is a same-contract re-emission with the seller key
    // swapped. It must not call the oracle or do any hashing.
    let out = compile(CALL_CODE).unwrap();
    let t = out
        .functions
        .iter()
        .find(|f| f.name == "transferSeller" && f.server_variant)
        .unwrap();
    let asm = t.asm.join(" ");
    assert!(
        !asm.contains(OP_CHECKSIGFROMSTACK),
        "transferSeller must not call oracle"
    );
    assert!(
        !t.asm.iter().any(|s| s.as_str() == OP_CAT),
        "transferSeller must not concatenate"
    );
    assert!(!asm.contains(OP_SHA256), "transferSeller must not hash");
    assert!(
        t.asm.iter().any(|s| s == OP_CHECKSIG),
        "transferSeller must keep seller checksig"
    );
}

#[test]
fn test_transfer_buyer_is_pure_keyswap() {
    let out = compile(CALL_CODE).unwrap();
    let t = out
        .functions
        .iter()
        .find(|f| f.name == "transferBuyer" && f.server_variant)
        .unwrap();
    let asm = t.asm.join(" ");
    assert!(
        !asm.contains(OP_CHECKSIGFROMSTACK),
        "transferBuyer must not call oracle"
    );
    assert!(
        !t.asm.iter().any(|s| s.as_str() == OP_CAT),
        "transferBuyer must not concatenate"
    );
    assert!(!asm.contains(OP_SHA256), "transferBuyer must not hash");
    assert!(
        t.asm.iter().any(|s| s == OP_CHECKSIG),
        "transferBuyer must keep buyer checksig"
    );
}

#[test]
fn test_abi_exposes_oracle_inputs() {
    // The ABI for settle must expose oraclePrice, oracleTime, and oracleSig
    // so an off-chain settler can construct the witness.
    let out = compile(CALL_CODE).unwrap();
    let settle = out
        .functions
        .iter()
        .find(|f| f.name == "settle" && f.server_variant)
        .unwrap();
    let names: Vec<&str> = settle
        .function_inputs
        .iter()
        .map(|i| i.name.as_str())
        .collect();
    assert!(names.contains(&"oraclePrice"), "missing oraclePrice input");
    assert!(names.contains(&"oracleTime"), "missing oracleTime input");
    assert!(names.contains(&"oracleSig"), "missing oracleSig input");
}
