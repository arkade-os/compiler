use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_SHA256FINALIZE, OP_SHA256INITIALIZE, OP_SHA256UPDATE,
};

// StabilityVault: Fuji-style signed price feed. The oracle signs
//   msg = sha256(ticker || price || time)
// and the contract reconstructs that hash on-stack at settlement time.
const VAULT_CODE: &str = r#"
import "single_sig.ark";

options {
  server = server;
  exit = exit;
}

contract StabilityVault(
  pubkey  seekerPk,
  pubkey  providerPk,
  pubkey  oraclePk,
  bytes32 ticker,
  int     targetUSD,
  int     totalCollateral,
  int     fundingSatPerBlock,
  int     openHeight,
  int     exit
) {
  function transfer(signature seekerSig, pubkey newSeekerPk) {
    require(checkSig(seekerSig, seekerPk), "invalid seeker sig");
    require(
      tx.outputs[0].scriptPubKey == new StabilityVault(
        newSeekerPk, providerPk, oraclePk, ticker,
        targetUSD, totalCollateral, fundingSatPerBlock, openHeight, exit
      ),
      "invalid transfer output"
    );
    require(tx.outputs[0].value >= totalCollateral, "collateral not preserved");
  }

  function split(signature seekerSig, int amountUSD, pubkey newSeekerPk) {
    require(checkSig(seekerSig, seekerPk), "invalid seeker sig");
    require(amountUSD > 0, "zero");
    require(amountUSD < targetUSD, "too big");

    int collateralA = totalCollateral * amountUSD / targetUSD;
    int collateralB = totalCollateral - collateralA;
    require(collateralA >= 330, "dust a");
    require(collateralB >= 330, "dust b");

    require(
      tx.outputs[0].scriptPubKey == new StabilityVault(
        newSeekerPk, providerPk, oraclePk, ticker,
        amountUSD, collateralA, fundingSatPerBlock, openHeight, exit
      ), "bad output 0"
    );
    require(
      tx.outputs[1].scriptPubKey == new StabilityVault(
        seekerPk, providerPk, oraclePk, ticker,
        targetUSD - amountUSD, collateralB, fundingSatPerBlock, openHeight, exit
      ), "bad output 1"
    );
  }

  function seekerRedeem(
    signature seekerSig,
    int       oraclePrice,
    int       oracleTime,
    signature oracleSig
  ) {
    require(checkSig(seekerSig, seekerPk), "invalid seeker sig");
    require(oraclePrice > 0, "invalid price");
    int oracleAge = tx.time - oracleTime;
    require(oracleAge <= 144, "stale oracle");

    let ctx1 = sha256Initialize(ticker);
    let ctx2 = sha256Update(ctx1, oraclePrice);
    let oracleMsg = sha256Finalize(ctx2, oracleTime);
    require(checkSigFromStack(oracleSig, oraclePk, oracleMsg), "bad oracle sig");

    int seekerRaw = targetUSD * 100000000 / oraclePrice
                  + fundingSatPerBlock * (tx.time - openHeight);

    if (seekerRaw <= 0) {
      require(tx.outputs[0].scriptPubKey == new SingleSig(providerPk), "not provider");
      require(tx.outputs[0].value >= totalCollateral, "underpaid");
    } else {
      require(tx.outputs[0].scriptPubKey == new SingleSig(seekerPk), "not seeker");
      if (seekerRaw >= totalCollateral) {
        require(tx.outputs[0].value >= totalCollateral, "underpaid");
      } else {
        require(tx.outputs[0].value >= seekerRaw, "underpaid");
        int providerPayout = totalCollateral - seekerRaw;
        if (providerPayout > 330) {
          require(tx.outputs[1].scriptPubKey == new SingleSig(providerPk), "not provider");
          require(tx.outputs[1].value >= providerPayout, "underpaid");
        }
      }
    }
  }

  function providerExit(
    signature providerSig,
    int       oraclePrice,
    int       oracleTime,
    signature oracleSig
  ) {
    require(checkSig(providerSig, providerPk), "invalid provider sig");
    require(oraclePrice > 0, "invalid price");
    int oracleAge = tx.time - oracleTime;
    require(oracleAge <= 144, "stale oracle");

    let ctx1 = sha256Initialize(ticker);
    let ctx2 = sha256Update(ctx1, oraclePrice);
    let oracleMsg = sha256Finalize(ctx2, oracleTime);
    require(checkSigFromStack(oracleSig, oraclePk, oracleMsg), "bad oracle sig");

    int seekerRaw = targetUSD * 100000000 / oraclePrice
                  + fundingSatPerBlock * (tx.time - openHeight);

    if (seekerRaw <= 0) {
      require(tx.outputs[0].scriptPubKey == new SingleSig(providerPk), "not provider");
      require(tx.outputs[0].value >= totalCollateral, "underpaid");
    } else {
      require(tx.outputs[0].scriptPubKey == new SingleSig(seekerPk), "not seeker");
      if (seekerRaw >= totalCollateral) {
        require(tx.outputs[0].value >= totalCollateral, "underpaid");
      } else {
        require(tx.outputs[0].value >= seekerRaw, "underpaid");
        int providerPayout = totalCollateral - seekerRaw;
        if (providerPayout > 330) {
          require(tx.outputs[1].scriptPubKey == new SingleSig(providerPk), "not provider");
          require(tx.outputs[1].value >= providerPayout, "underpaid");
        }
      }
    }
  }
}
"#;

const OFFER_CODE: &str = r#"
import "stability_vault.ark";

options {
  server = server;
  exit = exit;
}

contract StabilityOffer(
  pubkey  providerPk,
  pubkey  oraclePk,
  bytes32 ticker,
  int     fundingSatPerBlock,
  int     maxExposureBTC,
  int     collateralRatioPct,
  int     exit
) {
  function take(
    int       userBTC,
    pubkey    seekerPk,
    int       oraclePrice,
    int       oracleTime,
    signature oracleSig
  ) {
    require(userBTC > 0, "zero");
    require(userBTC <= maxExposureBTC, "too big");
    require(collateralRatioPct >= 100, "bad ratio");
    require(oraclePrice > 0, "invalid price");
    int oracleAge = tx.time - oracleTime;
    require(oracleAge <= 144, "stale oracle");

    let ctx1 = sha256Initialize(ticker);
    let ctx2 = sha256Update(ctx1, oraclePrice);
    let oracleMsg = sha256Finalize(ctx2, oracleTime);
    require(checkSigFromStack(oracleSig, oraclePk, oracleMsg), "bad oracle sig");

    int targetUSD       = userBTC * oraclePrice / 100000000;
    int totalCollateral = userBTC * (100 + collateralRatioPct) / 100;

    require(
      tx.outputs[0].scriptPubKey == new StabilityVault(
        seekerPk, providerPk, oraclePk, ticker,
        targetUSD, totalCollateral, fundingSatPerBlock, tx.time, exit
      ), "bad vault"
    );
    require(tx.outputs[0].value >= totalCollateral, "underpaid");

    int remaining = maxExposureBTC - userBTC;
    if (remaining > 0) {
      require(
        tx.outputs[1].scriptPubKey == new StabilityOffer(
          providerPk, oraclePk, ticker,
          fundingSatPerBlock, remaining, collateralRatioPct, exit
        ), "bad offer"
      );
    }
  }

  function withdraw(signature providerSig) {
    require(checkSig(providerSig, providerPk), "invalid provider sig");
  }
}
"#;

#[test]
fn test_vault_compiles_with_8_tapleaves() {
    let out = compile(VAULT_CODE).expect("vault compile");
    assert_eq!(out.name, "StabilityVault");
    assert_eq!(out.functions.len(), 8); // 4 fns × 2 variants
}

#[test]
fn test_vault_settlement_verifies_full_oracle_message() {
    // seekerRedeem and providerExit must reconstruct sha256(ticker||price||time)
    // and verify the oracle sig against it.
    let out = compile(VAULT_CODE).unwrap();
    for name in &["seekerRedeem", "providerExit"] {
        let f = out
            .functions
            .iter()
            .find(|f| &f.name == name && f.server_variant)
            .unwrap();
        let asm = f.asm.join(" ");
        assert!(
            asm.contains(OP_SHA256INITIALIZE),
            "{name}: missing SHA256INIT"
        );
        assert!(
            asm.contains(OP_SHA256UPDATE),
            "{name}: missing SHA256UPDATE"
        );
        assert!(
            asm.contains(OP_SHA256FINALIZE),
            "{name}: missing SHA256FINALIZE"
        );
        assert!(
            asm.contains(OP_CHECKSIGFROMSTACK),
            "{name}: missing oracle sig verify"
        );
        assert!(
            f.asm.iter().any(|s| s == OP_CHECKSIG),
            "{name}: missing user checksig"
        );
    }
}

#[test]
fn test_vault_transfer_is_pure_keyswap() {
    let out = compile(VAULT_CODE).unwrap();
    let t = out
        .functions
        .iter()
        .find(|f| f.name == "transfer" && f.server_variant)
        .unwrap();
    let asm = t.asm.join(" ");
    assert!(
        !asm.contains(OP_CHECKSIGFROMSTACK),
        "transfer must not call oracle"
    );
    assert!(!asm.contains(OP_SHA256INITIALIZE), "transfer must not hash");
    assert!(t.asm.iter().any(|s| s == OP_CHECKSIG));
}

#[test]
fn test_offer_compiles_with_4_tapleaves() {
    let out = compile(OFFER_CODE).expect("offer compile");
    assert_eq!(out.name, "StabilityOffer");
    assert_eq!(out.functions.len(), 4);
}

#[test]
fn test_offer_take_verifies_full_oracle_message() {
    let out = compile(OFFER_CODE).unwrap();
    let take = out
        .functions
        .iter()
        .find(|f| f.name == "take" && f.server_variant)
        .unwrap();
    let asm = take.asm.join(" ");
    assert!(
        asm.contains(OP_SHA256INITIALIZE),
        "take: missing SHA256INIT"
    );
    assert!(asm.contains(OP_SHA256UPDATE), "take: missing SHA256UPDATE");
    assert!(
        asm.contains(OP_SHA256FINALIZE),
        "take: missing SHA256FINALIZE"
    );
    assert!(
        asm.contains(OP_CHECKSIGFROMSTACK),
        "take: missing oracle sig verify"
    );
}
