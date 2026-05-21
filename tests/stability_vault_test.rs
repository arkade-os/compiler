use arkade_compiler::compile;
use arkade_compiler::opcodes::{OP_CAT, OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_SHA256};

// StabilityVault: USD-compound funding model with provider-driven rate updates.
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
  int     fundingRatePerSec,
  int     lastUpdate,
  int     collateralRatioPct,
  int     seekerExitFee,
  int     exit
) {
  function transfer(signature seekerSig, pubkey newSeekerPk) {
    require(checkSig(seekerSig, seekerPk), "invalid seeker sig");
    require(
      tx.outputs[0].scriptPubKey == new StabilityVault(
        newSeekerPk, providerPk, oraclePk, ticker,
        targetUSD, totalCollateral, fundingRatePerSec, lastUpdate,
        collateralRatioPct, seekerExitFee, exit
      ),
      "bad output"
    );
    require(tx.outputs[0].value >= totalCollateral, "collateral lost");
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
        amountUSD, collateralA, fundingRatePerSec, lastUpdate,
        collateralRatioPct, seekerExitFee, exit
      ), "bad output 0"
    );
    require(
      tx.outputs[1].scriptPubKey == new StabilityVault(
        seekerPk, providerPk, oraclePk, ticker,
        targetUSD - amountUSD, collateralB, fundingRatePerSec, lastUpdate,
        collateralRatioPct, seekerExitFee, exit
      ), "bad output 1"
    );
  }

  function merge(
    signature seekerSig,
    int       otherIdx,
    int       otherTargetUSD,
    int       otherTotalCollateral,
    int       otherFundingRatePerSec,
    int       otherLastUpdate,
    int       otherSeekerExitFee,
    int       mergedFundingRatePerSec,
    int       mergedSeekerExitFee
  ) {
    require(checkSig(seekerSig, seekerPk), "invalid seeker sig");
    require(this.activeInputIndex != otherIdx, "self-merge disallowed");

    require(
      tx.inputs[otherIdx].scriptPubKey == new StabilityVault(
        seekerPk, providerPk, oraclePk, ticker,
        otherTargetUSD, otherTotalCollateral, otherFundingRatePerSec, otherLastUpdate,
        collateralRatioPct, otherSeekerExitFee, exit
      ),
      "input not matching vault"
    );

    if (fundingRatePerSec >= otherFundingRatePerSec) {
      require(mergedFundingRatePerSec == fundingRatePerSec, "rate != max");
    } else {
      require(mergedFundingRatePerSec == otherFundingRatePerSec, "rate != max");
    }

    if (seekerExitFee >= otherSeekerExitFee) {
      require(mergedSeekerExitFee == seekerExitFee, "fee != max");
    } else {
      require(mergedSeekerExitFee == otherSeekerExitFee, "fee != max");
    }

    int elapsedA      = tx.offchainTime - lastUpdate;
    require(elapsedA >= 0, "clock regression A");
    int rateElapsedA  = fundingRatePerSec * elapsedA / 1000000;
    int deltaA        = targetUSD * rateElapsedA / 1000000;
    int accruedA      = targetUSD + deltaA;

    int elapsedB      = tx.offchainTime - otherLastUpdate;
    require(elapsedB >= 0, "clock regression B");
    int rateElapsedB  = otherFundingRatePerSec * elapsedB / 1000000;
    int deltaB        = otherTargetUSD * rateElapsedB / 1000000;
    int accruedB      = otherTargetUSD + deltaB;

    int mergedTargetUSD       = accruedA + accruedB;
    int mergedTotalCollateral = totalCollateral + otherTotalCollateral;

    require(
      tx.outputs[0].scriptPubKey == new StabilityVault(
        seekerPk, providerPk, oraclePk, ticker,
        mergedTargetUSD, mergedTotalCollateral, mergedFundingRatePerSec, tx.offchainTime,
        collateralRatioPct, mergedSeekerExitFee, exit
      ), "bad merged output"
    );
    require(tx.outputs[0].value >= mergedTotalCollateral, "underfunded");
  }

  function settleAndUpdateFunding(signature providerSig, int newFundingRatePerSec) {
    require(checkSig(providerSig, providerPk), "invalid provider sig");
    require(newFundingRatePerSec >= 0, "negative funding rate disallowed");

    int elapsed           = tx.offchainTime - lastUpdate;
    require(elapsed >= 0, "clock regression");
    int rateElapsedScaled = fundingRatePerSec * elapsed / 1000000;
    int delta             = targetUSD * rateElapsedScaled / 1000000;
    int newTargetUSD      = targetUSD + delta;
    require(newTargetUSD > 0, "claim wiped");
    if (fundingRatePerSec != 0) {
      require(delta > 0, "no accrual; wait longer");
    }

    require(
      tx.outputs[0].scriptPubKey == new StabilityVault(
        seekerPk, providerPk, oraclePk, ticker,
        newTargetUSD, totalCollateral, newFundingRatePerSec, tx.offchainTime,
        collateralRatioPct, seekerExitFee, exit
      ), "bad output"
    );
    require(tx.outputs[0].value >= totalCollateral, "collateral lost");
  }

  function addCapital(signature providerSig, int amount) {
    require(checkSig(providerSig, providerPk), "invalid provider sig");
    require(amount > 0, "zero amount");
    int newTotalCollateral = totalCollateral + amount;
    require(
      tx.outputs[0].scriptPubKey == new StabilityVault(
        seekerPk, providerPk, oraclePk, ticker,
        targetUSD, newTotalCollateral, fundingRatePerSec, lastUpdate,
        collateralRatioPct, seekerExitFee, exit
      ), "bad output"
    );
    require(tx.outputs[0].value >= newTotalCollateral, "underfunded");
  }

  function removeCapital(
    signature providerSig,
    int       amount,
    int       oraclePrice,
    int       oracleTime,
    signature oracleSig
  ) {
    require(checkSig(providerSig, providerPk), "invalid provider sig");
    require(amount > 0, "zero amount");
    require(oraclePrice > 0, "invalid price");
    int oracleAge = tx.offchainTime - oracleTime;
    require(oracleAge >= 0, "future-dated oracle");
    require(oracleAge <= 600, "stale oracle");

    let oracleMsg = sha256(ticker + oraclePrice + oracleTime);
    require(checkSigFromStack(oracleSig, oraclePk, oracleMsg), "bad oracle sig");

    int elapsed           = tx.offchainTime - lastUpdate;
    require(elapsed >= 0, "clock regression");
    int rateElapsedScaled = fundingRatePerSec * elapsed / 1000000;
    int delta             = targetUSD * rateElapsedScaled / 1000000;
    int newTargetUSD      = targetUSD + delta;
    int currentSeekerBase = newTargetUSD * 100000000 / oraclePrice;
    int minCollateral     = currentSeekerBase * (100 + collateralRatioPct) / 100;
    int newTotalCollateral = totalCollateral - amount;
    require(newTotalCollateral >= minCollateral, "would breach ratio");

    require(
      tx.outputs[0].scriptPubKey == new StabilityVault(
        seekerPk, providerPk, oraclePk, ticker,
        targetUSD, newTotalCollateral, fundingRatePerSec, lastUpdate,
        collateralRatioPct, seekerExitFee, exit
      ), "bad output 0"
    );
    require(tx.outputs[0].value >= newTotalCollateral, "underfunded");
    require(tx.outputs[1].scriptPubKey == new SingleSig(providerPk), "not provider");
    require(tx.outputs[1].value >= amount, "provider underpaid");
  }

  function seekerExit(
    signature seekerSig,
    int       oraclePrice,
    int       oracleTime,
    signature oracleSig
  ) {
    require(checkSig(seekerSig, seekerPk), "invalid seeker sig");
    require(oraclePrice > 0, "invalid price");
    int oracleAge = tx.offchainTime - oracleTime;
    require(oracleAge >= 0, "future-dated oracle");
    require(oracleAge <= 600, "stale oracle");

    let oracleMsg = sha256(ticker + oraclePrice + oracleTime);
    require(checkSigFromStack(oracleSig, oraclePk, oracleMsg), "bad oracle sig");

    int elapsed           = tx.offchainTime - lastUpdate;
    require(elapsed >= 0, "clock regression");
    int rateElapsedScaled = fundingRatePerSec * elapsed / 1000000;
    int delta             = targetUSD * rateElapsedScaled / 1000000;
    int newTargetUSD      = targetUSD + delta;
    int netTargetUSD      = newTargetUSD * (10000 - seekerExitFee) / 10000;
    int seekerRaw         = netTargetUSD * 100000000 / oraclePrice;

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
    int oracleAge = tx.offchainTime - oracleTime;
    require(oracleAge >= 0, "future-dated oracle");
    require(oracleAge <= 600, "stale oracle");

    let oracleMsg = sha256(ticker + oraclePrice + oracleTime);
    require(checkSigFromStack(oracleSig, oraclePk, oracleMsg), "bad oracle sig");

    int elapsed           = tx.offchainTime - lastUpdate;
    require(elapsed >= 0, "clock regression");
    int rateElapsedScaled = fundingRatePerSec * elapsed / 1000000;
    int delta             = targetUSD * rateElapsedScaled / 1000000;
    int newTargetUSD      = targetUSD + delta;
    int seekerRaw         = newTargetUSD * 100000000 / oraclePrice;

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
  int     fundingRatePerSec,
  int     maxExposureBTC,
  int     collateralRatioPct,
  int     seekerExitFee,
  int     takeFee,
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
    int oracleAge = tx.offchainTime - oracleTime;
    require(oracleAge >= 0, "future-dated oracle");
    require(oracleAge <= 600, "stale oracle");

    let oracleMsg = sha256(ticker + oraclePrice + oracleTime);
    require(checkSigFromStack(oracleSig, oraclePk, oracleMsg), "bad oracle sig");

    require(seekerExitFee >= 0, "negative exit fee");
    require(seekerExitFee <= 10000, "exit fee > 100%");
    require(takeFee >= 0, "negative take fee");
    require(takeFee <= 10000, "take fee > 100%");

    int targetUSD       = userBTC * oraclePrice / 100000000;
    int totalCollateral = userBTC * (100 + collateralRatioPct) / 100;
    int takeFeeSats     = userBTC * takeFee / 10000;
    int remaining       = maxExposureBTC - userBTC;

    if (takeFeeSats > 330) {
      require(
        tx.outputs[0].scriptPubKey == new StabilityVault(
          seekerPk, providerPk, oraclePk, ticker,
          targetUSD, totalCollateral, fundingRatePerSec, tx.offchainTime,
          collateralRatioPct, seekerExitFee, exit
        ), "bad vault"
      );
      require(tx.outputs[0].value >= totalCollateral, "underpaid");
      require(tx.outputs[1].scriptPubKey == new SingleSig(providerPk), "not provider");
      require(tx.outputs[1].value >= takeFeeSats, "fee underpaid");
      if (remaining > 0) {
        require(
          tx.outputs[2].scriptPubKey == new StabilityOffer(
            providerPk, oraclePk, ticker,
            fundingRatePerSec, remaining, collateralRatioPct,
            seekerExitFee, takeFee, exit
          ), "bad offer"
        );
      }
    } else {
      require(
        tx.outputs[0].scriptPubKey == new StabilityVault(
          seekerPk, providerPk, oraclePk, ticker,
          targetUSD, totalCollateral, fundingRatePerSec, tx.offchainTime,
          collateralRatioPct, seekerExitFee, exit
        ), "bad vault"
      );
      int dustVaultValue = totalCollateral + takeFeeSats;
      require(tx.outputs[0].value >= dustVaultValue, "underpaid");
      if (remaining > 0) {
        require(
          tx.outputs[1].scriptPubKey == new StabilityOffer(
            providerPk, oraclePk, ticker,
            fundingRatePerSec, remaining, collateralRatioPct,
            seekerExitFee, takeFee, exit
          ), "bad offer"
        );
      }
    }
  }

  function withdraw(signature providerSig) {
    require(checkSig(providerSig, providerPk), "invalid provider sig");
  }
}
"#;

#[test]
fn test_vault_compiles_with_16_tapleaves() {
    let out = compile(VAULT_CODE).expect("vault compile");
    assert_eq!(out.name, "StabilityVault");
    assert_eq!(out.functions.len(), 16); // 8 fns × 2 variants
}

#[test]
fn test_merge_emits_active_input_index_opcode() {
    use arkade_compiler::opcodes::OP_PUSHCURRENTINPUTINDEX;
    let out = compile(VAULT_CODE).unwrap();
    let f = out
        .functions
        .iter()
        .find(|f| f.name == "merge" && f.server_variant)
        .unwrap();
    assert!(
        f.asm.iter().any(|s| s == OP_PUSHCURRENTINPUTINDEX),
        "merge must emit OP_PUSHCURRENTINPUTINDEX for this.activeInputIndex"
    );
    assert!(
        f.asm.iter().any(|s| s == "OP_INSPECTINPUTSCRIPTPUBKEY"),
        "merge must inspect the other input's scriptPubKey"
    );
}

#[test]
fn test_vault_settlement_verifies_full_oracle_message() {
    // seekerExit and providerExit must reconstruct sha256(ticker || price || time)
    // via OP_CAT + OP_SHA256 and verify the oracle sig against it.
    let out = compile(VAULT_CODE).unwrap();
    for name in &["seekerExit", "providerExit"] {
        let f = out
            .functions
            .iter()
            .find(|f| &f.name == name && f.server_variant)
            .unwrap();
        let asm = f.asm.join(" ");
        let cat_count = f.asm.iter().filter(|s| s.as_str() == OP_CAT).count();
        assert!(
            cat_count >= 2,
            "{name}: expected >=2 OP_CAT (ticker+price, +time), found {cat_count}"
        );
        assert!(asm.contains(OP_SHA256), "{name}: missing OP_SHA256");
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
    assert!(
        !t.asm.iter().any(|s| s.as_str() == OP_CAT),
        "transfer must not concatenate"
    );
    assert!(!asm.contains(OP_SHA256), "transfer must not hash");
    assert!(t.asm.iter().any(|s| s == OP_CHECKSIG));
}

#[test]
fn test_vault_split_is_pure_keyswap() {
    let out = compile(VAULT_CODE).unwrap();
    let s = out
        .functions
        .iter()
        .find(|f| f.name == "split" && f.server_variant)
        .unwrap();
    let asm = s.asm.join(" ");
    assert!(
        !asm.contains(OP_CHECKSIGFROMSTACK),
        "split must not call oracle"
    );
    assert!(
        !s.asm.iter().any(|op| op.as_str() == OP_CAT),
        "split must not concatenate"
    );
    assert!(!asm.contains(OP_SHA256), "split must not hash");
    assert!(
        s.asm.iter().any(|op| op == OP_CHECKSIG),
        "split must keep user checksig"
    );
}

#[test]
fn test_settle_and_update_funding_does_no_oracle_call() {
    // Funding update is purely time-driven; no oracle witness involved.
    let out = compile(VAULT_CODE).unwrap();
    let f = out
        .functions
        .iter()
        .find(|f| f.name == "settleAndUpdateFunding" && f.server_variant)
        .unwrap();
    let asm = f.asm.join(" ");
    assert!(
        !asm.contains(OP_CHECKSIGFROMSTACK),
        "settleAndUpdateFunding must not call oracle"
    );
    assert!(
        f.asm.iter().any(|s| s == OP_CHECKSIG),
        "settleAndUpdateFunding must verify provider"
    );
}

#[test]
fn test_add_capital_does_no_oracle_call() {
    let out = compile(VAULT_CODE).unwrap();
    let f = out
        .functions
        .iter()
        .find(|f| f.name == "addCapital" && f.server_variant)
        .unwrap();
    let asm = f.asm.join(" ");
    assert!(
        !asm.contains(OP_CHECKSIGFROMSTACK),
        "addCapital must not call oracle"
    );
}

#[test]
fn test_remove_capital_verifies_oracle() {
    let out = compile(VAULT_CODE).unwrap();
    let f = out
        .functions
        .iter()
        .find(|f| f.name == "removeCapital" && f.server_variant)
        .unwrap();
    let asm = f.asm.join(" ");
    assert!(
        asm.contains(OP_CHECKSIGFROMSTACK),
        "removeCapital must verify oracle"
    );
    assert!(
        asm.contains(OP_SHA256),
        "removeCapital must hash oracle msg"
    );
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
    let cat_count = take.asm.iter().filter(|s| s.as_str() == OP_CAT).count();
    assert!(
        cat_count >= 2,
        "take: expected >=2 OP_CAT for ticker+price+time, found {cat_count}"
    );
    assert!(asm.contains(OP_SHA256), "take: missing OP_SHA256");
    assert!(
        asm.contains(OP_CHECKSIGFROMSTACK),
        "take: missing oracle sig verify"
    );
}
