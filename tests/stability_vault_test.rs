use arkade_compiler::compile;
use arkade_compiler::opcodes::{OP_CHECKSIG, OP_CHECKSIGFROMSTACK};

// ---------------------------------------------------------------------------
// StabilityVault — oracle-signed-price model
// oraclePk is a constructor param; price arrives as a witness arg signed by
// oraclePk. No on-chain beacon UTXO.
// ---------------------------------------------------------------------------
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
        newSeekerPk, providerPk, oraclePk,
        targetUSD, totalCollateral, fundingSatPerBlock, openHeight, exit
      ),
      "invalid transfer output"
    );
    require(tx.outputs[0].value >= totalCollateral, "collateral not preserved");
  }

  function split(signature seekerSig, int amountUSD, pubkey newSeekerPk) {
    require(checkSig(seekerSig, seekerPk), "invalid seeker sig");
    require(amountUSD > 0, "zero amount");
    require(amountUSD < targetUSD, "amount exceeds balance");

    int remainingUSD = targetUSD - amountUSD;
    int collateralA  = totalCollateral * amountUSD / targetUSD;
    int collateralB  = totalCollateral - collateralA;

    require(collateralA >= 330, "split amount too small");
    require(collateralB >= 330, "remainder too small");

    require(
      tx.outputs[0].scriptPubKey == new StabilityVault(
        newSeekerPk, providerPk, oraclePk,
        amountUSD, collateralA, fundingSatPerBlock, openHeight, exit
      ),
      "invalid split output 0"
    );
    require(tx.outputs[0].value >= collateralA, "insufficient collateral A");

    require(
      tx.outputs[1].scriptPubKey == new StabilityVault(
        seekerPk, providerPk, oraclePk,
        remainingUSD, collateralB, fundingSatPerBlock, openHeight, exit
      ),
      "invalid split output 1"
    );
    require(tx.outputs[1].value >= collateralB, "insufficient collateral B");
  }

  function seekerRedeem(signature seekerSig, int oraclePrice, signature oracleSig) {
    require(checkSig(seekerSig, seekerPk), "invalid seeker sig");
    require(oraclePrice > 0, "invalid oracle price");
    require(checkSigFromStack(oracleSig, oraclePk, oraclePrice), "invalid oracle signature");

    int blocksElapsed = tx.time - openHeight;
    int seekerBase    = targetUSD * 100000000 / oraclePrice;
    int funding       = fundingSatPerBlock * blocksElapsed;
    int seekerRaw     = seekerBase + funding;

    if (seekerRaw <= 0) {
      require(tx.outputs[0].value >= totalCollateral, "provider underpaid");
      require(tx.outputs[0].scriptPubKey == new SingleSig(providerPk), "output 0 not provider");
    } else {
      if (seekerRaw >= totalCollateral) {
        require(tx.outputs[0].value >= totalCollateral, "seeker underpaid");
        require(tx.outputs[0].scriptPubKey == new SingleSig(seekerPk), "output 0 not seeker");
      } else {
        require(tx.outputs[0].value >= seekerRaw, "seeker underpaid");
        require(tx.outputs[0].scriptPubKey == new SingleSig(seekerPk), "output 0 not seeker");
        int providerPayout = totalCollateral - seekerRaw;
        if (providerPayout > 330) {
          require(tx.outputs[1].value >= providerPayout, "provider underpaid");
          require(tx.outputs[1].scriptPubKey == new SingleSig(providerPk), "output 1 not provider");
        }
      }
    }
  }

  function providerExit(signature providerSig, int oraclePrice, signature oracleSig) {
    require(checkSig(providerSig, providerPk), "invalid provider sig");
    require(oraclePrice > 0, "invalid oracle price");
    require(checkSigFromStack(oracleSig, oraclePk, oraclePrice), "invalid oracle signature");

    int blocksElapsed = tx.time - openHeight;
    int seekerBase    = targetUSD * 100000000 / oraclePrice;
    int funding       = fundingSatPerBlock * blocksElapsed;
    int seekerRaw     = seekerBase + funding;

    if (seekerRaw <= 0) {
      require(tx.outputs[0].value >= totalCollateral, "provider underpaid");
      require(tx.outputs[0].scriptPubKey == new SingleSig(providerPk), "output 0 not provider");
    } else {
      if (seekerRaw >= totalCollateral) {
        require(tx.outputs[0].value >= totalCollateral, "seeker underpaid");
        require(tx.outputs[0].scriptPubKey == new SingleSig(seekerPk), "output 0 not seeker");
      } else {
        require(tx.outputs[0].value >= seekerRaw, "seeker underpaid");
        require(tx.outputs[0].scriptPubKey == new SingleSig(seekerPk), "output 0 not seeker");
        int providerPayout = totalCollateral - seekerRaw;
        if (providerPayout > 330) {
          require(tx.outputs[1].value >= providerPayout, "provider underpaid");
          require(tx.outputs[1].scriptPubKey == new SingleSig(providerPk), "output 1 not provider");
        }
      }
    }
  }
}
"#;

// ---------------------------------------------------------------------------
// StabilityOffer
// ---------------------------------------------------------------------------
const OFFER_CODE: &str = r#"
import "stability_vault.ark";

options {
  server = server;
  exit = exit;
}

contract StabilityOffer(
  pubkey  providerPk,
  pubkey  oraclePk,
  int     fundingSatPerBlock,
  int     maxExposureBTC,
  int     collateralRatioPct,
  int     exit
) {
  function take(int userBTC, pubkey seekerPk, int oraclePrice, signature oracleSig) {
    require(userBTC > 0, "zero deposit");
    require(userBTC <= maxExposureBTC, "exceeds offer capacity");
    require(collateralRatioPct >= 100, "collateral ratio below minimum");
    require(oraclePrice > 0, "invalid oracle price");
    require(checkSigFromStack(oracleSig, oraclePk, oraclePrice), "invalid oracle signature");

    int targetUSD      = userBTC * oraclePrice / 100000000;
    require(targetUSD > 0, "position too small");

    int totalCollateral = userBTC * (100 + collateralRatioPct) / 100;

    require(
      tx.outputs[0].scriptPubKey == new StabilityVault(
        seekerPk, providerPk, oraclePk,
        targetUSD, totalCollateral, fundingSatPerBlock, tx.time, exit
      ),
      "invalid vault output"
    );
    require(tx.outputs[0].value >= totalCollateral, "insufficient vault collateral");

    int remainingCapacity = maxExposureBTC - userBTC;
    if (remainingCapacity > 0) {
      require(
        tx.outputs[1].scriptPubKey == new StabilityOffer(
          providerPk, oraclePk,
          fundingSatPerBlock, remainingCapacity, collateralRatioPct, exit
        ),
        "invalid remaining offer"
      );
      int remainingCollateral = remainingCapacity * collateralRatioPct / 100;
      require(tx.outputs[1].value >= remainingCollateral, "insufficient offer collateral");
    }
  }

  function withdraw(signature providerSig) {
    require(checkSig(providerSig, providerPk), "invalid provider sig");
  }
}
"#;

// ---------------------------------------------------------------------------
// StabilityVault tests
// ---------------------------------------------------------------------------

#[test]
fn test_vault_parses() {
    let result = compile(VAULT_CODE);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

#[test]
fn test_vault_structure() {
    let output = compile(VAULT_CODE).unwrap();
    assert_eq!(output.name, "StabilityVault");
    // 4 functions × 2 variants = 8 tapleaves
    assert_eq!(output.functions.len(), 8);

    for name in &["transfer", "split", "seekerRedeem", "providerExit"] {
        assert!(
            output
                .functions
                .iter()
                .any(|f| &f.name == name && f.server_variant),
            "Missing {name} server variant"
        );
        assert!(
            output
                .functions
                .iter()
                .any(|f| &f.name == name && !f.server_variant),
            "Missing {name} exit variant"
        );
    }
}

#[test]
fn test_vault_transfer_has_no_oracle_call() {
    let output = compile(VAULT_CODE).unwrap();
    let transfer = output
        .functions
        .iter()
        .find(|f| f.name == "transfer" && f.server_variant)
        .unwrap();

    // transfer is a pure key-swap: no oracle price verification.
    assert!(
        !transfer
            .asm
            .iter()
            .any(|s| s.contains(OP_CHECKSIGFROMSTACK)),
        "transfer should not call {OP_CHECKSIGFROMSTACK}"
    );
    assert!(
        transfer.asm.iter().any(|s| s == OP_CHECKSIG),
        "transfer must have {OP_CHECKSIG} for seeker sig"
    );
}

#[test]
fn test_vault_seeker_redeem_verifies_oracle_sig() {
    let output = compile(VAULT_CODE).unwrap();
    let redeem = output
        .functions
        .iter()
        .find(|f| f.name == "seekerRedeem" && f.server_variant)
        .unwrap();

    assert!(
        redeem.asm.iter().any(|s| s.contains(OP_CHECKSIGFROMSTACK)),
        "seekerRedeem must verify oracle sig with {OP_CHECKSIGFROMSTACK}"
    );
    assert!(
        redeem.asm.iter().any(|s| s == OP_CHECKSIG),
        "seekerRedeem must have {OP_CHECKSIG} for seeker sig"
    );
}

#[test]
fn test_vault_provider_exit_verifies_oracle_sig() {
    let output = compile(VAULT_CODE).unwrap();
    let exit = output
        .functions
        .iter()
        .find(|f| f.name == "providerExit" && f.server_variant)
        .unwrap();

    assert!(
        exit.asm.iter().any(|s| s.contains(OP_CHECKSIGFROMSTACK)),
        "providerExit must verify oracle sig with {OP_CHECKSIGFROMSTACK}"
    );
    assert!(
        exit.asm.iter().any(|s| s == OP_CHECKSIG),
        "providerExit must have {OP_CHECKSIG} for provider sig"
    );
}

#[test]
fn test_vault_settlement_has_covenant_recursion() {
    let output = compile(VAULT_CODE).unwrap();

    // seekerRedeem and providerExit both produce SingleSig outputs (no recursion)
    // transfer and split produce recursive StabilityVault outputs
    let transfer = output
        .functions
        .iter()
        .find(|f| f.name == "transfer" && f.server_variant)
        .unwrap();

    let has_recursive = transfer
        .asm
        .iter()
        .any(|s| s.contains("new StabilityVault("));
    let has_output_inspect = transfer
        .asm
        .iter()
        .any(|s| s.contains("OP_INSPECTOUTPUTSCRIPTPUBKEY"));

    assert!(
        has_recursive || has_output_inspect,
        "transfer must emit recursive StabilityVault constructor or output inspect. ASM: {:?}",
        transfer.asm
    );
}

// ---------------------------------------------------------------------------
// StabilityOffer tests
// ---------------------------------------------------------------------------

#[test]
fn test_offer_parses() {
    let result = compile(OFFER_CODE);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

#[test]
fn test_offer_structure() {
    let output = compile(OFFER_CODE).unwrap();
    assert_eq!(output.name, "StabilityOffer");
    // 2 functions × 2 variants = 4
    assert_eq!(output.functions.len(), 4);

    for name in &["take", "withdraw"] {
        assert!(
            output
                .functions
                .iter()
                .any(|f| &f.name == name && f.server_variant),
            "Missing {name} server variant"
        );
        assert!(
            output
                .functions
                .iter()
                .any(|f| &f.name == name && !f.server_variant),
            "Missing {name} exit variant"
        );
    }
}

#[test]
fn test_offer_take_verifies_oracle_sig() {
    let output = compile(OFFER_CODE).unwrap();
    let take = output
        .functions
        .iter()
        .find(|f| f.name == "take" && f.server_variant)
        .unwrap();

    assert!(
        take.asm.iter().any(|s| s.contains(OP_CHECKSIGFROMSTACK)),
        "take must verify oracle sig with {OP_CHECKSIGFROMSTACK}"
    );
}

#[test]
fn test_offer_take_creates_vault() {
    let output = compile(OFFER_CODE).unwrap();
    let take = output
        .functions
        .iter()
        .find(|f| f.name == "take" && f.server_variant)
        .unwrap();

    let has_vault_constructor = take.asm.iter().any(|s| s.contains("new StabilityVault("));
    let has_output_inspect = take
        .asm
        .iter()
        .any(|s| s.contains("OP_INSPECTOUTPUTSCRIPTPUBKEY"));

    assert!(
        has_vault_constructor || has_output_inspect,
        "take must emit StabilityVault constructor or output inspect. ASM: {:?}",
        take.asm
    );
}

#[test]
fn test_offer_withdraw_has_only_checksig() {
    let output = compile(OFFER_CODE).unwrap();
    let withdraw = output
        .functions
        .iter()
        .find(|f| f.name == "withdraw" && f.server_variant)
        .unwrap();

    assert!(
        withdraw.asm.iter().any(|s| s == OP_CHECKSIG),
        "withdraw must have {OP_CHECKSIG}"
    );
    assert!(
        !withdraw
            .asm
            .iter()
            .any(|s| s.contains(OP_CHECKSIGFROMSTACK)),
        "withdraw must not call {OP_CHECKSIGFROMSTACK}"
    );
}
