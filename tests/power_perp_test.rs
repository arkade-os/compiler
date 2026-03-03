use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKLOCKTIMEVERIFY, OP_CHECKSIG, OP_INSPECTINASSETLOOKUP, OP_INSPECTOUTPUTSCRIPTPUBKEY,
};

// Power Perpetual Long Position
// Tracks index_price²; long profits when price rises.
const POWER_PERP_LONG_CODE: &str = r#"
options {
  server = operatorPk;
  exit = 2016;
}

contract PowerPerpLong(
  pubkey traderPk,
  pubkey operatorPk,
  bytes32 priceAssetId,
  int notionalSats,
  int precision,
  int fundingInterval,
  int lastSettledBlock,
  int lastPrice,
  int maintenanceBips
) {
  function settleFunding() {
    int fundingDeadline = lastSettledBlock + fundingInterval;
    require(tx.time >= fundingDeadline, "funding period not elapsed");
    int currentPrice = tx.inputs[1].assets.lookup(priceAssetId);
    require(currentPrice > 0, "invalid beacon price");
    int lastPow2 = lastPrice * lastPrice;
    int currentPow2 = currentPrice * currentPrice;
    int deltaPow2 = currentPow2 - lastPow2;
    int fundingDelta = notionalSats * deltaPow2 / precision;
    int collateralIn = tx.input.current.value;
    int collateralOut = collateralIn + fundingDelta;
    require(collateralOut > 0, "position insolvent");
    int minCollateral = notionalSats * currentPow2 / precision * maintenanceBips / 10000;
    require(collateralOut > minCollateral, "below maintenance margin");
    require(
      tx.outputs[0].scriptPubKey == new PowerPerpLong(
        traderPk, operatorPk, priceAssetId,
        notionalSats, precision, fundingInterval,
        tx.time, currentPrice, maintenanceBips
      ),
      "invalid position output"
    );
    require(tx.outputs[0].value >= collateralOut, "collateral not preserved");
    require(
      tx.outputs[1].assets.lookup(priceAssetId) >= currentPrice,
      "beacon must survive"
    );
  }

  function close(signature traderSig) {
    require(checkSig(traderSig, traderPk), "invalid trader signature");
  }

  function liquidate(signature liquidatorSig, pubkey liquidatorPk) {
    require(checkSig(liquidatorSig, liquidatorPk), "invalid liquidator signature");
    int currentPrice = tx.inputs[1].assets.lookup(priceAssetId);
    require(currentPrice > 0, "invalid beacon price");
    int lastPow2 = lastPrice * lastPrice;
    int currentPow2 = currentPrice * currentPrice;
    int deltaPow2 = currentPow2 - lastPow2;
    int pendingFunding = notionalSats * deltaPow2 / precision;
    int collateralIn = tx.input.current.value;
    int projectedCollateral = collateralIn + pendingFunding;
    int minCollateral = notionalSats * currentPow2 / precision * maintenanceBips / 10000;
    require(projectedCollateral <= minCollateral, "position still solvent");
    require(
      tx.outputs[0].scriptPubKey == new SingleSig(liquidatorPk),
      "output must go to liquidator"
    );
    require(
      tx.outputs[1].assets.lookup(priceAssetId) >= currentPrice,
      "beacon must survive"
    );
  }

  function addCollateral(signature traderSig) {
    require(checkSig(traderSig, traderPk), "invalid trader signature");
    require(
      tx.outputs[0].scriptPubKey == new PowerPerpLong(
        traderPk, operatorPk, priceAssetId,
        notionalSats, precision, fundingInterval,
        lastSettledBlock, lastPrice, maintenanceBips
      ),
      "invalid position output"
    );
    require(tx.outputs[0].value >= tx.input.current.value, "collateral must not decrease");
  }
}
"#;

// Power Perpetual Short Position
// Mirror of long; short profits when price² falls (reversed delta).
const POWER_PERP_SHORT_CODE: &str = r#"
options {
  server = operatorPk;
  exit = 2016;
}

contract PowerPerpShort(
  pubkey traderPk,
  pubkey operatorPk,
  bytes32 priceAssetId,
  int notionalSats,
  int precision,
  int fundingInterval,
  int lastSettledBlock,
  int lastPrice,
  int maintenanceBips
) {
  function settleFunding() {
    int fundingDeadline = lastSettledBlock + fundingInterval;
    require(tx.time >= fundingDeadline, "funding period not elapsed");
    int currentPrice = tx.inputs[1].assets.lookup(priceAssetId);
    require(currentPrice > 0, "invalid beacon price");
    int lastPow2 = lastPrice * lastPrice;
    int currentPow2 = currentPrice * currentPrice;
    int deltaPow2 = lastPow2 - currentPow2;
    int fundingDelta = notionalSats * deltaPow2 / precision;
    int collateralIn = tx.input.current.value;
    int collateralOut = collateralIn + fundingDelta;
    require(collateralOut > 0, "position insolvent");
    int minCollateral = notionalSats * currentPow2 / precision * maintenanceBips / 10000;
    require(collateralOut > minCollateral, "below maintenance margin");
    require(
      tx.outputs[0].scriptPubKey == new PowerPerpShort(
        traderPk, operatorPk, priceAssetId,
        notionalSats, precision, fundingInterval,
        tx.time, currentPrice, maintenanceBips
      ),
      "invalid position output"
    );
    require(tx.outputs[0].value >= collateralOut, "collateral not preserved");
    require(
      tx.outputs[1].assets.lookup(priceAssetId) >= currentPrice,
      "beacon must survive"
    );
  }

  function close(signature traderSig) {
    require(checkSig(traderSig, traderPk), "invalid trader signature");
  }

  function liquidate(signature liquidatorSig, pubkey liquidatorPk) {
    require(checkSig(liquidatorSig, liquidatorPk), "invalid liquidator signature");
    int currentPrice = tx.inputs[1].assets.lookup(priceAssetId);
    require(currentPrice > 0, "invalid beacon price");
    int lastPow2 = lastPrice * lastPrice;
    int currentPow2 = currentPrice * currentPrice;
    int deltaPow2 = lastPow2 - currentPow2;
    int pendingFunding = notionalSats * deltaPow2 / precision;
    int collateralIn = tx.input.current.value;
    int projectedCollateral = collateralIn + pendingFunding;
    int minCollateral = notionalSats * currentPow2 / precision * maintenanceBips / 10000;
    require(projectedCollateral <= minCollateral, "position still solvent");
    require(
      tx.outputs[0].scriptPubKey == new SingleSig(liquidatorPk),
      "output must go to liquidator"
    );
    require(
      tx.outputs[1].assets.lookup(priceAssetId) >= currentPrice,
      "beacon must survive"
    );
  }

  function addCollateral(signature traderSig) {
    require(checkSig(traderSig, traderPk), "invalid trader signature");
    require(
      tx.outputs[0].scriptPubKey == new PowerPerpShort(
        traderPk, operatorPk, priceAssetId,
        notionalSats, precision, fundingInterval,
        lastSettledBlock, lastPrice, maintenanceBips
      ),
      "invalid position output"
    );
    require(tx.outputs[0].value >= tx.input.current.value, "collateral must not decrease");
  }
}
"#;

// Power Perpetual Offer
// Standing offer for a maker to underwrite matched long/short positions.
const POWER_PERP_OFFER_CODE: &str = r#"
options {
  server = operatorPk;
  exit = 144;
}

contract PowerPerpOffer(
  pubkey makerPk,
  pubkey operatorPk,
  bytes32 priceAssetId,
  int notionalSats,
  int precision,
  int fundingInterval,
  int maintenanceBips,
  int maxPositions
) {
  function openLong(pubkey takerPk, int longCollateral, int shortCollateral) {
    require(longCollateral > 0, "zero long collateral");
    require(shortCollateral > 0, "zero short collateral");
    require(maxPositions > 0, "offer fully consumed");
    int entryPrice = tx.inputs[1].assets.lookup(priceAssetId);
    require(entryPrice > 0, "invalid entry price");
    int entryPow2 = entryPrice * entryPrice;
    int minCollateral = notionalSats * entryPow2 / precision * maintenanceBips / 10000 * 2;
    require(longCollateral >= minCollateral, "long undercollateralized");
    require(shortCollateral >= minCollateral, "short undercollateralized");
    require(
      tx.outputs[0].scriptPubKey == new PowerPerpLong(
        takerPk, operatorPk, priceAssetId,
        notionalSats, precision, fundingInterval,
        tx.time, entryPrice, maintenanceBips
      ),
      "invalid long position output"
    );
    require(tx.outputs[0].value >= longCollateral, "long collateral short");
    require(
      tx.outputs[1].scriptPubKey == new PowerPerpShort(
        makerPk, operatorPk, priceAssetId,
        notionalSats, precision, fundingInterval,
        tx.time, entryPrice, maintenanceBips
      ),
      "invalid short position output"
    );
    require(tx.outputs[1].value >= shortCollateral, "short collateral short");
    int remainingPositions = maxPositions - 1;
    if (remainingPositions > 0) {
      require(
        tx.outputs[2].scriptPubKey == new PowerPerpOffer(
          makerPk, operatorPk, priceAssetId,
          notionalSats, precision, fundingInterval,
          maintenanceBips, remainingPositions
        ),
        "invalid remaining offer"
      );
    }
    require(
      tx.outputs[3].assets.lookup(priceAssetId) >= entryPrice,
      "beacon must survive"
    );
  }

  function cancel(signature makerSig) {
    require(checkSig(makerSig, makerPk), "invalid maker signature");
  }

  function reprice(signature makerSig, int newNotional, int newMaintenanceBips) {
    require(checkSig(makerSig, makerPk), "invalid maker signature");
    require(newNotional > 0, "invalid notional");
    require(newMaintenanceBips > 0, "invalid maintenance bips");
    require(
      tx.outputs[0].scriptPubKey == new PowerPerpOffer(
        makerPk, operatorPk, priceAssetId,
        newNotional, precision, fundingInterval,
        newMaintenanceBips, maxPositions
      ),
      "invalid repriced offer"
    );
  }
}
"#;

// ── Compilation smoke tests ───────────────────────────────────────────────────

#[test]
fn test_power_perp_long_compiles() {
    let result = compile(POWER_PERP_LONG_CODE);
    assert!(
        result.is_ok(),
        "PowerPerpLong compilation failed: {:?}",
        result.err()
    );
}

#[test]
fn test_power_perp_short_compiles() {
    let result = compile(POWER_PERP_SHORT_CODE);
    assert!(
        result.is_ok(),
        "PowerPerpShort compilation failed: {:?}",
        result.err()
    );
}

#[test]
fn test_power_perp_offer_compiles() {
    let result = compile(POWER_PERP_OFFER_CODE);
    assert!(
        result.is_ok(),
        "PowerPerpOffer compilation failed: {:?}",
        result.err()
    );
}

// ── Structure tests ───────────────────────────────────────────────────────────

#[test]
fn test_power_perp_long_structure() {
    let output = compile(POWER_PERP_LONG_CODE).unwrap();
    assert_eq!(output.name, "PowerPerpLong");
    // 9 constructor params (compiler may include pubkey function params in ABI)
    assert!(
        output.parameters.len() >= 9,
        "Expected at least 9 params, got {}",
        output.parameters.len()
    );
    // 4 functions × 2 variants (server + exit) = 8
    assert_eq!(output.functions.len(), 8);

    for name in &["settleFunding", "close", "liquidate", "addCollateral"] {
        assert!(
            output
                .functions
                .iter()
                .any(|f| &f.name == name && f.server_variant),
            "Missing server variant for {}",
            name
        );
        assert!(
            output
                .functions
                .iter()
                .any(|f| &f.name == name && !f.server_variant),
            "Missing exit variant for {}",
            name
        );
    }
}

#[test]
fn test_power_perp_short_structure() {
    let output = compile(POWER_PERP_SHORT_CODE).unwrap();
    assert_eq!(output.name, "PowerPerpShort");
    assert!(
        output.parameters.len() >= 9,
        "Expected at least 9 params, got {}",
        output.parameters.len()
    );
    assert_eq!(output.functions.len(), 8);
}

#[test]
fn test_power_perp_offer_structure() {
    let output = compile(POWER_PERP_OFFER_CODE).unwrap();
    assert_eq!(output.name, "PowerPerpOffer");
    // 8 constructor params (compiler may include additional ABI entries)
    assert!(
        output.parameters.len() >= 8,
        "Expected at least 8 params, got {}",
        output.parameters.len()
    );
    // 3 functions × 2 variants = 6
    assert_eq!(output.functions.len(), 6);
}

// ── ASM correctness: long settleFunding ──────────────────────────────────────

#[test]
fn test_power_perp_long_settle_enforces_timelock() {
    let output = compile(POWER_PERP_LONG_CODE).unwrap();
    let settle = output
        .functions
        .iter()
        .find(|f| f.name == "settleFunding" && f.server_variant)
        .unwrap();
    assert!(
        settle
            .asm
            .iter()
            .any(|s| s.contains(OP_CHECKLOCKTIMEVERIFY)),
        "settleFunding must enforce funding period via CLTV. ASM: {:?}",
        settle.asm
    );
}

#[test]
fn test_power_perp_long_settle_reads_beacon() {
    let output = compile(POWER_PERP_LONG_CODE).unwrap();
    let settle = output
        .functions
        .iter()
        .find(|f| f.name == "settleFunding" && f.server_variant)
        .unwrap();
    assert!(
        settle
            .asm
            .iter()
            .any(|s| s.contains(OP_INSPECTINASSETLOOKUP)),
        "settleFunding must read price from beacon. ASM: {:?}",
        settle.asm
    );
}

#[test]
fn test_power_perp_long_settle_has_covenant_recursion() {
    let output = compile(POWER_PERP_LONG_CODE).unwrap();
    let settle = output
        .functions
        .iter()
        .find(|f| f.name == "settleFunding" && f.server_variant)
        .unwrap();
    let has_constructor = settle.asm.iter().any(|s| s.contains("new PowerPerpLong("));
    let has_output_inspect = settle
        .asm
        .iter()
        .any(|s| s.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY));
    assert!(
        has_constructor || has_output_inspect,
        "settleFunding must carry position forward via recursive covenant. ASM: {:?}",
        settle.asm
    );
}

// ── ASM correctness: long close / liquidate ───────────────────────────────────

#[test]
fn test_power_perp_long_close_requires_trader_sig() {
    let output = compile(POWER_PERP_LONG_CODE).unwrap();
    let close = output
        .functions
        .iter()
        .find(|f| f.name == "close" && f.server_variant)
        .unwrap();
    assert!(
        close.asm.iter().any(|s| s == OP_CHECKSIG),
        "close must require trader signature. ASM: {:?}",
        close.asm
    );
}

#[test]
fn test_power_perp_long_liquidate_reads_beacon() {
    let output = compile(POWER_PERP_LONG_CODE).unwrap();
    let liquidate = output
        .functions
        .iter()
        .find(|f| f.name == "liquidate" && f.server_variant)
        .unwrap();
    assert!(
        liquidate
            .asm
            .iter()
            .any(|s| s.contains(OP_INSPECTINASSETLOOKUP)),
        "liquidate must read current price from beacon. ASM: {:?}",
        liquidate.asm
    );
}

// ── ASM correctness: short settleFunding (reversed delta) ────────────────────

#[test]
fn test_power_perp_short_settle_enforces_timelock() {
    let output = compile(POWER_PERP_SHORT_CODE).unwrap();
    let settle = output
        .functions
        .iter()
        .find(|f| f.name == "settleFunding" && f.server_variant)
        .unwrap();
    assert!(
        settle
            .asm
            .iter()
            .any(|s| s.contains(OP_CHECKLOCKTIMEVERIFY)),
        "short settleFunding must enforce funding period. ASM: {:?}",
        settle.asm
    );
}

#[test]
fn test_power_perp_short_settle_reads_beacon() {
    let output = compile(POWER_PERP_SHORT_CODE).unwrap();
    let settle = output
        .functions
        .iter()
        .find(|f| f.name == "settleFunding" && f.server_variant)
        .unwrap();
    assert!(
        settle
            .asm
            .iter()
            .any(|s| s.contains(OP_INSPECTINASSETLOOKUP)),
        "short settleFunding must read beacon price. ASM: {:?}",
        settle.asm
    );
}

#[test]
fn test_power_perp_short_settle_has_covenant_recursion() {
    let output = compile(POWER_PERP_SHORT_CODE).unwrap();
    let settle = output
        .functions
        .iter()
        .find(|f| f.name == "settleFunding" && f.server_variant)
        .unwrap();
    let has_constructor = settle.asm.iter().any(|s| s.contains("new PowerPerpShort("));
    let has_output_inspect = settle
        .asm
        .iter()
        .any(|s| s.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY));
    assert!(
        has_constructor || has_output_inspect,
        "short settleFunding must carry position forward. ASM: {:?}",
        settle.asm
    );
}

// ── ASM correctness: offer openLong ──────────────────────────────────────────

#[test]
fn test_power_perp_offer_open_creates_both_positions() {
    let output = compile(POWER_PERP_OFFER_CODE).unwrap();
    let open = output
        .functions
        .iter()
        .find(|f| f.name == "openLong" && f.server_variant)
        .unwrap();
    let has_long = open.asm.iter().any(|s| s.contains("new PowerPerpLong("));
    let has_short = open.asm.iter().any(|s| s.contains("new PowerPerpShort("));
    let has_output_inspect = open
        .asm
        .iter()
        .any(|s| s.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY));
    assert!(
        (has_long && has_short) || has_output_inspect,
        "openLong must create both PowerPerpLong and PowerPerpShort. ASM: {:?}",
        open.asm
    );
}

#[test]
fn test_power_perp_offer_open_reads_beacon_price() {
    let output = compile(POWER_PERP_OFFER_CODE).unwrap();
    let open = output
        .functions
        .iter()
        .find(|f| f.name == "openLong" && f.server_variant)
        .unwrap();
    assert!(
        open.asm.iter().any(|s| s.contains(OP_INSPECTINASSETLOOKUP)),
        "openLong must read entry price from PriceBeacon. ASM: {:?}",
        open.asm
    );
}

#[test]
fn test_power_perp_offer_cancel_requires_maker_sig() {
    let output = compile(POWER_PERP_OFFER_CODE).unwrap();
    let cancel = output
        .functions
        .iter()
        .find(|f| f.name == "cancel" && f.server_variant)
        .unwrap();
    assert!(
        cancel.asm.iter().any(|s| s == OP_CHECKSIG),
        "cancel must require maker signature. ASM: {:?}",
        cancel.asm
    );
}
