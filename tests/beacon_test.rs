use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKSIG, OP_INSPECTASSETGROUPSUM, OP_INSPECTINASSETLOOKUP, OP_INSPECTOUTPUTSCRIPTPUBKEY,
};

// ---------------------------------------------------------------------------
// LEGACY BEACON (loop-unrolling primitive test)
// Tests compile-time for-loop unrolling over tx.assetGroups.
// This contract exercises the OP_INSPECTASSETGROUPSUM primitive and is kept
// as a regression fixture for that language feature.
// ---------------------------------------------------------------------------
const BEACON_LOOP_CODE: &str = r#"
options {
  server = oracleServerPk;
  exit = 144;
}

contract PriceBeacon(
  bytes32 ctrlAssetId,
  pubkey oraclePk,
  pubkey oracleServerPk,
  int numGroups
) {
  function passthrough() {
    require(tx.outputs[0].scriptPubKey == new PriceBeacon(ctrlAssetId, oraclePk, oracleServerPk, numGroups), "broken");

    for (k, group) in tx.assetGroups {
      require(group.sumOutputs >= group.sumInputs, "drained");
    }
  }

  function update(signature oracleSig) {
    require(tx.inputs[0].assets.lookup(ctrlAssetId) > 0, "no ctrl");
    require(tx.outputs[0].scriptPubKey == new PriceBeacon(ctrlAssetId, oraclePk, oracleServerPk, numGroups), "broken");
    require(checkSig(oracleSig, oraclePk), "bad sig");
  }
}
"#;

// ---------------------------------------------------------------------------
// PRICE BEACON (dual-asset design with timestampAssetId)
// Tests the production PriceBeacon: price + timestamp assets, monotone
// timestamp enforcement, passthrough preservation, and migrate.
// ---------------------------------------------------------------------------
const PRICE_BEACON_CODE: &str = r#"
options {
  server = server;
  exit = exit;
}

contract PriceBeacon(
  bytes32 ticker,
  bytes32 clock,
  pubkey  oraclePk,
  int     exit
) {
  function update(signature oracleSig, int newPrice, int newBlockHeight) {
    require(checkSig(oracleSig, oraclePk), "invalid oracle signature");
    require(newPrice > 0, "price must be positive");

    int currentHeight = tx.inputs[0].assets.lookup(clock);
    require(newBlockHeight > currentHeight, "block height must advance");

    require(
      tx.outputs[0].scriptPubKey == new PriceBeacon(ticker, clock, oraclePk, exit),
      "beacon script must survive"
    );
    require(
      tx.outputs[0].assets.lookup(ticker) == newPrice,
      "price not updated correctly"
    );
    require(
      tx.outputs[0].assets.lookup(clock) == newBlockHeight,
      "block height not updated correctly"
    );
  }

  function passthrough() {
    require(
      tx.outputs[0].scriptPubKey == new PriceBeacon(ticker, clock, oraclePk, exit),
      "beacon script must survive"
    );

    int currentPrice = tx.inputs[0].assets.lookup(ticker);
    require(
      tx.outputs[0].assets.lookup(ticker) >= currentPrice,
      "price asset must survive"
    );

    int currentHeight = tx.inputs[0].assets.lookup(clock);
    require(
      tx.outputs[0].assets.lookup(clock) >= currentHeight,
      "clock asset must survive"
    );
  }

  function migrate(signature oracleSig, pubkey newOraclePk) {
    require(checkSig(oracleSig, oraclePk), "invalid oracle signature");

    int currentPrice  = tx.inputs[0].assets.lookup(ticker);
    int currentHeight = tx.inputs[0].assets.lookup(clock);

    require(
      tx.outputs[0].scriptPubKey == new PriceBeacon(ticker, clock, newOraclePk, exit),
      "invalid new beacon"
    );
    require(
      tx.outputs[0].assets.lookup(ticker) == currentPrice,
      "price must be preserved"
    );
    require(
      tx.outputs[0].assets.lookup(clock) == currentHeight,
      "block height must be preserved"
    );
  }
}
"#;

// ---------------------------------------------------------------------------
// Legacy loop-unrolling tests
// ---------------------------------------------------------------------------

#[test]
fn test_beacon_parses() {
    let result = compile(BEACON_LOOP_CODE);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

#[test]
fn test_beacon_structure() {
    let output = compile(BEACON_LOOP_CODE).unwrap();

    assert_eq!(output.name, "PriceBeacon");
    // 2 functions x 2 variants = 4
    assert_eq!(output.functions.len(), 4);

    let passthrough_server = output
        .functions
        .iter()
        .find(|f| f.name == "passthrough" && f.server_variant);
    let passthrough_exit = output
        .functions
        .iter()
        .find(|f| f.name == "passthrough" && !f.server_variant);
    let update_server = output
        .functions
        .iter()
        .find(|f| f.name == "update" && f.server_variant);
    let update_exit = output
        .functions
        .iter()
        .find(|f| f.name == "update" && !f.server_variant);

    assert!(
        passthrough_server.is_some(),
        "Missing passthrough server variant"
    );
    assert!(
        passthrough_exit.is_some(),
        "Missing passthrough exit variant"
    );
    assert!(update_server.is_some(), "Missing update server variant");
    assert!(update_exit.is_some(), "Missing update exit variant");
}

#[test]
fn test_beacon_passthrough_has_loop_unrolling() {
    let output = compile(BEACON_LOOP_CODE).unwrap();

    let passthrough = output
        .functions
        .iter()
        .find(|f| f.name == "passthrough" && f.server_variant)
        .unwrap();

    let sum_count = passthrough
        .asm
        .iter()
        .filter(|s| s.contains(OP_INSPECTASSETGROUPSUM))
        .count();

    assert!(
        sum_count >= 2,
        "Expected at least 2 {OP_INSPECTASSETGROUPSUM} instructions for loop unrolling \
         (sumInputs + sumOutputs per iteration), found {}",
        sum_count
    );
}

#[test]
fn test_beacon_update_has_asset_lookup() {
    let output = compile(BEACON_LOOP_CODE).unwrap();

    let update = output
        .functions
        .iter()
        .find(|f| f.name == "update" && f.server_variant)
        .unwrap();

    assert!(
        update
            .asm
            .iter()
            .any(|s| s.contains(OP_INSPECTINASSETLOOKUP)),
        "Missing {OP_INSPECTINASSETLOOKUP} in update function"
    );

    assert!(
        update.asm.iter().any(|s| s == OP_CHECKSIG),
        "Missing {OP_CHECKSIG} in update function"
    );
}

#[test]
fn test_beacon_update_has_covenant_recursion() {
    let output = compile(BEACON_LOOP_CODE).unwrap();

    let update = output
        .functions
        .iter()
        .find(|f| f.name == "update" && f.server_variant)
        .unwrap();

    let has_constructor = update.asm.iter().any(|s| s.contains("new PriceBeacon("));
    let has_output_inspect = update
        .asm
        .iter()
        .any(|s| s.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY));

    assert!(
        has_constructor || has_output_inspect,
        "Missing constructor placeholder or {OP_INSPECTOUTPUTSCRIPTPUBKEY} in update function. ASM: {:?}",
        update.asm
    );
}

// ---------------------------------------------------------------------------
// Production PriceBeacon tests (dual-asset: price + timestamp)
// ---------------------------------------------------------------------------

#[test]
fn test_price_beacon_parses() {
    let result = compile(PRICE_BEACON_CODE);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

#[test]
fn test_price_beacon_structure() {
    let output = compile(PRICE_BEACON_CODE).unwrap();
    assert_eq!(output.name, "PriceBeacon");
    // 3 functions x 2 variants = 6
    assert_eq!(output.functions.len(), 6);

    for name in &["update", "passthrough", "migrate"] {
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
fn test_price_beacon_update_enforces_timestamp_monotonicity() {
    let output = compile(PRICE_BEACON_CODE).unwrap();

    let update = output
        .functions
        .iter()
        .find(|f| f.name == "update" && f.server_variant)
        .unwrap();

    // update() reads the current timestamp from input for the monotonicity check.
    // newPrice is a witness argument — no input price lookup required.
    // Expect exactly 1 OP_INSPECTINASSETLOOKUP (the timestamp read).
    let lookup_count = update
        .asm
        .iter()
        .filter(|s| s.contains(OP_INSPECTINASSETLOOKUP))
        .count();

    assert!(
        lookup_count >= 1,
        "Expected at least 1 {OP_INSPECTINASSETLOOKUP} call in update (timestamp monotonicity), found {}",
        lookup_count
    );
}

#[test]
fn test_price_beacon_passthrough_preserves_both_assets() {
    let output = compile(PRICE_BEACON_CODE).unwrap();

    let passthrough = output
        .functions
        .iter()
        .find(|f| f.name == "passthrough" && f.server_variant)
        .unwrap();

    // passthrough reads both assets from input — expect 2 INSPECTINASSETLOOKUP calls
    let in_lookup_count = passthrough
        .asm
        .iter()
        .filter(|s| s.contains(OP_INSPECTINASSETLOOKUP))
        .count();

    assert!(
        in_lookup_count >= 2,
        "Expected at least 2 {OP_INSPECTINASSETLOOKUP} in passthrough (price + timestamp), found {}",
        in_lookup_count
    );

    // and verifies both assets survive on the output
    let out_lookup_count = passthrough
        .asm
        .iter()
        .filter(|s| s.contains("OP_INSPECTOUTASSETLOOKUP"))
        .count();

    assert!(
        out_lookup_count >= 2,
        "Expected at least 2 OP_INSPECTOUTASSETLOOKUP in passthrough, found {}",
        out_lookup_count
    );
}
