use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKSIG, OP_INSPECTASSETGROUPSUM, OP_INSPECTINASSETLOOKUP, OP_INSPECTOUTPUTSCRIPTPUBKEY,
};

// Loop-unrolling primitive test over tx.assetGroups.
const BEACON_LOOP_CODE: &str = r#"
contract PriceBeacon(
  bytes32 ctrlAssetIdTxid, int ctrlAssetIdGidx,
  pubkey oraclePk,
  int numGroups
) {
  function passthrough() {
    require(tx.outputs[0].scriptPubKey == new PriceBeacon(ctrlAssetIdTxid, ctrlAssetIdGidx, oraclePk, numGroups), "broken");

    for (k, group) in tx.assetGroups {
      require(group.sumOutputs >= group.sumInputs, "drained");
    }
  }

  function update(signature oracleSig) {
    require(tx.inputs[0].assets.lookup(ctrlAssetIdTxid, ctrlAssetIdGidx) > 0, "no ctrl");
    require(tx.outputs[0].scriptPubKey == new PriceBeacon(ctrlAssetIdTxid, ctrlAssetIdGidx, oraclePk, numGroups), "broken");
    require(checkSig(oracleSig, oraclePk), "bad sig");
  }
}
"#;

// Price beacon with separate ticker and clock assets.
const PRICE_BEACON_CODE: &str = r#"
contract PriceBeacon(
  bytes32 tickerTxid, int tickerGidx,
  bytes32 clockTxid, int clockGidx,
  pubkey  oraclePk,
  int     exit
) {
  function update(signature oracleSig, int newPrice, int newBlockHeight) {
    require(checkSig(oracleSig, oraclePk), "invalid oracle signature");
    require(newPrice > 0, "price must be positive");

    int currentHeight = tx.inputs[0].assets.lookup(clockTxid, clockGidx);
    require(newBlockHeight >= currentHeight, "block height must not regress");

    require(
      tx.outputs[0].scriptPubKey == new PriceBeacon(tickerTxid, tickerGidx, clockTxid, clockGidx, oraclePk, exit),
      "beacon script must survive"
    );
    require(
      tx.outputs[0].assets.lookup(tickerTxid, tickerGidx) == newPrice,
      "price not updated correctly"
    );
    require(
      tx.outputs[0].assets.lookup(clockTxid, clockGidx) == newBlockHeight,
      "block height not updated correctly"
    );
  }

  function passthrough() {
    require(
      tx.outputs[0].scriptPubKey == new PriceBeacon(tickerTxid, tickerGidx, clockTxid, clockGidx, oraclePk, exit),
      "beacon script must survive"
    );

    int currentPrice = tx.inputs[0].assets.lookup(tickerTxid, tickerGidx);
    require(
      tx.outputs[0].assets.lookup(tickerTxid, tickerGidx) >= currentPrice,
      "price asset must survive"
    );

    int currentHeight = tx.inputs[0].assets.lookup(clockTxid, clockGidx);
    require(
      tx.outputs[0].assets.lookup(clockTxid, clockGidx) >= currentHeight,
      "clock asset must survive"
    );
  }

  function migrate(signature oracleSig, pubkey newOraclePk) {
    require(checkSig(oracleSig, oraclePk), "invalid oracle signature");

    int currentPrice  = tx.inputs[0].assets.lookup(tickerTxid, tickerGidx);
    int currentHeight = tx.inputs[0].assets.lookup(clockTxid, clockGidx);

    require(
      tx.outputs[0].scriptPubKey == new PriceBeacon(tickerTxid, tickerGidx, clockTxid, clockGidx, newOraclePk, exit),
      "invalid new beacon"
    );
    require(
      tx.outputs[0].assets.lookup(tickerTxid, tickerGidx) == currentPrice,
      "price must be preserved"
    );
    require(
      tx.outputs[0].assets.lookup(clockTxid, clockGidx) == currentHeight,
      "block height must be preserved"
    );
  }
}
"#;

// Loop-unrolling tests.

#[test]
fn test_beacon_parses() {
    let result = compile(BEACON_LOOP_CODE);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

#[test]
fn test_beacon_structure() {
    let output = compile(BEACON_LOOP_CODE).unwrap();

    assert_eq!(output.name, "PriceBeacon");
    assert_eq!(output.functions.len(), 2);

    // Both groups should exist
    assert!(
        crate::common::group(&output, "passthrough")
            .arkade
            .is_some(),
        "Missing passthrough arkade covenant"
    );
    assert!(
        crate::common::group(&output, "update").arkade.is_some(),
        "Missing update arkade covenant"
    );
}

#[test]
fn test_beacon_passthrough_has_loop_unrolling() {
    let output = compile(BEACON_LOOP_CODE).unwrap();

    let asm_tokens = crate::common::arkade_asm_tokens(&output, "passthrough");
    let sum_count = asm_tokens
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

    let update_asm = crate::common::arkade_asm(&output, "update");

    assert!(
        update_asm.contains(OP_INSPECTINASSETLOOKUP),
        "Missing {OP_INSPECTINASSETLOOKUP} in update function"
    );
    assert!(
        update_asm.contains(OP_CHECKSIG),
        "Missing {OP_CHECKSIG} in update function"
    );
}

#[test]
fn test_beacon_update_has_covenant_recursion() {
    let output = compile(BEACON_LOOP_CODE).unwrap();

    let update_asm = crate::common::arkade_asm(&output, "update");

    let has_constructor = update_asm.contains("new PriceBeacon(");
    let has_output_inspect = update_asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY);

    assert!(
        has_constructor || has_output_inspect,
        "Missing constructor placeholder or {OP_INSPECTOUTPUTSCRIPTPUBKEY} in update function. ASM: {}",
        update_asm
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
    // 3 covenant functions → 3 groups
    assert_eq!(output.functions.len(), 3);

    for name in &["update", "passthrough", "migrate"] {
        assert!(
            crate::common::group(&output, name).arkade.is_some(),
            "Missing {name} arkade covenant"
        );
    }
}

#[test]
fn test_price_beacon_update_enforces_timestamp_monotonicity() {
    let output = compile(PRICE_BEACON_CODE).unwrap();

    let update_asm_tokens = crate::common::arkade_asm_tokens(&output, "update");

    // update() reads the current timestamp from input for the monotonicity check.
    let lookup_count = update_asm_tokens
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

    let passthrough_asm_tokens = crate::common::arkade_asm_tokens(&output, "passthrough");

    // passthrough reads both assets from input — expect 2 INSPECTINASSETLOOKUP calls
    let in_lookup_count = passthrough_asm_tokens
        .iter()
        .filter(|s| s.contains(OP_INSPECTINASSETLOOKUP))
        .count();

    assert!(
        in_lookup_count >= 2,
        "Expected at least 2 {OP_INSPECTINASSETLOOKUP} in passthrough (price + timestamp), found {}",
        in_lookup_count
    );

    // and verifies both assets survive on the output
    let out_lookup_count = passthrough_asm_tokens
        .iter()
        .filter(|s| s.contains("OP_INSPECTOUTASSETLOOKUP"))
        .count();

    assert!(
        out_lookup_count >= 2,
        "Expected at least 2 OP_INSPECTOUTASSETLOOKUP in passthrough, found {}",
        out_lookup_count
    );
}
