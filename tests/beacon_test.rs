use arkade_compiler::compile;

/// Test contract from PLAN.md Commit 5: For Loops (Compile-Time Unrolled)
///
/// This test validates:
/// - `for (k, group) in tx.assetGroups` parsing
/// - Compile-time loop unrolling based on numGroups constructor param
/// - Each unrolled iteration uses OP_INSPECTASSETGROUPSUM
const BEACON_CODE: &str = r#"
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

#[test]
fn test_beacon_parses() {
    let result = compile(BEACON_CODE);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

#[test]
fn test_beacon_structure() {
    let output = compile(BEACON_CODE).unwrap();

    assert_eq!(output.name, "PriceBeacon");
    // 2 functions x 2 variants = 4
    assert_eq!(output.functions.len(), 4);

    // Verify we have both functions with both variants
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
    let output = compile(BEACON_CODE).unwrap();

    let passthrough = output
        .functions
        .iter()
        .find(|f| f.name == "passthrough" && f.server_variant)
        .unwrap();

    // For loop should be unrolled - check for OP_INSPECTASSETGROUPSUM
    // Each iteration does: group.sumOutputs and group.sumInputs
    // With numGroups constructor param, the compiler unrolls the loop
    let sum_count = passthrough
        .asm
        .iter()
        .filter(|s| s.contains("OP_INSPECTASSETGROUPSUM"))
        .count();

    // For the passthrough function, the for loop should be unrolled with
    // OP_INSPECTASSETGROUPSUM calls (2 per iteration: sumInputs + sumOutputs).
    // At minimum, we expect 2 calls for a single iteration.
    assert!(
        sum_count >= 2,
        "Expected at least 2 OP_INSPECTASSETGROUPSUM instructions for loop unrolling \
         (sumInputs + sumOutputs per iteration), found {}",
        sum_count
    );
}

#[test]
fn test_beacon_update_has_asset_lookup() {
    let output = compile(BEACON_CODE).unwrap();

    let update = output
        .functions
        .iter()
        .find(|f| f.name == "update" && f.server_variant)
        .unwrap();

    // Should have asset lookup for control asset check
    assert!(
        update
            .asm
            .iter()
            .any(|s| s.contains("OP_INSPECTINASSETLOOKUP")),
        "Missing OP_INSPECTINASSETLOOKUP in update function"
    );

    // Should have signature check
    assert!(
        update.asm.iter().any(|s| s == "OP_CHECKSIG"),
        "Missing OP_CHECKSIG in update function"
    );
}

#[test]
fn test_beacon_update_has_covenant_recursion() {
    let output = compile(BEACON_CODE).unwrap();

    let update = output
        .functions
        .iter()
        .find(|f| f.name == "update" && f.server_variant)
        .unwrap();

    // Should have constructor placeholder for covenant recursion
    // The constructor syntax `new PriceBeacon(...)` emits as a placeholder
    let has_constructor = update.asm.iter().any(|s| s.contains("new PriceBeacon("));

    // Should also have output scriptPubKey inspection for the comparison
    let has_output_inspect = update
        .asm
        .iter()
        .any(|s| s.contains("OP_INSPECTOUTPUTSCRIPTPUBKEY"));

    assert!(
        has_constructor || has_output_inspect,
        "Missing constructor placeholder or OP_INSPECTOUTPUTSCRIPTPUBKEY in update function for covenant recursion. ASM: {:?}",
        update.asm
    );
}
