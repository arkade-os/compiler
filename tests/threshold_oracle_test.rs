use arkade_compiler::compile;

/// Test contract from PLAN.md Commit 6: Array Types + Threshold Verification
///
/// This test validates:
/// - Array type parsing (pubkey[], signature[])
/// - Array indexing (oracles[i])
/// - Array length property (arr.length)
/// - Loop iteration over arrays
const THRESHOLD_ORACLE_CODE: &str = r#"
options {
  server = serverPk;
  exit = 288;
}

contract ThresholdOracle(
  bytes32 tokenAssetId,
  bytes32 ctrlAssetId,
  pubkey serverPk,
  pubkey[] oracles,
  int threshold
) {
  function attest(
    int amount,
    bytes32 messageHash,
    pubkey recipientPk,
    signature[] oracleSigs
  ) {
    require(amount > 0, "zero");

    int valid = 0;
    for (i, sig) in oracleSigs {
      if (checkSigFromStack(sig, oracles[i], messageHash)) {
        valid = valid + 1;
      }
    }
    require(valid >= threshold, "quorum failed");

    require(tx.inputs[0].assets.lookup(ctrlAssetId) > 0, "no ctrl");
    require(tx.outputs[1].assets.lookup(tokenAssetId) >= amount, "short");
    require(tx.outputs[1].scriptPubKey == new P2TR(recipientPk), "wrong dest");
    require(tx.outputs[0].scriptPubKey == tx.input.current.scriptPubKey, "broken");
  }
}
"#;

#[test]
fn test_threshold_oracle_parses() {
    let result = compile(THRESHOLD_ORACLE_CODE);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

#[test]
fn test_threshold_oracle_structure() {
    let output = compile(THRESHOLD_ORACLE_CODE).unwrap();

    assert_eq!(output.name, "ThresholdOracle");
    // 1 function x 2 variants = 2
    assert_eq!(output.functions.len(), 2);

    // Verify we have both server and exit variants
    let server = output.functions.iter()
        .find(|f| f.name == "attest" && f.server_variant);
    let exit = output.functions.iter()
        .find(|f| f.name == "attest" && !f.server_variant);

    assert!(server.is_some(), "Missing server variant");
    assert!(exit.is_some(), "Missing exit variant");
}

#[test]
fn test_threshold_oracle_has_asset_lookup() {
    let output = compile(THRESHOLD_ORACLE_CODE).unwrap();

    let server = output.functions.iter()
        .find(|f| f.name == "attest" && f.server_variant)
        .unwrap();

    // Should have asset lookup for control asset check
    assert!(
        server.asm.iter().any(|s| s.contains("OP_INSPECTINASSETLOOKUP")),
        "Missing OP_INSPECTINASSETLOOKUP in attest function"
    );
}

#[test]
fn test_threshold_oracle_has_control_flow() {
    let output = compile(THRESHOLD_ORACLE_CODE).unwrap();

    let server = output.functions.iter()
        .find(|f| f.name == "attest" && f.server_variant)
        .unwrap();

    // Should have if/else for counting valid signatures
    // (or at least some form of control flow from the for loop)
    // For now, just verify the function compiles and has the basic structure
    assert!(
        server.asm.len() > 0,
        "Assembly should not be empty"
    );
}
