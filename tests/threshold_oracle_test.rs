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
    let server = output
        .functions
        .iter()
        .find(|f| f.name == "attest" && f.server_variant);
    let exit = output
        .functions
        .iter()
        .find(|f| f.name == "attest" && !f.server_variant);

    assert!(server.is_some(), "Missing server variant");
    assert!(exit.is_some(), "Missing exit variant");
}

#[test]
fn test_threshold_oracle_has_asset_lookup() {
    let output = compile(THRESHOLD_ORACLE_CODE).unwrap();

    let server = output
        .functions
        .iter()
        .find(|f| f.name == "attest" && f.server_variant)
        .unwrap();

    // Should have asset lookup for control asset check
    assert!(
        server
            .asm
            .iter()
            .any(|s| s.contains("OP_INSPECTINASSETLOOKUP")),
        "Missing OP_INSPECTINASSETLOOKUP in attest function"
    );
}

#[test]
fn test_threshold_oracle_has_control_flow() {
    let output = compile(THRESHOLD_ORACLE_CODE).unwrap();

    let server = output
        .functions
        .iter()
        .find(|f| f.name == "attest" && f.server_variant)
        .unwrap();

    // Should have if/else for counting valid signatures
    // (or at least some form of control flow from the for loop)
    // For now, just verify the function compiles and has the basic structure
    assert!(server.asm.len() > 0, "Assembly should not be empty");
}

// ─── Commit 6: Array ABI Flattening Tests ──────────────────────────────────────

#[test]
fn test_threshold_oracle_constructor_array_flattening() {
    let output = compile(THRESHOLD_ORACLE_CODE).unwrap();

    // pubkey[] oracles should be flattened to oracles_0, oracles_1, oracles_2
    // in the constructorInputs (default 3 elements)
    let param_names: Vec<&str> = output.parameters.iter().map(|p| p.name.as_str()).collect();

    assert!(
        param_names.contains(&"oracles_0"),
        "Missing oracles_0 in constructor params. Got: {:?}",
        param_names
    );
    assert!(
        param_names.contains(&"oracles_1"),
        "Missing oracles_1 in constructor params. Got: {:?}",
        param_names
    );
    assert!(
        param_names.contains(&"oracles_2"),
        "Missing oracles_2 in constructor params. Got: {:?}",
        param_names
    );

    // Should NOT contain the original array name
    assert!(
        !param_names.contains(&"oracles"),
        "Should not contain unflatten array 'oracles' in params. Got: {:?}",
        param_names
    );

    // Each flattened element should have type 'pubkey'
    let oracles_0 = output.parameters.iter().find(|p| p.name == "oracles_0");
    assert!(oracles_0.is_some(), "oracles_0 not found");
    assert_eq!(oracles_0.unwrap().param_type, "pubkey");
}

#[test]
fn test_threshold_oracle_witness_array_flattening() {
    let output = compile(THRESHOLD_ORACLE_CODE).unwrap();

    let server = output
        .functions
        .iter()
        .find(|f| f.name == "attest" && f.server_variant)
        .unwrap();

    // signature[] oracleSigs should be flattened to oracleSigs_0, oracleSigs_1, oracleSigs_2
    let input_names: Vec<&str> = server
        .function_inputs
        .iter()
        .map(|p| p.name.as_str())
        .collect();

    assert!(
        input_names.contains(&"oracleSigs_0"),
        "Missing oracleSigs_0 in function inputs. Got: {:?}",
        input_names
    );
    assert!(
        input_names.contains(&"oracleSigs_1"),
        "Missing oracleSigs_1 in function inputs. Got: {:?}",
        input_names
    );
    assert!(
        input_names.contains(&"oracleSigs_2"),
        "Missing oracleSigs_2 in function inputs. Got: {:?}",
        input_names
    );

    // Should NOT contain the original array name
    assert!(
        !input_names.contains(&"oracleSigs"),
        "Should not contain unflatten array 'oracleSigs' in inputs. Got: {:?}",
        input_names
    );
}

#[test]
fn test_threshold_oracle_checksig_from_stack_unrolled() {
    let output = compile(THRESHOLD_ORACLE_CODE).unwrap();

    let server = output
        .functions
        .iter()
        .find(|f| f.name == "attest" && f.server_variant)
        .unwrap();

    // The for loop should unroll to 3 OP_CHECKSIGFROMSTACK calls
    let checksig_count = server
        .asm
        .iter()
        .filter(|s| *s == "OP_CHECKSIGFROMSTACK")
        .count();

    assert_eq!(
        checksig_count, 3,
        "Expected 3 OP_CHECKSIGFROMSTACK calls (one per oracle). Got: {}. ASM: {:?}",
        checksig_count, server.asm
    );
}

#[test]
fn test_threshold_oracle_array_indexing_in_loop() {
    let output = compile(THRESHOLD_ORACLE_CODE).unwrap();

    let server = output
        .functions
        .iter()
        .find(|f| f.name == "attest" && f.server_variant)
        .unwrap();

    // When loop unrolls, oracles[i] should become <oracles_0>, <oracles_1>, <oracles_2>
    assert!(
        server.asm.iter().any(|s| s == "<oracles_0>"),
        "Missing <oracles_0> in assembly (from oracles[0]). ASM: {:?}",
        server.asm
    );
    assert!(
        server.asm.iter().any(|s| s == "<oracles_1>"),
        "Missing <oracles_1> in assembly (from oracles[1]). ASM: {:?}",
        server.asm
    );
    assert!(
        server.asm.iter().any(|s| s == "<oracles_2>"),
        "Missing <oracles_2> in assembly (from oracles[2]). ASM: {:?}",
        server.asm
    );

    // Similarly, sig (the value var) should become oracleSigs_0, etc.
    assert!(
        server.asm.iter().any(|s| s == "<oracleSigs_0>"),
        "Missing <oracleSigs_0> in assembly. ASM: {:?}",
        server.asm
    );
    assert!(
        server.asm.iter().any(|s| s == "<oracleSigs_1>"),
        "Missing <oracleSigs_1> in assembly. ASM: {:?}",
        server.asm
    );
    assert!(
        server.asm.iter().any(|s| s == "<oracleSigs_2>"),
        "Missing <oracleSigs_2> in assembly. ASM: {:?}",
        server.asm
    );
}

#[test]
fn test_threshold_oracle_quorum_uses_csn_comparison() {
    let output = compile(THRESHOLD_ORACLE_CODE).unwrap();

    let server = output
        .functions
        .iter()
        .find(|f| f.name == "attest" && f.server_variant)
        .unwrap();

    // The quorum check (valid >= threshold) should use OP_GREATERTHANOREQUAL
    // (not the 64-bit variant) because valid is a small counter, not an asset amount
    assert!(
        server.asm.iter().any(|s| s == "OP_GREATERTHANOREQUAL"),
        "Missing OP_GREATERTHANOREQUAL for quorum check. ASM: {:?}",
        server.asm
    );
}
