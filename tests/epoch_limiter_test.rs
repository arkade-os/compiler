use arkade_compiler::compile;

/// Test contract from PLAN.md Commit 4: If/Else + Variable Reassignment
///
/// This test validates the architectural requirements for:
/// - `let` bindings for variable declarations
/// - `if/else` control flow statements
/// - Variable reassignment
/// - Virtual stack model for branch normalization
const EPOCH_LIMITER_CODE: &str = r#"
options {
  server = adminServerPk;
  exit = 288;
}

contract EpochLimiter(
  bytes32 epochStartAssetId,
  bytes32 epochTotalAssetId,
  bytes32 ctrlAssetId,
  int epochLimit,
  int epochBlocks,
  pubkey adminPk,
  pubkey adminServerPk
) {
  function check(int transferAmount, int epochStartIdx, int epochTotalIdx) {
    require(transferAmount > 0, "zero");

    let epochStart = tx.assetGroups[epochStartIdx].sumInputs;
    let epochTotal = tx.assetGroups[epochTotalIdx].sumInputs;

    require(tx.inputs[0].assets.lookup(ctrlAssetId) > 0, "no ctrl");

    if (tx.time >= epochStart + epochBlocks) {
      let newStart = tx.time;
      require(tx.assetGroups[epochStartIdx].sumOutputs == newStart, "start not reset");
      require(tx.assetGroups[epochTotalIdx].sumOutputs == transferAmount, "total wrong");
      require(transferAmount <= epochLimit, "exceeds limit");
    } else {
      let newTotal = epochTotal + transferAmount;
      require(tx.assetGroups[epochStartIdx].sumOutputs == epochStart, "start mutated");
      require(tx.assetGroups[epochTotalIdx].sumOutputs == newTotal, "total wrong");
      require(newTotal <= epochLimit, "exceeds limit");
    }

    require(tx.outputs[0].assets.lookup(ctrlAssetId) >= tx.inputs[0].assets.lookup(ctrlAssetId), "ctrl leaked");
    require(tx.outputs[0].scriptPubKey == tx.input.current.scriptPubKey, "broken");
  }
}
"#;

#[test]
fn test_epoch_limiter_parses() {
    let result = compile(EPOCH_LIMITER_CODE);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

#[test]
fn test_epoch_limiter_structure() {
    let output = compile(EPOCH_LIMITER_CODE).unwrap();

    assert_eq!(output.name, "EpochLimiter");
    // 1 function x 2 variants (server + exit)
    assert_eq!(output.functions.len(), 2);

    // Verify we have both server and exit variants
    let server_func = output
        .functions
        .iter()
        .find(|f| f.name == "check" && f.server_variant);
    let exit_func = output
        .functions
        .iter()
        .find(|f| f.name == "check" && !f.server_variant);

    assert!(server_func.is_some(), "Missing server variant");
    assert!(exit_func.is_some(), "Missing exit variant");
}

#[test]
fn test_epoch_limiter_has_if_else() {
    let output = compile(EPOCH_LIMITER_CODE).unwrap();

    let server_func = output
        .functions
        .iter()
        .find(|f| f.name == "check" && f.server_variant)
        .unwrap();

    // Check for if/else opcodes in the assembly
    assert!(
        server_func.asm.iter().any(|s| s == "OP_IF"),
        "Missing OP_IF in assembly: {:?}",
        server_func.asm
    );
    assert!(
        server_func.asm.iter().any(|s| s == "OP_ELSE"),
        "Missing OP_ELSE in assembly: {:?}",
        server_func.asm
    );
    assert!(
        server_func.asm.iter().any(|s| s == "OP_ENDIF"),
        "Missing OP_ENDIF in assembly: {:?}",
        server_func.asm
    );
}

#[test]
fn test_epoch_limiter_branch_structure() {
    let output = compile(EPOCH_LIMITER_CODE).unwrap();

    let server_func = output
        .functions
        .iter()
        .find(|f| f.name == "check" && f.server_variant)
        .unwrap();

    // Find positions of control flow opcodes
    let if_idx = server_func.asm.iter().position(|s| s == "OP_IF");
    let else_idx = server_func.asm.iter().position(|s| s == "OP_ELSE");
    let endif_idx = server_func.asm.iter().position(|s| s == "OP_ENDIF");

    // Verify correct ordering: IF < ELSE < ENDIF
    assert!(if_idx.is_some() && else_idx.is_some() && endif_idx.is_some());
    assert!(if_idx.unwrap() < else_idx.unwrap());
    assert!(else_idx.unwrap() < endif_idx.unwrap());
}

#[test]
fn test_epoch_limiter_asset_group_introspection() {
    let output = compile(EPOCH_LIMITER_CODE).unwrap();

    let server_func = output
        .functions
        .iter()
        .find(|f| f.name == "check" && f.server_variant)
        .unwrap();

    // Should have OP_INSPECTASSETGROUPSUM for reading group sums
    assert!(
        server_func
            .asm
            .iter()
            .any(|s| s.contains("OP_INSPECTASSETGROUPSUM")),
        "Missing OP_INSPECTASSETGROUPSUM in assembly"
    );
}

#[test]
fn test_epoch_limiter_64bit_arithmetic() {
    let output = compile(EPOCH_LIMITER_CODE).unwrap();

    let server_func = output
        .functions
        .iter()
        .find(|f| f.name == "check" && f.server_variant)
        .unwrap();

    // Should use 64-bit arithmetic for asset amounts
    // At minimum: OP_ADD64 for epochStart + epochBlocks and epochTotal + transferAmount
    let has_add64 = server_func.asm.iter().any(|s| s == "OP_ADD64");

    assert!(has_add64, "Missing 64-bit arithmetic opcodes");
}

#[test]
fn test_epoch_limiter_server_variant_has_checksig() {
    let output = compile(EPOCH_LIMITER_CODE).unwrap();

    let server_func = output
        .functions
        .iter()
        .find(|f| f.name == "check" && f.server_variant)
        .unwrap();

    // Server variant should have server signature check
    assert!(
        server_func
            .asm
            .iter()
            .any(|s| s == "OP_CHECKSIG" || s == "OP_CHECKSIGVERIFY"),
        "Server variant missing signature check"
    );
}

#[test]
fn test_epoch_limiter_exit_variant_has_timelock() {
    let output = compile(EPOCH_LIMITER_CODE).unwrap();

    let exit_func = output
        .functions
        .iter()
        .find(|f| f.name == "check" && !f.server_variant)
        .unwrap();

    // Exit variant should have CSV timelock (288 blocks)
    assert!(
        exit_func
            .asm
            .iter()
            .any(|s| s == "OP_CHECKLOCKTIMEVERIFY" || s == "OP_CHECKSEQUENCEVERIFY"),
        "Exit variant missing timelock check"
    );
}
