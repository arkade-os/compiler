use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_ADD64, OP_CHECKSIG, OP_ELSE, OP_ENDIF, OP_IF, OP_INSPECTASSETGROUPSUM,
};

use crate::common::{arkade_asm, arkade_asm_tokens, leaf_asm};

/// Exercises let bindings, branch emission, reassignment, and branch stack normalization.
const EPOCH_LIMITER_CODE: &str = r#"
contract EpochLimiter(
  bytes32 ctrlAssetIdTxid, int ctrlAssetIdGidx,
  int epochLimit,
  int epochBlocks
) {
  function check(int transferAmount, int epochStartIdx, int epochTotalIdx) {
    require(transferAmount > 0, "zero");

    let epochStart = tx.assetGroups[epochStartIdx].sumInputs;
    let epochTotal = tx.assetGroups[epochTotalIdx].sumInputs;

    require(tx.inputs[0].assets.lookup(ctrlAssetIdTxid, ctrlAssetIdGidx) > 0, "no ctrl");

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

    require(tx.outputs[0].assets.lookup(ctrlAssetIdTxid, ctrlAssetIdGidx) >= tx.inputs[0].assets.lookup(ctrlAssetIdTxid, ctrlAssetIdGidx), "ctrl leaked");
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
    assert_eq!(output.functions.len(), 1);
    assert_eq!(output.functions[0].name, "check");
}

#[test]
fn test_epoch_limiter_has_if_else() {
    let output = compile(EPOCH_LIMITER_CODE).unwrap();

    let asm_str = arkade_asm(&output, "check");

    // Check for if/else opcodes in the covenant assembly
    assert!(
        asm_str.contains(OP_IF),
        "Missing OP_IF in assembly: {}",
        asm_str
    );
    assert!(
        asm_str.contains(OP_ELSE),
        "Missing OP_ELSE in assembly: {}",
        asm_str
    );
    assert!(
        asm_str.contains(OP_ENDIF),
        "Missing OP_ENDIF in assembly: {}",
        asm_str
    );
}

#[test]
fn test_epoch_limiter_branch_structure() {
    let output = compile(EPOCH_LIMITER_CODE).unwrap();

    let tokens = arkade_asm_tokens(&output, "check");

    // Find positions of control flow opcodes
    let if_idx = tokens.iter().position(|s| s == OP_IF);
    let else_idx = tokens.iter().position(|s| s == OP_ELSE);
    let endif_idx = tokens.iter().position(|s| s == OP_ENDIF);

    // Verify correct ordering: IF < ELSE < ENDIF
    assert!(if_idx.is_some() && else_idx.is_some() && endif_idx.is_some());
    assert!(if_idx.unwrap() < else_idx.unwrap());
    assert!(else_idx.unwrap() < endif_idx.unwrap());
}

#[test]
fn test_epoch_limiter_asset_group_introspection() {
    let output = compile(EPOCH_LIMITER_CODE).unwrap();
    let asm_str = arkade_asm(&output, "check");

    // Should have OP_INSPECTASSETGROUPSUM for reading group sums
    assert!(
        asm_str.contains(OP_INSPECTASSETGROUPSUM),
        "Missing {OP_INSPECTASSETGROUPSUM} in assembly"
    );
}

#[test]
fn test_epoch_limiter_64bit_arithmetic() {
    let output = compile(EPOCH_LIMITER_CODE).unwrap();
    let asm_str = arkade_asm(&output, "check");

    // Should use 64-bit arithmetic for asset amounts
    let has_add64 = asm_str.contains(OP_ADD64);
    assert!(has_add64, "Missing 64-bit arithmetic opcodes");
}

#[test]
fn test_epoch_limiter_default_leaf_has_checksig() {
    // The synthesized default leaf must carry the SERVER_KEY + EMULATOR_KEY guard.
    let output = compile(EPOCH_LIMITER_CODE).unwrap();
    let l = leaf_asm(&output, "check", "check");

    assert!(
        l.contains(OP_CHECKSIG),
        "Default leaf missing OP_CHECKSIG: {}",
        l
    );
    assert!(
        l.contains("<SERVER_KEY>"),
        "Default leaf missing <SERVER_KEY>: {}",
        l
    );
}
