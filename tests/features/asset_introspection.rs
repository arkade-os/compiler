use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_INSPECTINASSETAT, OP_INSPECTINASSETCOUNT, OP_INSPECTOUTASSETAT, OP_INSPECTOUTASSETCOUNT,
    OP_NIP,
};

/// Test asset count and indexed asset access opcodes
#[test]
fn test_asset_count_parsing() {
    let code = r#"
        contract AssetCounter(pubkey owner) {
            function checkAssetCount(signature ownerSig, int expectedCount) {
                require(checkSig(ownerSig, owner));
                require(tx.outputs[0].assets.length >= expectedCount);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse asset count: {:?}",
        result.err()
    );

    let output = result.unwrap();
    assert_eq!(output.name, "AssetCounter");

    // Check that the covenant ASM contains the asset count opcode
    let asm_str = crate::common::arkade_asm(&output, "checkAssetCount");
    assert!(
        asm_str.contains(OP_INSPECTOUTASSETCOUNT),
        "Expected {OP_INSPECTOUTASSETCOUNT} in ASM: {}",
        asm_str
    );
}

#[test]
fn test_asset_at_amount_parsing() {
    let code = r#"
        contract AssetInspector(pubkey owner) {
            function checkAssetAmount(signature ownerSig, int minAmount) {
                require(checkSig(ownerSig, owner));
                require(tx.outputs[0].assets[0].amount >= minAmount);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse asset at amount: {:?}",
        result.err()
    );

    let output = result.unwrap();

    // Check that the covenant ASM contains the asset at opcode
    let asm_str = crate::common::arkade_asm(&output, "checkAssetAmount");
    assert!(
        asm_str.contains(OP_INSPECTOUTASSETAT),
        "Expected {OP_INSPECTOUTASSETAT} in ASM: {}",
        asm_str
    );
    // Should have OP_NIP to extract amount (drops txid and gidx)
    assert!(
        asm_str.contains(OP_NIP),
        "Expected {OP_NIP} for amount extraction in ASM: {}",
        asm_str
    );
}

#[test]
fn test_asset_at_assetid_cannot_be_bound_as_one_value() {
    let code = r#"
        contract AssetIdInspector(pubkey owner, bytes32 expectedTxid) {
            function checkAssetId(signature ownerSig) {
                require(checkSig(ownerSig, owner));
                let assetId = tx.outputs[0].assets[0].assetId;
            }
        }
    "#;

    let error = compile(code)
        .expect_err("assetId is a two-item value")
        .to_string();
    assert!(
        error.contains("expression produces 2 stack items"),
        "assetId binding must be rejected: {error}"
    );
}

#[test]
fn test_input_asset_count() {
    let code = r#"
        contract InputAssetCounter(pubkey owner) {
            function checkInputAssets(signature ownerSig) {
                require(checkSig(ownerSig, owner));
                require(tx.inputs[0].assets.length >= 1);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse input asset count: {:?}",
        result.err()
    );

    let output = result.unwrap();

    // Check that the covenant ASM contains the input asset count opcode
    let asm_str = crate::common::arkade_asm(&output, "checkInputAssets");
    assert!(
        asm_str.contains(OP_INSPECTINASSETCOUNT),
        "Expected {OP_INSPECTINASSETCOUNT} in ASM: {}",
        asm_str
    );
}

#[test]
fn test_input_asset_at() {
    let code = r#"
        contract InputAssetInspector(pubkey owner) {
            function checkInputAssetAmount(signature ownerSig, int minAmount) {
                require(checkSig(ownerSig, owner));
                require(tx.inputs[0].assets[0].amount >= minAmount);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse input asset at: {:?}",
        result.err()
    );

    let output = result.unwrap();

    // Check that the covenant ASM contains the input asset at opcode
    let asm_str = crate::common::arkade_asm(&output, "checkInputAssetAmount");
    assert!(
        asm_str.contains(OP_INSPECTINASSETAT),
        "Expected {OP_INSPECTINASSETAT} in ASM: {}",
        asm_str
    );
}

#[test]
fn test_asset_count_with_variable_index() {
    let code = r#"
        contract DynamicAssetCounter(pubkey owner) {
            function checkAssets(signature ownerSig, int outputIdx) {
                require(checkSig(ownerSig, owner));
                require(tx.outputs[outputIdx].assets.length >= 1);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse asset count with variable: {:?}",
        result.err()
    );

    let output = result.unwrap();

    let asm_str = crate::common::arkade_asm(&output, "checkAssets");
    assert!(
        asm_str.contains("OP_PICK OP_INSPECTOUTASSETCOUNT"),
        "Expected symbolic outputIdx read in ASM: {asm_str}"
    );
    assert!(
        !asm_str.contains("<outputIdx>"),
        "Function inputs must not remain placeholders: {asm_str}"
    );
    assert!(
        asm_str.contains(OP_INSPECTOUTASSETCOUNT),
        "Expected {OP_INSPECTOUTASSETCOUNT} in ASM: {}",
        asm_str
    );
}
