use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_DROP, OP_INSPECTINASSETAT, OP_INSPECTINASSETCOUNT, OP_INSPECTOUTASSETAT,
    OP_INSPECTOUTASSETCOUNT, OP_NIP,
};

/// Test asset count and indexed asset access opcodes
#[test]
fn test_asset_count_parsing() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract AssetCounter(pubkey serverKey, pubkey owner) {
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

    // Find the server variant function
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "checkAssetCount" && f.server_variant)
        .expect("Should have checkAssetCount server variant");

    // Check that the ASM contains the asset count opcode
    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains(OP_INSPECTOUTASSETCOUNT),
        "Expected {OP_INSPECTOUTASSETCOUNT} in ASM: {}",
        asm_str
    );
}

#[test]
fn test_asset_at_amount_parsing() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract AssetInspector(pubkey serverKey, pubkey owner) {
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

    // Find the server variant function
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "checkAssetAmount" && f.server_variant)
        .expect("Should have checkAssetAmount server variant");

    // Check that the ASM contains the asset at opcode
    let asm_str = func.asm.join(" ");
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
fn test_asset_at_assetid_parsing() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract AssetIdInspector(pubkey serverKey, pubkey owner, bytes32 expectedTxid) {
            function checkAssetId(signature ownerSig) {
                require(checkSig(ownerSig, owner));
                let assetId = tx.outputs[0].assets[0].assetId;
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse asset at assetId: {:?}",
        result.err()
    );

    let output = result.unwrap();

    // Find the server variant function
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "checkAssetId" && f.server_variant)
        .expect("Should have checkAssetId server variant");

    // Check that the ASM contains the asset at opcode
    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains(OP_INSPECTOUTASSETAT),
        "Expected {OP_INSPECTOUTASSETAT} in ASM: {}",
        asm_str
    );
    // Should have OP_DROP to remove amount and keep assetId (txid, gidx)
    assert!(
        asm_str.contains(OP_DROP),
        "Expected {OP_DROP} for assetId extraction in ASM: {}",
        asm_str
    );
}

#[test]
fn test_input_asset_count() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract InputAssetCounter(pubkey serverKey, pubkey owner) {
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

    // Find the server variant function
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "checkInputAssets" && f.server_variant)
        .expect("Should have checkInputAssets server variant");

    // Check that the ASM contains the input asset count opcode
    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains(OP_INSPECTINASSETCOUNT),
        "Expected {OP_INSPECTINASSETCOUNT} in ASM: {}",
        asm_str
    );
}

#[test]
fn test_input_asset_at() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract InputAssetInspector(pubkey serverKey, pubkey owner) {
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

    // Find the server variant function
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "checkInputAssetAmount" && f.server_variant)
        .expect("Should have checkInputAssetAmount server variant");

    // Check that the ASM contains the input asset at opcode
    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains(OP_INSPECTINASSETAT),
        "Expected {OP_INSPECTINASSETAT} in ASM: {}",
        asm_str
    );
}

#[test]
fn test_asset_count_with_variable_index() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract DynamicAssetCounter(pubkey serverKey, pubkey owner) {
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

    let func = output
        .functions
        .iter()
        .find(|f| f.name == "checkAssets" && f.server_variant)
        .expect("Should have checkAssets server variant");

    let asm_str = func.asm.join(" ");
    // Should have the variable index placeholder
    assert!(
        asm_str.contains("<outputIdx>"),
        "Expected <outputIdx> in ASM: {}",
        asm_str
    );
    assert!(
        asm_str.contains(OP_INSPECTOUTASSETCOUNT),
        "Expected {OP_INSPECTOUTASSETCOUNT} in ASM: {}",
        asm_str
    );
}
