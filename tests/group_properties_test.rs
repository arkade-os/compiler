use arkade_compiler::compile;

/// Test that group.assetId emits OP_INSPECTASSETGROUPASSETID
#[test]
fn test_group_asset_id_basic() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract AssetIdTest(pubkey serverKey, bytes32 tokenAssetId, bytes32 expectedAssetId) {
            function checkAssetId(signature ownerSig, pubkey owner) {
                require(checkSig(ownerSig, owner));
                let tokenGroup = tx.assetGroups.find(tokenAssetId);
                require(tokenGroup.assetId == expectedAssetId, "asset id mismatch");
            }
        }
    "#;

    let result = compile(code);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();
    assert_eq!(output.name, "AssetIdTest");

    let func = output
        .functions
        .iter()
        .find(|f| f.name == "checkAssetId" && f.server_variant)
        .expect("checkAssetId server variant not found");

    let asm_str = func.asm.join(" ");

    // assetId emits: OP_INSPECTASSETGROUPASSETID
    assert!(
        asm_str.contains("OP_INSPECTASSETGROUPASSETID"),
        "Expected OP_INSPECTASSETGROUPASSETID for assetId access: {}",
        asm_str
    );
}

/// Test that group.isFresh emits the correct opcode sequence:
/// OP_INSPECTASSETGROUPASSETID OP_DROP OP_TXHASH OP_EQUAL
#[test]
fn test_group_is_fresh_basic() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract FreshAssetTest(pubkey serverKey, bytes32 newAssetId) {
            function verifyFresh(signature ownerSig, pubkey owner) {
                require(checkSig(ownerSig, owner));
                let group = tx.assetGroups.find(newAssetId);
                require(group.isFresh == 1, "must be fresh");
            }
        }
    "#;

    let result = compile(code);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();
    assert_eq!(output.name, "FreshAssetTest");

    let func = output
        .functions
        .iter()
        .find(|f| f.name == "verifyFresh" && f.server_variant)
        .expect("verifyFresh server variant not found");

    let asm_str = func.asm.join(" ");

    // isFresh emits: OP_INSPECTASSETGROUPASSETID OP_DROP OP_TXHASH OP_EQUAL
    assert!(
        asm_str.contains("OP_INSPECTASSETGROUPASSETID"),
        "Expected OP_INSPECTASSETGROUPASSETID for isFresh check: {}",
        asm_str
    );
    assert!(
        asm_str.contains("OP_DROP"),
        "Expected OP_DROP for isFresh check: {}",
        asm_str
    );
    assert!(
        asm_str.contains("OP_TXHASH"),
        "Expected OP_TXHASH for isFresh check: {}",
        asm_str
    );
}

/// Test isFresh combined with delta for NFT minting pattern
#[test]
fn test_is_fresh_with_delta_combo() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract NFTMintTest(pubkey serverKey, bytes32 nftAssetId, bytes32 ctrlAssetId) {
            function mintNFT(signature issuerSig, pubkey issuer) {
                require(checkSig(issuerSig, issuer));
                let nftGroup = tx.assetGroups.find(nftAssetId);
                require(nftGroup.isFresh == 1, "must be new asset");
                require(nftGroup.delta == 1, "must mint exactly 1");
                require(nftGroup.control == ctrlAssetId, "wrong control");
            }
        }
    "#;

    let result = compile(code);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "mintNFT" && f.server_variant)
        .expect("mintNFT server variant not found");

    let asm_str = func.asm.join(" ");

    // Verify all three group property opcodes are present
    assert!(
        asm_str.contains("OP_INSPECTASSETGROUPASSETID"),
        "Expected OP_INSPECTASSETGROUPASSETID for isFresh: {}",
        asm_str
    );
    assert!(
        asm_str.contains("OP_TXHASH"),
        "Expected OP_TXHASH for isFresh: {}",
        asm_str
    );
    // delta uses OP_SUB64 for sumOutputs - sumInputs
    assert!(
        asm_str.contains("OP_SUB64"),
        "Expected OP_SUB64 for delta: {}",
        asm_str
    );
    assert!(
        asm_str.contains("OP_INSPECTASSETGROUPCTRL"),
        "Expected OP_INSPECTASSETGROUPCTRL for control: {}",
        asm_str
    );
}

/// Test isFresh == 0 for verifying existing (non-fresh) assets
#[test]
fn test_is_fresh_zero_for_existing_asset() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract ExistingAssetTest(pubkey serverKey, bytes32 assetId) {
            function transferExisting(signature ownerSig, pubkey owner) {
                require(checkSig(ownerSig, owner));
                let group = tx.assetGroups.find(assetId);
                require(group.isFresh == 0, "must be existing asset");
                require(group.delta == 0, "must be transfer only");
            }
        }
    "#;

    let result = compile(code);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "transferExisting" && f.server_variant)
        .expect("transferExisting server variant not found");

    let asm_str = func.asm.join(" ");

    // isFresh emits the same opcode sequence regardless of comparison value
    assert!(
        asm_str.contains("OP_INSPECTASSETGROUPASSETID"),
        "Expected OP_INSPECTASSETGROUPASSETID: {}",
        asm_str
    );
    assert!(
        asm_str.contains("OP_TXHASH"),
        "Expected OP_TXHASH: {}",
        asm_str
    );
}

/// Test group.metadataHash emits OP_INSPECTASSETGROUPMETADATAHASH
#[test]
fn test_group_metadata_hash() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract MetadataTest(pubkey serverKey, bytes32 assetId, bytes32 expectedHash) {
            function verifyMetadata(signature ownerSig, pubkey owner) {
                require(checkSig(ownerSig, owner));
                let group = tx.assetGroups.find(assetId);
                require(group.metadataHash == expectedHash, "metadata mismatch");
            }
        }
    "#;

    let result = compile(code);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "verifyMetadata" && f.server_variant)
        .expect("verifyMetadata server variant not found");

    let asm_str = func.asm.join(" ");

    assert!(
        asm_str.contains("OP_INSPECTASSETGROUPMETADATAHASH"),
        "Expected OP_INSPECTASSETGROUPMETADATAHASH: {}",
        asm_str
    );
}

/// Test all group properties together (comprehensive test)
#[test]
fn test_all_group_properties() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract AllPropertiesTest(
            pubkey serverKey,
            bytes32 assetId,
            bytes32 ctrlAssetId,
            bytes32 expectedMetadata
        ) {
            function fullCheck(signature sig, pubkey pk, int expectedDelta) {
                require(checkSig(sig, pk));
                let group = tx.assetGroups.find(assetId);

                // Test all group properties
                require(group.isFresh == 1, "not fresh");
                require(group.delta == expectedDelta, "wrong delta");
                require(group.control == ctrlAssetId, "wrong control");
                require(group.metadataHash == expectedMetadata, "wrong metadata");
                require(group.sumOutputs >= group.sumInputs, "outputs < inputs");
            }
        }
    "#;

    let result = compile(code);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "fullCheck" && f.server_variant)
        .expect("fullCheck server variant not found");

    let asm_str = func.asm.join(" ");

    // All group property opcodes should be present
    assert!(
        asm_str.contains("OP_FINDASSETGROUPBYASSETID"),
        "Expected OP_FINDASSETGROUPBYASSETID: {}",
        asm_str
    );
    assert!(
        asm_str.contains("OP_INSPECTASSETGROUPASSETID"),
        "Expected OP_INSPECTASSETGROUPASSETID for isFresh: {}",
        asm_str
    );
    assert!(
        asm_str.contains("OP_TXHASH"),
        "Expected OP_TXHASH for isFresh: {}",
        asm_str
    );
    assert!(
        asm_str.contains("OP_SUB64"),
        "Expected OP_SUB64 for delta: {}",
        asm_str
    );
    assert!(
        asm_str.contains("OP_INSPECTASSETGROUPCTRL"),
        "Expected OP_INSPECTASSETGROUPCTRL: {}",
        asm_str
    );
    assert!(
        asm_str.contains("OP_INSPECTASSETGROUPMETADATAHASH"),
        "Expected OP_INSPECTASSETGROUPMETADATAHASH: {}",
        asm_str
    );
    assert!(
        asm_str.contains("OP_INSPECTASSETGROUPSUM"),
        "Expected OP_INSPECTASSETGROUPSUM for sumInputs/sumOutputs: {}",
        asm_str
    );
}
