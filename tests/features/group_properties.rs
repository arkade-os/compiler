use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_0, OP_1, OP_DROP, OP_FINDASSETGROUPBYASSETID, OP_INSPECTASSETGROUPASSETID,
    OP_INSPECTASSETGROUPCTRL, OP_INSPECTASSETGROUPMETADATAHASH, OP_INSPECTASSETGROUPNUM,
    OP_INSPECTASSETGROUPSUM, OP_SUB, OP_TXID,
};

use crate::common::arkade_asm;

/// Test that group.assetId emits OP_INSPECTASSETGROUPASSETID
#[test]
fn test_group_asset_id_basic() {
    let code = r#"
        contract AssetIdTest(bytes32 tokenAssetIdTxid, int tokenAssetIdGidx, bytes32 expectedAssetId) {
            function checkAssetId(signature ownerSig, pubkey owner) {
                require(checkSig(ownerSig, owner));
                let tokenGroup = tx.assetGroups.find(tokenAssetIdTxid, tokenAssetIdGidx);
                require(tokenGroup.assetId == expectedAssetId, "asset id mismatch");
            }
        }
    "#;

    let result = compile(code);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();
    assert_eq!(output.name, "AssetIdTest");

    let asm_str = arkade_asm(&output, "checkAssetId");

    // assetId emits: OP_INSPECTASSETGROUPASSETID
    assert!(
        asm_str.contains(OP_INSPECTASSETGROUPASSETID),
        "Expected {OP_INSPECTASSETGROUPASSETID} for assetId access: {}",
        asm_str
    );
}

/// Test that group.isFresh emits the correct opcode sequence:
/// OP_INSPECTASSETGROUPASSETID OP_DROP OP_TXID OP_EQUAL
#[test]
fn test_group_is_fresh_basic() {
    let code = r#"
        contract FreshAssetTest(bytes32 newAssetIdTxid, int newAssetIdGidx) {
            function verifyFresh(signature ownerSig, pubkey owner) {
                require(checkSig(ownerSig, owner));
                let group = tx.assetGroups.find(newAssetIdTxid, newAssetIdGidx);
                require(group.isFresh == 1, "must be fresh");
            }
        }
    "#;

    let result = compile(code);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();
    assert_eq!(output.name, "FreshAssetTest");

    let asm_str = arkade_asm(&output, "verifyFresh");

    // isFresh emits: OP_INSPECTASSETGROUPASSETID OP_DROP OP_TXID OP_EQUAL
    assert!(
        asm_str.contains(OP_INSPECTASSETGROUPASSETID),
        "Expected {OP_INSPECTASSETGROUPASSETID} for isFresh check: {}",
        asm_str
    );
    assert!(
        asm_str.contains(OP_DROP),
        "Expected {OP_DROP} for isFresh check: {}",
        asm_str
    );
    assert!(
        asm_str.contains(OP_TXID),
        "Expected {OP_TXID} for isFresh check: {}",
        asm_str
    );
}

/// Test isFresh combined with delta for NFT minting pattern
#[test]
fn test_is_fresh_with_delta_combo() {
    let code = r#"
        contract NFTMintTest(bytes32 nftAssetIdTxid, int nftAssetIdGidx, bytes32 ctrlAssetIdTxid, int ctrlAssetIdGidx) {
            function mintNFT(signature issuerSig, pubkey issuer) {
                require(checkSig(issuerSig, issuer));
                let nftGroup = tx.assetGroups.find(nftAssetIdTxid, nftAssetIdGidx);
                require(nftGroup.isFresh == 1, "must be new asset");
                require(nftGroup.delta == 1, "must mint exactly 1");
                require(nftGroup.controlIs(ctrlAssetIdTxid, ctrlAssetIdGidx), "wrong control");
            }
        }
    "#;

    let result = compile(code);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();
    let asm_str = arkade_asm(&output, "mintNFT");

    // Verify all three group property opcodes are present
    assert!(
        asm_str.contains(OP_INSPECTASSETGROUPASSETID),
        "Expected {OP_INSPECTASSETGROUPASSETID} for isFresh: {}",
        asm_str
    );
    assert!(
        asm_str.contains(OP_TXID),
        "Expected {OP_TXID} for isFresh: {}",
        asm_str
    );
    // delta uses OP_SUB for sumOutputs - sumInputs
    assert!(
        asm_str.contains(OP_SUB),
        "Expected {OP_SUB} for delta: {}",
        asm_str
    );
    assert!(
        asm_str.contains(OP_INSPECTASSETGROUPCTRL),
        "Expected {OP_INSPECTASSETGROUPCTRL} for control: {}",
        asm_str
    );
}

/// Test isFresh == 0 for verifying existing (non-fresh) assets
#[test]
fn test_is_fresh_zero_for_existing_asset() {
    let code = r#"
        contract ExistingAssetTest(bytes32 assetIdTxid, int assetIdGidx) {
            function transferExisting(signature ownerSig, pubkey owner) {
                require(checkSig(ownerSig, owner));
                let group = tx.assetGroups.find(assetIdTxid, assetIdGidx);
                require(group.isFresh == 0, "must be existing asset");
                require(group.delta == 0, "must be transfer only");
            }
        }
    "#;

    let result = compile(code);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();
    let asm_str = arkade_asm(&output, "transferExisting");

    // isFresh emits the same opcode sequence regardless of comparison value
    assert!(
        asm_str.contains(OP_INSPECTASSETGROUPASSETID),
        "Expected {OP_INSPECTASSETGROUPASSETID}: {}",
        asm_str
    );
    assert!(asm_str.contains(OP_TXID), "Expected {OP_TXID}: {}", asm_str);
}

/// Test group.metadataHash emits OP_INSPECTASSETGROUPMETADATAHASH
#[test]
fn test_group_metadata_hash() {
    let code = r#"
        contract MetadataTest(bytes32 assetIdTxid, int assetIdGidx, bytes32 expectedHash) {
            function verifyMetadata(signature ownerSig, pubkey owner) {
                require(checkSig(ownerSig, owner));
                let group = tx.assetGroups.find(assetIdTxid, assetIdGidx);
                require(group.metadataHash == expectedHash, "metadata mismatch");
            }
        }
    "#;

    let result = compile(code);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();
    let asm_str = arkade_asm(&output, "verifyMetadata");

    assert!(
        asm_str.contains(OP_INSPECTASSETGROUPMETADATAHASH),
        "Expected {OP_INSPECTASSETGROUPMETADATAHASH}: {}",
        asm_str
    );
}

/// Test all group properties together (comprehensive test)
#[test]
fn test_all_group_properties() {
    let code = r#"
        contract AllPropertiesTest(
            bytes32 assetIdTxid, int assetIdGidx,
            bytes32 ctrlAssetIdTxid, int ctrlAssetIdGidx,
            bytes32 expectedMetadata
        ) {
            function fullCheck(signature sig, pubkey pk, int expectedDelta) {
                require(checkSig(sig, pk));
                let group = tx.assetGroups.find(assetIdTxid, assetIdGidx);

                // Test all group properties
                require(group.isFresh == 1, "not fresh");
                require(group.delta == expectedDelta, "wrong delta");
                require(group.controlIs(ctrlAssetIdTxid, ctrlAssetIdGidx), "wrong control");
                require(group.metadataHash == expectedMetadata, "wrong metadata");
                require(group.sumOutputs >= group.sumInputs, "outputs < inputs");
            }
        }
    "#;

    let result = compile(code);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();
    let asm_str = arkade_asm(&output, "fullCheck");

    // All group property opcodes should be present
    assert!(
        asm_str.contains(OP_FINDASSETGROUPBYASSETID),
        "Expected {OP_FINDASSETGROUPBYASSETID}: {}",
        asm_str
    );
    assert!(
        asm_str.contains(OP_INSPECTASSETGROUPASSETID),
        "Expected {OP_INSPECTASSETGROUPASSETID} for isFresh: {}",
        asm_str
    );
    assert!(
        asm_str.contains(OP_TXID),
        "Expected {OP_TXID} for isFresh: {}",
        asm_str
    );
    assert!(
        asm_str.contains(OP_SUB),
        "Expected {OP_SUB} for delta: {}",
        asm_str
    );
    assert!(
        asm_str.contains(OP_INSPECTASSETGROUPCTRL),
        "Expected {OP_INSPECTASSETGROUPCTRL}: {}",
        asm_str
    );
    assert!(
        asm_str.contains(OP_INSPECTASSETGROUPMETADATAHASH),
        "Expected {OP_INSPECTASSETGROUPMETADATAHASH}: {}",
        asm_str
    );
    assert!(
        asm_str.contains(OP_INSPECTASSETGROUPSUM),
        "Expected {OP_INSPECTASSETGROUPSUM} for sumInputs/sumOutputs: {}",
        asm_str
    );
}

/// Test group.numInputs emits OP_INSPECTASSETGROUPNUM with source=0
#[test]
fn test_group_num_inputs() {
    let code = r#"
        contract NumInputsTest(bytes32 assetIdTxid, int assetIdGidx) {
            function checkInputCount(signature sig, pubkey pk) {
                require(checkSig(sig, pk));
                let group = tx.assetGroups.find(assetIdTxid, assetIdGidx);
                require(group.numInputs >= 1, "need at least one input");
            }
        }
    "#;

    let result = compile(code);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();
    let asm_str = arkade_asm(&output, "checkInputCount");

    // numInputs emits: <group> OP_0 OP_INSPECTASSETGROUPNUM
    assert!(
        asm_str.contains(OP_INSPECTASSETGROUPNUM),
        "Expected {OP_INSPECTASSETGROUPNUM} for numInputs: {}",
        asm_str
    );
    assert!(
        asm_str.contains(OP_0),
        "Expected {OP_0} (source=inputs) for numInputs: {}",
        asm_str
    );
}

/// Test group.numOutputs emits OP_INSPECTASSETGROUPNUM with source=1
#[test]
fn test_group_num_outputs() {
    let code = r#"
        contract NumOutputsTest(bytes32 assetIdTxid, int assetIdGidx) {
            function checkOutputCount(signature sig, pubkey pk) {
                require(checkSig(sig, pk));
                let group = tx.assetGroups.find(assetIdTxid, assetIdGidx);
                require(group.numOutputs >= 2, "need at least two outputs");
            }
        }
    "#;

    let result = compile(code);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();
    let asm_str = arkade_asm(&output, "checkOutputCount");

    // numOutputs emits: <group> OP_1 OP_INSPECTASSETGROUPNUM
    assert!(
        asm_str.contains(OP_INSPECTASSETGROUPNUM),
        "Expected {OP_INSPECTASSETGROUPNUM} for numOutputs: {}",
        asm_str
    );
    assert!(
        asm_str.contains(OP_1),
        "Expected {OP_1} (source=outputs) for numOutputs: {}",
        asm_str
    );
}

/// Test numInputs and numOutputs together
#[test]
fn test_group_num_io_together() {
    let code = r#"
        contract NumIOTest(bytes32 assetIdTxid, int assetIdGidx) {
            function checkCounts(signature sig, pubkey pk) {
                require(checkSig(sig, pk));
                let group = tx.assetGroups.find(assetIdTxid, assetIdGidx);
                require(group.numInputs >= 1, "need inputs");
                require(group.numOutputs >= 1, "need outputs");
                require(group.numOutputs >= group.numInputs, "outputs must be >= inputs");
            }
        }
    "#;

    let result = compile(code);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();
    let asm_str = arkade_asm(&output, "checkCounts");

    // Should have multiple OP_INSPECTASSETGROUPNUM calls
    let count = asm_str.matches(OP_INSPECTASSETGROUPNUM).count();
    assert!(
        count >= 2,
        "Expected at least 2 {OP_INSPECTASSETGROUPNUM} calls, got {}: {}",
        count,
        asm_str
    );
}
