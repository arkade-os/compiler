use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_0, OP_1, OP_2DROP, OP_DROP, OP_FINDASSETGROUPBYASSETID, OP_INSPECTASSETGROUP,
    OP_INSPECTASSETGROUPASSETID, OP_INSPECTASSETGROUPCTRL, OP_INSPECTASSETGROUPMETADATAHASH,
    OP_INSPECTASSETGROUPNUM, OP_INSPECTASSETGROUPSUM, OP_NIP, OP_SUB, OP_SWAP, OP_TXID,
};

use crate::common::arkade_asm;

/// Test that group.assetId returns an AssetId struct.
#[test]
fn test_group_asset_id_returns_struct() {
    let code = r#"
        contract AssetIdTest(bytes32 tokenAssetIdTxid, int tokenAssetIdGidx) {
            function checkAssetId(signature ownerSig, pubkey owner) {
                require(checkSig(ownerSig, owner));
                let tokenGroup = tx.assetGroups.find(tokenAssetIdTxid, tokenAssetIdGidx);
                AssetId id = tokenGroup.assetId;
                require(id.txid == tokenAssetIdTxid, "asset txid mismatch");
                require(id.gidx == tokenAssetIdGidx, "asset gidx mismatch");
                let sameGroup = tx.assetGroups.find(id.txid, id.gidx);
                require(sameGroup == tokenGroup);
            }
        }
    "#;

    let output = compile(code).expect("group assetId returns an AssetId struct");
    let asm = crate::common::arkade_asm_tokens(&output, "checkAssetId");
    assert!(asm.iter().any(|token| token == OP_INSPECTASSETGROUPASSETID));
    assert!(asm.iter().any(|token| token == OP_SWAP));
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
                require(group.isFresh == true, "must be fresh");
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
                require(nftGroup.isFresh == true, "must be new asset");
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

/// Test isFresh == false for verifying existing (non-fresh) assets
#[test]
fn test_is_fresh_zero_for_existing_asset() {
    let code = r#"
        contract ExistingAssetTest(bytes32 assetIdTxid, int assetIdGidx) {
            function transferExisting(signature ownerSig, pubkey owner) {
                require(checkSig(ownerSig, owner));
                let group = tx.assetGroups.find(assetIdTxid, assetIdGidx);
                require(group.isFresh == false, "must be existing asset");
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
                require(group.isFresh == true, "not fresh");
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

/// tx.assetGroups[k].outputs[j].amount emits OP_INSPECTASSETGROUP (source=1
/// for outputs) followed by two OP_NIP to drop type and data, leaving amount.
#[test]
fn test_group_io_access_output_amount() {
    let code = r#"
        contract GroupIOTest(pubkey owner) {
            function spend(signature sig) {
                require(checkSig(sig, owner));
                require(tx.assetGroups[0].outputs[0].amount >= 0);
            }
        }
    "#;

    let output = compile(code).expect("group IO access compiles");
    let asm = crate::common::arkade_asm_tokens(&output, "spend");
    let window = asm
        .windows(4)
        .find(|w| w[0] == OP_1 && w[1] == OP_INSPECTASSETGROUP && w[2] == OP_NIP && w[3] == OP_NIP);
    assert!(
        window.is_some(),
        "expected OP_1 {OP_INSPECTASSETGROUP} {OP_NIP} {OP_NIP}: {asm:?}"
    );
}

#[test]
fn test_group_io_access_output_type() {
    let code = r#"
        contract GroupIOTest(pubkey owner) {
            function spend(signature sig) {
                require(checkSig(sig, owner));
                require(tx.assetGroups[0].outputs[0].type >= 0);
            }
        }
    "#;

    let output = compile(code).expect("group IO access compiles");
    let asm = crate::common::arkade_asm_tokens(&output, "spend");
    assert!(
        asm.windows(3)
            .any(|w| w[0] == OP_1 && w[1] == OP_INSPECTASSETGROUP && w[2] == OP_2DROP),
        "expected OP_1 {OP_INSPECTASSETGROUP} {OP_2DROP}: {asm:?}"
    );
}

#[test]
fn test_group_accesses_ignore_whitespace_and_comments() {
    let compile_body = |body: &str| {
        let code = format!(
            "contract GroupIOTest(pubkey owner) {{ function spend(signature sig, int g, bytes32 t) {{
                require(checkSig(sig, owner));
                require(t == t);
                {body}
            }} }}"
        );
        let output = compile(&code).unwrap_or_else(|error| panic!("{body}: {error}"));
        crate::common::arkade_asm_tokens(&output, "spend")
    };

    for (plain, spaced) in [
        (
            "require(tx.assetGroups[g].outputs[1].amount >= 0);",
            "require(tx.assetGroups[ g ].outputs[ 1 // io\n ]. amount >= 0);",
        ),
        (
            "require(tx.assetGroups[g].outputs[g].type >= 0);",
            "require(tx.assetGroups[ g ].outputs[\tg ]. type >= 0);",
        ),
        (
            "require(tx.assetGroups[0].sumInputs >= tx.assetGroups[g].numOutputs);",
            "require(tx.assetGroups[ 0 ].sumInputs >= tx.assetGroups[ g ].numOutputs);",
        ),
        (
            "require(tx.assetGroups[g].outputs[1].amount >= 0);",
            "require(tx . assetGroups // groups\n [g] . outputs [1] . amount >= 0);",
        ),
        (
            "require(tx.assetGroups[0].sumInputs >= tx.assetGroups[g].numOutputs);",
            "require(tx.assetGroups [0] . sumInputs >= tx.assetGroups[g]\n.numOutputs);",
        ),
        (
            "require(tx.assetGroups.length >= g);",
            "require(tx . assetGroups . length >= g);",
        ),
        (
            "let x = tx.assetGroups.find(t, g); require(x == x);",
            "let x = tx.assetGroups . find(t, g); require(x == x);",
        ),
        (
            "require(tx.input.current.value >= g);",
            "require(tx . input . current . value >= g);",
        ),
    ] {
        assert_eq!(compile_body(plain), compile_body(spaced), "{spaced}");
    }
}

#[test]
fn group_input_fields_normalize_both_record_widths() {
    let output = compile(
        r#"
        contract GroupIOTest(pubkey owner) {
            function spend(signature sig) {
                require(checkSig(sig, owner));
                let amount = tx.assetGroups[0].inputs[0].amount;
                require(amount >= tx.assetGroups[0].inputs[1].index + tx.assetGroups[0].inputs[2].type);
            }
        }
    "#,
    )
    .expect("input record fields are single values");
    let asm = crate::common::arkade_asm(&output, "spend");
    assert_eq!(asm.matches("OP_0 OP_INSPECTASSETGROUP").count(), 3, "{asm}");
    assert_eq!(
        asm.matches("OP_SIZE 32 OP_EQUAL OP_IF OP_DROP OP_ENDIF")
            .count(),
        3,
        "{asm}"
    );
}

#[test]
fn only_input_records_have_a_txid() {
    let body = |record: &str| {
        format!("contract C(bytes32 t) {{ function spend() {{ require(tx.assetGroups[0].{record}[0].txid == t); }} }}")
    };
    let asm = crate::common::arkade_asm(&compile(&body("inputs")).expect("input txid"), "spend");
    assert!(asm.contains("OP_SIZE 32 OP_EQUALVERIFY OP_NIP"), "{asm}");
    let error = compile(&body("outputs"))
        .expect_err("outputs have no txid")
        .to_string();
    assert!(
        error.contains("asset group output records have no txid"),
        "{error}"
    );
}

/// Without a property, the raw (type, data..., amount) tuple isn't one
/// stack item and can't be bound either.
#[test]
fn test_group_io_access_without_property_is_rejected() {
    let code = r#"
        contract GroupIOTest(pubkey owner) {
            function spend(signature sig) {
                require(checkSig(sig, owner));
                let result = tx.assetGroups[0].outputs[0];
                require(result >= 0);
            }
        }
    "#;

    let error = compile(code)
        .expect_err("a raw group IO access must not bind a value")
        .to_string();
    assert!(error.contains("does not produce one stack item"), "{error}");
}

#[test]
fn test_group_access_as_constructor_argument_is_parsed() {
    let code = r#"
        contract T(int amount, pubkey owner) {
            function spend(signature sig) {
                require(checkSig(sig, owner));
                require(amount >= 0);
                require(tx.outputs[0].scriptPubKey == new T(tx.assetGroups[0].sumInputs, owner));
            }
        }
    "#;

    let error = compile(code)
        .expect_err("computed constructor arguments are rejected")
        .to_string();
    assert!(
        error.contains("computed contract arguments are not supported"),
        "{error}"
    );
    assert!(!error.contains("is undefined"), "{error}");
}

#[test]
fn inline_group_properties_emit_their_opcode() {
    for (property, opcode) in [
        ("numInputs", "OP_INSPECTASSETGROUPNUM"),
        ("numOutputs", "OP_INSPECTASSETGROUPNUM"),
        ("sumInputs", "OP_INSPECTASSETGROUPSUM"),
        ("sumOutputs", "OP_INSPECTASSETGROUPSUM"),
        (
            "delta",
            "OP_DUP OP_1 OP_INSPECTASSETGROUPSUM OP_SWAP OP_0 OP_INSPECTASSETGROUPSUM OP_SUB",
        ),
        ("hasControl", "OP_INSPECTASSETGROUPCTRL OP_NIP OP_NIP"),
        ("controlAssetId", "OP_INSPECTASSETGROUPCTRL OP_VERIFY"),
        ("metadataHash", "OP_INSPECTASSETGROUPMETADATAHASH"),
        ("assetId", "OP_INSPECTASSETGROUPASSETID"),
        (
            "isFresh",
            "OP_INSPECTASSETGROUPASSETID OP_DROP OP_TXID OP_EQUAL",
        ),
    ] {
        for group in ["tx.assetGroups[0]", "tx.assetGroups.find(t, 0)"] {
            let code = format!(
                "contract V(bytes32 t) {{ function spend() {{ let x = {group}.{property}; require(x == x); }} }}"
            );
            let output = compile(&code).unwrap_or_else(|error| panic!("{code}: {error}"));
            let asm = arkade_asm(&output, "spend");
            assert!(asm.contains(opcode), "{group}.{property}: {asm}");
        }
    }
}

#[test]
fn asset_groups_bind_pass_index_and_nest_like_other_values() {
    let code = r#"
        struct Watch { AssetGroup group; int floor; }
        contract V(bytes32 t) {
            function spend(AssetGroup g, AssetGroup[2] gs, int i, Watch w) {
                require(g.outputs[0].amount >= 0);
                require(gs[i].delta >= 0);
                require(gs[i].controlIs(t, 0));
                AssetGroup found = tx.assetGroups.find(t, 0);
                require(found.outputs[0].type >= 0);
                require(tx.assetGroups.find(t, 1).isFresh);
                require(tx.assetGroups[i].controlIs(t, 2));
                require(w.group.sumOutputs >= w.floor);
                for (k, h) in gs {
                    require(h.sumOutputs >= h.sumInputs);
                }
            }
        }
    "#;
    let output = compile(code).unwrap_or_else(|error| panic!("{error}"));
    let covenant = crate::common::group(&output, "spend")
        .arkade
        .as_ref()
        .unwrap();
    let types: Vec<_> = covenant
        .inputs
        .iter()
        .map(|input| input.param_type.as_str())
        .collect();
    assert_eq!(types, ["AssetGroup", "AssetGroup[2]", "int", "Watch"]);
    let asm = arkade_asm(&output, "spend");
    assert_eq!(asm.matches("OP_INSPECTASSETGROUPCTRL").count(), 2, "{asm}");
    assert_eq!(asm.matches("OP_INSPECTASSETGROUP ").count(), 2, "{asm}");
    assert_eq!(
        asm.matches("OP_FINDASSETGROUPBYASSETID").count(),
        2,
        "{asm}"
    );
}

#[test]
fn asset_groups_are_typed() {
    for (statement, expected) in [
        (
            "AssetGroup g = 0; require(g.delta == 0);",
            "binding 'g' declares type 'AssetGroup' but initializer has type 'int'",
        ),
        (
            "int k = tx.assetGroups.find(t, 0); require(k == 0);",
            "binding 'k' declares type 'int' but initializer has type 'AssetGroup'",
        ),
        (
            "AssetGroup g = tx.assetGroups[0]; require(g + 1 > 0);",
            "arithmetic '+' operand has type 'AssetGroup', expected 'int'",
        ),
        (
            "AssetGroup g = tx.assetGroups[0]; require(g > g);",
            "comparison '>' is not defined between 'AssetGroup' and 'AssetGroup'",
        ),
        (
            "AssetGroup g = tx.assetGroups[0]; require(tx.assetGroups[g].delta == 0);",
            "tx.assetGroups[] operand has type 'AssetGroup', expected 'int'",
        ),
        (
            "int g = 0; require(g.delta == 0);",
            "asset group property operand has type 'int', expected 'AssetGroup'",
        ),
    ] {
        let code = format!("contract V(bytes32 t) {{ function spend() {{ {statement} }} }}");
        let error = compile(&code).expect_err(statement).to_string();
        assert!(error.contains(expected), "{statement}: {error}");
    }
}
