use arkade_bindgen::artifact::load_artifact_str;
use arkade_bindgen::ir::{build_ir, Encoding};

fn load_fixture(name: &str) -> String {
    let path = format!(
        "{}/tests/fixtures/{}.json",
        env!("CARGO_MANIFEST_DIR"),
        name
    );
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to load fixture '{}': {}", path, e))
}

#[test]
fn test_ir_htlc_groups_and_order() {
    let ir = build_ir(&load_artifact_str(&load_fixture("htlc")).unwrap()).unwrap();

    assert_eq!(ir.name, "HTLC");
    assert_eq!(ir.constructor_fields.len(), 5);

    // Groups preserve artifact order.
    let names: Vec<&str> = ir.groups.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, ["claim", "refund", "unilateral"]);
}

#[test]
fn test_ir_constructor_field_encoding() {
    let ir = build_ir(&load_artifact_str(&load_fixture("htlc")).unwrap()).unwrap();

    let fields = &ir.constructor_fields;
    assert_eq!(fields[0].name, "sender");
    assert_eq!(fields[0].encoding, Encoding::Compressed33);
    assert_eq!(fields[1].name, "receiver");
    assert_eq!(fields[1].encoding, Encoding::Compressed33);
    assert_eq!(fields[2].name, "preimageHash");
    assert_eq!(fields[2].encoding, Encoding::Raw20);
    assert_eq!(fields[3].name, "refundTime");
    assert_eq!(fields[3].encoding, Encoding::ScriptNum);
}

#[test]
fn test_ir_covenant_group_leaf_and_injected_witness() {
    let ir = build_ir(&load_artifact_str(&load_fixture("htlc")).unwrap()).unwrap();

    let claim = ir.groups.iter().find(|g| g.name == "claim").unwrap();
    // Covenant-backed group carries an emulator covenant.
    assert!(
        claim.covenant.is_some(),
        "claim group should have a covenant"
    );
    assert_eq!(claim.leaves.len(), 1);

    let leaf = &claim.leaves[0];
    assert_eq!(leaf.name, "claim");
    // Full witness is preimage + two injected co-signer sigs.
    assert_eq!(leaf.witness_fields.len(), 3);
    // User supplies only the non-injected fields.
    let user: Vec<&str> = leaf.user_fields().iter().map(|f| f.name.as_str()).collect();
    assert_eq!(user, ["preimage"]);
    // serverSig / emulatorSig are marked injected.
    let injected: Vec<&str> = leaf
        .witness_fields
        .iter()
        .filter(|f| f.is_injected)
        .map(|f| f.name.as_str())
        .collect();
    assert_eq!(injected, ["serverSig", "emulatorSig"]);
}

#[test]
fn test_ir_standalone_leaf_group_has_no_covenant() {
    let ir = build_ir(&load_artifact_str(&load_fixture("htlc")).unwrap()).unwrap();

    let uni = ir.groups.iter().find(|g| g.name == "unilateral").unwrap();
    assert!(uni.covenant.is_none(), "standalone exit has no covenant");
    let leaf = &uni.leaves[0];
    let user: Vec<&str> = leaf.user_fields().iter().map(|f| f.name.as_str()).collect();
    assert_eq!(user, ["senderSig"]);
}

#[test]
fn test_ir_single_sig_contract() {
    let ir = build_ir(&load_artifact_str(&load_fixture("single_sig")).unwrap()).unwrap();

    assert_eq!(ir.name, "SingleSig");
    assert_eq!(ir.constructor_fields.len(), 2);
    let names: Vec<&str> = ir.groups.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, ["spend", "unilateral"]);
}

#[test]
fn test_encoding_roundtrip() {
    let encodings = vec![
        ("compressed-33", Encoding::Compressed33),
        ("schnorr-64", Encoding::Schnorr64),
        ("raw", Encoding::Raw),
        ("raw-20", Encoding::Raw20),
        ("raw-32", Encoding::Raw32),
        ("scriptnum", Encoding::ScriptNum),
        ("le64", Encoding::Le64),
        ("le32", Encoding::Le32),
    ];

    for (s, expected) in encodings {
        let parsed = Encoding::parse(s);
        assert_eq!(parsed, expected);
        assert_eq!(parsed.as_str(), s);
    }
}
