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
fn test_ir_htlc_pairing() {
    let json = load_fixture("htlc");
    let artifact = load_artifact_str(&json).unwrap();
    let ir = build_ir(&artifact).unwrap();

    assert_eq!(ir.name, "HTLC");
    assert_eq!(ir.constructor_fields.len(), 4);
    assert_eq!(ir.functions.len(), 3); // together, refund, claim

    // Verify function names and ordering
    assert_eq!(ir.functions[0].name, "together");
    assert_eq!(ir.functions[1].name, "refund");
    assert_eq!(ir.functions[2].name, "claim");
}

#[test]
fn test_ir_constructor_field_encoding() {
    let json = load_fixture("htlc");
    let artifact = load_artifact_str(&json).unwrap();
    let ir = build_ir(&artifact).unwrap();

    let fields = &ir.constructor_fields;
    assert_eq!(fields[0].name, "sender");
    assert_eq!(fields[0].encoding, Encoding::Compressed33);
    assert_eq!(fields[1].name, "receiver");
    assert_eq!(fields[1].encoding, Encoding::Compressed33);
    assert_eq!(fields[2].name, "hash");
    assert_eq!(fields[2].encoding, Encoding::Raw);
    assert_eq!(fields[3].name, "refundTime");
    assert_eq!(fields[3].encoding, Encoding::ScriptNum);
}

#[test]
fn test_ir_server_sig_excluded_from_user_fields() {
    let json = load_fixture("htlc");
    let artifact = load_artifact_str(&json).unwrap();
    let ir = build_ir(&artifact).unwrap();

    let claim = &ir.functions[2];
    assert_eq!(claim.name, "claim");

    // Cooperative: user gets receiverSig + preimage, serverSig is excluded
    assert_eq!(claim.cooperative.user_fields.len(), 2);
    assert_eq!(claim.cooperative.user_fields[0].name, "receiverSig");
    assert_eq!(claim.cooperative.user_fields[1].name, "preimage");

    // But all_fields includes serverSig
    assert_eq!(claim.cooperative.all_fields.len(), 3);
    assert!(claim.cooperative.all_fields[2].is_server_injected);
    assert_eq!(claim.cooperative.all_fields[2].name, "serverSig");

    // Exit: no serverSig at all
    assert_eq!(claim.exit.user_fields.len(), 2);
    assert_eq!(claim.exit.all_fields.len(), 2);
}

#[test]
fn test_ir_legacy_artifact_infers_encoding() {
    let json = load_fixture("htlc_legacy");
    let artifact = load_artifact_str(&json).unwrap();
    let ir = build_ir(&artifact).unwrap();

    let claim = &ir.functions[0];
    assert_eq!(claim.name, "claim");

    // Cooperative: inferred from functionInputs + added serverSig
    assert_eq!(claim.cooperative.user_fields.len(), 2);
    assert_eq!(
        claim.cooperative.user_fields[0].encoding,
        Encoding::Schnorr64
    );
    assert_eq!(claim.cooperative.user_fields[1].encoding, Encoding::Raw);

    // serverSig should be added for cooperative variant
    assert_eq!(claim.cooperative.all_fields.len(), 3);
    assert!(claim.cooperative.all_fields[2].is_server_injected);

    // Exit: no serverSig
    assert_eq!(claim.exit.user_fields.len(), 2);
    assert_eq!(claim.exit.all_fields.len(), 2);
}

#[test]
fn test_ir_single_function_contract() {
    let json = load_fixture("single_sig");
    let artifact = load_artifact_str(&json).unwrap();
    let ir = build_ir(&artifact).unwrap();

    assert_eq!(ir.name, "SingleSig");
    assert_eq!(ir.constructor_fields.len(), 1);
    assert_eq!(ir.functions.len(), 1);
    assert_eq!(ir.functions[0].name, "spend");
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
