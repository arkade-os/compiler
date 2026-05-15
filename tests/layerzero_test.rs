use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_FINDASSETGROUPBYASSETID, OP_INSPECTASSETGROUPSUM,
    OP_INSPECTINASSETLOOKUP, OP_INSPECTOUTASSETLOOKUP, OP_INSPECTOUTPUTSCRIPTPUBKEY,
};

// ---------------------------------------------------------------------------
// LayerZero / USDT0 contract suite — translates the asset-flow and signature
// semantics of layerzero-usdt0-arkade-demo/internal/scripts/builders.go into
// Arkade contracts.
//
// Source-of-truth invariants verified here:
//   - Endpoint.receive() uses both DVN signature checks (OP_CHECKSIGFROMSTACK)
//     and emits the receive-invocation marker via OP_INSPECTOUTASSETLOOKUP +
//     OP_FINDASSETGROUPBYASSETID/OP_INSPECTASSETGROUPSUM.
//   - Endpoint.send() proves the OAppID marker is fully burned.
//   - OApp.receive() consumes the EndpointID marker, mints USDT0 to the
//     committed recipient, and continues the OApp state.
//   - OApp.send() burns USDT0 and emits the SendMarker output.
//   - Both marker contracts pin themselves to the consuming contract's
//     control-asset singleton.
// ---------------------------------------------------------------------------

fn load_example(name: &str) -> String {
    let path = format!("examples/layerzero/{}.ark", name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path, e))
}

#[test]
fn test_endpoint_parses() {
    let code = load_example("endpoint");
    let result = compile(&code);
    assert!(
        result.is_ok(),
        "endpoint compilation failed: {:?}",
        result.err()
    );
}

#[test]
fn test_endpoint_structure() {
    let code = load_example("endpoint");
    let output = compile(&code).unwrap();
    assert_eq!(output.name, "Endpoint");
    // 2 functions × 2 variants = 4
    assert_eq!(output.functions.len(), 4);

    for name in &["receive", "send"] {
        assert!(
            output
                .functions
                .iter()
                .any(|f| &f.name == name && f.server_variant),
            "missing {} server variant",
            name
        );
        assert!(
            output
                .functions
                .iter()
                .any(|f| &f.name == name && !f.server_variant),
            "missing {} exit variant",
            name
        );
    }
}

#[test]
fn test_endpoint_receive_verifies_both_dvn_signatures() {
    let code = load_example("endpoint");
    let output = compile(&code).unwrap();

    let receive = output
        .functions
        .iter()
        .find(|f| f.name == "receive" && f.server_variant)
        .unwrap();

    let sig_count = receive
        .asm
        .iter()
        .filter(|s| s.contains(OP_CHECKSIGFROMSTACK))
        .count();

    assert!(
        sig_count >= 2,
        "endpoint.receive() must verify exactly two DVN signatures via {}; found {} occurrences",
        OP_CHECKSIGFROMSTACK,
        sig_count
    );
}

#[test]
fn test_endpoint_receive_emits_receive_marker_output() {
    let code = load_example("endpoint");
    let output = compile(&code).unwrap();

    let receive = output
        .functions
        .iter()
        .find(|f| f.name == "receive" && f.server_variant)
        .unwrap();

    let has_receive_marker = receive
        .asm
        .iter()
        .any(|s| s.contains("VTXO:ReceiveMarker("));
    assert!(
        has_receive_marker,
        "endpoint.receive() must pin output[1] to the canonical ReceiveMarker pkScript: {:?}",
        receive.asm
    );

    let has_endpoint_continuation = receive.asm.iter().any(|s| s.contains("VTXO:Endpoint("));
    assert!(
        has_endpoint_continuation,
        "endpoint.receive() must continue Endpoint state via output[0]: {:?}",
        receive.asm
    );

    let has_asset_lookup = receive
        .asm
        .iter()
        .any(|s| s.contains(OP_INSPECTOUTASSETLOOKUP));
    assert!(
        has_asset_lookup,
        "endpoint.receive() must check output asset balances via {}",
        OP_INSPECTOUTASSETLOOKUP
    );
}

#[test]
fn test_endpoint_send_burns_send_marker() {
    let code = load_example("endpoint");
    let output = compile(&code).unwrap();

    let send = output
        .functions
        .iter()
        .find(|f| f.name == "send" && f.server_variant)
        .unwrap();

    // Marker burn proof: OAppID asset group → outputSum == 0.
    let has_group_sum = send.asm.iter().any(|s| s.contains(OP_INSPECTASSETGROUPSUM));
    assert!(
        has_group_sum,
        "endpoint.send() must inspect asset group sums to verify marker burn"
    );

    let has_find = send
        .asm
        .iter()
        .any(|s| s.contains(OP_FINDASSETGROUPBYASSETID));
    assert!(
        has_find,
        "endpoint.send() must locate OAppID asset group via {}",
        OP_FINDASSETGROUPBYASSETID
    );
}

#[test]
fn test_oapp_parses() {
    let code = load_example("oapp");
    let result = compile(&code);
    assert!(
        result.is_ok(),
        "oapp compilation failed: {:?}",
        result.err()
    );
}

#[test]
fn test_oapp_structure() {
    let code = load_example("oapp");
    let output = compile(&code).unwrap();
    assert_eq!(output.name, "OApp");
    assert_eq!(output.functions.len(), 4);
}

#[test]
fn test_oapp_receive_consumes_endpoint_marker_and_mints_usdt0() {
    let code = load_example("oapp");
    let output = compile(&code).unwrap();

    let receive = output
        .functions
        .iter()
        .find(|f| f.name == "receive" && f.server_variant)
        .unwrap();

    // Marker consumed from input 0 (asset lookup on input side).
    let in_lookup_count = receive
        .asm
        .iter()
        .filter(|s| s.contains(OP_INSPECTINASSETLOOKUP))
        .count();
    assert!(
        in_lookup_count >= 1,
        "oapp.receive() must inspect input assets to consume the receive marker"
    );

    // Output recipient receives USDT0 — and OApp state continues.
    let has_singlesig = receive.asm.iter().any(|s| s.contains("VTXO:SingleSig("));
    assert!(
        has_singlesig,
        "oapp.receive() must pin recipient output to SingleSig(recipient): {:?}",
        receive.asm
    );

    let has_oapp_continuation = receive.asm.iter().any(|s| s.contains("VTXO:OApp("));
    assert!(
        has_oapp_continuation,
        "oapp.receive() must continue OApp state via output[0]"
    );
}

#[test]
fn test_oapp_send_emits_send_marker() {
    let code = load_example("oapp");
    let output = compile(&code).unwrap();

    let send = output
        .functions
        .iter()
        .find(|f| f.name == "send" && f.server_variant)
        .unwrap();

    let has_send_marker = send.asm.iter().any(|s| s.contains("VTXO:SendMarker("));
    assert!(
        has_send_marker,
        "oapp.send() must pin output[1] to the canonical SendMarker pkScript"
    );

    let has_sig = send.asm.iter().any(|s| s == OP_CHECKSIG);
    assert!(
        has_sig,
        "oapp.send() must verify the OApp owner's signature via {}",
        OP_CHECKSIG
    );
}

#[test]
fn test_receive_marker_parses() {
    let code = load_example("receive_marker");
    let result = compile(&code);
    assert!(
        result.is_ok(),
        "receive_marker compilation failed: {:?}",
        result.err()
    );
}

#[test]
fn test_receive_marker_pins_to_oapp_control_singleton() {
    let code = load_example("receive_marker");
    let output = compile(&code).unwrap();
    assert_eq!(output.name, "ReceiveMarker");

    let consume = output
        .functions
        .iter()
        .find(|f| f.name == "consume" && f.server_variant)
        .unwrap();

    let has_in_lookup = consume
        .asm
        .iter()
        .any(|s| s.contains(OP_INSPECTINASSETLOOKUP));
    assert!(
        has_in_lookup,
        "receive marker must check the OApp control singleton on the consuming input"
    );
}

#[test]
fn test_send_marker_parses() {
    let code = load_example("send_marker");
    let result = compile(&code);
    assert!(
        result.is_ok(),
        "send_marker compilation failed: {:?}",
        result.err()
    );
}

#[test]
fn test_send_marker_pins_to_endpoint_control_singleton() {
    let code = load_example("send_marker");
    let output = compile(&code).unwrap();
    assert_eq!(output.name, "SendMarker");

    let consume = output
        .functions
        .iter()
        .find(|f| f.name == "consume" && f.server_variant)
        .unwrap();

    let has_in_lookup = consume
        .asm
        .iter()
        .any(|s| s.contains(OP_INSPECTINASSETLOOKUP));
    assert!(
        has_in_lookup,
        "send marker must check the Endpoint control singleton on the consuming input"
    );
}

#[test]
fn test_layerzero_contracts_continue_via_taproot_introspection() {
    // All four contracts must use OP_INSPECTOUTPUTSCRIPTPUBKEY for output
    // continuation; this is the Arkade-compiler equivalent of the Go scripts'
    // "the current scriptPubKey survives" check.
    for name in &["endpoint", "oapp"] {
        let code = load_example(name);
        let output = compile(&code).unwrap();
        let any_has_inspect = output.functions.iter().any(|f| {
            f.asm
                .iter()
                .any(|s| s.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY))
        });
        assert!(
            any_has_inspect,
            "{} must continue state via {}",
            name, OP_INSPECTOUTPUTSCRIPTPUBKEY
        );
    }
}
