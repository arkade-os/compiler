use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_FINDASSETGROUPBYASSETID, OP_INSPECTASSETGROUPSUM,
    OP_INSPECTINASSETLOOKUP, OP_INSPECTINPUTARKADESCRIPTHASH, OP_INSPECTINPUTPACKET,
    OP_INSPECTINPUTSCRIPTPUBKEY, OP_INSPECTOUTASSETLOOKUP, OP_INSPECTOUTPUTSCRIPTPUBKEY,
    OP_INSPECTPACKET, OP_PUSHCURRENTINPUTINDEX, OP_SHA256, OP_SUBSTR,
};

/// Assert the recursive-covenant continuation pattern: the function's asm must
/// contain `OP_INSPECTOUTPUTSCRIPTPUBKEY OP_PUSHCURRENTINPUTINDEX
/// OP_INSPECTINPUTSCRIPTPUBKEY`, i.e. output[k].scriptPubKey is pinned to the
/// spent input's own pkScript (mirrors the Go reference's state-continuation
/// check in BuildEndpointReceiveScript / BuildOAppReceiveScript).
fn has_self_continuation(asm: &[String]) -> bool {
    asm.windows(3).any(|w| {
        w[0] == OP_INSPECTOUTPUTSCRIPTPUBKEY
            && w[1] == OP_PUSHCURRENTINPUTINDEX
            && w[2] == OP_INSPECTINPUTSCRIPTPUBKEY
    })
}

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

    // Both DVNs are verified via require(checkSigFromStack(...)) — the
    // introspector has no OP_CHECKSIGFROMSTACKVERIFY variant, so the contract
    // uses the plain opcode wrapped in require(). The signed message is the
    // prover-supplied attestedHash, pinned on chain to both the LzReceive
    // header hash and the DvnAttestation packet field.
    let sig_count = receive
        .asm
        .iter()
        .filter(|s| *s == OP_CHECKSIGFROMSTACK)
        .count();

    assert!(
        sig_count >= 2,
        "endpoint.receive() must verify both DVN signatures via {}; found {} occurrences",
        OP_CHECKSIGFROMSTACK,
        sig_count
    );
}

#[test]
fn test_endpoint_receive_uses_packet_introspection() {
    // The packet-native rewrite must use OP_INSPECTPACKET, OP_SUBSTR, and
    // OP_SHA256 to enforce route, version, size, and the DVN attested-hash
    // binding to the LzReceive header.
    let code = load_example("endpoint");
    let output = compile(&code).unwrap();
    let receive = output
        .functions
        .iter()
        .find(|f| f.name == "receive" && f.server_variant)
        .unwrap();

    for op in [OP_INSPECTPACKET, OP_SUBSTR, OP_SHA256] {
        assert!(
            receive.asm.iter().any(|s| s == op),
            "endpoint.receive() must use {} for native packet enforcement",
            op
        );
    }
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

    assert!(
        has_self_continuation(&receive.asm),
        "endpoint.receive() must continue Endpoint state via the recursive \
         covenant (output pkScript == current input pkScript): {:?}",
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
    assert!(
        receive
            .asm
            .iter()
            .any(|s| s.contains(OP_INSPECTINASSETLOOKUP)),
        "oapp.receive() must inspect input assets to consume the receive marker"
    );

    // Previous-tx packet introspection (OP_INSPECTINPUTPACKET) is now used
    // to read the LzReceivePacket from the marker input.
    assert!(
        receive.asm.iter().any(|s| s == OP_INSPECTINPUTPACKET),
        "oapp.receive() must read the LzReceive packet via {}",
        OP_INSPECTINPUTPACKET
    );

    // The recipient output's scriptPubKey is pinned to the credit message
    // x-only key via OP_INSPECTOUTPUTSCRIPTPUBKEY + OP_SUBSTR.
    assert!(
        receive
            .asm
            .iter()
            .any(|s| s.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY)),
        "oapp.receive() must pin recipient output scriptPubKey"
    );

    assert!(
        has_self_continuation(&receive.asm),
        "oapp.receive() must continue OApp state via the recursive covenant \
         (output pkScript == current input pkScript)"
    );
}

#[test]
fn test_marker_contracts_use_input_arkade_script_hash() {
    // Both invocation marker contracts now bind themselves to a specific
    // consumer closure via OP_INSPECTINPUTARKADESCRIPTHASH, mirroring the Go
    // reference (BuildReceiveInvocationScript / BuildSendInvocationScript).
    for name in &["receive_marker", "send_marker"] {
        let code = load_example(name);
        let output = compile(&code).unwrap();
        let consume = output
            .functions
            .iter()
            .find(|f| f.name == "consume" && f.server_variant)
            .unwrap();
        assert!(
            consume
                .asm
                .iter()
                .any(|s| s == OP_INSPECTINPUTARKADESCRIPTHASH),
            "{}.consume() must check the consumer's Arkade-script hash via {}",
            name,
            OP_INSPECTINPUTARKADESCRIPTHASH
        );
        assert!(
            consume.asm.iter().any(|s| s == OP_PUSHCURRENTINPUTINDEX),
            "{}.consume() must pin its own input position via {}",
            name,
            OP_PUSHCURRENTINPUTINDEX
        );
    }
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

    // The only OP_CHECKSIG in the server variant must be the server cosign
    // added by the compiler — there is NO contract-level owner sig (mirrors
    // BuildOAppSendScript). Authority comes from the OApp control singleton
    // and the per-UTXO USDT0 input scripts.
    let server_key_pos = send
        .asm
        .iter()
        .position(|s| s == "<SERVER_KEY>")
        .expect("server variant must contain <SERVER_KEY>");
    let checksigs_before_server: usize = send
        .asm
        .iter()
        .take(server_key_pos)
        .filter(|s| *s == OP_CHECKSIG)
        .count();
    assert_eq!(
        checksigs_before_server, 0,
        "oapp.send() must not perform a contract-level owner signature check; \
         found {} OP_CHECKSIG before <SERVER_KEY>",
        checksigs_before_server
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
