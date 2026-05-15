# LayerZero / USDT0 Arkade Contracts

Arkade rendering of the LayerZero / USDT0 prototype originally implemented as
Go script builders in `layerzero-usdt0-arkade-demo` (see
`internal/scripts/builders.go` and `docs/contract-system.md` in that repo for
the full spec, plus `internal/protocol/types.go` for packet layouts).

These four contracts now use the canonical introspector opcode set
end-to-end — packet introspection (`tx.packet(...)`, `tx.inputs[i].packet(...)`),
byte slicing (`substr`, `cat`, `bin2num`, `size`), input arkade-script-hash
binding (`tx.inputs[i].arkadeScriptHash`), and inline SHA256
(`sha256(substr(...))`) — to enforce the full Go-script semantics on chain.
See `https://github.com/ArkLabsHQ/introspector` for the opcode reference.

## Contracts

| File | Role | Go counterpart |
|---|---|---|
| `endpoint.ark` | LayerZero Endpoint state + receive/send transitions | `BuildEndpointReceiveScript`, `BuildEndpointSendScript` |
| `oapp.ark` | USDT0 OApp state + receive/send transitions | `BuildOAppReceiveScript`, `BuildOAppSendScript` |
| `receive_marker.ark` | Endpoint→OApp invocation marker | `BuildReceiveInvocationScript` |
| `send_marker.ark` | OApp→Endpoint invocation marker | `BuildSendInvocationScript` |

## Flow

```
                 inbound LayerZero packet (DVN-attested)
                              │
                              ▼
   ┌───────────────────────────────────────────────┐
   │ Endpoint.receive()                            │
   │   - verifies both DVN signatures              │
   │   - checks LzReceive route fields, packet     │
   │     sizes, versions, and DVN attested-hash    │
   │     binding (sha256 of LzReceive header)      │
   │   - continues Endpoint state                  │
   │   - mints 1 EndpointID asset → ReceiveMarker  │
   └───────────────────────────────────────────────┘
                              │
                              ▼
   ┌───────────────────────────────────────────────┐
   │ OApp.receive()                                │
   │   - reads LzReceive from the marker's prev-Ark│
   │     tx (tx.inputs[0].packet)                  │
   │   - pins recipient output to credit message's │
   │     x-only key                                │
   │   - consumes ReceiveMarker (burns EndpointID) │
   │   - continues OApp state                      │
   │   - mints USDT0 = credit message amount       │
   └───────────────────────────────────────────────┘

   ┌───────────────────────────────────────────────┐
   │ OApp.send()                                   │
   │   - emits OAppSendInvocation packet           │
   │   - burns USDT0 by the invocation amount      │
   │   - continues OApp state                      │
   │   - mints 1 OAppID asset → SendMarker         │
   └───────────────────────────────────────────────┘
                              │
                              ▼
   ┌───────────────────────────────────────────────┐
   │ Endpoint.send()                               │
   │   - reads OAppSendInvocation from marker prev │
   │     tx via tx.inputs[1].packet                │
   │   - checks LzSend GUID = sha256(invocation)   │
   │   - per-field equality between invocation and │
   │     LzSend (sender, dstEID, receiver, amount, │
   │     remoteRecipient, messageHash)             │
   │   - consumes SendMarker (burns OAppID)        │
   │   - continues Endpoint state                  │
   └───────────────────────────────────────────────┘
```

## On-chain enforcement

Every check in the Go reference (`internal/scripts/builders.go`) is now
expressed in Arkade:

| Invariant class | Arkade construct | Underlying opcodes |
|---|---|---|
| DVN 2-of-2 signature over the canonical receive hash | `checkSigFromStackVerify(dvn*Sig, dvn*Pk, attestedHash)` | `OP_CHECKSIGFROMSTACKVERIFY` |
| Endpoint/OApp state continuation | `tx.outputs[0].scriptPubKey == new …` | `OP_INSPECTOUTPUTSCRIPTPUBKEY` + VTXO placeholder |
| Marker mint (1 unit) | `tx.outputs[i].assets.lookup(marker) == 1` + `group.sumOutputs == 1` | `OP_INSPECTOUTASSETLOOKUP`, `OP_INSPECTASSETGROUPSUM` |
| Marker burn | `group.sumOutputs == 0` | same |
| USDT0 delta == credited amount | `usdt0Group.delta == bin2num(substr(packet, off, 8))` | `OP_INSPECTASSETGROUPSUM`, `OP_SUBSTR`, `OP_BIN2NUM` |
| Marker pinned to consumer | `tx.inputs[i].arkadeScriptHash == expectedHash` | `OP_INSPECTINPUTARKADESCRIPTHASH` |
| Marker at expected input position | `this.activeInputIndex == k` | `OP_PUSHCURRENTINPUTINDEX` |
| Packet version | `substr(tx.packet(t), 0, 1) == 1` | `OP_INSPECTPACKET`, `OP_SUBSTR` |
| Packet size | `size(tx.packet(t)) == N` | `OP_INSPECTPACKET`, `OP_SIZE`, `OP_NIP` |
| Route preservation | `substr(tx.packet(t), off, len) == endpointID` | `OP_INSPECTPACKET`, `OP_SUBSTR`, `OP_EQUAL` |
| Numeric packet fields | `bin2num(substr(packet, off, 4))` | `OP_BIN2NUM` |
| DVN attested-hash binding | `sha256(substr(recv, 1, 140)) == attestedHash` | `OP_INSPECTPACKET`, `OP_SUBSTR`, `OP_SHA256` |
| LzSend GUID = sha256(invocation) | `sha256(substr(tx.inputs[1].packet(20), 0, 175)) == substr(tx.packet(19), 77, 32)` | `OP_INSPECTINPUTPACKET`, `OP_SHA256`, `OP_INSPECTPACKET`, `OP_SUBSTR` |

The only deliberately-deferred check is **nonce monotonicity** (inbound nonce
in next state = previous inbound nonce + 1, and the same for outbound on
`send`). Expressing that needs access to the *previous* Endpoint state
packet via `tx.inputs[currentInputIndex].packet(EndpointState)`, which the
introspector exposes but the compiler's parameterised input-packet form
needs a literal-or-witness index. The route-prefix hash check pins
endpointID/oappID/route/DVN-keys; combined with DVN-attested hash binding
to the LzReceive header, an attacker who tampers with the nonce field in
the next-state packet would need a valid DVN attestation over the
manipulated header — which they don't have. Adding the strict +1 check is
a small follow-up once `tx.inputs[currentInputIndex]` is wired.

## Local checks

```bash
# build and run the layerzero contract tests
cargo test --test layerzero_test
cargo test --test packet_primitives_test   # primitive opcode pinning

# compile a single contract
cargo run -- examples/layerzero/endpoint.ark -o /tmp/endpoint.json

# refresh the playground bundle
./playground/generate_contracts.sh
```

The four contracts also show up under "LayerZero / USDT0" in the playground
sidebar once `./playground/build.sh` has been run.
