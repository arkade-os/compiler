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
| DVN 2-of-2 signature over the canonical receive hash | `require(checkSigFromStack(dvn*Sig, dvn*Pk, attestedHash))` | `OP_CHECKSIGFROMSTACK` |
| Endpoint/OApp state continuation | `tx.outputs[0].scriptPubKey == tx.input.current.scriptPubKey` | `OP_INSPECTOUTPUTSCRIPTPUBKEY` + `OP_PUSHCURRENTINPUTINDEX` + `OP_INSPECTINPUTSCRIPTPUBKEY` |
| Marker output pinning | `tx.outputs[1].scriptPubKey == new ReceiveMarker(…)` | `OP_INSPECTOUTPUTSCRIPTPUBKEY` + VTXO placeholder |
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

## Witness convention

A few of the contract bodies reference identifiers that are neither
constructor parameters nor `let` bindings — `attestedHash`, `dvn0Sig`,
`dvn1Sig` in `Endpoint.receive()`. These are **prover-supplied witness
inputs** declared in the function signature; the Arkade compiler picks
them up from the parameter list and emits the matching `witnessSchema`
entries. The on-chain script then pins each witness to a canonical
packet-derived value before it is used:

- `attestedHash` is pinned twice — once against
  `sha256(substr(LzReceive, 1, 140))` (the on-chain reconstruction of
  the DVN-signed header) and once against `substr(DvnAttestation, 1, 32)`
  (the in-packet attested hash). Both DVN signatures verify over it.
- `dvn0Sig` / `dvn1Sig` are checked with `require(checkSigFromStack(...))` against
  the contract-baked DVN pubkeys (which are themselves pinned against the
  in-packet DVN pubkey slots in the Endpoint state).

This is the same pattern the existing examples use for hash preimages
(see `htlc.ark`'s `claim(preimage)` and `fuji_safe.ark`'s
`liquidate(currentPrice)`). The witness supplies an unverified value;
the contract body proves it equals the canonical on-chain value before
relying on it.

## Constructor decomposition

Some `bytes32` constructor parameters (`endpointCtrlAssetId`,
`endpointIDAssetId`, `oappIDAssetId`, `usdt0AssetId`) appear in the
generated JSON as `_txid` + `_gidx` pairs, while others
(`oappCtrlAssetId`, `endpointID`, `oappID`, `remoteOApp`) appear as
single `bytes32` values. This is by design: the compiler decomposes
only the asset IDs that are passed to `tx.{inputs,outputs}[i].assets.lookup(...)`
or to `tx.assetGroups.find(...)` inside the function bodies — those
need to be split into the `(txid32, gidx_u16)` pair the underlying
`OP_INSPECT*ASSETLOOKUP` / `OP_FINDASSETGROUPBYASSETID` opcodes consume.
`bytes32` params that only get passed through to a child constructor
(`new ReceiveMarker(oappCtrlAssetId, …)`) stay as a single 32-byte value.
The split shows up in the JSON but is invisible at the Arkade source level.

## Nonce monotonicity

The only deliberately-deferred check is **strict nonce monotonicity**
(inbound nonce in next state = previous inbound nonce + 1, and the same
for outbound on `send`). Expressing that needs access to the *previous*
Endpoint state packet via `tx.inputs[currentInputIndex].packet(EndpointState)`,
which the introspector exposes but the compiler's parameterised
input-packet form needs a literal-or-witness index.

**Off-chain safety net.** Replay of a DVN attestation is not actually
possible at the LayerZero protocol layer: each DVN signs over the
full LzReceive header, which includes the inbound nonce as one of its
fields. An on-chain replay would require a fresh DVN attestation over
the *new* (replayed) header at the next nonce slot — which honest DVNs
will not produce, since the source-chain event is single-use and the
DVN's signing rule binds (srcEID, sender, dstEID, receiver, nonce) to a
specific emitted event. The route-prefix hash check baked into Endpoint
pins endpointID/oappID/route/DVN-keys, so an attacker who tampers with
the nonce field in the next-state packet would need a valid DVN
attestation over the manipulated header — which they don't have.

Adding the strict +1 check is a small follow-up once
`tx.inputs[currentInputIndex]` is wired into the compiler grammar.

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
