# LayerZero / USDT0 Arkade Contracts

Arkade rendering of the LayerZero / USDT0 prototype originally implemented as
Go script builders in `layerzero-usdt0-arkade-demo` (see
`internal/scripts/builders.go` and `docs/contract-system.md` in that repo for
the full spec, plus `internal/protocol/types.go` for packet layouts).

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
   │   - continues Endpoint state                  │
   │   - mints 1 EndpointID asset → ReceiveMarker  │
   └───────────────────────────────────────────────┘
                              │
                              ▼
   ┌───────────────────────────────────────────────┐
   │ OApp.receive()                                │
   │   - consumes ReceiveMarker (burns EndpointID) │
   │   - continues OApp state                      │
   │   - mints USDT0 to credited recipient         │
   └───────────────────────────────────────────────┘

   ┌───────────────────────────────────────────────┐
   │ OApp.send()                                   │
   │   - burns USDT0                               │
   │   - continues OApp state                      │
   │   - mints 1 OAppID asset → SendMarker         │
   └───────────────────────────────────────────────┘
                              │
                              ▼
   ┌───────────────────────────────────────────────┐
   │ Endpoint.send()                               │
   │   - consumes SendMarker (burns OAppID)        │
   │   - continues Endpoint state                  │
   │   - emits LzSendPacket (outbound relay)       │
   └───────────────────────────────────────────────┘
```

## What is enforced in the Arkade contract vs. the introspector layer

The Arkade compiler renders the **asset-flow** and **signature** invariants
of the Go scripts directly. **Packet-level** invariants are enforced by the
introspector runtime that wraps the contract:

| Invariant class | Enforced in `.ark` | Notes |
|---|---|---|
| DVN 2-of-2 signature over receive hash | ✅ `checkSigFromStack` | The hash is computed off-chain by the relayer and passed as a witness |
| Endpoint/OApp state continuation | ✅ `tx.outputs[0].scriptPubKey == new ...` | Route is part of constructor params, so a recursive equality enforces preservation |
| Marker mint (1 unit) | ✅ `tx.outputs[i].assets.lookup(marker) == 1` + `group.sumOutputs == 1` | Combined output-asset and group-sum checks |
| Marker burn | ✅ `group.sumOutputs == 0` + input asset check | Mirrors `OP_INSPECTASSETGROUPSUM` on the Go side |
| USDT0 delta == credited amount | ✅ `usdt0Group.delta == amount` | Group delta = output sum − input sum |
| Marker pinned to consuming contract | ✅ control-asset singleton on consuming input | Defense-in-depth check from the Go marker scripts |
| Packet version / size / field layout | ⛔ delegated | Needs `OP_INSPECTPACKET` + `OP_SUBSTR`, not exposed in the Arkade compiler grammar |
| Inbound/outbound nonce monotonicity | ⛔ delegated | Needs packet-field extraction + `OP_BIN2NUM` |
| `sha256(OAppSendInvocation) == LzSend.guid` | ⛔ delegated | Needs packet introspection |
| Marker input position + Arkade-script-hash binding | ⛔ delegated | Needs `OP_PUSHCURRENTINPUTINDEX` equality + `OP_INSPECTINPUTARKADESCRIPTHASH` |

For the parts marked "delegated", the Go demo's `internal/scripts/builders.go`
remains the authoritative implementation. The Arkade contracts here are the
high-level surface that an Arkade-script-aware introspector runs alongside
those packet-level checks.

## Local checks

```bash
# build and run the layerzero contract tests
cargo test --test layerzero_test

# compile a single contract
cargo run -- examples/layerzero/endpoint.ark -o /tmp/endpoint.json

# refresh the playground bundle
./playground/generate_contracts.sh
```

The four contracts also show up under "LayerZero / USDT0" in the playground
sidebar once `./playground/build.sh` has been run.
