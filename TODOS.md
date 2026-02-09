# Arkade Compiler — Remaining Tasks

## Current Status

- **Build:** Passing
- **Tests:** 81 passing, 0 failing
- **Commits 1-6:** Complete (core primitives)
- **Opcode Implementation:** Phase 1-7 Complete

---

## Completed Work

### Commit 4 — If/Else + Variable Reassignment

- `if_stmt`, `block`, `var_assign` rules
- `OP_IF`/`OP_ELSE`/`OP_ENDIF` emission
- Tests: `epoch_limiter_test.rs` (8 tests)

### Commit 5 — For Loops (Compile-Time Unrolled)

- `for_stmt` rule, `Statement::ForIn`
- Loop unrolling over `tx.assetGroups`
- Group property substitution (`sumInputs`, `sumOutputs`)
- Tests: `beacon_test.rs` (5 tests)

### Commit 6 — Array Types + Indexing

- Array type flattening in constructor/function ABI
- `arr[i]` indexing resolution during loop unrolling
- Loop unrolling over array variables
- Tests: `threshold_oracle_test.rs` (9 tests)

### Phase 1 — .assets APIs (NEW)

- `tx.outputs[o].assets.length` → `OP_INSPECTOUTASSETCOUNT`
- `tx.inputs[i].assets.length` → `OP_INSPECTINASSETCOUNT`
- `tx.outputs[o].assets[t].assetId` → `OP_INSPECTOUTASSETAT`
- `tx.outputs[o].assets[t].amount` → `OP_INSPECTOUTASSETAT`
- `tx.inputs[i].assets[t].assetId` → `OP_INSPECTINASSETAT`
- `tx.inputs[i].assets[t].amount` → `OP_INSPECTINASSETAT`
- Tests: `asset_introspection_test.rs` (6 tests)

### Phase 2 — Transaction Introspection (NEW)

- `tx.version` → `OP_INSPECTVERSION`
- `tx.locktime` → `OP_INSPECTLOCKTIME`
- `tx.numInputs` → `OP_INSPECTNUMINPUTS`
- `tx.numOutputs` → `OP_INSPECTNUMOUTPUTS`
- `tx.weight` → `OP_TXWEIGHT`
- Tests: `tx_introspection_test.rs` (5 tests)

### Phase 3 — Indexed Input/Output Introspection (NEW)

- `tx.inputs[i].value` → `OP_INSPECTINPUTVALUE`
- `tx.inputs[i].scriptPubKey` → `OP_INSPECTINPUTSCRIPTPUBKEY`
- `tx.inputs[i].sequence` → `OP_INSPECTINPUTSEQUENCE`
- `tx.inputs[i].outpoint` → `OP_INSPECTINPUTOUTPOINT`
- `tx.inputs[i].issuance` → `OP_INSPECTINPUTISSUANCE`
- `tx.outputs[o].value` → `OP_INSPECTOUTPUTVALUE`
- `tx.outputs[o].scriptPubKey` → `OP_INSPECTOUTPUTSCRIPTPUBKEY`
- `tx.outputs[o].nonce` → `OP_INSPECTOUTPUTNONCE`
- Tests: `io_introspection_test.rs` (11 tests)

---

## API Spec Alignment Analysis

Comparing examples to `arkade-script-with-assets.md` and `ArkadeKitties.md`:

### Currently Implemented & Used in Examples

| Feature | API | Opcode | Used In |
|---------|-----|--------|---------|
| Input asset lookup | `tx.inputs[i].assets.lookup(assetId)` | `OP_INSPECTINASSETLOOKUP` | token_vault, controlled_mint, fee_adapter |
| Output asset lookup | `tx.outputs[o].assets.lookup(assetId)` | `OP_INSPECTOUTASSETLOOKUP` | token_vault, controlled_mint |
| Group sum (inputs) | `tx.assetGroups[k].sumInputs` | `OP_INSPECTASSETGROUPSUM k 0` | beacon |
| Group sum (outputs) | `tx.assetGroups[k].sumOutputs` | `OP_INSPECTASSETGROUPSUM k 1` | beacon |
| Group count | `tx.assetGroups.length` | `OP_INSPECTNUMASSETGROUPS` | (parser ready) |

### Now Fully Implemented & Demonstrated in Examples

| Feature        | API                              | Opcode                                             | Used In                                   |
|----------------|----------------------------------|----------------------------------------------------|-------------------------------------------|
| Find group     | `tx.assetGroups.find(assetId)`   | `OP_FINDASSETGROUPBYASSETID`                       | controlled_mint, nft_mint, arkade_kitties |
| Group control  | `group.control`                  | `OP_INSPECTASSETGROUPCTRL k`                       | controlled_mint, nft_mint, arkade_kitties |
| Group delta    | `group.delta`                    | `sumOutputs - sumInputs` via `OP_SUB64`            | controlled_mint, nft_mint, arkade_kitties |
| Metadata hash  | `group.metadataHash`             | `OP_INSPECTASSETGROUPMETADATAHASH k`               | arkade_kitties                            |
| Fresh check    | `group.isFresh`                  | `OP_INSPECTASSETGROUPASSETID k` + `OP_TXHASH`      | nft_mint, arkade_kitties                  |
| Group asset ID | `tx.assetGroups[k].assetId`      | `OP_INSPECTASSETGROUPASSETID k`                    | group_properties_test                     |

### Gap Summary

All asset group features are now implemented and tested. The `examples/controlled_mint.ark` now uses the full asset group API including `find()`, `delta`, and `control` properties.

### Phase 4 — Streaming SHA256

- `sha256Initialize(data)` → `OP_SHA256INITIALIZE`
- `sha256Update(ctx, chunk)` → `OP_SHA256UPDATE`
- `sha256Finalize(ctx, lastChunk)` → `OP_SHA256FINALIZE`
- Tests: `new_opcodes_test.rs` (3 tests + 1 workflow test)

### Phase 5 — Conversion & Arithmetic

- `neg64(value)` → `OP_NEG64`
- `le64ToScriptNum(value)` → `OP_LE64TOSCRIPTNUM`
- `le32ToLe64(value)` → `OP_LE32TOLE64`
- Tests: `new_opcodes_test.rs` (3 tests + 1 chain test)

### Phase 6 — Crypto Opcodes

- `ecMulScalarVerify(k, P, Q)` → `OP_ECMULSCALARVERIFY`
- `tweakVerify(P, k, Q)` → `OP_TWEAKVERIFY`
- `checkSigFromStackVerify(sig, pk, msg)` → `OP_CHECKSIGFROMSTACKVERIFY`
- Tests: `new_opcodes_test.rs` (3 tests)

---

### Phase 7 — Group Properties & Examples

- `group.isFresh` → `OP_INSPECTASSETGROUPASSETID` + `OP_DROP` + `OP_TXHASH` + `OP_EQUAL`
- `group.assetId` → `OP_INSPECTASSETGROUPASSETID` (returns txid32, gidx_u16 tuple)
- New example: `nft_mint.ark` (NFT minting with isFresh/delta/control)
- New example: `arkade_kitties.ark` (breeding with metadataHash/isFresh/control)
- Tests: `group_properties_test.rs` (6 tests), `arkade_kitties_test.rs` (9 tests)

---

## Potential Future Work

All originally planned features are now complete. Potential extensions:

1. **Additional example contracts** for other use cases
2. **Loop unrolling with isFresh** in for-loop contexts
3. **Tuple destructuring** for `group.assetId` (txid, gidx) pairs

---

## Test Summary

| Commit | Feature | Tests |
|--------|---------|-------|
| 1 | Asset Lookups | 2/2 |
| 2 | Asset Groups | 2/2 |
| 3 | Arithmetic | 2/2 |
| 4 | If/Else | 8/8 |
| 5 | For Loops | 5/5 |
| 6 | Arrays | 9/9 |
| Phase 1 | .assets APIs | 6/6 |
| Phase 2 | Tx Introspection | 5/5 |
| Phase 3 | I/O Introspection | 11/11 |
| Phase 4 | Streaming SHA256 | 4/4 |
| Phase 5 | Conversion & Arithmetic | 4/4 |
| Phase 6 | Crypto Opcodes | 3/3 |
| Phase 7 | Group Properties (isFresh, assetId) | 6/6 |
| Phase 7 | ArkadeKitties Example | 9/9 |
| **Total** | | **81/81** |

---

## Test Commands

```bash
# Run all tests
cargo test

# Run specific test
cargo test --test beacon_test

# Run with output
cargo test --test beacon_test -- --nocapture
```
