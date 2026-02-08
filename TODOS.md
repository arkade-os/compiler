# Arkade Compiler — Remaining Tasks

## Current Status

- **Build:** Passing
- **Tests:** 67 passing, 0 failing
- **Commits 1-6:** Complete (core primitives)
- **Opcode Implementation:** Phase 1-6 Complete

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

### Specified in Docs but Missing from Examples

| Feature | API | Opcode | Notes |
|---------|-----|--------|-------|
| Find group by ID | `tx.assetGroups.find(assetId)` | `OP_FINDASSETGROUPBYASSETID` | Parser has `GroupFind`, not used in examples |
| Group control | `group.control` | `OP_INSPECTASSETGROUPCTRL k` | Parser has `GroupProperty`, not fully tested |
| Group delta | `group.delta` | `sumOutputs - sumInputs` via `OP_SUB64` | Parser ready, not used in examples |
| Metadata hash | `group.metadataHash` | `OP_INSPECTASSETGROUPMETADATAHASH k` | Parser has `GroupProperty` |
| Fresh check | `group.isFresh` | `OP_INSPECTASSETGROUPASSETID k` + `OP_TXID OP_EQUAL` | Not implemented |
| Group asset ID | `tx.assetGroups[k].assetId` | `OP_INSPECTASSETGROUPASSETID k` | Not implemented |

### Gap Summary

The PLAN.md Commit 2 example (`controlled_mint.ark`) specifies:

```solidity
let tokenGroup = tx.assetGroups.find(tokenAssetId);
require(tokenGroup.delta == amount, "delta mismatch");
require(tokenGroup.control == ctrlAssetId, "wrong control");
```

But the actual `examples/controlled_mint.ark` uses simpler asset lookups instead.

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

## Potential Future Work

1. **Update examples** to demonstrate full asset group API:
   - `tx.assetGroups.find(assetId)` for group discovery
   - `group.control` for control asset verification
   - `group.delta` for mint/burn detection

2. **Implement missing group features**:
   - `group.isFresh` → `OP_INSPECTASSETGROUPASSETID k` + `OP_TXHASH OP_EQUAL`
   - `group.assetId` → returns `(txid32, gidx_u16)` tuple

3. **Add ArkadeKitties-style contracts** to examples:
   - Commit-reveal breeding with oracle randomness
   - Metadata hash verification
   - Control asset enforcement for species validation

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
| **Total** | | **67/67** |

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
