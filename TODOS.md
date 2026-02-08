# Arkade Compiler — Remaining Tasks

## Current Status

- **Build:** Passing
- **Tests:** 33 passing, 0 failing
- **Commits 1-6:** Complete (core primitives)

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

---

## Potential Future Work

1. **Update examples** to demonstrate full asset group API:
   - `tx.assetGroups.find(assetId)` for group discovery
   - `group.control` for control asset verification
   - `group.delta` for mint/burn detection

2. **Implement missing features**:
   - `group.isFresh` -> `OP_INSPECTASSETGROUPASSETID k` + txid comparison
   - `group.assetId` -> returns `(txid32, gidx_u16)` tuple

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
| **Total** | | **28/28** |

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
