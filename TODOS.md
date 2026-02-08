# Arkade Compiler — Remaining Tasks

## Current Status

- **Build:** Passing
- **Tests:** 33 passing, 0 failing
- **Commits 1-6:** Complete

---

## Commit 4 — If/Else + Variable Reassignment

**Status:** Complete

### Grammar/Parser/AST: DONE
- `if_stmt`, `block`, `var_assign` rules in grammar.pest
- `Statement::IfElse`, `Statement::VarAssign` in models
- Parser handles if/else and variable assignment

### Compiler Codegen: DONE
- [x] `OP_IF`/`OP_ELSE`/`OP_ENDIF` emission
- [x] Recursive codegen for branches

### Test: `tests/epoch_limiter_test.rs`
- 8 tests passing

---

## Commit 5 — For Loops (Compile-Time Unrolled)

**Status:** Complete

### Grammar/Parser/AST: DONE
- `for_stmt` rule in grammar.pest
- `Statement::ForIn` in models
- Parser handles `for (k, group) in iterable { body }`

### Compiler Codegen: DONE
- [x] Recognize `tx.assetGroups` as iterable
- [x] Default to 3 iterations for unrolling
- [x] Unroll loop body N times
- [x] Substitute `index_var` with literal 0, 1, 2, ...
- [x] Transform `group.sumOutputs` → `Expression::GroupSum { index: k, source: Outputs }`
- [x] Transform `group.sumInputs` → `Expression::GroupSum { index: k, source: Inputs }`

### Test: `tests/beacon_test.rs`
- 5 tests passing

---

## Commit 6 — Array Types + Indexing

**Status:** Complete

### Grammar/Parser/AST: DONE
- `data_type` allows `[]` suffix in grammar.pest
- `Expression::ArrayIndex`, `Expression::ArrayLength` in models
- Parser handles array types and indexing

### Compiler Codegen: DONE
- [x] Array type flattening in constructor ABI (e.g., `pubkey[] oracles` → `oracles_0`, `oracles_1`, `oracles_2`)
- [x] Array type flattening in function witness ABI (e.g., `signature[] sigs` → `sigs_0`, `sigs_1`, `sigs_2`)
- [x] `arr[i]` indexing (resolve to `arr_{i}` when `i` is literal/unrolled)
- [x] Loop unrolling over array variables (not just `tx.assetGroups`)

### Test: `tests/threshold_oracle_test.rs`
- 9 tests passing

---

## Summary

| Commit | Feature | Parser | Compiler | Tests |
|--------|---------|--------|----------|-------|
| 1 | Asset Lookups | DONE | DONE | 2/2 |
| 2 | Asset Groups | DONE | DONE | 2/2 |
| 3 | Arithmetic | DONE | DONE | 2/2 |
| 4 | If/Else | DONE | DONE | 8/8 |
| 5 | For Loops | DONE | DONE | 5/5 |
| 6 | Arrays | DONE | DONE | 9/9 |

---

## Files Modified

| File | Changes |
|------|---------|
| `src/compiler/mod.rs` | Array flattening, loop unrolling over arrays, array index substitution |

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
