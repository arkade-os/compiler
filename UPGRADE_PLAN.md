# Arkade Compiler v1.0 Upgrade Plan

## Executive Summary

The Arkade Compiler has a solid foundation but requires significant work before a v1.0 release. This document outlines **38 issues** across 7 categories, prioritized for developer action.

**Current State:**
- Build: **PASSES** (with 4 warnings)
- Tests: **FAIL** (broken imports from legacy renaming)
- Core functionality: Working for basic contracts
- Production readiness: **NOT READY**

---

## Priority 1: Critical Blockers

These issues **MUST** be fixed before any other work. Tests cannot run.

### 1.1 Test Configuration Broken

| Issue | File | Problem |
|-------|------|---------|
| Wrong import | `tests/*.rs:1` | Uses `use taplang::compile;` instead of `use arkade_compiler::compile;` |
| Missing lib config | `Cargo.toml` | No `[lib]` section defined |
| Wrong binary name | `tests/htlc_test.rs:173` | References `CARGO_BIN_EXE_tapc` instead of `arkadec` |
| Legacy extension | `tests/htlc_test.rs:130` | Creates `htlc.tap` file instead of `htlc.ark` |

**Fix (estimated effort: 30 minutes):**
```toml
# Add to Cargo.toml
[lib]
name = "arkade_compiler"
path = "src/lib.rs"
```

```rust
// Change in all test files
use arkade_compiler::compile;
```

---

## Priority 2: Specification Violations (Bugs)

These issues cause the compiler to behave contrary to documented specification.

### 2.1 Internal Functions Generate Spending Paths

**Location:** `src/compiler/mod.rs:74-82`

**Problem:** Functions marked `internal` should NOT generate spending paths, but currently they do.

**Current Code:**
```rust
for function in &contract.functions {
    let collaborative_function = generate_function(function, &contract, true);
    json.functions.push(collaborative_function);
    // ... always adds both variants
}
```

**Required Fix:**
```rust
for function in &contract.functions {
    if function.is_internal {
        continue; // Skip internal functions
    }
    // ...
}
```

**Impact:** Contracts with internal helper functions produce incorrect output with extra spending paths.

### 2.2 Compiler Name Not Updated

**Location:** `src/compiler/mod.rs:67`

**Problem:** Output JSON contains `"compiler": {"name": "taplang"}` instead of `"arkade-compiler"`.

### 2.3 TapLangParser Not Renamed

**Location:** `src/parser/mod.rs:9`, `src/parser/debug.rs:8`

**Problem:** Parser struct still named `TapLangParser` instead of `ArkadeParser`.

---

## Priority 3: Error Handling (Crashes → Errors)

The parser **crashes** on unexpected input instead of returning user-friendly errors.

### 3.1 Panics in Parser (5 locations)

| Line | Code | Better Approach |
|------|------|-----------------|
| `parser/mod.rs:264` | `panic!("Unexpected left expression...")` | Return `Err("...")` |
| `parser/mod.rs:274` | `panic!("Unexpected right expression...")` | Return `Err("...")` |
| `parser/mod.rs:301` | `panic!("Unexpected left expression...")` | Return `Err("...")` |
| `parser/mod.rs:307` | `panic!("Unexpected right expression...")` | Return `Err("...")` |
| `parser/mod.rs:390` | `panic!("Unexpected rule...")` | Return `Err("...")` |

**Developer Impact:** Contract with unexpected syntax crashes entire CLI instead of showing error.

### 3.2 Unchecked Unwraps (34 locations)

The parser uses `.unwrap()` on parsing results without checking if tokens exist.

**Example Problem:**
```rust
// Current (crashes if no parameter)
let param_type = param_inner.next().unwrap().as_str().to_string();

// Better (returns error)
let param_type = param_inner.next()
    .ok_or("Expected parameter type")?
    .as_str().to_string();
```

**High-Risk Lines:** 57, 62, 65, 69-70, 93-94, 130, 133, 137-138

---

## Priority 4: Incomplete Features

Features that are parsed but silently ignored.

### 4.1 Variable Declarations Ignored

**Location:** `src/parser/mod.rs:186-189`

```rust
Rule::variable_declaration => {
    // In a more complete implementation, we would handle variable declarations
    // For now, we just ignore them
}
```

**Impact:** This Arkade code compiles but the variable is ignored:
```solidity
function example() {
    bytes32 myHash = sha256(preimage);  // <- SILENTLY IGNORED
    require(myHash == expectedHash);
}
```

### 4.2 Function Calls Ignored

**Location:** `src/parser/mod.rs:182-185`

```rust
Rule::function_call_stmt => {
    // In a more complete implementation, we would handle function calls
    // For now, we just ignore them
}
```

**Impact:** Internal function calls are silently dropped.

### 4.3 Custom Error Messages Discarded

**Location:** `src/parser/mod.rs:178`

```rust
let _message = inner.next().unwrap().as_str().to_string();  // Underscore = unused
```

**Impact:** Developer-provided error messages in `require()` are thrown away.

---

## Priority 5: Assembly Generation Issues

### 5.1 Incorrect Operand Order

**Location:** `src/compiler/mod.rs:243-247`

```rust
// Current (WRONG order for Bitcoin Script)
(Expression::Variable(var), "==", Expression::Variable(var2)) => {
    asm.push(format!("<{}>", var));   // left
    asm.push("OP_EQUAL".to_string()); // operator first!
    asm.push(format!("<{}>", var2));  // right after operator
}
```

**Bitcoin Script requires:** `<left> <right> OP_EQUAL`

### 5.2 Silent Fallback to OP_FALSE

**Location:** `src/compiler/mod.rs:421-424`

```rust
_ => {
    // Default handling for unmatched patterns
    asm.push("OP_FALSE".to_string());
}
```

**Impact:** Unknown expression patterns silently generate `OP_FALSE` instead of erroring.

### 5.3 Unknown CurrentInput Properties Default Silently

**Location:** `src/compiler/mod.rs:408-411`

```rust
_ => {
    // Default to script pubkey for unknown properties
    asm.push("OP_INPUTBYTECODE".to_string());
}
```

**Impact:** `tx.input.current.unknownProperty` compiles without error.

### 5.4 P2TR Constructor Not Properly Compiled

**Location:** `src/parser/mod.rs:312-321`

P2TR constructors are converted to dummy comparisons and lose semantic meaning.

---

## Priority 6: Code Quality

### 6.1 Compiler Warnings (4)

```
warning: unused import: `std::error::Error` (src/main.rs:3)
warning: struct `Operation` is never constructed (src/models/mod.rs:58)
warning: struct `ScriptPath` is never constructed (src/models/mod.rs:65)
warning: variant `Sha256` is never constructed (src/models/mod.rs:158)
```

### 6.2 Large Function Needs Refactoring

**Location:** `src/compiler/mod.rs:191-430`

`generate_base_asm_instructions()` is 240 lines with 40+ match arms. Should be split into:
- `generate_checksig_asm()`
- `generate_comparison_asm()`
- `generate_timelock_asm()`
- `generate_hash_asm()`

### 6.3 Dead Code to Remove

| Item | Location | Action |
|------|----------|--------|
| `Operation` struct | `models/mod.rs:58-61` | Remove |
| `ScriptPath` struct | `models/mod.rs:65-73` | Remove |
| `Expression::Sha256` | `models/mod.rs:158` | Remove (never constructed) |

---

## Priority 7: Documentation

### 7.1 Parser Module Undocumented

**Location:** `src/parser/mod.rs`

**Stats:**
- `lib.rs`: 50 doc comments
- `compiler/mod.rs`: 51 doc comments
- `models/mod.rs`: 54 doc comments
- `parser/mod.rs`: **0 doc comments**

**Functions needing docs:**
- `parse()` - Entry point
- `build_ast()` - AST construction
- `parse_contract()` - Contract parsing
- `parse_function()` - Function parsing
- `parse_complex_expression()` - 15 rule types

### 7.2 Outdated References in Documentation

| File | Line | Issue |
|------|------|-------|
| `src/lib.rs:7` | Doc mentions "TapLang" | Should say "Arkade Script" |
| `src/lib.rs:32` | Example uses `taplang` | Should use `arkade_compiler` |
| `src/models/mod.rs:101` | Mentions "TapLang contract" | Should say "Arkade Script" |

---

## Priority 8: Security & Validation

### 8.1 No Input Size Limits

**Location:** `src/main.rs:60`

```rust
let source = fs::read_to_string(&source_path)?;  // No size check
```

**Risk:** Memory exhaustion with large files.

### 8.2 No Parameter Name Validation

Parameter names aren't validated against:
- Reserved words (`function`, `contract`, etc.)
- Bitcoin Script restrictions
- Conflicting identifiers

### 8.3 No Server Key Validation

**Location:** `src/compiler/mod.rs:103-108`

`server_key_param` isn't validated to exist in contract parameters.

---

## Priority 9: Test Coverage Gaps

### 9.1 Missing Test Cases

| Test Type | Description |
|-----------|-------------|
| Internal functions | Verify internal functions don't generate paths |
| Negative tests | Invalid syntax, missing options, etc. |
| Edge cases | Empty functions, 0 parameters, etc. |
| Assembly correctness | Verify actual Bitcoin Script semantics |

### 9.2 Test Assertion Bug

**Location:** `tests/bare_vtxo_test.rs:85`

```rust
assert_eq!(timeout_function.asm[3], "0");  // Wrong! Should be "144"
```

---

## Implementation Roadmap

### Phase 1: Foundation (Required for Testing)
- [ ] Add `[lib]` section to Cargo.toml
- [ ] Fix test imports (`taplang` → `arkade_compiler`)
- [ ] Fix CLI test binary reference
- [ ] Update file extensions in tests

### Phase 2: Correctness (Specification Compliance)
- [ ] Filter internal functions from output
- [ ] Update compiler name to `arkade-compiler`
- [ ] Rename `TapLangParser` to `ArkadeParser`
- [ ] Fix assembly operand order

### Phase 3: Robustness (Error Handling)
- [ ] Replace panics with Result returns
- [ ] Add proper error messages for unwraps
- [ ] Remove silent OP_FALSE fallback
- [ ] Validate server key exists in parameters

### Phase 4: Code Quality
- [ ] Remove dead code (Operation, ScriptPath, Sha256)
- [ ] Fix compiler warnings
- [ ] Refactor large match statement
- [ ] Add parser documentation

### Phase 5: Features (Nice to Have)
- [ ] Implement variable declarations
- [ ] Implement function calls
- [ ] Preserve custom error messages
- [ ] Add input size limits

---

## Verification Checklist

Before v1.0 release, verify:

```bash
# All tests pass
cargo test

# No warnings
cargo build 2>&1 | grep -c "warning:" # should be 0

# Clippy clean
cargo clippy -- -D warnings

# Examples compile correctly
cargo run -- examples/bare.ark
cargo run -- examples/htlc.ark
cargo run -- examples/fuji_safe.ark

# Documentation builds
cargo doc --no-deps
```

---

## Appendix: Files Changed Summary

| File | Changes Required |
|------|------------------|
| `Cargo.toml` | Add `[lib]` section |
| `src/lib.rs` | Update docs (TapLang → Arkade) |
| `src/main.rs` | Remove unused import |
| `src/parser/mod.rs` | Rename parser, add error handling, add docs |
| `src/parser/debug.rs` | Rename parser |
| `src/compiler/mod.rs` | Filter internals, fix asm order, rename compiler |
| `src/models/mod.rs` | Remove dead code, update docs |
| `tests/bare_vtxo_test.rs` | Fix imports, fix assertions |
| `tests/htlc_test.rs` | Fix imports, fix binary name, fix extension |
| `tests/fuji_safe_test.rs` | Fix imports |

---

*Generated by comprehensive code review. Last updated: 2025-12-28*
