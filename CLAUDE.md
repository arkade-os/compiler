# CLAUDE.md - Arkade Compiler

This file provides guidance for AI assistants working with the Arkade Compiler codebase.

## Project Overview

**Arkade Compiler** (`arkadec`) is a Rust-based compiler that transforms Arkade Script contracts into Bitcoin Script assembly and JSON artifacts for use with Taproot libraries. The language is designed for Virtual Transaction Outputs (VTXOs) on Bitcoin, supporting dual-path execution (cooperative with server signature OR unilateral with timelock exit).

- **Language:** Rust (Edition 2021)
- **Binary:** `arkadec`
- **Version:** 0.1.0
- **License:** MIT

## Quick Reference

```bash
# Build the project
cargo build

# Run the compiler
cargo run -- contract.ark
arkadec contract.ark -o output.json

# Run all tests
cargo test

# Run specific test
cargo test test_htlc_contract
```

## Directory Structure

```
/home/user/compiler/
├── src/
│   ├── main.rs              # CLI entry point (clap-based)
│   ├── lib.rs               # Library exports: compile(), models, parser
│   ├── parser/
│   │   ├── mod.rs           # Pest parser implementation
│   │   ├── grammar.pest     # PEG grammar (35+ rules)
│   │   └── debug.rs         # Parser debugging utilities
│   ├── compiler/
│   │   └── mod.rs           # AST → JSON compilation with dual-path generation
│   └── models/
│       └── mod.rs           # AST types: Contract, Function, Requirement, Expression
├── tests/
│   ├── bare_vtxo_test.rs    # BareVTXO contract tests
│   ├── htlc_test.rs         # HTLC contract tests
│   └── fuji_safe_test.rs    # Fuji Safe contract tests
├── examples/
│   ├── bare.ark             # Simple VTXO contract
│   ├── htlc.ark             # Hash Time-Locked Contract
│   ├── fuji_safe.ark        # Complex lending protocol
│   └── *.json               # Compiled outputs
├── Cargo.toml
└── README.md
```

## Architecture

### Compiler Pipeline

```
Source Code (.ark) → [Parser] → AST → [Compiler] → JSON Output
```

1. **Parser** (`src/parser/`): Uses Pest grammar to tokenize and build AST
2. **AST** (`src/models/`): Contract, Function, Requirement, Expression nodes
3. **Compiler** (`src/compiler/`): Generates two variants per function:
   - `serverVariant: true` - Cooperative path (user sig + server sig)
   - `serverVariant: false` - Exit path (user sig + timelock)

### Key Types

```rust
// Main AST types
Contract { name, parameters, options, functions }
Function { name, parameters, requirements, is_internal }
Requirement { CheckSig, CheckMultisig, After, HashEqual, Comparison }
Expression { Variable, Literal, Property, Sha256, CurrentInput }

// Output types
ContractJson { contractName, constructorInputs, functions, source, compiler, updatedAt }
AbiFunction { name, functionInputs, serverVariant, require, asm }
```

## Code Conventions

### Arkade Script Syntax (.ark files)

```solidity
options {
  server = serverParam;   // Server key from contract params
  exit = 144;             // Exit timelock in blocks
  renew = 1008;           // Optional: renewal timelock
}

contract ContractName(type param1, type param2) {
  function functionName(type arg) {
    require(checkSig(sig, pubkey));
    require(tx.time >= timestamp);
  }

  function helperFunc() internal {
    // Not a spending path
  }
}
```

### Supported Data Types

- `pubkey` - Bitcoin public key
- `signature` - Bitcoin signature
- `bytes`, `bytes20`, `bytes32` - Byte arrays
- `int` - Integer values
- `bool` - Boolean values
- `asset` - Taproot Asset identifier

### Assembly Output Conventions

- Placeholders use angle brackets: `<pubkey>`, `<signature>`, `<SERVER_KEY>`
- Opcodes are uppercase: `OP_CHECKSIG`, `OP_CHECKLOCKTIMEVERIFY`
- Function inputs reference parameter names directly

## Testing

### Test Structure

```rust
#[test]
fn test_contract_name() {
    let code = r#"...contract source..."#;
    let result = compile(code);
    assert!(result.is_ok());

    let output = result.unwrap();
    assert_eq!(output.name, "ExpectedName");
    // Check function counts, assembly, requirements
}
```

### Running Tests

```bash
cargo test                      # All tests
cargo test test_htlc            # Pattern match
cargo test --test htlc_test     # Specific file
```

## Common Tasks

### Adding a New Requirement Type

1. Add variant to `Requirement` enum in `src/models/mod.rs`
2. Add parsing rule in `src/parser/grammar.pest`
3. Handle parsing in `src/parser/mod.rs`
4. Generate assembly in `src/compiler/mod.rs`

### Adding a New Expression Type

1. Add variant to `Expression` enum in `src/models/mod.rs`
2. Add grammar rule in `src/parser/grammar.pest`
3. Parse in `parse_expression()` in `src/parser/mod.rs`
4. Handle in `generate_base_asm_instructions()` in `src/compiler/mod.rs`

### Modifying Output Format

- JSON output structure: `ContractJson` and `AbiFunction` in `src/models/mod.rs`
- Serialization uses serde with `#[serde(rename = "...")]` for field names

## Dependencies

| Crate | Purpose |
|-------|---------|
| `pest` / `pest_derive` | PEG parser generator |
| `serde` / `serde_json` | JSON serialization |
| `clap` | CLI argument parsing |
| `chrono` | Timestamp generation |

## Error Handling

- Library functions return `Result<T, String>` with descriptive error messages
- Parse errors are prefixed with "Parse error: "
- CLI uses `Box<dyn std::error::Error>` for rich error handling

## Important Notes

1. **Dual-Path Generation**: Every non-internal function automatically gets two output variants - cooperative (with server signature) and exit (with timelock)

2. **File Extensions**:
   - `.ark` - Arkade Script source files (current)
   - `.tap` - Legacy TapLang format (deprecated)
   - `.json` - Compiled output

3. **Internal Functions**: Functions marked `internal` are helpers and don't generate spending paths

4. **The `<SERVER_KEY>` Placeholder**: Automatically injected for cooperative paths based on `options.server`

## Git Conventions

- Commit messages use prefixes: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`
- Main branch is the default development branch
- Tests should pass before committing (`cargo test`)
