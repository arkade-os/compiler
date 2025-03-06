# Elements Taproot Opcodes Implementation

This document describes the implementation of the new Elements Taproot opcodes (OP_SUCCESS196-228) in the TapLang compiler.

## Overview

The Elements Taproot opcodes provide additional functionality to the Bitcoin Taproot script language, including:

1. **Streaming SHA256 opcodes** - For hashing data larger than 520 bytes
2. **Transaction introspection opcodes** - For examining transaction inputs, outputs, and metadata
3. **64-bit arithmetic opcodes** - For performing arithmetic operations on 64-bit integers
4. **Conversion opcodes** - For converting between different numeric formats
5. **Crypto opcodes** - For advanced cryptographic operations

## Implementation Details

### 1. Opcodes Definition

The opcodes are defined in `src/models/opcodes.rs` as an enum with variants for each opcode. Each opcode has a corresponding numeric value (196-228) and a string representation.

```rust
pub enum Opcode {
    // Streaming SHA256 opcodes
    SHA256INITIALIZE,  // OP_SUCCESS196
    SHA256UPDATE,      // OP_SUCCESS197
    SHA256FINALIZE,    // OP_SUCCESS198
    
    // Transaction introspection opcodes
    // ...
    
    // 64-bit arithmetic opcodes
    // ...
    
    // Conversion opcodes
    // ...
    
    // Crypto opcodes
    // ...
}
```

### 2. Opcode Implementation

The implementation of the opcodes is in `src/compiler/opcodes.rs`. Each opcode has a corresponding function that creates a `ScriptOp` struct with the opcode and optional data.

```rust
pub struct ScriptOp {
    pub opcode: Opcode,
    pub data: Option<Vec<u8>>,
}
```

The opcodes are organized into modules based on their functionality:

- `sha256` - Streaming SHA256 opcodes
- `tx_introspection` - Transaction introspection opcodes
- `arithmetic` - 64-bit arithmetic opcodes
- `conversion` - Conversion opcodes
- `crypto` - Crypto opcodes

### 3. Parser Extensions

The parser is extended in `src/parser/elements_opcodes.rs` to support the new opcodes in the TapLang language. The extensions include:

- New expression types for each opcode category
- Functions to convert these expressions to requirements
- Helper functions for working with the new expressions

### 4. Grammar Extensions

The grammar is extended in `src/parser/grammar.pest` to support the new opcodes in the TapLang language. The extensions include:

- New rules for each opcode category
- New rules for each individual opcode
- Integration with the existing expression system

### 5. Compiler Extensions

The compiler is extended in `src/compiler/mod.rs` to handle the new opcodes when generating assembly instructions. The extensions include:

- New patterns in the `generate_base_asm_instructions` function for each opcode category
- Logic to extract arguments and generate the appropriate assembly instructions

## Usage Examples

See `examples/elements_opcodes.tap` for examples of how to use the new opcodes in TapLang.

### Streaming SHA256 Example

```
// Initialize the SHA256 context with the first preimage
bytes32 context = sha256Initialize(preimage1);

// Update the context with the second preimage
bytes32 updatedContext = sha256Update(context, preimage2);

// Finalize the hash
bytes32 hash = sha256Finalize(updatedContext, "");
```

### Transaction Introspection Example

```
// Get the current input index
int currentIdx = tx.currentInputIndex;

// Inspect input properties
bytes32 outpoint = tx.input[inputIndex].outpoint;
bytes32 inputValue = tx.input[inputIndex].value;
```

### 64-bit Arithmetic Example

```
// Addition
int64 sum = add64(a, b);

// Subtraction
int64 difference = sub64(a, b);
```

### Crypto Operations Example

```
// Verify EC scalar multiplication
require(ecmulscalarVerify(scalar, pointP, pointQ) == true);

// Verify key tweaking
require(tweakVerify(internalKey, tweak, outputKey) == true);
```

## Resource Limits

The implementation respects the resource limits defined in the Elements Taproot specification:

- Script size limit: No explicit limit, implicitly bounded by block weight
- Non-push opcodes limit: No explicit limit
- Sigops limit: Per-script budget of 50 + witness size in bytes
- Stack element count limit: 1000 elements in stack and altstack combined
- Stack element size limit: 520 bytes per stack element

## References

- [Elements Taproot Opcodes Specification](https://github.com/ElementsProject/elements/blob/master/doc/taproot-sighash.mediawiki)
- [BIP 342: Validation of Taproot Scripts](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)
- [Elements Project](https://github.com/ElementsProject/elements) 