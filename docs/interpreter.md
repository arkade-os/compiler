# TapLang Interpreter

This document describes the interpreter implementation for TapLang, which handles both standard Bitcoin opcodes and the new Elements opcodes (OP_SUCCESS196-228).

## Overview

The TapLang interpreter provides a unified execution environment for Bitcoin and Elements scripts. It includes:

1. A stack-based execution model that matches Bitcoin's script execution
2. Support for standard Bitcoin opcodes
3. Support for the new Elements opcodes (OP_SUCCESS196-228)
4. Transaction introspection capabilities
5. Comprehensive error handling

## Implementation Details

### 1. Stack Items

The interpreter uses a flexible stack item type that can represent different data types:

```rust
pub enum StackItem {
    /// Boolean value
    Bool(bool),
    /// Integer value
    Int(i64),
    /// Bytes value
    Bytes(Vec<u8>),
    /// SHA256 context for streaming operations
    Sha256Context(Vec<u8>),
}
```

Each stack item can be converted between different representations as needed.

### 2. Execution Context

The execution context maintains the state of script execution:

```rust
pub struct ExecutionContext {
    /// Main stack
    pub stack: Vec<StackItem>,
    /// Alt stack
    pub alt_stack: Vec<StackItem>,
    /// Transaction data
    pub tx_data: HashMap<String, StackItem>,
    /// Execution flags
    pub flags: u32,
}
```

### 3. Opcode Execution

The interpreter executes opcodes one by one, handling both standard Bitcoin opcodes and the new Elements opcodes:

```rust
pub fn execute_opcode(&mut self, opcode: &Opcode, data: Option<&[u8]>) -> ExecutionResult {
    match opcode {
        // Standard Bitcoin opcodes
        Opcode::OP_0 => { /* ... */ },
        Opcode::OP_1 => { /* ... */ },
        // ...

        // Elements opcodes - Streaming SHA256
        Opcode::SHA256INITIALIZE => { /* ... */ },
        Opcode::SHA256UPDATE => { /* ... */ },
        Opcode::SHA256FINALIZE => { /* ... */ },
        // ...

        // Elements opcodes - Transaction Introspection
        Opcode::INSPECTINPUTOUTPOINT => { /* ... */ },
        // ...

        // Elements opcodes - 64-bit Arithmetic
        Opcode::ADD64 => { /* ... */ },
        // ...

        // Elements opcodes - Conversion
        Opcode::SCRIPTNUMTOLE64 => { /* ... */ },
        // ...

        // Elements opcodes - Crypto
        Opcode::ECMULSCALARVERIFY => { /* ... */ },
        // ...
    }
}
```

### 4. Script Execution

The interpreter can execute complete scripts by parsing them into opcodes and executing them in sequence:

```rust
pub fn execute_script(&mut self, script: &[u8]) -> ExecutionResult {
    // Parse script into opcodes and execute them
    // ...
}
```

## Usage Examples

### Basic Usage

```rust
use taplang::interpreter::{ExecutionContext, StackItem, ExecutionResult};
use taplang::models::opcodes::Opcode;

// Create a new execution context
let mut ctx = ExecutionContext::new();

// Push values onto the stack
ctx.push(StackItem::Int(40));
ctx.push(StackItem::Int(2));

// Execute an opcode
match ctx.execute_opcode(&Opcode::ADD64, None) {
    ExecutionResult::Success => {
        let success = ctx.pop().unwrap().to_bool();
        let result = ctx.pop().unwrap().to_int().unwrap();
        println!("Result: {}, Success: {}", result, success);
    },
    ExecutionResult::Failure(err) => {
        println!("Error: {}", err);
    }
}
```

### Executing a Complete Script

```rust
use taplang::interpreter::{ExecutionContext, ExecutionResult};

// Create a new execution context
let mut ctx = ExecutionContext::new();

// Example script: OP_1 OP_2 OP_ADD
let script = vec![0x51, 0x52, 0x93];

// Execute the script
match ctx.execute_script(&script) {
    ExecutionResult::Success => {
        println!("Script executed successfully");
    },
    ExecutionResult::Failure(err) => {
        println!("Script execution failed: {}", err);
    }
}
```

## Integration with Compiler

The interpreter can be integrated with the TapLang compiler to execute compiled scripts:

```rust
use taplang::compiler;
use taplang::interpreter::{ExecutionContext, ExecutionResult};

// Compile TapLang code to Bitcoin script
let source_code = "contract Example() { /* ... */ }";
let contract_json = compiler::compile(source_code).unwrap();

// Extract the script from the compiled contract
let script_hex = &contract_json.functions[0].asm.join(" ");
let script = hex::decode(script_hex).unwrap();

// Execute the script
let mut ctx = ExecutionContext::new();
match ctx.execute_script(&script) {
    ExecutionResult::Success => {
        println!("Script executed successfully");
    },
    ExecutionResult::Failure(err) => {
        println!("Script execution failed: {}", err);
    }
}
```

## Resource Limits

The interpreter respects the resource limits defined in the Elements Taproot specification:

- Stack element count limit: 1000 elements in stack and altstack combined
- Stack element size limit: 520 bytes per stack element
- Sigops limit: Per-script budget of 50 + witness size in bytes

## References

- [Bitcoin Script](https://en.bitcoin.it/wiki/Script)
- [Elements Taproot Opcodes Specification](https://github.com/ElementsProject/elements/blob/master/doc/taproot-sighash.mediawiki)
- [BIP 342: Validation of Taproot Scripts](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki) 