# TapLang

A compiler for TapLang - a simple, expressive language for creating Bitcoin Taproot scripts.

## Language Features

TapLang allows you to define Bitcoin Taproot contracts with:

- Strong typing (pubkey, signature, bytes32, int, bool)
- Multiple spending paths
- High-level expressions that compile to Bitcoin Script
- Block-based options for contract configuration
- Automatic server-variant path generation for settlement

## Installation

```bash
cargo install --path .
```

## Usage

```bash
tapc contract.tap
```

This will compile your TapLang contract to a JSON file that can be used with Bitcoin Taproot libraries.

## Contract Options

TapLang supports a block-based options approach for contract configuration:

```solidity
// Contract configuration options
options {
  // Server key parameter from contract parameters
  server = server;
  
  // Renewal timelock: 7 days (1008 blocks)
  renew = 1008;
  
  // Exit timelock: 24 hours (144 blocks)
  exit = 144;
}
```

Available options:

- `server`: Specifies which parameter contains the server public key
- `renew`: Specifies the renewal timelock in blocks
- `exit`: Specifies the exit timelock in blocks

## Example HTLC Contract

```solidity
// Contract configuration options
options {
  // Server key parameter from contract parameters
  server = server;
  
  // Exit timelock: 24 hours (144 blocks)
  exit = 144;
}

contract HTLC(
  pubkey sender,
  pubkey receiver,
  bytes32 hash,
  int timelock,
  pubkey server
) {
  // Cooperative close path
  // This will automatically be compiled into two variants:
  // 1. serverVariant: true - requires multisig + server signature
  // 2. serverVariant: false - requires multisig + exit timelock
  function together(signature senderSig, signature receiverSig) {
    require(checkMultisig([sender, receiver], [senderSig, receiverSig]));
  }
  
  // Refund path
  // This will automatically be compiled into two variants:
  // 1. serverVariant: true - requires sender signature + timelock + server signature
  // 2. serverVariant: false - requires sender signature + timelock + exit timelock
  function refund(signature senderSig) {
    require(checkSig(senderSig, sender));
    require(tx.time >= timelock);
  }
  
  // Claim path
  // This will automatically be compiled into two variants:
  // 1. serverVariant: true - requires receiver signature + valid preimage + server signature
  // 2. serverVariant: false - requires receiver signature + valid preimage + exit timelock
  function claim(signature receiverSig, bytes32 preimage) {
    require(checkSig(receiverSig, receiver));
    require(sha256(preimage) == hash);
  }
}
```

## JSON Output Format

The compiler generates a JSON output with the following structure:

```json
{
  "contractName": "HTLC",
  "constructorInputs": [
    { "name": "sender", "type": "pubkey" },
    { "name": "receiver", "type": "pubkey" },
    { "name": "hash", "type": "bytes32" },
    { "name": "timelock", "type": "int" },
    { "name": "server", "type": "pubkey" }
  ],
  "functions": [
    {
      "name": "claim",
      "functionInputs": [
        { "name": "receiverSig", "type": "signature" },
        { "name": "preimage", "type": "bytes32" }
      ],
      "serverVariant": true,
      "require": [
        { "type": "signature" },
        { "type": "hash" },
        { "type": "serverSignature" }
      ],
      "asm": [
        "<receiver>",
        "<receiverSig>",
        "OP_CHECKSIG",
        "<preimage>",
        "OP_SHA256",
        "<hash>",
        "OP_EQUAL",
        "<SERVER_KEY>",
        "<serverSig>",
        "OP_CHECKSIG"
      ]
    },
    {
      "name": "claim",
      "functionInputs": [
        { "name": "receiverSig", "type": "signature" },
        { "name": "preimage", "type": "bytes32" }
      ],
      "serverVariant": false,
      "require": [
        { "type": "signature" },
        { "type": "hash" },
        { "type": "older", "message": "Exit timelock of 144 blocks" }
      ],
      "asm": [
        "<receiver>",
        "<receiverSig>",
        "OP_CHECKSIG",
        "<preimage>",
        "OP_SHA256",
        "<hash>",
        "OP_EQUAL",
        "144",
        "OP_CHECKLOCKTIMEVERIFY",
        "OP_DROP"
      ]
    }
  ],
  "source": "...",
  "compiler": {
    "name": "taplang",
    "version": "0.1.0"
  },
  "updatedAt": "2025-03-05T23:28:28.331335+00:00"
}
```

Each function in the contract is compiled into two variants:

- `serverVariant: true`: Requires a server signature for settlement
- `serverVariant: false`: Requires an exit timelock for unilateral settlement

## Library Usage

You can also use TapLang as a library in your Rust projects:

```rust
use taplang::compile;

fn main() {
    let source_code = std::fs::read_to_string("contract.tap").unwrap();
    let result = compile(&source_code).unwrap();
    println!("{}", serde_json::to_string_pretty(&result).unwrap());
}
```

## License

MIT
