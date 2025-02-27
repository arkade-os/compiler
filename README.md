# TapLang

A compiler for TapLang - a simple, expressive language for creating Bitcoin Taproot scripts.

## Language Features

TapLang allows you to define Bitcoin Taproot contracts with:

- Strong typing (pubkey, signature, bytes32, int, bool)
- Multiple spending paths
- High-level expressions that compile to Bitcoin Script
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


## Example HTLC Contract

```solidity
contract HTLC(
  pubkey sender,
  pubkey receiver,
  bytes32 hash,
  int timelock
) {

  function together(signature senderSig, signature receiverSig) {
    require(checkMultisig([sender, receiver], [senderSig, receiverSig]));
  }
  
  function refund(signature senderSig) {
    require(checkSig(senderSig, sender));
    require(tx.time >= timelock);
  }
  
  function claim(signature receiverSig, bytes32 preimage) {
    require(checkSig(receiverSig, receiver));
    require(sha256(preimage) == hash);
  }
}
```

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
