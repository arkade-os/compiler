# Arkade Compiler

Arkade Language is a high-level contract language that compiles down to Arkade Script, an extended version of Bitcoin Script designed for the Arkade OS. Arkade Language lets developers write expressive, stateful smart contracts that compile to scripts executable by Arkade’s Virtual Machine.

Arkade Script supports advanced primitives for arithmetic, introspection, and asset flows across Virtual Transaction Outputs (VTXOs), enabling rich offchain transaction logic with unilateral onchain exit guarantees. Contracts are verified and executed inside secure Trusted Execution Environments (TEEs) and signed by the Arkade Signer, ensuring verifiable and tamper-proof execution.

This language significantly lowers the barrier for Bitcoin-native app development, allowing contracts to be written in a structured, Ivy-like syntax and compiled into Arkade-native scripts.

## Playground

Try Arkade Script in your browser — no installation required:

**[arkadeos.github.io/compiler](https://arkadeos.github.io/compiler)**

### Run the Playground Locally

**Prerequisites:**

- [Rust](https://rustup.rs/) toolchain
- [`wasm-pack`](https://rustwasm.github.io/wasm-pack/installer/):
  ```bash
  cargo install wasm-pack
  # or
  curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
  ```

**Build and serve:**

```bash
# Build the WASM package and set up the playground
./playground/build.sh

# Serve locally (default port 8080)
./playground/serve.sh

# Or specify a custom port
./playground/serve.sh 3000
```

Then open [http://localhost:8080](http://localhost:8080) in your browser.

**What the build script does:**

1. Generates `contracts.js` from the `.ark` example files in `examples/`
2. Compiles the Rust compiler to WebAssembly using `wasm-pack`
3. Outputs the WASM package to `playground/pkg/`

## Basic Usage

```bash
arkadec contract.ark
```

This will compile your Arkade Script contract to a JSON file that can be used with Bitcoin Taproot libraries.

## Compiler Options

The Arkade Compiler supports several command-line options:

```bash
# Output assembly instead of bytecode
arkadec --output=asm contract.ark

# Generate debug information
arkadec --debug contract.ark

# Specify output file
arkadec --output-file=contract.json contract.ark
```

## Compilation Artifacts

The compiler produces a JSON file containing:

- Contract metadata (name, version, etc.)
- Constructor parameters
- Function definitions
- Generated script for each function (both cooperative and unilateral paths)
- Source map for debugging

Example output:

```json
{
  "contractName": "MyContract",
  "constructorInputs": [
    { "name": "user", "type": "pubkey" }
  ],
  "functions": [
    {
      "name": "spend",
      "functionInputs": [
        { "name": "userSig", "type": "signature" }
      ],
      "serverVariant": true,
      "require": [
        { "type": "signature" },
        { "type": "serverSignature" }
      ],
      "asm": [
        "<user>",
        "<userSig>",
        "OP_CHECKSIG",
        "<SERVER_KEY>",
        "<serverSig>",
        "OP_CHECKSIG"
      ]
    },
    {
      "name": "spend",
      "functionInputs": [
        { "name": "userSig", "type": "signature" }
      ],
      "serverVariant": false,
      "require": [
        { "type": "signature" },
        { "type": "older", "message": "Exit timelock of 144 blocks" }
      ],
      "asm": [
        "<user>",
        "<userSig>",
        "OP_CHECKSIG",
        "144",
        "OP_CHECKLOCKTIMEVERIFY",
        "OP_DROP"
      ]
    }
  ],
  "source": "...",
  "compiler": {
    "name": "arkade-script",
    "version": "0.1.0"
  },
  "updatedAt": "2023-03-06T01:27:51.391557+00:00"
}
```

## Examples

### Basic VTXO Contract

```solidity
// Contract configuration options
options {
  // Server key 
  server = server;
  
  // Exit timelock: 24 hours (144 blocks)
  exit = 144;
}

contract BareVTXO(
  pubkey user
) {
  // Single signature spend path
  // This will automatically be compiled into:
  // 1. Cooperative path: checkSig(user) && checkSig(server)
  // 2. Exit path: checkSig(user) && after 144 blocks
  function spend(signature userSig) {
    require(checkSig(userSig, user));
  }
}
```

### HTLC Contract

```solidity
// Contract configuration options
options {
  // Server key 
  server = server;
  
  // Exit timelock: 24 hours (144 blocks)
  exit = 144;
}

contract HTLC(
  pubkey sender,
  pubkey receiver,
  bytes hash,
  int refundTime
) {
  // Cooperative close path
  function together(signature senderSig, signature receiverSig) {
    require(checkMultisig([sender, receiver], [senderSig, receiverSig]));
  }
  
  // Refund path
  function refund(signature senderSig) {
    require(checkSig(senderSig, sender));
    require(tx.time >= refundTime);
  }
  
  // Claim path
  function claim(signature receiverSig, bytes preimage) {
    require(checkSig(receiverSig, receiver));
    require(sha256(preimage) == hash);
  }
}
```

### Fuji Safe Contract

```solidity
// Contract configuration options
options {
  // Server key parameter from contract parameters
  server = treasuryPk;
  
  // Exit timelock: 24 hours (144 blocks)
  exit = 144;
}

// Fuji Safe Contract
contract FujiSafe(
  // The asset commitment hash (client-side validated)
  bytes assetCommitmentHash,
  // The amount being borrowed
  int borrowAmount,
  // The borrower's public key
  pubkey borrowerPk,
  // The treasury's public key
  pubkey treasuryPk,
  // The expiration timeout in blocks
  int expirationTimeout,
  // The price level for liquidation
  int priceLevel,
  // The setup timestamp
  int setupTimestamp,
  // The oracle's public key
  pubkey oraclePk,
  // The asset pair identifier
  bytes assetPair
) {
  // Helper function to verify Fuji token burning via Taproot output
  // Takes the pubkey to use as the internal key for the P2TR output
  function verifyFujiBurning(pubkey internalKey) internal {
    // In Taproot, we verify the output is a P2TR that commits to our asset
    // Using the provided pubkey as the internal key
    bytes p2trScript = new P2TR(internalKey, assetCommitmentHash);
    
    // Verify output 0 has the correct P2TR scriptPubKey and value
    require(tx.outputs[0].scriptPubKey == p2trScript, "P2TR output mismatch");
    require(tx.outputs[0].value == borrowAmount, "Value mismatch");
  }

  // Claim: Treasury can unlock all collateral after expiration when burning Fuji
  function claim(signature treasurySig) {
    // Check that expiration timeout has passed
    require(tx.time >= expirationTimeout, "Expiration timeout not reached");
    
    // Verify burning of Fuji token using treasury key
    verifyFujiBurning(treasuryPk);
    
    // Require treasury signature
    require(checkSig(treasurySig, treasuryPk), "Invalid treasury signature");
  }
  
  // Liquidation: Treasury can unlock all collateral with attestation price below the liquidation target
  function liquidate(int currentPrice, signature oracleSig, signature treasurySig) {
    // Check price is below liquidation threshold
    require(currentPrice < priceLevel, "Price not below liquidation threshold");
    
    // Verify timestamp is after setup
    require(tx.time >= setupTimestamp, "Timestamp before setup");
    
    // Create message for oracle signature verification
    bytes message = sha256(assetPair);
    
    // Verify oracle signature on price data
    require(checkSigFromStack(oracleSig, oraclePk, message), "Invalid oracle signature");
    
    // Verify burning of Fuji token using treasury key
    verifyFujiBurning(treasuryPk);
    
    // Require treasury signature
    require(checkSig(treasurySig, treasuryPk), "Invalid treasury signature");
  }
  
  // Private Redemption: Only owner can unlock all collateral with key when burning Fuji
  function redeem(signature borrowerSig) {
    // Verify burning of Fuji token using borrower key
    verifyFujiBurning(borrowerPk);
    
    // Require borrower signature
    require(checkSig(borrowerSig, borrowerPk), "Invalid borrower signature");
  }
  
  // Treasury Renew: Treasury can unilaterally renew the expiration time
  function renew(signature treasurySig) {
    // For renewal, we ensure the output is another P2TR with the same key and value
    // This preserves the Taproot commitment structure
    
    // Using the new tx.input.current syntax to access the current input's properties
    bytes currentScript = tx.input.current.scriptPubKey;
    int currentValue = tx.input.current.value;
    
    // Verify that output 0 has the same P2TR script as the current input
    require(tx.outputs[0].scriptPubKey == currentScript, "P2TR output mismatch");
    require(tx.outputs[0].value == currentValue, "Value mismatch");
    
    // Require treasury signature
    require(checkSig(treasurySig, treasuryPk), "Invalid treasury signature");
  }
}
```

## Language Reference

TapLang is a domain-specific language for writing Bitcoin Taproot contracts with a focus on readability and safety.

### Data Types

TapLang supports the following data types:

- `pubkey`: Bitcoin public key
- `signature`: Bitcoin signature
- `bytes`: Arbitrary byte array
- `bytes20`: 20-byte array (useful for hashes)
- `bytes32`: 32-byte array (useful for hashes)
- `int`: Integer value
- `bool`: Boolean value
- `asset`: Taproot Asset (for asset-aware contracts)

### Contract Structure

A TapLang contract consists of:

1. An optional `options` block for configuration
2. A `contract` declaration with parameters
3. One or more `function` declarations that define spending paths

Example:

```solidity
// Optional configuration
options {
  server = treasuryPk;
  exit = 144;
}

// Contract declaration with parameters
contract MyContract(
  pubkey user
) {
  // Function declarations (spending paths)
  function spend(signature userSig) {
    require(checkSig(userSig, user));
  }
}
```

### Options Block

The options block configures contract-wide settings:

```solidity
options {
  // Server key 
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

### Functions

Functions define spending paths for the contract:

```solidity
function spend(signature userSig) {
  require(checkSig(userSig, user));
}
```

Functions can be marked as `internal` to indicate they are helper functions and not spending paths:

```solidity
function verifyCondition() internal {
  // Helper logic
}
```

### Expressions

Arkade Script supports various expressions:

#### Signature Verification

```solidity
// Single signature verification
require(checkSig(userSig, user));

// Multi-signature verification
require(checkMultisig([user, admin], [userSig, adminSig]));

// Signature verification from stack
require(checkSigFromStack(oracleSig, oraclePk, message));
```

#### Hash Verification

```solidity
// SHA-256 hash verification
require(sha256(preimage) == hash);
```

#### Timelock Verification

```solidity
// Absolute timelock
require(tx.time >= expirationTime);
```

#### Transaction Introspection

TapLang provides access to transaction data:

```solidity
// Access transaction time
require(tx.time >= lockTime);

// Access outputs
require(tx.outputs[0].value == amount);
require(tx.outputs[0].scriptPubKey == script);

// Access inputs
require(tx.inputs[0].value == amount);
require(tx.inputs[0].scriptPubKey == script);

// Access the current input (new syntax)
require(tx.input.current.value == amount);
require(tx.input.current.scriptPubKey == script);
```

#### Current Input Access

TapLang provides a special syntax for accessing the current input being spent:

```solidity
// Access the current input's value
int currentValue = tx.input.current.value;

// Access the current input's scriptPubKey
bytes currentScript = tx.input.current.scriptPubKey;

// Access the current input's sequence number
int sequence = tx.input.current.sequence;

// Access the current input's outpoint
bytes outpoint = tx.input.current.outpoint;
```

This is more intuitive than using an index variable:

```solidity
// Old approach (less intuitive)
int currentIndex = 0; // Assume the current input is at index 0
int currentValue = tx.inputs[currentIndex].value;

// New approach (more intuitive)
int currentValue = tx.input.current.value;
```

### Variable Declarations

You can declare variables to store intermediate values:

```solidity
bytes message = sha256(timestamp + currentPrice + assetPair);
bytes p2trScript = new P2TR(internalKey, assetCommitmentHash);
```

### Error Messages

You can provide custom error messages for require statements:

```solidity
require(tx.time >= expirationTimeout, "Expiration timeout not reached");
```

## Artifact Format

TapLang compiles contracts to a JSON format that can be used with Bitcoin Taproot libraries.

### JSON Structure

```json
{
  "contractName": "MyContract",
  "constructorInputs": [
    { "name": "user", "type": "pubkey" }
  ],
  "functions": [
    {
      "name": "spend",
      "functionInputs": [
        { "name": "userSig", "type": "signature" }
      ],
      "serverVariant": true,
      "require": [
        { "type": "signature" },
        { "type": "serverSignature" }
      ],
      "asm": [
        "<user>",
        "<userSig>",
        "OP_CHECKSIG",
        "<SERVER_KEY>",
        "<serverSig>",
        "OP_CHECKSIG"
      ]
    },
    {
      "name": "spend",
      "functionInputs": [
        { "name": "userSig", "type": "signature" }
      ],
      "serverVariant": false,
      "require": [
        { "type": "signature" },
        { "type": "older", "message": "Exit timelock of 144 blocks" }
      ],
      "asm": [
        "<user>",
        "<userSig>",
        "OP_CHECKSIG",
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
  "updatedAt": "2023-03-06T01:27:51.391557+00:00"
}
```

### Key Components

- `contractName`: The name of the contract
- `constructorInputs`: The parameters required to instantiate the contract
- `functions`: The spending paths of the contract
  - Each function has two variants:
    - `serverVariant: true`: Requires server signature (cooperative path)
    - `serverVariant: false`: Requires timelock (exit path)
- `require`: The requirements for each spending path
- `asm`: The Bitcoin Script assembly code for each spending path
