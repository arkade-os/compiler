# Arkade Compiler

Arkade Language is a high-level contract language that compiles down to Arkade Script, an extended version of Bitcoin Script designed for the Arkade OS. Arkade Language lets developers write expressive, stateful smart contracts that compile to scripts executable by Arkade's Virtual Machine.

Arkade Script supports advanced primitives for arithmetic, introspection, and asset flows across Virtual Transaction Outputs (VTXOs), enabling rich offchain transaction logic with unilateral onchain exit guarantees. Contracts are verified and executed inside secure Trusted Execution Environments (TEEs) and signed by the Arkade Signer, ensuring verifiable and tamper-proof execution.

This language significantly lowers the barrier for Bitcoin-native app development, allowing contracts to be written in a structured, Ivy-like syntax and compiled into Arkade-native scripts.

## Playground

Try Arkade Script in your browser — no installation required:

**[arkade-os.github.io/compiler](https://arkade-os.github.io/compiler)**

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

This compiles your Arkade Language contract to a JSON artifact for use with Ark libraries.

```bash
# Specify output file
arkadec contract.ark -o contract.json
```

## Compilation Artifacts

The compiler produces a JSON file containing:

- Contract metadata (name, version, etc.)
- Constructor parameters
- Function definitions with both cooperative and exit spending paths
- Assembly for each path

Example — `SingleSig` compiled output:

```json
{
  "contractName": "SingleSig",
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
        "OP_CHECKSEQUENCEVERIFY",
        "OP_DROP"
      ]
    }
  ],
  "source": "...",
  "compiler": {
    "name": "arkade-script",
    "version": "0.1.0"
  },
  "updatedAt": "2024-01-01T00:00:00Z"
}
```

## Examples

### SingleSig — Bare VTXO

The simplest VTXO: a single public key controls spending.

```solidity
options {
  server = server;
  renew = 1008;
  exit = 144;
}

contract SingleSig(pubkey user) {
  function spend(signature userSig) {
    require(checkSig(userSig, user));
  }
}
```

Each function compiles to two variants automatically:

- **Cooperative** (`serverVariant: true`): `checkSig(user) && checkSig(server)`
- **Exit** (`serverVariant: false`): `checkSig(user) && after 144 blocks`

### HTLC — Hash Time-Locked Contract

```solidity
options {
  server = server;
  renew = 1008;
  exit = 144;
}

contract HTLC(pubkey sender, pubkey receiver, bytes hash, int refundTime) {
  function together(signature senderSig, signature receiverSig) {
    require(checkMultisig([sender, receiver], [senderSig, receiverSig]));
  }

  function refund(signature senderSig) {
    require(checkSig(senderSig, sender));
    require(tx.time >= refundTime);
  }

  function claim(signature receiverSig, bytes preimage) {
    require(checkSig(receiverSig, receiver));
    require(sha256(preimage) == hash);
  }
}
```

### Recursive VTXO — Contract Instantiation

Use `import` and `new ContractName(args)` to enforce that a transaction output carries a specific VTXO contract. This is how VTXOs are forwarded or transformed on-chain.

```solidity
import "single_sig.ark";

options {
  server = operator;
  exit = 144;
}

contract RecursiveVtxo(pubkey ownerPk) {
  // Forward ownership to output 0, maintaining the SingleSig VTXO shape.
  function send() {
    require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk));
  }
}
```

The `new SingleSig(ownerPk)` expression compiles to a `<VTXO:SingleSig(<ownerPk>)>` placeholder. At runtime the Ark server resolves this placeholder to the actual Taproot scriptPubKey of the child contract, so the introspection check is pure Bitcoin Script.

**Cooperative path ASM:**

```text
0 OP_INSPECTOUTPUTSCRIPTPUBKEY <VTXO:SingleSig(<ownerPk>)> OP_EQUAL
<SERVER_KEY> <serverSig> OP_CHECKSIG
```

**Exit path ASM** — because introspection opcodes are not available on pure Bitcoin Script exit paths, the compiler automatically falls back to N-of-N CHECKSIG:

```text
<ownerPk> <ownerPkSig> OP_CHECKSIG
144 OP_CHECKSEQUENCEVERIFY OP_DROP
```

#### Splitting to two outputs

```solidity
import "single_sig.ark";

options {
  server = operator;
  exit = 144;
}

contract Splitter(pubkey alicePk, pubkey bobPk) {
  function split() {
    require(tx.outputs[0].scriptPubKey == new SingleSig(alicePk));
    require(tx.outputs[1].scriptPubKey == new SingleSig(bobPk));
  }
}
```

#### Self-referential covenant (renew pattern)

```solidity
import "self.ark";

options {
  server = operator;
  exit = 144;
}

contract FujiSafe(
  bytes assetCommitmentHash,
  int borrowAmount,
  pubkey borrowerPk,
  pubkey treasuryPk,
  int expirationTimeout,
  int priceLevel,
  int setupTimestamp,
  pubkey oraclePk,
  bytes assetPair
) {
  // Treasury can renew the VTXO without changing any parameters.
  function renew(signature treasurySig) {
    int currentValue = tx.input.current.value;

    require(
      tx.outputs[0].scriptPubKey == new FujiSafe(
        assetCommitmentHash, borrowAmount, borrowerPk, treasuryPk,
        expirationTimeout, priceLevel, setupTimestamp, oraclePk, assetPair
      ),
      "contract mismatch"
    );
    require(tx.outputs[0].value == currentValue, "Value mismatch");
    require(checkSig(treasurySig, treasuryPk), "Invalid treasury signature");
  }
}
```

## Language Reference

### Data Types

- `pubkey`: Bitcoin public key (32-byte x-only, BIP340)
- `signature`: Bitcoin signature (64-byte BIP340 Schnorr)
- `bytes`: Arbitrary byte array
- `bytes20`: 20-byte array
- `bytes32`: 32-byte array
- `int`: Integer value (CScriptNum)
- `bool`: Boolean value
- `asset`: Asset identifier (for asset-aware contracts)

### Contract Structure

An Arkade Language file may start with zero or more `import` declarations, followed by an `options` block and a `contract` declaration:

```solidity
import "other_contract.ark";   // optional — imports for contract instantiation

options {
  server = operator;  // Ark operator key
  renew = 1008;       // renewal timelock in blocks (optional)
  exit = 144;         // exit timelock in blocks
}

contract MyContract(pubkey user) {
  function spend(signature userSig) {
    require(checkSig(userSig, user));
  }
}
```

### Options Block

| Field    | Required | Description                                        |
|----------|----------|----------------------------------------------------|
| `server` | yes      | Parameter name holding the Ark operator public key |
| `exit`   | yes      | Unilateral exit timelock in blocks                 |
| `renew`  | no       | Cooperative renewal timelock in blocks             |

### Functions

Functions define spending paths. Every non-`internal` function produces two compiled variants:

```solidity
// Spending path — compiled to cooperative + exit variants
function spend(signature userSig) {
  require(checkSig(userSig, user));
}

// Helper — not a spending path, inlined into callers
function verify() internal {
  require(tx.outputs[0].value > 0);
}
```

### Imports and Contract Instantiation

Use `import` to declare which contracts may appear in `new` expressions:

```solidity
import "single_sig.ark";
import "htlc.ark";
```

Use `new ContractName(arg1, arg2, ...)` as the right-hand side of a `scriptPubKey` comparison to enforce the shape of an output or input VTXO:

```solidity
// Output enforcement
require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk));

// Input enforcement
require(tx.inputs[0].scriptPubKey == new HTLC(sender, receiver, hash, refundTime));

// Current input enforcement (recursive covenant)
require(tx.input.current.scriptPubKey == new SingleSig(ownerPk));
```

**Zero-argument constructors** are supported:

```solidity
require(tx.outputs[0].scriptPubKey == new StaticContract());
```

**Exit path fallback:** any function that uses `new ContractName(...)` automatically falls back to an N-of-N CHECKSIG chain on the exit path, because the `OP_INSPECTOUTPUTSCRIPTPUBKEY` opcode is not available in pure Bitcoin Script.

### Expressions

#### Signature Verification

```solidity
require(checkSig(userSig, user));
require(checkMultisig([user, admin], [userSig, adminSig]));
require(checkSigFromStack(oracleSig, oraclePk, message));
```

#### Hash Verification

```solidity
require(sha256(preimage) == hash);
```

#### Timelock

```solidity
require(tx.time >= expirationTime);   // absolute (CHECKLOCKTIMEVERIFY)
```

#### Transaction Introspection

```solidity
// Outputs
require(tx.outputs[0].value == amount);
require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk));

// Indexed inputs
require(tx.inputs[0].value == amount);
require(tx.inputs[0].scriptPubKey == script);

// Current input (self-reference)
require(tx.input.current.value == amount);
require(tx.input.current.scriptPubKey == script);
```

`tx.input.current` properties: `value`, `scriptPubKey`, `sequence`, `outpoint`.

### Variable Declarations

```solidity
bytes message = sha256(timestamp + currentPrice + assetPair);
int currentValue = tx.input.current.value;
```

### Error Messages

```solidity
require(tx.time >= expirationTimeout, "Expiration timeout not reached");
```

## Artifact Format

Arkade Language compiles to Arkade Script and produces a JSON artifact for use with Ark libraries.

### Key Fields

| Field               | Description                                                              |
|---------------------|--------------------------------------------------------------------------|
| `contractName`      | Contract identifier                                                      |
| `constructorInputs` | Parameters baked into the tapscript leaf at instantiation                |
| `functions`         | Spending paths — each appears twice (cooperative + exit)                 |
| `serverVariant`     | `true` = cooperative (needs server sig), `false` = exit (needs timelock) |
| `require`           | Human-readable spending conditions                                       |
| `asm`               | Arkade Script assembly; `<name>` = placeholder resolved at runtime       |

### VTXO Placeholder Format

Contract instantiation expressions in ASM use the format:

```text
<VTXO:ContractName(<arg1>,<arg2>)>
```

The Ark runtime resolves this placeholder to the Taproot scriptPubKey of the named contract instantiated with the given arguments. Options (`server`, `exit`, `renew`) are inherited from the enclosing contract.
