# Arkade Compiler

Arkade Language is a high-level contract language that compiles down to Arkade Script, an extended version of Bitcoin Script designed for the Arkade OS. Arkade Language lets developers write expressive, stateful smart contracts that compile to scripts executable by Arkade's Virtual Machine.

Arkade Script supports advanced primitives for arithmetic, introspection, and asset flows across Virtual Transaction Outputs (VTXOs), enabling rich offchain transaction logic with unilateral onchain exit guarantees. Contracts are verified and executed inside secure Trusted Execution Environments (TEEs) and signed by the Arkade Signer, ensuring verifiable and tamper-proof execution.

This language significantly lowers the barrier for Bitcoin-native app development, allowing contracts to be written in a structured, Ivy-like syntax and compiled into Arkade-native scripts.

## Development Setup
- Setup pre-commit checks
  ```bash
  cp ./scripts/pre-commit .git/hooks 
  ```

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

This compiles your Arkade Language contract to a JSON artifact for use with Arkade libraries.

```bash
# Specify output file
arkadec contract.ark -o contract.json
```

## Compilation Artifacts

The compiler produces a JSON file containing:

- Contract metadata (name, version, etc.)
- Constructor parameters
- Spend groups in `functions[]`
- Optional `arkade` covenant assembly per function-backed group
- One or more L1 tapleaves per group, each with witness metadata and ASM

Example — `SingleSig` compiled output:

```json
{
  "contractName": "SingleSig",
  "constructorInputs": [
    { "name": "user", "type": "pubkey" },
    { "name": "exit", "type": "int" }
  ],
  "functions": [
    {
      "name": "spend",
      "arkade": {
        "inputs": [{ "name": "userSig", "type": "signature" }],
        "asm": ["<user>", "<userSig>", "OP_CHECKSIG"]
      },
      "leaves": [
        {
          "name": "spend",
          "witness": [
            {
              "name": "serverSig",
              "type": "signature",
              "encoding": "schnorr-64",
              "injected": true
            },
            {
              "name": "emulatorSig",
              "type": "signature",
              "encoding": "schnorr-64",
              "injected": true
            }
          ],
          "asm": [
            "<SERVER_KEY>",
            "OP_CHECKSIGVERIFY",
            "<EMULATOR_KEY:spend>",
            "OP_CHECKSIG"
          ]
        }
      ]
    }
  ],
  "source": "...",
  "compiler": {
    "name": "arkade-compiler",
    "version": "0.1.0"
  },
  "updatedAt": "2024-01-01T00:00:00Z"
}
```

## Examples

### SingleSig — Bare VTXO

The simplest VTXO: a single public key controls spending.

```solidity
contract SingleSig(pubkey user, int exit) {
  function spend(signature userSig) {
    require(checkSig(userSig, user));
  }

  function unilateral(signature userSig) tapscript {
    require(older(exit));
    require(checkSig(userSig, user));
  }
}
```

The covenant function emits arkade ASM. The `unilateral` tapscript is a pure L1 CSV exit leaf.

### HTLC — Hash Time-Locked Contract

```solidity
contract HTLC(
  pubkey sender,
  pubkey receiver,
  bytes20 preimageHash,
  int refundTime,
  int exit
) {
  function claim() {
    require(tx.outputs[0].value >= tx.inputs[0].value);
  }
  function refund() {
    require(tx.outputs[0].value >= tx.inputs[0].value);
  }

  function claim(bytes preimage, signature serverSig, signature emulatorSig) tapscript {
    require(hash160(preimage) == preimageHash);
    require(checkMultisig([server, emulator], [serverSig, emulatorSig], 2));
  }
  function refund(signature serverSig, signature emulatorSig) tapscript {
    require(tx.time >= refundTime);
    require(checkMultisig([server, emulator], [serverSig, emulatorSig], 2));
  }

  function unilateral(signature senderSig) tapscript {
    require(older(exit));
    require(checkSig(senderSig, sender));
  }
}
```

### Recursive VTXO — Contract Instantiation

Use `import` and `new ContractName(args)` to enforce that a transaction output carries a specific VTXO contract. This is how VTXOs are forwarded or transformed on-chain.

```solidity
import "single_sig.ark";

contract RecursiveVtxo(pubkey ownerPk, int exit) {
  // Forward ownership to output 0, maintaining the SingleSig VTXO shape.
  function send() {
    require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk, exit));
  }
}
```

The `new SingleSig(ownerPk, exit)` expression compiles to a `<VTXO:SingleSig(<ownerPk>,<exit>)>` placeholder. At runtime the Arkade Operator resolves this placeholder to the actual Taproot scriptPubKey of the child contract, so the introspection check is pure Bitcoin Script.

**Arkade covenant ASM:**

```text
0 OP_INSPECTOUTPUTSCRIPTPUBKEY <VTXO:SingleSig(<ownerPk>,<exit>)> OP_EQUAL
```

If no matching tapscript is declared for `send`, the compiler synthesizes a default collaborative leaf:

```text
<SERVER_KEY> OP_CHECKSIGVERIFY <EMULATOR_KEY:send> OP_CHECKSIG
```

#### Splitting to two outputs

```solidity
import "single_sig.ark";

contract Splitter(pubkey alicePk, pubkey bobPk, int exit) {
  function split() {
    require(tx.outputs[0].scriptPubKey == new SingleSig(alicePk, exit));
    require(tx.outputs[1].scriptPubKey == new SingleSig(bobPk, exit));
  }
}
```

#### Self-referential covenant (renew pattern)

```solidity
import "self.ark";

contract FujiSafe(
  bytes assetCommitmentHash,
  int borrowAmount,
  pubkey borrowerPk,
  pubkey treasuryPk,
  int expirationTimeout,
  int priceLevel,
  int setupTimestamp,
  pubkey oraclePk,
  bytes assetPair,
  int exit
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

An Arkade Language file may start with zero or more `import` declarations, followed by a `contract` declaration:

```solidity
import "other_contract.ark";   // optional — imports for contract instantiation

contract MyContract(pubkey user, int exit) {
  function spend(signature userSig) {
    require(checkSig(userSig, user));
  }

  function unilateral(signature userSig) tapscript {
    require(older(exit));
    require(checkSig(userSig, user));
  }
}
```

### Functions

Functions without a modifier define arkade covenants. `tapscript` functions define L1 tapleaves. A covenant function with no matching or tweaked tapleaf receives a synthesized collaborative leaf using `server` and `tweak(emulator, functionName)`.

```solidity
// Arkade covenant.
function spend(signature userSig) {
  require(checkSig(userSig, user));
}

// L1 CSV exit leaf.
function unilateral(signature userSig) tapscript {
  require(older(exit));
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

Pure L1 exits are expressed as explicit `tapscript` functions, usually with `older(exit)`.

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

Arkade Language compiles to Arkade Script and produces a JSON artifact for use with Arkade libraries.

### Key Fields

| Field               | Description                                                              |
|---------------------|--------------------------------------------------------------------------|
| `contractName`      | Contract identifier                                                      |
| `constructorInputs` | Constructor parameters baked into instantiated scripts                   |
| `functions`         | Spend groups: `{ name, arkade?, leaves[] }`                              |
| `arkade`            | Optional emulator-run covenant `{ inputs, asm }`                         |
| `leaves`            | L1 tapleaf objects `{ name, witness, asm }`                              |
| `witness`           | Spend-time witness fields, with `injected: true` for infrastructure sigs |
| `asm`               | Assembly tokens; `<name>` = placeholder resolved at runtime              |

### VTXO Placeholder Format

Contract instantiation expressions in ASM use the format:

```text
<VTXO:ContractName(<arg1>,<arg2>)>
```

The Arkade runtime resolves this placeholder to the Taproot scriptPubKey of the named contract instantiated with the given arguments.
