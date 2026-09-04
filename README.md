# Arkade Compiler

Arkade Language is a contract language for Bitcoin. You write a contract as a set of spend functions over constructor state. The compiler, `arkadec`, turns it into a JSON artifact with two kinds of script: Arkade covenants, which the Arkade VM executes offchain, and L1 tapscript leaves, which give every party a unilateral exit on Bitcoin. Arkade libraries consume the artifact directly, and `arkade-bindgen` turns it into typed TypeScript or Go stubs.

The language covers signature and multisig checks, absolute and relative timelocks, transaction introspection, Arkade Assets and asset groups, byte-string parsing, fixed-size arrays, structs, and recursive contract instantiation with `new`.

## Try it in the browser

**[arkade-os.github.io/compiler](https://arkade-os.github.io/compiler)**

The playground runs the real compiler as WebAssembly. Nothing is installed and nothing leaves your browser. Pick a contract from the Explorer, edit it, and press **Ctrl+Enter** (or **Ctrl+S**). The right panel shows four tabs:

| Tab | What you get |
|---|---|
| JSON Output | The full artifact, the same bytes `arkadec` writes to disk |
| Assembly | Every spend group: the Arkade covenant ASM and each tapscript leaf, opcodes and `<placeholders>` highlighted |
| Bindings | Generated TypeScript or Go client code for the artifact, switchable per target |
| Errors | Parse, type, and validation errors; the offending line is selected in the editor |

The Explorer ships the single-file examples (SingleSig, HTLC, FujiSafe, StructVault, NonInteractiveSwap) and the multi-file projects (Stability, LayerZero / USDT0, Options, Bonds). You can add files and folders, rename, drag between folders, and everything persists in `localStorage`. The link button copies a URL with your current source compressed into the hash, so a contract can be shared without a backend.

Every pull request gets its own build at `https://arkade-os.github.io/compiler/pr-previews/pr-<number>/`, posted as a comment on the PR.

## A tour by example

Every snippet below compiles on `master`. Paste any of them into the playground.

### One key, one exit

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

`spend` has no modifier, so it is an Arkade covenant: the body compiles to covenant ASM that the Arkade VM runs. Because `spend` declares no tapscript of its own, the compiler synthesizes the collaborative L1 leaf `<SERVER_KEY> OP_CHECKSIGVERIFY <EMULATOR_KEY:spend> OP_CHECKSIG` for it. `unilateral` is marked `tapscript`, so it is a pure L1 leaf: a CSV delay followed by the user's key.

### Hash and time locks

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

A covenant and a tapscript with the same name form one spend group. The covenant enforces the payout; the leaf with the same name is the L1 shape for that path. `server` and `emulator` are reserved key roles that Arkade infrastructure signs for, so their signatures are marked `injected` in the artifact.

### Recursive VTXOs with `new`

```solidity
import "single_sig.ark";

contract Splitter(pubkey alicePk, pubkey bobPk, int exit) {
  function split() {
    require(tx.outputs[0].scriptPubKey == new SingleSig(alicePk, exit));
    require(tx.outputs[1].scriptPubKey == new SingleSig(bobPk, exit));
  }
}
```

`new SingleSig(alicePk, exit)` compiles to the opaque placeholder `<VTXO:SingleSig(<alicePk>,<exit>)>`. The Arkade runtime resolves it to the child contract's Taproot scriptPubKey at instantiation, so the check itself is a plain `OP_INSPECTOUTPUTSCRIPTPUBKEY ... OP_EQUAL`. Arguments must be constructor parameters or literals; function inputs only exist at spend time and cannot be baked into a placeholder. A contract can instantiate itself with `import "self.ark";` to enforce state continuation (see `examples/fuji_safe`).

### Assets

```solidity
contract TokenVault(
  pubkey ownerPk,
  bytes32 tokenAssetIdTxid,
  int tokenAssetIdGidx,
  bytes32 ctrlAssetIdTxid,
  int ctrlAssetIdGidx,
  int exit
) {
  function deposit(signature ownerSig) {
    require(tx.inputs[0].assets.lookup(ctrlAssetIdTxid, ctrlAssetIdGidx) > 0, "no ctrl in input");
    require(tx.outputs[0].assets.lookup(ctrlAssetIdTxid, ctrlAssetIdGidx) > 0, "no ctrl in output");
    require(
      tx.outputs[0].assets.lookup(tokenAssetIdTxid, tokenAssetIdGidx) >=
        tx.inputs[0].assets.lookup(tokenAssetIdTxid, tokenAssetIdGidx),
      "token balance decreased"
    );
    require(checkSig(ownerSig, ownerPk), "invalid owner signature");
  }

  function unilateral(signature ownerSig) tapscript {
    require(older(exit));
    require(checkSig(ownerSig, ownerPk));
  }
}
```

An Asset ID is a `(bytes32 txid, int gidx)` pair. `assets.lookup` asserts the asset is present on that input or output and yields its amount; `assets.has` is the boolean form. For supply accounting across the whole transaction, `tx.assetGroups.find(txid, gidx)` returns a group with `sumInputs`, `sumOutputs`, `delta`, `controlIs(txid, gidx)`, and friends (see `examples/controlled_mint`).

### Arrays, structs, loops

```solidity
struct Signer {
  pubkey key;
  int weight;
}

struct Policy {
  Signer primary;
  int[2] limits;
  int exitDelay;
}

contract StructVault(Policy policy) {
  function update(Policy next, signature sig, bytes32 message) {
    require(checkSigFromStack(sig, policy.primary.key, message));

    int total = 0;
    for (i, limit) in next.limits {
      total = total + limit;
    }
    require(total >= policy.primary.weight);

    Policy local = {
      primary: { key: next.primary.key, weight: total },
      limits: [next.limits[0], next.limits[1]],
      exitDelay: policy.exitDelay
    };
    require(local.primary.weight == total);
  }

  function unilateral(signature sig) tapscript {
    require(older(policy.exitDelay));
    require(checkSig(sig, policy.primary.key));
  }
}
```

Arrays are fixed-size and part of the type. Loops unroll at compile time, one copy per element, so script size grows with the declared size. Structs flatten to their scalar leaves; the artifact keeps the declaration so clients can flatten the same way. `examples/threshold_oracle` shows the same machinery counting `checkSigFromStack` successes over `pubkey[3] oracles` to enforce a quorum.

### More in `examples/`

| Directory | Shows |
|---|---|
| `single_sig`, `htlc` | Minimum viable VTXO and hash/time locks |
| `non_interactive_swap` | Atomic asset swap with `new SingleSig(...)` payout and CLTV cancel |
| `payment_auth` | Introspection-driven payout splits with `if`/`else` and `tx.input.current.value` |
| `token_vault`, `controlled_mint`, `nft_mint` | Asset lookups, asset groups, control assets |
| `struct_vault`, `threshold_oracle` | Structs, arrays, loops, oracle quorum |
| `fuji_safe`, `stability`, `bonds`, `options` | Stateful contracts that recreate themselves with `new` |
| `layerzero` | Packet introspection, `substr`/`cat`/`bin2num`, cross-input binding via `arkadeScriptHash` |
| `arkade_kitties` | NFT breeding with asset-group introspection |

The `.md` files next to those contracts explain the economics and transaction layouts.

## Install and run

Requires a Rust toolchain ([rustup.rs](https://rustup.rs/)).

```bash
cargo install --path .              # installs arkadec
arkadec contract.ark                # writes contract.json in the current directory
arkadec contract.ark -o out.json
```

Type-check warnings go to stderr; errors abort with a non-zero exit. From a checkout, `cargo run -- examples/htlc/htlc.ark -o /tmp/htlc.json` is the fastest way to inspect output.

Generate client bindings from one artifact or a directory of them:

```bash
cargo run -p arkade-bindgen -- contract.json --lang typescript,go -o ./generated/
cargo run -p arkade-bindgen -- --list-targets
```

`--embed` inlines the artifact JSON into the generated file; `--package` sets the module or namespace name.

Use the compiler as a library with `arkade_compiler::compile(source) -> Result<ContractJson, _>`. The `wasm` feature exposes `compile`, `validate`, and `version` through `wasm-bindgen`; that is what the playground calls.

### Run the playground locally

```bash
cargo install wasm-pack
./playground/build.sh     # regenerates contracts.js from examples/ and builds pkg/ with wasm-pack
./playground/serve.sh     # http://localhost:8080, pass a port to override
```

`playground/contracts.js` and `playground/pkg/` are generated and git-ignored. Add a contract to the playground by adding a `.ark` file under `examples/` and registering it in `playground/main.js`.

### Tests

```bash
cargo test --workspace                                   # unit, feature, and example tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
./scripts/e2e.sh -v                                      # builds arkadec, runs artifacts through the Arkade VM and btcd (Go)
cp ./scripts/pre-commit .git/hooks                       # fmt + test before every commit
```

The E2E suite pins its dependencies in `tests/e2e/go.mod`; no Docker or emulator checkout is needed.

## Language reference

### File layout

```solidity
import "other.ark";          // zero or more; declares contracts usable in `new`
struct Name { ... }          // zero or more, before the contract
contract Name(<params>) {    // exactly one
  function ...
}
```

Comments use `//`. Identifiers start with a letter and contain letters, digits, and underscores. Number literals are decimal integers; string literals appear only in `import` and as `require` messages.

### Types

| Type | Meaning |
|---|---|
| `pubkey` | BIP340 x-only public key |
| `signature` | 64-byte BIP340 Schnorr signature |
| `bytes`, `bytes20`, `bytes32` | Byte arrays, unsized or fixed |
| `int` | CScriptNum integer |
| `bool` | Boolean |
| `asset` | Asset identifier |
| `T[n]` | Fixed-size array of a scalar type, `n` a positive literal |
| `struct` | User-declared, nested structs and scalar arrays allowed |
| `AssetId`, `Outpoint`, `ECPoint` | Native result structs: `{txid, gidx}`, `{txid, vout}`, `{x, y}` |

Arrays and structs are allowed in constructor and covenant parameters and as locals. Tapscript inputs must be scalars. Arrays of structs, whole-struct assignment, and whole-struct comparison are not supported.

### Functions

```solidity
function name(<params>) { ... }             // Arkade covenant, run by the Arkade VM
function name(<params>) tapscript { ... }   // L1 tapleaf, plain Bitcoin Script
```

A covenant with no tapscript of the same name gets a synthesized `server` + `tweak(emulator, name)` leaf. A covenant and a tapscript that share a name form one spend group. A tapscript with no matching covenant is a standalone leaf, which is how unilateral exits are written.

The `internal` modifier parses and excludes the function from the spend surface, but call statements to it are currently dropped by the parser rather than inlined. Do not rely on `internal` for enforcement until that lands; write the checks in the calling function.

Every spend path must contain at least one `require`. An `if` without `else`, or an `else` branch without a `require`, is rejected as a bare path.

### Statements (covenant bodies)

```solidity
require(<expr>);
require(<expr>, "message");
let x = <expr>;                    // inferred type
int fee = amount / 100;            // declared type
Policy p = { primary: {...}, limits: [1, 2], exitDelay: 10 };
int[3] scale = [1, 2, 3];
x = <expr>;                        // reassignment keeps the declared type
scale[1] = 10;                     // literal index only on master, see Upcoming
p.primary.weight = 5;
if (<expr>) { ... } else { ... }
for (i, item) in arr { ... }       // unrolled at compile time
```

Shadowing a live name is an error. Constructor parameters cannot be reassigned.

### Expressions

Arithmetic `+ - * /` and unary `-` on `int`. Comparison `== != < <= > >=`. `+` on byte operands is concatenation; mixing an `int` into a byte concatenation is an error until you widen it with `num2bin(value, width)`, because the width is consensus-visible. `arr.length` folds to the declared size. Array indices may be any `int` expression when reading; a runtime index emits a bounds check.

### Built-ins

**Signatures.** `checkSig(sig, key)`, `checkMultisig([keys], [sigs], threshold?)` with N-of-N when the threshold is omitted (covenants accept any threshold, via `OP_CHECKSIGADD`), `checkSigFromStack(sig, key, message)` and its `Verify` form. `tweak(emulator, fn)` is a key expression usable only inside tapscripts.

**Hashes.** `sha256`, `hash160`, `hash256`, `ripemd160` as `require(hashFn(preimage) == hash)`. `sha256(expr)` also works as a value, including over concatenations and `substr` results. Streaming: `sha256Initialize`, `sha256Update`, `sha256Finalize`. Runtime-selected: `digest(data, hashType)`, `sighash(hashType)`.

**Time.** In covenants, `tx.time` is the transaction locktime as an `int`, so `require(tx.time >= deadline)` is a CLTV check. In tapscripts, `older(n)` emits CSV and `after(n)` or `tx.time >= n` emits CLTV. `after(...)` is tapscript-only.

**Transaction.** `tx.version`, `tx.locktime`, `tx.numInputs`, `tx.numOutputs`, `tx.weight`, `tx.id`, `this.activeInputIndex`, `this.activeBytecode`.

**Inputs and outputs.** `tx.inputs[i].value | scriptPubKey | sequence | outpoint | arkadeScriptHash | arkadeWitnessHash`, `tx.outputs[o].value | scriptPubKey`, and `tx.input.current.value | scriptPubKey | sequence | outpoint` for the input being spent.

**Assets.** On any input or output: `.assets.lookup(txid, gidx)` (asserts presence, yields amount), `.assets.has(txid, gidx)`, `.assets.length`, `.assets[t].assetId`, `.assets[t].amount`. Groups: `tx.assetGroups.find(txid, gidx)`, `.has(txid, gidx)`, `.length`, and per group `numInputs`, `numOutputs`, `sumInputs`, `sumOutputs`, `delta`, `hasControl`, `controlIs(txid, gidx)`, `metadataHash`, `assetId`, `isFresh`.

**Bytes.** `substr(data, offset, size)`, `cat(a, b)`, `bin2num(bytes)`, `num2bin(value, size)`, `reverseBytes(bytes)`, `size(bytes)`.

**Packets.** `tx.packet(type)` and `tx.inputs[i].packet(type)` return the raw extension packet bytes and assert presence.

**Arithmetic and curves.** `modExp(base, exp, mod)`, `ecAdd(x1, y1, x2, y2, curve)` and `ecMul(x, y, k, curve)` returning `ECPoint`, `ecPairing(...)`, `ecMulScalarVerify(k, P, Q)`, `tweakVerify(P, k, Q)`.

**Instantiation.** `new Contract(args...)` on either side of a `scriptPubKey` comparison against `tx.outputs[o]`, `tx.inputs[i]`, or `tx.input.current`. Zero-argument constructors are allowed. Array arguments flatten element by element.

### Tapscript bodies

A tapscript body is `require` statements only, and must follow the closure template in source order: an optional single hash condition, then an optional single timelock, then exactly one `checkSig` or `checkMultisig`. Hash plus CSV is a recognized shape; hash plus CLTV is not, so split it into two leaves. arkd accepts only N-of-N leaves, so a `checkMultisig` threshold, if written, must equal the key count, and each signature must be a declared `signature` input aligned 1:1 with its key.

Keys resolve to constructor `pubkey` parameters, declared `pubkey` inputs, or the roles `server` and `emulator`. Any leaf without a CSV delay is a forfeit path and must include `server`. A leaf whose name matches a covenant must include bare `emulator`, which the compiler tweaks with that covenant's hash. A leaf with no matching covenant may not use bare `emulator`; it either stays standalone or binds to one covenant with `tweak(emulator, fn)`. Inputs named `server` or `emulator` are rejected.

## Artifact format

```json
{
  "contractName": "HTLC",
  "constructorInputs": [{ "name": "sender", "type": "pubkey" }, ...],
  "structs": [],
  "functions": [
    {
      "name": "claim",
      "arkade": { "inputs": [], "asm": ["<exit>", "<refundTime>", "..."] },
      "leaves": [
        {
          "name": "claim",
          "witness": [
            { "name": "preimage", "type": "bytes", "encoding": "raw" },
            { "name": "serverSig", "type": "signature", "encoding": "schnorr-64", "injected": true },
            { "name": "emulatorSig", "type": "signature", "encoding": "schnorr-64", "injected": true }
          ],
          "asm": ["OP_HASH160", "<preimageHash>", "OP_EQUAL", "OP_VERIFY", "<SERVER_KEY>", "OP_CHECKSIGVERIFY", "<EMULATOR_KEY:claim>", "OP_CHECKSIG"]
        }
      ]
    },
    { "name": "unilateral", "leaves": [ ... ] }
  ],
  "source": "...",
  "compiler": { "name": "arkade-compiler", "version": "0.1.0" },
  "updatedAt": "2026-01-01T00:00:00Z"
}
```

| Field | Meaning |
|---|---|
| `constructorInputs` | One entry per source parameter, declaration order; arrays keep their size in the type, structs keep their type name |
| `structs` | User struct layouts, so clients can flatten parameters the way the compiler does |
| `functions[]` | Spend groups: `{ name, arkade?, leaves[] }` |
| `arkade` | `{ inputs, asm }`; absent for groups made only of standalone leaves |
| `leaves[]` | `{ name, witness, asm }`; `witness` lists spend-time values in source order, `injected: true` marks infrastructure signatures |
| `warnings` | Type-check warnings, omitted when empty |

Witness `encoding` values: `compressed-33`, `schnorr-64`, `raw`, `raw-20`, `raw-32`, `scriptnum`. `updatedAt` changes on every compile; ignore it when diffing artifacts.

### Covenant stack ABI

`constructorInputs`, `arkade.inputs`, and `witness` describe the source ABI, not the physical stack. Clients expand an array entry `oracles` of type `pubkey[3]` into `oracles.0`, `oracles.1`, `oracles.2`, and a struct entry into its scalar leaves in field order, recursively, using dotted paths such as `policy.primary.key`.

Clients serialize covenant inputs in reverse `arkade.inputs` order. Every covenant `asm` opens with one `<name>` placeholder per expanded constructor input, also reversed, which instantiation replaces with data pushes before the covenant hash is computed. The VM installs the function witness first, so constructor values sit above function inputs; the body reaches everything through `OP_PICK` and friends and never emits function inputs as placeholders. After instantiation the only remaining placeholders are `<VTXO:Contract(<a>,<b>)>` tokens, which the runtime resolves to the child contract's scriptPubKey.

## Upcoming

The README tracks `master`. These are in review and will change what compiles:

**Expression-indexed element writes ([#82](https://github.com/arkade-os/compiler/pull/82)).** `scale[writeIndex + 1] = 10;` and `state.values[i + 1] = next;` become legal with any `int` index expression, with lower and upper bound checks emitted at runtime. Reassignment of scalars and elements moves to `OP_PUT`, which shortens the emitted covenant. On `master` an element write needs a literal index.

**Artifact static analysis ([#81](https://github.com/arkade-os/compiler/pull/81)).** A public `arkade_compiler::analysis::analyze_output(&ContractJson)` re-derives each leaf's closure from its ASM and re-runs the tapscript rules against the emitted artifact, so consumers can validate artifacts they did not compile themselves.

**Wall-clock time.** Several draft example PRs reference `tx.offchainTime`, the TEE introspector's unix-seconds clock, as distinct from `tx.time` block height. It is not a recognized binding on `master` yet, so those examples keep it in comments.

## Security

See [SECURITY.md](SECURITY.md) for the disclosure process.
