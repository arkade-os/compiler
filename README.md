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

The Explorer ships the single-file examples (SingleSig, HTLC, FujiSafe, StructVault, NonInteractiveSwap) and the multi-file projects (Stability, LayerZero / USDT0, Options, Bonds). You can add files and folders, rename, drag between folders, and everything persists in `localStorage`. The compiler resolves imports from the Explorer's files. The link button copies a URL containing the selected contract and its dependencies. Shared bundles support up to 1 MiB of encoded URL content and 4 MiB of decompressed source data.

Every pull request gets its own build at `https://arkade-os.github.io/compiler/pr-previews/pr-<number>/`, posted as a comment on the PR.

## A tour by example

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
    require(after(refundTime));
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

`new SingleSig(alicePk, exit)` compiles to the opaque placeholder `<VTXO:SingleSig(<alicePk>,<exit>)>`. The Arkade runtime resolves it to the child contract's Taproot scriptPubKey at instantiation, so the check itself is a plain `OP_INSPECTOUTPUTSCRIPTPUBKEY ... OP_EQUAL`. Arguments are constructor parameters or literals, resolved when the contract is instantiated. A contract can instantiate itself without an import to enforce state continuation (see `examples/fuji_safe`).

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
| `escrow` | Oracle release to a committed script, timeout refund, CSV exit for both parties; `escrow.md` |
| `non_interactive_swap` | Atomic asset swap with `new SingleSig(...)` payout and locktime-gated cancel |
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

Use `arkade_compiler::compile(source)` for standalone source, `compile_file(path)` to load an entry file and its relative imports, or `compile_sources(entry, &files)` for an in-memory project (`BTreeMap<String, String>` mapping paths to source text). All return `Result<ContractJson, _>`. Standalone source uses `main.ark` as its filename. The `wasm` feature exposes `compile`, `compile_sources`, `validate`, and `version`; the WASM `compile_sources(entry, files)` accepts the file map as a JSON string and returns the artifact as a JSON string.

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
node playground/imports.test.mjs                         # after the playground build
./scripts/e2e.sh -v                                      # builds arkadec, runs artifacts through the Arkade VM and btcd (Go)
cp ./scripts/pre-commit .git/hooks                       # fmt + test before every commit
```

The E2E suite pins its dependencies in `tests/e2e/go.mod`; no Docker or emulator checkout is needed.

## Language reference

### File layout

```solidity
pragma arkade ^0.1.0;        // optional, before imports and declarations
import "./other.ark";        // zero or more; imports a file's declarations
struct Name { ... }          // zero or more, before the contract or library
contract Name(<params>) {    // entry files require a contract
  function ...
}
// Imported files may declare a library instead, or just structs:
// library Name { ... }
```

Comments use `//`. Identifiers start with a letter and contain letters, digits, and underscores. Number literals are decimal integers. Double-quoted strings are `bytes` literals in expressions and declarations (see [Byte literals](#byte-literals)), and also serve as `import` paths and `require` messages.

### Version pragma

Each source file may start with one `pragma arkade <constraint>;` directive, including imported libraries and struct-only files. It is optional; existing files compile without one. Comments and whitespace may precede it.

Use three-component versions such as `0.1.0`, with optional `=`, `^`, `~`, `>`, `>=`, `<`, or `<=` operators. Multiple constraints form a range (`>=0.1.0 <0.2.0`); `||` separates alternatives (`^0.1.0 || ^0.2.0`). Version components cannot have leading zeroes. Partial versions, wildcards, prerelease versions, and build metadata are not supported.

`0.1.0` is a placeholder while compiler versioning is being established. For now, pragmas validate syntax only: even a constraint for a future version compiles. Compatibility checks are deferred. Pragmas apply to their own file, remain verbatim in the artifact's source bundle, and do not affect generated scripts.

### Imports

Imports use explicit `.ark` paths relative to the importing file. Each file may declare top-level structs and at most one contract or library. An import exposes those structs, the declaration's constants and exported helpers, and a contract's constructor through `new Contract(...)`. The entry contract defines the artifact's spend groups; imported files supply reusable definitions.

```solidity
// types.ark
struct Policy { int maximum; }
```

```solidity
// fees.ark
library Fees {
    const int MINIMUM = 10;
    function calculate(int amount) int { return amount / 100; }
}
```

```solidity
// vault.ark
import "./types.ark";
import "./fees.ark";

contract Vault(Policy policy) {
    function spend(int amount) {
        require(amount >= Fees.MINIMUM);
        require(Fees.calculate(amount) <= policy.maximum);
    }
}
```

Structs use their declared names; constants and exported helpers use `Name.member`. Each file sees its own declarations and its direct imports. Dependencies load recursively, and imported code keeps its defining scope. Helpers inline into covenants; constants fold into literals, including in tapscript timelocks and multisig thresholds.

Struct, contract, and library names must be unique across loaded files. The compiler loads each normalized path once and reports missing files, unknown members, namespace collisions, and circular imports as errors. Import chains have a maximum depth of 128 files, including the entry file.

`new Contract(args...)` refers to the current contract or a directly imported contract. The compiler checks constructor argument counts and types and emits a VTXO placeholder for the runtime to resolve.

### Libraries

A `library Name { ... }` groups reusable constants and functions without constructor parameters or spend entrypoints. Import its `.ark` file and call exported functions as `Name.function(...)`. A library cannot be instantiated with `new`, declare tapscripts, or serve as the compilation entry file.

```solidity
library Fees {
    const int BASIS = 10000;

    function calculate(int amount, int bps) int {
        checkRate(bps);
        return amount * bps / BASIS;
    }

    private function checkRate(int bps) {
        require(bps >= 0);
        require(bps <= BASIS);
    }
}
```

Plain `function` and `public function` are exported; `private function` is callable only within its defining library. `static function` is also accepted as an exported library helper. All library functions are stateless: they see their parameters, locals, and constants, and can inspect the transaction and enforce `require` checks. They cannot capture a calling contract's constructor state. Pass any required contract state as arguments.

Libraries can import other libraries, contracts, and struct files using the same direct-import scope rules. Local helper calls can be unqualified or use the library's own name, including calls to private helpers. Calls inline using the existing helper return and recursion rules; library functions never create ABI entrypoints or witness inputs of their own. Library constants can also be used in tapscripts, but helper calls remain covenant-only.

### Types

| Type | Meaning |
|---|---|
| `pubkey` | BIP340 x-only public key |
| `signature` | 64-byte BIP340 Schnorr signature |
| `bytes`, `bytes20`, `bytes32` | Byte arrays, unsized or fixed |
| `int` | CScriptNum integer |
| `bool` | Boolean |
| `asset` | Asset identifier |
| `T[n]` | Fixed-size array of a scalar type, `n` a positive integer literal or `int` constant |
| `struct` | User-declared, nested structs and scalar arrays allowed |
| `AssetId`, `Outpoint`, `ECPoint` | Native result structs: `{txid, gidx}`, `{txid, vout}`, `{x, y}` |

Arrays and structs can be constructor parameters, covenant parameters, or locals. Arrays contain scalar elements; structs contain scalars, arrays, and nested structs. Read and assign fields individually; `require` compares whole arrays and structs with `==` and `!=` when both sides have the same declared type. Tapscript inputs are scalars.

### Functions

```solidity
function name(<params>) { ... }                // Public Arkade transaction entrypoint
public function name(<params>) { ... }         // Explicit public visibility
private function name(<params>) { ... }        // Void helper
private function name(<params>) bool { ... }   // Helper with a typed result
static function name(<params>) int { ... }     // Helper without access to constructor state
function name(<params>) tapscript { ... }      // L1 tapleaf, plain Bitcoin Script
```

A covenant with no tapscript of the same name gets a synthesized `server` + `tweak(emulator, name)` leaf. A covenant and a tapscript that share a name form one spend group. A tapscript with no matching covenant is a standalone leaf, which is how unilateral exits are written.

Private functions are helpers called from covenants and other private helpers in the same contract. Calls inline into the caller's script. Public functions define transaction entrypoints, and tapscript functions define L1 leaves. Functions can be declared in any order; call graphs must be acyclic.

Arguments are evaluated once, left to right, and passed by value. Private helpers see their own parameters and locals plus immutable constructor state. Modifying a parameter changes the helper's local copy.

Static helpers see only their own parameters, locals, and compile-time constants. They can call other static helpers and are accessible through imports. Both private and static helpers use the same inlining and return rules.

A helper's return type follows its parameter list and can be a scalar, fixed-size array, or struct. Every path through a value-returning helper must return a compatible value, and each call's result must be used. Void helpers use `return;` or fall through. Early returns exit the helper and resume the caller. To enforce a boolean result, use `require(predicate(...));`.

```solidity
contract Minimum(int minimum) {
    private function sufficient(int amount) bool {
        return amount >= minimum;
    }

    function spend(int amount) {
        require(sufficient(amount));
    }
}
```

Every spend path must contain at least one `require`, directly or through a helper that enforces a requirement on every path. An `if` without `else`, or an `else` branch without a `require`, is rejected as a bare path.

### Byte literals

Double-quoted strings and `0x` hex literals both have type `bytes`. Strings use UTF-8 and JSON escapes (`\"`, `\\`, `\n`, `\r`, `\t`, `\b`, `\f`, `\/`, and `\uXXXX`). Hex literals accept either digit case and require at least one complete byte pair. Use `""` for empty bytes.

```ark
bytes x = "hello";
bytes y = 0xdeadbeef;
bytes z = 0xDEADBEEF;
require(x == 0x68656c6c6f);
require(size("ž") == 2);
require(sha256("hello" + 0x00) == expectedHash);
```

Literals work in byte expressions, calls, comparisons, arrays, structs, and constants. They follow the same type rules as `bytes` variables; they do not implicitly become `int`, `pubkey`, `signature`, `bytes20`, or `bytes32`. Assembly stores byte data as `0x`-prefixed hex tokens and empty bytes as `OP_0`; consumers must decode these tokens as data pushes, preserving leading zeros.

### Constants

```solidity
const int EXIT_DELAY = 144;
const int HALF_DELAY = EXIT_DELAY / 2;
const int KEY_COUNT = 2;
const bool STRICT = HALF_DELAY > 0;
```

Constants are `int`, `bool`, or `bytes` compile-time expressions declared anywhere in the contract body. Initializers support literals, references to local or imported constants (including forward references), parentheses, arithmetic (`+`, `-`, `*`, `/`, unary `-`), comparisons, and boolean logic (`!`, `&&`, `||`); `bytes` constants accept a literal or another `bytes` constant. Integer arithmetic uses checked signed 64-bit values; division truncates toward zero. Cycles, runtime values, type mismatches, and out-of-range literals are rejected even in skipped operands. Division by zero and arithmetic overflow are rejected when evaluated. The compiler substitutes their values before validation; they occupy no constructor or witness inputs.

A constant is readable in covenant bodies, private and static helpers, array indices (including crypto operands), multisig thresholds, and a tapleaf's `older(...)` or `after(...)` operand. A delay shared by a covenant and its L1 exit is written once. Array sizes accept positive integer literals or `int` constants, such as `pubkey[KEY_COUNT]` or `int[Config.SIZE]`, in constructor parameters, function parameters, struct fields, and local declarations.

Constants are immutable, and their names must be distinct from all other bindings and function names in the contract.

```solidity
contract Vault(pubkey owner) {
    const int EXIT_DELAY = 144;

    static function pct(int amount, int bps) int {
        return amount * bps / 10000;
    }

    function spend(signature sig, int amount) {
        require(checkSig(sig, owner));
        require(pct(amount, 50) > 0);
    }

    function exit(signature sig) tapscript {
        require(older(EXIT_DELAY));
        require(checkSig(sig, owner));
    }
}
```

### Statements (covenant bodies)

```solidity
require(<expr>);
require(<expr>, "message");
let x = <expr>;                    // inferred type
int fee = amount / 100;            // declared type
Policy p = { primary: {...}, limits: [1, 2], exitDelay: 10 };
int[3] scale = [1, 2, 3];
x = <expr>;                        // reassignment keeps the declared type
scale[x + 1] = 10;                 // runtime index with bounds checking
p.primary.weight = 5;
if (<expr>) { ... } else { ... }
for (i, item) in arr { ... }       // unrolled at compile time
for (COUNT) { ... }                // COUNT is a non-negative compile-time int expression
```

Each live binding has a unique name. Constructor parameters are immutable.

### Expressions

Arithmetic `+ - * /` and unary `-` on `int`. Comparison `== != < <= > >=`. Boolean `!`, `&&`, and `||` on `bool` in covenant functions. Precedence from highest to lowest is unary operators, multiplication/division, addition/subtraction, comparisons, `&&`, then `||`; parentheses override it. Logical operators evaluate left to right and short-circuit: `&&` skips the right operand when the left is false, and `||` skips it when the left is true. Both operands must be valid boolean expressions even when one is skipped. `+` on byte operands is concatenation; mixing an `int` into a byte concatenation is an error until you widen it with `num2bin(value, width)`, because the width is consensus-visible. `arr.length` folds to the declared size. Array reads and writes accept `int` index expressions; runtime indices emit bounds checks.

### Built-ins

**Signatures.** `checkSig(sig, key)`, `checkMultisig([keys], [sigs], threshold?)` with N-of-N when the threshold is omitted (covenants accept any threshold, via `OP_CHECKSIGADD`), `checkSigFromStack(sig, key, message)` and its `Verify` form. `tweak(emulator, fn)` is a key expression usable only inside tapscripts.

**Hashes.** `sha256`, `hash160`, `hash256`, `ripemd160` as `require(hashFn(preimage) == hash)`. `sha256(expr)` also works as a value, including over concatenations and `substr` results. Streaming: `sha256Initialize`, `sha256Update`, `sha256Finalize`. Runtime-selected: `digest(data, hashType)`, `sighash(hashType)`.

**Time.** In covenants, `tx.time` reads the transaction locktime using `OP_INSPECTLOCKTIME`, and `require(tx.time >= deadline)` compares it with the bound, whether a literal, constant, or runtime value. In tapscripts, `older(n)` emits CSV and `after(n)` emits CLTV. Both are tapscript-only; `tx.time` is not available in tapscripts.

In covenants, `checkTime(timestamp)` returns whether the emulator's wall clock has reached a Unix timestamp in seconds, including equality. Use `require(checkTime(unlockAt))` to enforce it. A future timestamp returns false; a negative timestamp fails execution. This check is independent of transaction locktime and sequence.

**Transaction.** `tx.version`, `tx.locktime`, `tx.numInputs`, `tx.numOutputs`, `tx.weight`, `tx.id`, `this.activeInputIndex`, `this.activeBytecode`. In covenants, `this.expiry` returns the executing VTXO's Unix expiry timestamp in seconds through `OP_PUSHEXPIRY`; execution fails if expiry is unavailable.

**Continuation.** `require(this.tunnel(outputIndex))` preserves the current input's logical scriptPubKey, bitcoin value, and assets at the selected output. An explicit policy supplies all three compile-time boolean fields: `this.tunnel(outputIndex, {scriptPubKey: true, value: true, assets: false})`. With asset preservation enabled, an optional fixed list excludes specific `AssetId` values: `this.tunnel(outputIndex, {scriptPubKey: true, value: true, assets: true}, [feeAsset])`. At least one property must be selected. A mismatch fails execution; success returns true. Tunneling is covenant-only and does not establish intent type, timing, packet preservation, or a unique input-to-output mapping.

**Intent messages.** In covenants, `tx.intent.field("type")` returns the encoded field bytes and asserts presence; `tx.intent.has("type")` returns presence without keeping the value. Paths are quoted literals with dot-separated lowercase keys or canonical decimal indexes, such as `"cosigners.0"`; queries, wildcards, leading-zero indexes, and indexes at or above 1048576 are rejected. Present false, zero, and empty strings still count as present. Integer fields use Script-number encoding: `bin2num(tx.intent.field("expire_at"))`. Require `tx.intent.field("type") == "register"` before relying on register-specific fields. Missing context, null, missing fields, and non-integer numbers are misses; `field` fails on a miss and `has` returns false. Both use the emulator's result-size and compute limits.

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
  "source": { "entry": "htlc.ark", "files": { "htlc.ark": "..." } },
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
| `warnings` | Type-check and validation warnings include their source file path; omitted when empty |
| `source` | `{ entry, files }`: original entry source and every recursively imported file, including comments |

Witness `encoding` values: `compressed-33`, `schnorr-64`, `raw`, `raw-20`, `raw-32`, `scriptnum`. `updatedAt` changes on every compile; ignore it when diffing artifacts.

The `source` bundle contains the entry file and every loaded dependency, preserving their text verbatim, including comments. Paths are normalized and relative; native compilation strips the common directory prefix. Recompile a bundle with the same compiler version using `compile_sources(&source.entry, &source.files)`. Standalone compilation produces a one-file bundle with entry `main.ark`.

Type-check and validation warnings identify their source file relative to the bundle root, including warnings from dependencies.

### Covenant stack ABI

`constructorInputs`, `arkade.inputs`, and `witness` describe the source ABI, not the physical stack. Clients expand an array entry `oracles` of type `pubkey[3]` into `oracles.0`, `oracles.1`, `oracles.2`, and a struct entry into its scalar leaves in field order, recursively, using dotted paths such as `policy.primary.key`.

Clients serialize covenant inputs in reverse `arkade.inputs` order. Every covenant `asm` opens with one `<name>` placeholder per expanded constructor input, also reversed, which instantiation replaces with data pushes before the covenant hash is computed. The VM installs the function witness first, so constructor values sit above function inputs; the body reaches everything through `OP_PICK` and friends and never emits function inputs as placeholders. After instantiation the only remaining placeholders are `<VTXO:Contract(<a>,<b>)>` tokens, which the runtime resolves to the child contract's scriptPubKey.

## Security

See [SECURITY.md](SECURITY.md) for the disclosure process.
