# Arkade Compiler

[![Build](https://github.com/arkade-os/compiler/actions/workflows/build.yml/badge.svg)](https://github.com/arkade-os/compiler/actions/workflows/build.yml)
[![Release](https://github.com/arkade-os/compiler/actions/workflows/release.yml/badge.svg)](https://github.com/arkade-os/compiler/actions/workflows/release.yml)
[![GitHub release](https://img.shields.io/github/v/release/arkade-os/compiler?sort=semver)](https://github.com/arkade-os/compiler/releases/latest)
[![crates.io](https://img.shields.io/crates/v/arkade-compiler)](https://crates.io/crates/arkade-compiler)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

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
| Diagnostics | Compiler warnings and errors; an offending line is selected in the editor when available |

The Explorer ships the single-file examples (SingleSig, HTLC, FujiSafe, StructVault, NonInteractiveSwap) and the multi-file projects (Stability, LayerZero / USDT0, Options, Bonds). You can add files and folders, rename, drag between folders, and everything persists in `localStorage`. The compiler resolves imports from the Explorer's files. The link button copies a URL containing the selected contract and its dependencies. Shared bundles support up to 1 MiB of encoded URL content and 4 MiB of decompressed source data.

Every pull request gets its own build at `https://arkade-os.github.io/compiler/pr-previews/pr-<number>/`, posted as a comment on the PR.

## A tour by example

### One key, one exit

```solidity
contract SingleSig(pubkey user) {
  function spend(signature userSig) {
    require(checkSig(userSig, user));
  }

  function unilateral(signature userSig) tapscript {
    require(older(serverExitDelay));
    require(checkSig(userSig, user));
  }
}
```

`spend` has no modifier, so it is an Arkade covenant: the body compiles to covenant ASM that the Arkade VM runs. Because `spend` declares no tapscript of its own, the compiler synthesizes the collaborative L1 leaf `<SERVER_KEY> OP_CHECKSIGVERIFY <EMULATOR_KEY:spend> OP_CHECKSIG` for it. `unilateral` is marked `tapscript`, so it is a pure L1 leaf: a CSV delay followed by the user's key. `serverExitDelay` is arkd's unilateral exit delay; it lowers to `<SERVER_EXIT_DELAY>`, which the SDK fills from the server's config, so it is not a constructor input.

### Hash and time locks

```solidity
contract HTLC(
  pubkey sender,
  pubkey receiver,
  bytes20 preimageHash,
  int refundTime
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
    require(older(serverExitDelay));
    require(checkSig(senderSig, sender));
  }
}
```

A covenant and a tapscript with the same name form one spend group. The covenant enforces the payout; the leaf with the same name is the L1 shape for that path. `server` and `emulator` are reserved key roles that Arkade infrastructure signs for, so their signatures are marked `injected` in the artifact.

### Recursive VTXOs with `new`

```solidity
import "single_sig.ark";

contract Splitter(pubkey alicePk, pubkey bobPk) {
  function split() {
    require(tx.outputs[0].scriptPubKey == new SingleSig(alicePk));
    require(tx.outputs[1].scriptPubKey == new SingleSig(bobPk));
  }
}
```

`new SingleSig(alicePk)` compiles to the opaque placeholder `<CONTRACT:SingleSig(<alicePk>)>`. The Arkade runtime resolves it to the child contract's 32-byte Taproot output key (witness program) at instantiation, so the check itself is a plain `OP_INSPECTOUTPUTSCRIPTPUBKEY ... OP_EQUAL`. Arguments are constructor parameters or literals, resolved when the contract is instantiated. A contract can instantiate itself without an import to enforce state continuation (see `examples/fuji_safe`).

### Assets

```solidity
contract TokenVault(
  pubkey ownerPk,
  bytes32 tokenAssetIdTxid,
  int tokenAssetIdGidx,
  bytes32 ctrlAssetIdTxid,
  int ctrlAssetIdGidx
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
    require(older(serverExitDelay));
    require(checkSig(ownerSig, ownerPk));
  }
}
```

An Asset ID is a `(bytes32 txid, int gidx)` pair. `assets.lookup` asserts the asset is present on that input or output and yields its amount; `assets.has` is the boolean form. For supply accounting across the whole transaction, `tx.assetGroups.find(txid, gidx)` returns an `AssetGroup` with `sumInputs`, `sumOutputs`, `delta`, `controlIs(txid, gidx)`, and friends (see `examples/controlled_mint`).

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
| `fuji_safe`, `stability`, `bonds` | Stateful contracts that recreate themselves with `new` |
| `option` | Cash-settled covered call and limited put with an on-stack oracle TWAP |
| `layerzero` | Packet introspection, `substr`/`cat`/`bin2num`, cross-input binding via `arkadeScriptHash` |
| `arkade_kitties` | NFT breeding with asset-group introspection |

The `.md` files next to those contracts explain the economics and transaction layouts.

## Install and run

Prebuilt `arkadec` and `arkade-bindgen` binaries for Linux, macOS, and Windows are attached to each [GitHub release](https://github.com/arkade-os/compiler/releases) with a `SHA256SUMS` file. With a Rust toolchain ([rustup.rs](https://rustup.rs/)), install from crates.io or a checkout instead:

```bash
cargo install arkade-compiler --locked   # installs arkadec
cargo install arkade-bindgen --locked
cargo install --path . --locked          # installs arkadec from a checkout
arkadec contract.ark                     # writes contract.json in the current directory
arkadec contract.ark -o out.json
arkadec contract.ark --no-optimize       # skips peephole optimization of Arkade covenants
```

Warnings go to stderr; type and validation errors abort with a non-zero exit. From a checkout, `cargo run -- examples/htlc/htlc.ark -o /tmp/htlc.json` is the fastest way to inspect output.

Generate client bindings from one artifact or a directory of them:

```bash
cargo run -p arkade-bindgen -- contract.json --lang typescript,go -o ./generated/
cargo run -p arkade-bindgen -- --list-targets
```

`--embed` inlines the artifact JSON into the generated file; `--package` sets the module or namespace name.

The TypeScript SDK reads the artifact directly with `programFromArtifact`; generating bindings is optional.

Use `arkade_compiler::compile(source)` for standalone source, `compile_file(path)` to load an entry file and its relative imports, or `compile_sources(entry, &files)` for an in-memory project (`BTreeMap<String, String>` mapping paths to source text). All return `Result<ContractJson, _>`. Standalone source uses `main.ark` as its filename. The `wasm` feature exposes `compile`, `compile_sources`, `compile_sources_with_diagnostics`, `validate`, and `version`; `compile_sources(entry, files)` returns the artifact JSON, while `compile_sources_with_diagnostics(entry, files)` returns `{ artifact: string, warnings: string[] }` for the playground.

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

### Releasing

`arkade-compiler` and `arkade-bindgen` share the version in the root `Cargo.toml` `[workspace.package]` table. To release, bump it in a PR (on a minor bump, also raise `arkade-bindgen`'s `arkade-compiler` requirement), merge, and push `v<version>` from the merge commit. `.github/workflows/release.yml` checks the tag against the version, builds binaries for five targets, creates a GitHub release with `SHA256SUMS`, and publishes both crates to crates.io through trusted publishing. A tag with a suffix such as `v0.1.0-test` creates a GitHub pre-release and skips crates.io; remove it with `gh release delete <tag> --cleanup-tag`.

Trusted publishing can only be configured on existing crates, so the first crates.io release is manual: a crate owner runs `cargo publish --locked -p arkade-compiler && cargo publish --locked -p arkade-bindgen` from the commit to be tagged, enables trusted publishing for both crates (repository `arkade-os/compiler`, workflow `release.yml`, environment `crates-io`), and then pushes the tag. The workflow skips crates whose version is already published.

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

Pragmas currently validate syntax only: even a constraint for a future compiler version compiles. Compatibility checks are deferred. Pragmas apply to their own file, remain verbatim in the artifact's source bundle, and do not affect generated scripts.

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

`new Contract(args...)` refers to the current contract or a directly imported contract. The compiler checks constructor argument counts and types and emits a contract placeholder for the runtime to resolve.

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
| `pubkey` | Alias of `bytes` for public keys of any length, e.g. 32-byte x-only or 33-byte compressed |
| `signature` | 64-byte BIP340 Schnorr signature |
| `bytes`, `bytes20`, `bytes32` | Byte arrays, unsized or fixed |
| `int` | CScriptNum integer |
| `bool` | Boolean |
| `asset` | Asset identifier |
| `AssetGroup` | An asset group of the transaction; a witness or constructor value is its packet position |
| `T[n]` | Fixed-size array of a scalar or struct type, `n` a positive integer literal or `int` constant |
| `struct` | User-declared, nested structs and fixed-size arrays allowed |
| `AssetId`, `Outpoint`, `ECPoint`, `G2Point` | Native structs: `{txid, gidx}`, `{txid, vout}`, `{x, y}`, `{xC1, xC0, yC1, yC0}` |

Arrays and structs can be constructor parameters, covenant parameters, or locals. Arrays contain scalars or structs; structs contain scalars, arrays, and nested structs. Indexed fields support literal and runtime indexes, such as `items[0].value` and `items[index].value`. Read and assign fields individually; `require` compares whole arrays and structs with `==` and `!=` when both sides have the same declared type. Tapscript inputs are scalars.

### Functions

```solidity
function name(<params>) { ... }                // Public Arkade transaction entrypoint
public function name(<params>) { ... }         // Explicit public visibility
private function name(<params>) { ... }        // Void helper
private function name(<params>) bool { ... }   // Helper with a typed result
static function name(<params>) int { ... }     // Helper without access to constructor state
function name(<params>) tapscript { ... }      // L1 tapleaf, plain Bitcoin Script
```

A covenant and its tapscripts form one spend group: a tapscript whose name matches the covenant, and a tapscript that tweaks a key to that covenant. The group keeps a synthesized `server` + `tweak(emulator, name)` leaf unless one of those tapscripts already signs with `emulator`. A constructor-pubkey tweak is an extra leaf; it does not replace that emulator leaf. A tapscript that tweaks nothing is a standalone leaf, which is how unilateral exits are written.

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

Constants are `int`, `bool`, or `bytes` compile-time expressions declared anywhere in the contract body. Initializers support literals, references to local or imported constants (including forward references), parentheses, arithmetic (`+`, `-`, `*`, `/`, `%`, `<<`, `>>`, unary `-`), comparisons, and boolean logic (`!`, `&&`, `||`); `bytes` constants accept a literal or another `bytes` constant. Integer arithmetic uses checked signed 64-bit values; division truncates toward zero and `%` takes the sign of the dividend. Cycles, runtime values, type mismatches, and out-of-range literals are rejected even in skipped operands. Division or modulo by zero and arithmetic overflow are rejected when evaluated. The compiler substitutes their values before validation; they occupy no constructor or witness inputs.

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

Arithmetic `+ - * /`, remainder `%` (with the sign of the dividend, so `-7 % 2 == -1`) and unary `-` on `int`. Shifts `<<` and `>>` on `int`: the count must not be negative, and `>>` is arithmetic, rounding toward negative infinity. Bytewise `&`, `|`, `^` and unary `~` on bytes; the two-operand forms need operands of equal length, checked at compile time when both lengths are known and by the VM otherwise. Comparison `== != < <= > >=`. Boolean `!`, `&&`, and `||` on `bool` in covenant functions. Precedence from highest to lowest is unary operators, multiplication/division/remainder, addition/subtraction, shifts, `&`, `^`, `|`, comparisons, `&&`, then `||`; parentheses override it, and `a & mask == b` means `(a & mask) == b`. Logical operators evaluate left to right and short-circuit: `&&` skips the right operand when the left is false, and `||` skips it when the left is true. Both operands must be valid boolean expressions even when one is skipped. `+` on byte operands is concatenation; mixing an `int` into a byte concatenation is an error until you widen it with `num2bin(value, width)`, because the width is consensus-visible. `arr.length` folds to the declared size. Array reads and writes accept `int` index expressions; runtime indices emit bounds checks.

### Built-ins

**Signatures.** In covenants, `checkSig(sig, key)`, `checkSigFromStack(sig, key, message)`, and `checkMultisig(keys, sigs, threshold?)` return `bool` and accept computed operands. Multisig takes equal-length fixed arrays, including array literals, bindings, and helper results, and uses `OP_CHECKSIGADD`. Omitting the threshold means N-of-N; explicit thresholds accept `int` expressions and must be between 1 and N, with runtime bounds checks for computed thresholds. `checkSigFromStackVerify(sig, key, message)` accepts computed operands but produces no value and must appear directly inside `require`. Tapscript signature checks retain their closure syntax and constant thresholds. `tweak(base, fn)` is a tapscript-only key expression. `base` is `emulator` or a constructor pubkey, and the key is tweaked by `fn`'s covenant.

**Hashes.** In covenants, `sha256(expr)` and `hash256(expr)` return `bytes32`; `sha1(expr)`, `hash160(expr)` and `ripemd160(expr)` return `bytes20`. All five accept computed byte operands and work in bindings, helper returns, nested calls, and comparisons. Use `sha1` only for legacy interoperability: its [collision resistance is broken](https://www.nist.gov/news-events/news/2022/12/nist-retires-sha-1-cryptographic-algorithm), so do not use it for commitments, hashlocks, or other security-critical purposes; prefer `sha256` or `hash256`. Tapscript hashlocks use `require(hashFn(preimage) == hash)` with `sha256`, `hash256`, `hash160`, or `ripemd160`. Streaming: `sha256Initialize`, `sha256Update`, `sha256Finalize`. Runtime-selected: `digest(data, hashType)`, `sighash(hashType)`.

**Merkle proofs.** `merkleRoot(leafTag, branchTag, proof, leaf)` returns the `bytes32` root that `OP_MERKLEBRANCHVERIFY` computes with BIP-341 tagged hashes: the leaf is `tagged_hash(leafTag, leaf)`, and each 32-byte sibling in `proof` is combined in sorted order as `tagged_hash(branchTag, min || max)`. An empty `leafTag` (`""`) takes a 32-byte `leaf` as already hashed. Compare the result yourself, e.g. `require(merkleRoot("leaf", "branch", proof, leaf) == root)`; the VM fails the spend when `proof` is not a multiple of 32 bytes, `branchTag` is empty, or a prehashed `leaf` is not exactly 32 bytes.

**Time.** In covenants, `tx.time` reads the transaction locktime using `OP_INSPECTLOCKTIME`, and `require(tx.time >= deadline)` compares it with the bound, whether a literal, constant, or runtime value. In tapscripts, `older(n)` emits CSV and `after(n)` emits CLTV. Both are tapscript-only; `tx.time` is not available in tapscripts. Wrap a literal or constant in `blocks(n)` or `seconds(n)` to state its unit. `older(blocks(144))` pushes `144`, and `older(seconds(1024))` pushes the BIP68 time-based sequence `4194306` (a multiple of 512 seconds, at most 33553920). `after(blocks(n))` takes a block height below 500000000, and `after(seconds(n))` takes a Unix timestamp at or above it. A parameter, or a literal without a unit, is pushed as the raw BIP68 sequence or nLockTime; the compiler warns on a literal or constant without a unit. arkd rejects block-based timelocks unless the server allows them, so arkd exit leaves should use `older(serverExitDelay)`.

In covenants, `checkTime(timestamp)` returns whether the emulator's wall clock has reached a Unix timestamp in seconds, including equality. Use `require(checkTime(unlockAt))` to enforce it. A future timestamp returns false; a negative timestamp fails execution. This check is independent of transaction locktime and sequence.

**Transaction.** `tx.version`, `tx.locktime`, `tx.numInputs`, `tx.numOutputs`, `tx.weight`, `tx.id`, `this.activeInputIndex`, `this.activeBytecode`. In covenants, `this.expiry` returns the executing VTXO's Unix expiry timestamp in seconds through `OP_PUSHEXPIRY`; execution fails if expiry is unavailable.

**Continuation.** `require(this.tunnel(outputIndex))` preserves the current input's logical scriptPubKey, bitcoin value, and assets at the selected output. An explicit policy supplies all three compile-time boolean fields: `this.tunnel(outputIndex, {scriptPubKey: true, value: true, assets: false})`. With asset preservation enabled, an optional fixed list excludes specific `AssetId` values: `this.tunnel(outputIndex, {scriptPubKey: true, value: true, assets: true}, [feeAsset])`. At least one property must be selected. A mismatch fails execution; success returns true. Tunneling is covenant-only and does not establish intent type, timing, packet preservation, or a unique input-to-output mapping.

**Intent messages.** In covenants, `tx.intent.field("type")` returns the encoded field bytes and asserts presence; `tx.intent.has("type")` returns presence without keeping the value. Paths are quoted literals with dot-separated lowercase keys or canonical decimal indexes, such as `"cosigners.0"`; queries, wildcards, leading-zero indexes, and indexes at or above 1048576 are rejected. Present false, zero, and empty strings still count as present. Integer fields use Script-number encoding: `bin2num(tx.intent.field("expire_at"))`. Require `tx.intent.field("type") == "register"` before relying on register-specific fields. Missing context, null, missing fields, and non-integer numbers are misses; `field` fails on a miss and `has` returns false. Both use the emulator's result-size and compute limits.

**Inputs and outputs.** `tx.inputs[i].value | scriptPubKey | witnessVersion | sequence | outpoint | arkadeScriptHash | arkadeWitnessHash`, `tx.outputs[o].value | scriptPubKey | witnessVersion`, and `tx.input.current.value | scriptPubKey | witnessVersion | sequence | outpoint | arkadeScriptHash | arkadeWitnessHash` for the input being spent. For native witness programs, `scriptPubKey` is the program and `witnessVersion` is its version (0-16).

**Assets.** On any input or output: `.assets.lookup(txid, gidx)` (asserts presence, yields amount), `.assets.has(txid, gidx)`, `.assets.length`, `.assets[t].assetId`, `.assets[t].amount`. Groups: `tx.assetGroups.find(txid, gidx)` (asserts presence) and `tx.assetGroups[k]` (the group at packet position `k`) yield an `AssetGroup`; `tx.assetGroups.has(txid, gidx)` and `.length` inspect the packet. Every `AssetGroup` value, whether bound, a parameter, an array element, or inline such as `tx.assetGroups[k].delta`, has `numInputs`, `numOutputs`, `sumInputs`, `sumOutputs`, `delta`, `hasControl`, `controlIs(txid, gidx)`, `controlAssetId` (fails the spend when the group has no control asset), `metadataHash`, `assetId`, `isFresh`. An `int` has no group members; turn a position into a group with `tx.assetGroups[k]`. A group's `inputs[j]` and `outputs[j]` records have `amount`, `type` and `index`: an output's `type` is 1 and its `index` is its vout; an input's `type` is 1 for a local input, whose `index` is its vin, and 2 for an intent input, whose `index` is the output it references in the intent transaction and whose `txid` is that transaction; `txid` fails the spend on a local input, so read it behind a type check, such as `g.inputs[j].type == 1 || g.inputs[j].txid == t`, when the kind is not fixed, and does not exist on outputs. An index outside the group's records fails the spend.

**Bytes.** `substr(data, offset, size)`, `left(data, count)`, `right(data, count)`, `cat(a, b)`, `bin2num(bytes)`, `num2bin(value, size)`, `reverseBytes(bytes)`, `size(bytes)`. In covenants, `left` and `right` return the first or last `count` bytes. Zero returns empty bytes; negative counts and counts exceeding the data length fail execution.

**Types and casts.** Type errors are fatal. Equality needs matching types, except that `bytes20`, `bytes32`, `pubkey`, and `signature` widen implicitly to `bytes`, including in bindings, arguments, and `+` concatenation. `bytes20(x)`, `bytes32(x)`, `pubkey(x)`, and `signature(x)` narrow a `bytes` value; the sized casts verify the length at runtime with `OP_SIZE <n> OP_EQUALVERIFY`, while `pubkey` and `signature` add no opcodes because the VM validates keys and signatures when they are consumed. `int(0x...)` reads a hex literal big-endian and folds it to a decimal constant, so `int(0x0100)` is `256`; `int(flag)` and `bool(n)` emit `OP_0NOTEQUAL`, so the result is always `0` or `1`, even for a spender-supplied witness value. Casting a value to its own type, such as `int(42)` or `bytes20(hash)`, is a no-op. Use `bin2num` and `num2bin` to convert between `int` and `bytes`, and compare `bool` values with `true` or `false`. Byte builtins (`substr`, `cat`, `bin2num`, `reverseBytes`, `size`, `digest`, and the `checkSigFromStack` message) take bytes-like operands; sizes, offsets, indexes, packet types, hash types, and tapscript timelocks take `int`. A hash comparison's expected value matches the digest width: `bytes32` for `sha256` and `hash256`, `bytes20` for `hash160` and `ripemd160`, or unbounded `bytes`.

**Packets.** `tx.packet(type)` and `tx.inputs[i].packet(type)` return the raw extension packet bytes and assert presence.

**Arithmetic and curves.** In covenants, `abs(value)`, `min(a, b)`, and `max(a, b)` take and return `int`; `within(value, lower, upper)` takes `int` operands and returns `bool` for `lower <= value && value < upper`. Empty or reversed ranges return false. Also available: `modExp(base, exp, mod)`, `ecAdd(P, Q, curve)` and `ecMul(P, k, curve)` taking and returning `ECPoint`, `ecPairing(g1, g2, curve)` over aligned `ECPoint[n]` and `G2Point[n]` arrays (1–16 pairs), `ecMulScalarVerify(k, P, Q)`, `tweakVerify(P, k, Q)`.

**Instantiation.** `new Contract(args...)` on either side of a `scriptPubKey` comparison against `tx.outputs[o]`, `tx.inputs[i]`, or `tx.input.current`. Zero-argument constructors are allowed. Array arguments flatten element by element.

### Tapscript bodies

A tapscript body is `require` statements only, and must follow the closure template in source order: an optional single hash condition, then an optional single timelock, then exactly one `checkSig` or `checkMultisig`. Hash plus CSV is a recognized shape; hash plus CLTV is not, so split it into two leaves. arkd accepts only N-of-N leaves, so a `checkMultisig` threshold, if written, must equal the key count, and each signature must be a declared `signature` input aligned 1:1 with its key.

Keys resolve to constructor `pubkey` parameters, declared `pubkey` inputs, or the roles `server` and `emulator`. Any leaf without a CSV delay is a forfeit path and must include `server`. A leaf whose name matches a covenant must include bare `emulator`, which the compiler tweaks with that covenant's hash. A leaf with no matching covenant may not use bare `emulator`; it either stays standalone or binds to one covenant with `tweak(emulator, fn)` or `tweak(constructorPubkey, fn)`. Every tweak in a tapscript must name that same covenant. `older(serverExitDelay)` uses arkd's unilateral exit delay and lowers to `<SERVER_EXIT_DELAY>`, which the SDK fills from the server's config. Inputs named `server`, `emulator`, or `serverExitDelay` are rejected.

## Artifact format

```json
{
  "formatVersion": 1,
  "contractName": "HTLC",
  "constructorInputs": [{ "name": "sender", "type": "pubkey" }, "..."],
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
    { "name": "unilateral", "leaves": [ "..." ] }
  ],
  "source": { "entry": "htlc.ark", "files": { "htlc.ark": "..." } },
  "compiler": { "name": "arkadec", "version": "0.1.0", "options": { "optimize": true } },
  "fingerprint": "sha256:...",
  "updatedAt": "2026-01-01T00:00:00Z"
}
```

| Field | Meaning |
|---|---|
| `formatVersion` | Artifact schema version; absent on legacy artifacts |
| `constructorInputs` | One entry per source parameter, declaration order; arrays keep their size in the type, structs keep their type name |
| `structs` | User struct layouts, so clients can flatten parameters the way the compiler does |
| `functions[]` | Spend groups: `{ name, arkade?, leaves[] }` |
| `arkade` | `{ inputs, asm }`; absent for groups made only of standalone leaves |
| `leaves[]` | `{ name, witness, asm }`; `witness` lists spend-time values in source order, `injected: true` marks infrastructure signatures |
| `source` | `{ entry, files }`: original entry source and every recursively imported file, including comments |
| `compiler.options` | Effective compilation settings; `optimize` applies to Arkade covenant assembly |
| `fingerprint` | SHA-256 of compact artifact JSON before `fingerprint` and `updatedAt` are added; includes source, ABI, compiler settings, and unresolved script templates |

The fingerprint identifies artifact content, but does not authenticate its origin. Recompile the bundled source with a trusted compiler to verify an artifact received from elsewhere.

Covenant spend groups come first in function declaration order, followed by standalone tapscript groups in tapscript declaration order, regardless of how the declarations are interleaved. Author-written leaves within a covenant group keep their declaration order; a synthesized emulator leaf, when needed, comes first. Clients use this order to build the Taproot tree. Reordering leaves can change the output key and address; retain the original artifact to spend existing outputs.

Witness `encoding` values: `schnorr-64`, `raw`, `raw-20`, `raw-32`, `scriptnum`. `updatedAt` changes on every compile; ignore it when diffing artifacts.

The `source` bundle contains the entry file and every loaded dependency, preserving their text verbatim, including comments. Paths are normalized and relative; native compilation strips the common directory prefix. Recompile a bundle with the same compiler version using `compile_sources(&source.entry, &source.files)`. Standalone compilation produces a one-file bundle with entry `main.ark`.

Type-check and validation warnings remain available on the Rust compilation result, are printed by the CLI, and appear in the playground's Diagnostics tab, but are not serialized into artifacts. They identify their source file relative to the bundle root, including warnings from dependencies.

### Covenant stack ABI

`constructorInputs`, `arkade.inputs`, and `witness` describe the source ABI, not the physical stack. Clients expand an array entry `oracles` of type `pubkey[3]` into `oracles.0`, `oracles.1`, `oracles.2`, and a struct entry into its scalar leaves in field order, recursively, using dotted paths such as `policy.primary.key`.

Clients serialize covenant inputs in reverse `arkade.inputs` order. Every covenant `asm` opens with one `<name>` placeholder per expanded constructor input, also reversed, which instantiation replaces with data pushes before the covenant hash is computed. The VM installs the function witness first, so constructor values sit above function inputs; the body reaches everything through `OP_PICK` and friends and never emits function inputs as placeholders. After instantiation the only remaining placeholders are `<CONTRACT:Contract(<a>,<b>)>` tokens, which the runtime resolves to the child contract's 32-byte Taproot output key (witness program).

## Security

See [SECURITY.md](SECURITY.md) for the disclosure process.
