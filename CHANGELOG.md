# Changelog

All notable changes to the Arkade Compiler are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). `arkade-compiler` and `@arkade-os/compiler` share one version.

## [0.1.0] - Unreleased

The first stable release of Arkade Language and its toolchain.

- **Arkade Language**, a contract language for Bitcoin. A contract is a set of spend functions over constructor state: an Arkade Script function compiles to Arkade Script and defines an operator-enforced path, and a tapscript function compiles to an L1 tapscript leaf and, unless it is bound to an Arkade Script function, defines a Bitcoin-enforced path. It covers signature and multisig checks, absolute and relative timelocks, transaction introspection, Arkade Assets and asset groups, byte-string parsing, fixed-size arrays, structs, imports, libraries, and instantiation of other contracts with `new`.
- **`arkadec`**, the CLI, writes a JSON artifact with both kinds of script. `--check` lists diagnostics, `--debug` writes Arkade Script source maps, `--report` shows script sizes, stack peaks and opcode counts, `--explain` lists and documents lints and error codes, and `--builtins` prints the builtin docs. Each GitHub release attaches binaries for Linux, macOS and Windows.
- **`arkade-compiler`**, the Rust crate: `compile`, `compile_file` and `compile_sources`, and `analyze` and `check` for editors and tools, with the typed AST, symbols and positioned diagnostics.
- **`@arkade-os/compiler`**, the npm package: the compiler as WebAssembly for Node.js and browsers, with `compile`, `check`, `symbolAt`, `completionsAt`, `builtinDocs` and `version`.
- **Playground** at [arkade-os.github.io/compiler](https://arkade-os.github.io/compiler) runs the compiler in the browser, with live diagnostics, hover, go to definition, completion, and artifact and assembly views.

### Changed since 0.1.0-rc.1

**Breaking**

- `server` is now `operator` and `serverExitDelay` is now `operatorExitDelay`. The placeholders `<SERVER_KEY>` and `<SERVER_EXIT_DELAY>` are now `<OPERATOR_KEY>` and `<OPERATOR_EXIT_DELAY>`, and the injected witness `serverSig` is now `operatorSig` (#283).
- `emulator` is no longer a role and `<EMULATOR_KEY:f>` is no longer emitted. An Arkade Script function without a replacing leaf gets one default leaf, `<OPERATOR_KEY:f> OP_CHECKSIG`, and `tweak(operator, f)` pushes `<OPERATOR_KEY:f>`. A tapscript named after an Arkade Script function must tweak a key to that function and must have no CSV delay (#283).
- `ArkadeCovenant` is now `ArkadeScript` in Rust and npm; only npm keeps `ArkadeCovenant` as a deprecated alias. The artifact JSON is unchanged (#282).
- `require` holds one boolean expression: the Rust `Requirement` enum is gone and `Statement::Require` holds an `Expression` (#272). `ArkType` gains `Void` (#276), and `ContractJson::format_version` is a required `u32` (#263).
- `bin2num` and `num2bin` are now `bytes2int` and `int2bytes` (#252).
- `merkleRoot` emits `OP_MERKLEBRANCHROOT`, the Arkade VM's name for `0xb3`, instead of `OP_MERKLEBRANCHVERIFY`, and the Rust `Opcode::MerkleBranchVerify` and `opcodes::OP_MERKLEBRANCHVERIFY` are now `Opcode::MerkleBranchRoot` and `opcodes::OP_MERKLEBRANCHROOT` (#309).
- `sha256Initialize` and `sha256Update` return a `bytes` context instead of `bytes32`, so `bytes32 ctx = sha256Initialize(data);` no longer compiles (#215).
- Asset APIs take one `AssetId` operand instead of a `(txid, gidx)` pair, and `tx.assetGroups.find` is now `tx.assetGroups.lookup` (#266).
- A contract that instantiates itself is rejected, and a contract instantiated with `new` must compile as an entry file would, its own lint attributes included. The artifact pins each instantiated contract's code hash in `contracts` (#253).
- Arkade Script `checkMultisig(keys, sigs, k)` passes when at least `k` signatures are valid, and tapscript `checkMultisig` no longer takes a threshold (#261).
- Removed: the `asset` type (#260), `this.activeBytecode`, which is `tx.input.current.script` (#256), and `public function` and `static` on library functions (#255).
- Every expression must have a type, and asset group records `g.inputs[j]` and `g.outputs[j]` are `AssetGroupInput` and `AssetGroupOutput` struct values (#276).
- Version pragmas are checked against the compiler version (#257), the `offchain-locktime` lint denies by default (#254), and Arkade Script functions reject non-canonical `bool` witnesses at entry (#214).
- Hex literals are emitted in lowercase (#251).

**Stricter validation and API**

- A tapscript input may feed at most one hash preimage or signature in a leaf, since the witness carries each input once (#287).
- A raw `older(n)` may set only the 16 value bits and the type flag that BIP68 reads, and the error points to `blocks(n)` and `seconds(n)` (#287).
- Keywords end at a word boundary, so glued forms such as `functionspend(` no longer parse (#291).
- Reserved keywords and type names are rejected for every declared name, and a function of any kind named after a builtin call is rejected (#291).
- Most public Rust enums, `CompileOptions` and several AST and symbol structs are `#[non_exhaustive]`, so `CompileOptions` is built from `CompileOptions::default()`. The `operators` and `properties` modules are crate-private, and the `compile*` functions return `arkade_compiler::Error`, a `Send + Sync` newtype, instead of `Box<dyn Error>` (#288).
- The TypeScript `Diagnostic` declares `suggestions: Suggestion[]`, with a new exported `Suggestion` type (#288).
- A leaf's `witness` is documented as its inputs in declaration order, not the stack order; clients build the stack from the leaf script (#289).

**Added**

- A configurable linter with security, correctness, performance and style lints, `@allow`, `@warn`, `@deny` and `@expect` attributes, and CLI level flags (#192).
- Stable error codes with explanations and suggested edits, and errors that point at the mistake in source terms (#225, #228).
- Builtin and transaction member docs for hover, completion and go to definition, printed by `arkadec --builtins` (#197).
- `else if` chains (#240), block comments, trailing commas and digit separators (#264), named struct literals (#266), `.length` everywhere a length exists (#262), `pubkey`, `bytes20` and `bytes32` constants (#259), and `bytes2uint` (#252).
- Field and index access on computed results (`make().value`, `getArray()[i]`), `for ... in` over array expressions, and computed arrays in `ecPairing` (#239).
- The verify builtins return `true`, so they work anywhere a `bool` does (#265).
- `compile(input, { debug: false })` in npm skips the debug file (#231).
- The README is split into focused pages under `docs/`: the tour, playground, CLI, API, artifact format, lints, development and the language reference (#284).

**Removed**

- `arkade-bindgen` and the playground Bindings tab; clients generate typed code from the artifact and its stack ABI in `docs/artifact.md` (#285).

**Fixed**

- `controlIs` compares `gidx` as a number (#273), runtime-indexed arrays are bound once (#277), and unrolled indexes past an array's end fail at runtime in unoptimized builds (#281).
- Struct and array literals, bindings and comparisons work as builtin operands, copy initializers and boolean operands, typed from what they are compared with (#201, #216, #217, #220, #224, #232, #245), and tapscript operands resolve by binding time and parse as access paths (#199, #237).
- Diagnostics report tapscript-only and Arkade Script-only calls by context (#258) and unknown `tx` and `this` members in validation (#268), and validator errors on parameters, tapscript inputs, structs and empty contracts carry source locations (#280).

[0.1.0]: https://github.com/arkade-os/compiler/compare/v0.1.0-rc.1...v0.1.0
