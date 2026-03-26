# arkade-bindgen Implementation Plan

## Overview

Create `arkade-bindgen` — a Rust crate that reads compiled Arkade contract JSON artifacts and generates typed client SDK bindings. Phase 1 delivers TypeScript + Go backends with stub runtime libraries.

## Prerequisites

### Step 0: Regenerate example JSON artifacts (includes witnessSchema)
Current example `.json` files are stale — they lack `witnessSchema`. Compile all `.ark` examples fresh so we have proper test fixtures.

- Run `cargo run -- examples/htlc.ark -o examples/htlc.json` (and similar for all examples)
- Commit as a separate preparatory change

## Step 1: Convert to Cargo Workspace

**Files changed:** `Cargo.toml` (root), new `arkade-bindgen/Cargo.toml`

Root `Cargo.toml` becomes a workspace:
```toml
[workspace]
members = ["arkade-compiler", "arkade-bindgen"]
resolver = "2"
```

Move existing compiler crate content into `arkade-compiler/` subdirectory OR (simpler) keep compiler at root with explicit path. Actually — simplest approach: keep the compiler Cargo.toml where it is and add a workspace section:

```toml
[workspace]
members = [".", "arkade-bindgen"]
```

New `arkade-bindgen/Cargo.toml`:
```toml
[package]
name = "arkade-bindgen"
version = "0.1.0"
edition = "2021"

[dependencies]
arkade-compiler = { path = ".." }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
clap = { version = "4.5", features = ["derive"] }
```

## Step 2: Artifact Loading (`arkade-bindgen/src/artifact.rs`)

Reuse `arkade_compiler::ContractJson` and related types directly via path dependency. Provide convenience loaders:

```rust
pub fn load_artifact(path: &Path) -> Result<ContractJson, Error>
pub fn load_artifact_str(json: &str) -> Result<ContractJson, Error>
```

Validates required fields (contractName, functions). Handles missing `witnessSchema` gracefully.

## Step 3: Naming Utilities (`arkade-bindgen/src/naming.rs`)

Case conversion functions:
- `to_pascal_case("receiverSig")` → `"ReceiverSig"`
- `to_snake_case("receiverSig")` → `"receiver_sig"`
- `to_camel_case("ReceiverSig")` → `"receiverSig"`

Special handling: all-caps acronyms like "HTLC" stay "HTLC" in PascalCase, become "htlc" in snake_case.

## Step 4: Intermediate Representation (`arkade-bindgen/src/ir.rs`)

Core types:
```rust
pub struct ContractIR {
    pub name: String,                    // PascalCase
    pub constructor_fields: Vec<Field>,
    pub functions: Vec<FunctionIR>,
    pub source: Option<String>,
    pub compiler_version: Option<String>,
}

pub struct FunctionIR {
    pub name: String,
    pub cooperative: VariantIR,
    pub exit: VariantIR,
}

pub struct VariantIR {
    pub user_fields: Vec<Field>,         // Fields caller supplies (excl serverSig)
    pub all_fields: Vec<Field>,          // Including server-injected
    pub asm: Vec<String>,
    pub requirements: Vec<String>,       // Doc strings from require[]
    pub is_nofn_fallback: bool,
}

pub struct Field {
    pub name: String,
    pub ark_type: String,
    pub encoding: Encoding,
    pub is_server_injected: bool,
}

pub enum Encoding {
    Compressed33, Schnorr64, Raw, Raw20, Raw32,
    ScriptNum, Le64, Le32, Unknown(String),
}
```

Construction: `pub fn build_ir(artifact: &ContractJson) -> Result<ContractIR, Error>`

Key logic:
1. Group functions by name → pair cooperative (serverVariant=true) + exit (serverVariant=false)
2. If witnessSchema present, build Fields from it; else fall back to functionInputs with type-inferred encoding
3. Mark `serverSig` as server-injected, exclude from user_fields
4. Detect N-of-N fallback via require type="nOfNMultisig"
5. Build constructor_fields from constructorInputs with inferred encoding

## Step 5: CodegenTarget Trait (`arkade-bindgen/src/targets/mod.rs`)

```rust
pub trait CodegenTarget {
    fn name(&self) -> &str;
    fn file_extension(&self) -> &str;
    fn generate(&self, ir: &ContractIR, options: &CodegenOptions) -> Result<GeneratedFile, Error>;
}

pub struct CodegenOptions {
    pub embed_artifact: bool,
    pub package_name: Option<String>,
    pub artifact_json: Option<String>,  // For embedding
}

pub struct GeneratedFile {
    pub filename: String,
    pub content: String,
}

pub fn get_target(name: &str) -> Option<Box<dyn CodegenTarget>>
```

## Step 6: TypeScript Backend (`arkade-bindgen/src/targets/typescript.rs`)

Generated file structure per contract:
1. File header (auto-generated comment)
2. Imports from `@arkade-os/contract-sdk`
3. Constructor params interface (`HTLCParams`)
4. Per-function witness interfaces (cooperative + exit)
5. Contract class extending `ArkContract<Params>`
6. Method objects with `{ cooperative, exit }` pattern

Type mapping:
| Encoding | TypeScript |
|---|---|
| compressed-33 | `Uint8Array` |
| schnorr-64 | `Uint8Array` |
| raw | `Uint8Array` |
| raw-20 | `Uint8Array` |
| raw-32 | `Uint8Array` |
| scriptnum | `bigint` |
| le64 | `bigint` |
| le32 | `number` |

Naming: camelCase fields, PascalCase types, snake_case filenames.

## Step 7: Go Backend (`arkade-bindgen/src/targets/go.rs`)

Generated file structure per contract:
1. File header (`// Code generated by arkade-bindgen. DO NOT EDIT.`)
2. Package declaration
3. Import from `github.com/arkade-os/contract-sdk-go/ark`
4. Params struct, witness structs (fixed-size arrays)
5. Contract struct wrapping `*ark.Contract`
6. Constructor function `NewHTLC(params) (*HTLC, error)`
7. Methods: `ClaimCooperative(w)`, `ClaimExit(w)` returning `(*ark.WitnessStack, error)`

Type mapping:
| Encoding | Go |
|---|---|
| compressed-33 | `[33]byte` |
| schnorr-64 | `[64]byte` |
| raw | `[]byte` |
| raw-20 | `[20]byte` |
| raw-32 | `[32]byte` |
| scriptnum | `int64` |
| le64 | `uint64` |
| le32 | `uint32` |

Naming: PascalCase everything (exported). Package default: `contracts`.

## Step 8: CLI (`arkade-bindgen/src/main.rs`)

Clap-based CLI:
```
arkade-bindgen [OPTIONS] <INPUT>

Arguments:
  <INPUT>  Path to .json artifact or directory of artifacts

Options:
  --lang <TARGETS>      Comma-separated: typescript, go
  -o, --output <DIR>    Output directory [default: ./generated/]
  --embed               Embed artifact JSON inline
  --package <NAME>      Package/namespace name
  --list-targets        List available targets and exit
```

## Step 9: Library API (`arkade-bindgen/src/lib.rs`)

```rust
pub fn generate(
    artifacts: &[&str],       // paths to .json files
    output_dir: &str,
    target: Target,
    options: &Options,
) -> Result<Vec<GeneratedFile>, Error>
```

Suitable for use in `build.rs` scripts.

## Step 10: Test Fixtures

Generate fresh `.json` artifacts from compiler examples (WITH witnessSchema):
- `tests/fixtures/htlc.json`
- `tests/fixtures/single_sig.json`
- `tests/fixtures/non_interactive_swap.json`

Also include one fixture WITHOUT witnessSchema for backward-compat testing.

## Step 11: Snapshot Tests

For each fixture × backend, assert generated code matches expected output:
- `tests/typescript_test.rs` — test TS generation for all fixtures
- `tests/go_test.rs` — test Go generation for all fixtures

Tests use string comparison (normalize whitespace if needed).

## Step 12: Build & Validate

- `cargo build` — both crates compile
- `cargo test` — all tests pass (compiler + bindgen)
- `cargo fmt --check` — formatting clean

## File Tree (Final State)

```
compiler/                          # workspace root
├── Cargo.toml                     # workspace + compiler crate
├── src/                           # arkade-compiler (unchanged)
├── tests/                         # compiler tests (unchanged)
├── examples/                      # .ark + regenerated .json
└── arkade-bindgen/
    ├── Cargo.toml
    ├── src/
    │   ├── main.rs
    │   ├── lib.rs
    │   ├── artifact.rs
    │   ├── ir.rs
    │   ├── naming.rs
    │   └── targets/
    │       ├── mod.rs
    │       ├── typescript.rs
    │       └── go.rs
    └── tests/
        ├── fixtures/
        │   ├── htlc.json
        │   ├── single_sig.json
        │   └── non_interactive_swap.json
        ├── typescript_test.rs
        └── go_test.rs
```

## Key Design Decisions

1. **Path dependency on arkade-compiler** — reuse ContractJson/WitnessElement types directly
2. **No runtime implementation yet** — generated code references stub SDKs
3. **Backward compat** — handle artifacts with and without witnessSchema
4. **Wraps existing SDKs** — TS runtime wraps @ArkLabsHQ/ts-sdk (PR #319), Go wraps go-sdk + introspector
5. **String-based codegen** — no template engine (Tera/Handlebars) in Phase 1; direct string building
