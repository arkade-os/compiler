# Command line

## Install

Prebuilt `arkadec` and `arkade-bindgen` binaries for Linux, macOS, and Windows are attached to each [GitHub release](https://github.com/arkade-os/compiler/releases) with a `SHA256SUMS` file.

With a Rust toolchain ([rustup.rs](https://rustup.rs/)), install from crates.io or a checkout instead:

```bash
cargo install arkade-compiler --locked   # installs arkadec
cargo install arkade-bindgen --locked
cargo install --path . --locked          # installs arkadec from a checkout
```

## Compile with `arkadec`

```bash
arkadec contract.ark                     # writes contract.json in the current directory
arkadec contract.ark -o out.json
arkadec contract.ark --check             # diagnostics only, no artifact
```

| Option | Effect |
|---|---|
| `-o`, `--output <path>` | Writes the artifact to `<path>` instead of `<name>.json` in the current directory |
| `--no-optimize` | Skips constant folding, static branch removal, and assembly optimization |
| `--check` | Prints every error and warning as `file:line:column` and writes no artifact |
| `--check --json` | Prints the same diagnostics as a JSON array |
| `--debug` | Also writes `<name>.debug.json` with Arkade Script source maps; see [Debug file](artifact.md#debug-file) |
| `--report` | Prints each Arkade Script's bytes, stack peak and opcode execution counts; see [Script report](#script-report) |
| `--allow`, `--warn`, `--deny <lint>` | Set lint levels; see [Lints](lints.md#from-the-command-line) |
| `--explain <id>` | Prints what a lint or an error code (`unknown-name`, `unknown-function`) reports, why it matters and how to fix it |
| `--builtins` | Prints every builtin and `tx`/`this` member, with its signature and docs, as JSON |

The source file must have the `.ark` extension.

- When compiling, warnings go to stderr, and type and validation errors abort with a non-zero exit.
- `--check` prints its diagnostics to stdout and exits with status 1 when any of them is an error.
- A diagnostic with a fix-it prints it as a `help:` line, and `--check --json` gives it as `suggestions`, in the form [the WASM API](api.md#wasm) uses.

From a checkout, `cargo run -- examples/htlc/htlc.ark -o /tmp/htlc.json` is the fastest way to inspect output.

## Script report

`--report` shows, for each Arkade Script:

- its size, as a lower bound;
- its peak stack items;
- an upper bound on executions of each named opcode, sorted by name.

How the counts are computed:

- Branches take the maximum per opcode; sequential work adds up.
- Correlated conditions are counted independently, so the counts can overestimate actual execution.
- The report excludes data pushes without named opcodes.

Opcode counts are informational: a row does not imply that the opcode has a configured budget. Compute budgets are operator-configurable and are not enforced by the compiler. Compare the counts against the target deployment's per-input limits, and check its request-wide budget for the complete transaction.

## Generate client bindings

`arkade-bindgen` generates client bindings from one artifact or a directory of them:

```bash
arkade-bindgen contract.json --lang typescript,go -o ./generated/
arkade-bindgen --list-targets
```

| Option | Effect |
|---|---|
| `--lang <targets>` | Comma-separated targets: `typescript` (or `ts`) and `go` |
| `-o`, `--output <dir>` | Output directory, `./generated/` by default; with several targets, each writes into `<dir>/<target>/` |
| `--embed` | Inlines the artifact JSON into the generated file |
| `--package <name>` | Go package name, `contracts` by default |
| `--list-targets` | Lists the available targets |

- A directory input reads the `.json` files directly inside it, not in subdirectories.
- Without `--embed`, the generated code loads `<snake_name>.json` from its own directory, so place the artifact there.
- Generated TypeScript depends on `@arkade-os/contract-sdk`, and generated Go on `github.com/arkade-os/contract-sdk-go/ark`.

The TypeScript SDK reads the artifact directly with `programFromArtifact`, so generating bindings is optional.
