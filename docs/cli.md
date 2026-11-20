# Command line

## Install

Prebuilt `arkadec` binaries for Linux, macOS, and Windows are attached to each [GitHub release](https://github.com/arkade-os/compiler/releases) with a `SHA256SUMS` file.

With a Rust toolchain ([rustup.rs](https://rustup.rs/)), install from crates.io or a checkout instead:

```bash
cargo install arkade-compiler --locked   # installs arkadec
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
| `--explain <id>` | Prints what a lint or an error code (`unknown-name`, `unknown-function`) reports, why it matters and how to fix it; with no id, lists every lint, with its category and default level, and every error code |
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
