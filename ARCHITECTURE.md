# Architecture

This is a map of the compiler for someone about to change it. The rules for how the code is written are in [docs/rules.md](docs/rules.md).

## Bird's-eye view

`arkadec` turns `.ark` source into a JSON artifact. The artifact holds one Arkade Script per public function, run by the Arkade VM as a covenant, and the L1 tapscript leaves arkd builds the VTXO from. A contract's address is derived from those scripts, so **the same source must compile to the same bytes forever**. CI enforces it: when any compiled contract changes, the version has to leave `^<last release>` (see `scripts/check-output-version.sh`).

One compilation runs these phases in order. Each phase reads only what the earlier ones produced.

```
source ─ imports ─ parser ─ types ─ validator ─┬─ lint ────────────────┐
                                               └─ compiler (emission) ─┴─ artifact ─ validator (self-check)
```

| Phase | Module | Takes | Produces | Errors |
|---|---|---|---|---|
| Loading | `imports.rs` | an entry path and a file reader | every module of the program, parsed once, names resolved across files | `LoadError` |
| Parsing | `parser/` | one file's text | a `Contract` AST (`models/ast.rs`), constants resolved | `ParseError` |
| Typing | `types/` | an untyped AST | the same AST with `Expression::ty` set on every expression | none; an untypable expression stays `Unknown` |
| Validation | `validator/` | a typed AST | the errors the grammar cannot express | `ValidationError` |
| Leaf checks | `compiler/tapscript.rs` | each `tapscript` declaration | a checked leaf in a closure shape arkd recognizes | `TapscriptError` |
| Lints | `lint/` | a validated AST | warnings for code that compiles but is likely wrong | `FindingKind` |
| Emission | `compiler/` | a validated AST and checked leaves | `ContractJson` (`models/artifact.rs`) | `CompileError` |
| Self-check | `validator/output.rs` | the artifact | invariants of the emitted scripts | `ValidationError`, wrapped as `CompileErrorKind::OutputValidation` |

`lib.rs`, `main.rs` and `wasm.rs` are three front ends over the same `imports::Analysis`: the Rust API, the CLI and the playground and editor bindings.

## Code map

- `imports.rs`: the only place that reads files. Imports are relative and acyclic; each module is prepared once and its exports are visible by name to importers.
- `parser/`: pest grammar (`grammar.pest`) and the mapping into the AST. PEG alternatives are ordered, so reordering them changes what parses.
- `models/`: the AST and the artifact. The artifact shape is a public interface read by the TypeScript and Go SDKs.
- `types/`: one pass that types every expression. Everything after it reads `Expression::ty` and never infers again.
- `validator/`: semantic errors. It does not emit and does not warn.
- `lint/`: warnings, each with an id and a level set by `@allow`/`@warn`/`@deny`/`@expect` or the caller.
- `compiler/`: code generation.
  - `lowering.rs` unrolls loops and folds constants;
  - `expr.rs`, `statements.rs`, `access.rs`, `functions.rs` emit through the stack model in `stack.rs`;
  - `optimization.rs` peephole-rewrites the result;
  - `tapscript.rs` builds the L1 leaves.
- `opcodes/`, `operators.rs`, `properties.rs`, `builtins.rs`: tables. Each opcode, operator, `tx`/`this` property and builtin is described once, and every phase reads that description instead of matching names.
- `diagnostics.rs`: `Diagnostic`, the one public form of an error or warning, and its JSON.
- `errors/`: error codes with `arkadec --explain` text.
- `symbols.rs`: definitions and references for editors.

## Invariants

- **Output is deterministic and stable.** No time, environment or hash-map iteration order reaches the scripts or their order. `updatedAt` is the only field that changes between identical builds.
- **Covenants and tapscript leaves stay separate.** A covenant is Arkade Script for the VM; a leaf is L1 tapscript for arkd. They share no emission code and are tested separately.
- **Each script ends with exactly one true item on the stack.** The generator's stack model (`compiler/stack.rs`) tracks every slot, and `validator/output.rs` checks the emitted artifact.
- **Optimized and unoptimized scripts behave the same.** The E2E suite and its differential fuzzer run both on the VM.
- **Typing happens once.** No phase after `types/` infers a type.
- **A phase reports its own errors.** It does not format another phase's errors; it wraps them.

## Testing

- `tests/features.rs`, `tests/examples.rs`: compile source and assert on scripts, artifacts and diagnostics.
- `tests/diagnostics/`: expected diagnostics, rewritten with `BLESS=1`.
- `tests/e2e/`: Go suite that runs artifacts on the Arkade VM, optimized and not, plus the differential fuzzer.
- `scripts/compare-output.sh <ref>`: compiles every contract with `<ref>` and the working tree and lists any whose `codeHash` differs.
