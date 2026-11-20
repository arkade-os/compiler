# Rust, WASM and npm APIs

## JavaScript and TypeScript

The [`@arkade-os/compiler` package](../npm/README.md) runs the compiler in Node.js and browsers. It provides:

- `compile({ entry, files }, { optimize, debug })`
- `check({ entry, files }, { optimize })`
- `symbolAt(input, { line, column })`
- `completionsAt(input, { line, column })`
- `builtinDocs()`
- `version()`

It includes prebuilt WASM and declarations, selects the runtime loader automatically, and returns compiler artifacts, debug source maps, and positioned errors and warnings. It wraps the [WASM bindings](#wasm), and the playground uses it.

Release tags publish it to npm, as [Releasing](development.md#releasing) describes. See the package README for usage and tarball installation.

## Rust

### Compile

| Function | Compiles |
|---|---|
| `arkade_compiler::compile(source)` | Standalone source, under the filename `main.ark` |
| `compile_file(path)` | An entry file and its relative imports, loaded from disk |
| `compile_sources(entry, &files)` | An in-memory project: a `BTreeMap<String, String>` mapping paths to source text |

All return `Result<ContractJson, Error>` and optimize. `Error` is `Send + Sync` and displays the error located in its file. `compile_file_with_options(path, options)` and `compile_sources_with_options(entry, &files, options)` take a `CompileOptions`. Outside the crate, start from `CompileOptions::default()`, which enables optimization, and set its `optimize` field.

### Analyze

For editors and tools, `analyze(entry, &files)` runs parsing, import resolution, typing and validation once. `analyze_file(path)` does the same for an entry file and its imports from the filesystem.

The returned `Analysis` gives:

| Method | Returns |
|---|---|
| `diagnostics()` | Every error and warning |
| `contract()` | The typed AST, with each expression's `ty()` |
| `compile(options)` | The artifact; its errors are `Diagnostic`s with spans |
| `check(options)` | The diagnostics plus, for a contract, code generation's first error |
| `symbols()` | Every definition, with its type and, for locals, where it is visible, and every reference to one, by file and byte span |
| `source(file)` | The text of each file the analysis read, to place those spans |

Files that fail validation still get symbols. On the returned `Symbols`, `definition_at(file, offset)` resolves the name under a cursor, and `visible_at(file, offset)` lists every name usable there.

`diagnostics_with(&levels)`, `compile_with(options, &levels)` and `check_with(options, &levels)` take [lint levels](lints.md) as a `lint::Levels`. Build one with `Levels::default()` and `set_named(id, level)`, which accepts the same names as the CLI's lint flags.

### Other functions

- `check(entry, &files)` returns what `Analysis::check` does.
- `diagnostics::to_json` gives a diagnostic the JSON form the CLI and WASM use.
- `builtin_docs()` returns the JSON that `arkadec --builtins` prints.

## WASM

The `wasm` feature exposes `compile`, `compile_sources`, `compile_sources_with_diagnostics`, `check_sources`, `symbol_at`, `completions_at`, `builtin_docs`, `validate`, and `version`.

| Function | Returns |
|---|---|
| `compile_sources(entry, files, optimize?)` | The artifact JSON |
| `compile_sources_with_diagnostics(entry, files, optimize?, debug?)` | `{ artifact: string \| null, debug: string \| null, diagnostics }`; `debug` is `null` when the `debug` argument is `false` |
| `check_sources(entry, files, optimize?)` | The diagnostics alone, as `Analysis::check` does, so a library entry is not an error |
| `symbol_at(entry, files, line, column)` | The name at a position with its kind, type, definition and references |
| `completions_at(entry, files, line, column)` | The names usable at a position, with library members and struct fields |

`files` is a JSON object mapping paths to source text. Omitted `optimize` and `debug` arguments default to `true`.

`compile_sources_with_diagnostics` reports compilation errors as diagnostics with a `null` artifact, not a thrown error. Each diagnostic has:

- `severity`, `message` and `file`;
- `code`: a lint's id, an error code's id such as `unknown-name`, or else the pass that raised it (`validation`, `type`, `emission` or `internal`), and `null` for file, pragma, parse and import errors and for a library compiled as the entry;
- 1-based `start` and `end` `{ line, column }` positions with UTF-16 columns, or `null` when the diagnostic has no location;
- `suggestions`: fix-its, each `{ message, start, end, replacement }`.

The playground compiles with `compile_sources_with_diagnostics` and diagnoses sources as you type with `check_sources`.
