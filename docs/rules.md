# Code rules

These rules keep the compiler readable for years. Clippy enforces the ones marked **(lint)**; review enforces the rest. The map of the code is in [ARCHITECTURE.md](../ARCHITECTURE.md).

## Output

- **A change that is not meant to change compiled contracts must leave every artifact byte-identical.** Check with `scripts/compare-output.sh master`. A change that is meant to change them bumps the version, and CI says so.
- Diagnostics text, codes and spans are a public interface too. Changing one is a deliberate change with a test, never a side effect of a refactor.

## Types

- **Name what a value means.** Use a struct with named fields instead of a tuple, an enum instead of a `bool` parameter or a bitmask, and `Range` instead of `(usize, usize)`. If a value needs a comment to explain it, it probably needs a type.
- Make invalid states unrepresentable where it costs little.
- A concept's behavior is a method on its type, in its file. A phase's logic is a function in that phase's module.
- Conversions go through `From`, `TryFrom`, `FromStr` and `Display`.

## Errors

- **Each phase has one error enum** (`ParseError`, `LoadError`, `CompileErrorKind`, `ValidationError`, …). One variant per kind of error, with data in named fields.
- **Text is produced only in `Display`.** No `Result<_, String>` and no `Err(format!(...))` inside the crate.
- A phase wraps an earlier phase's error through `From`, so `?` works; it never re-renders it as a string.
- Strings appear only at the public boundary (`lib.rs`, `wasm.rs`, `Diagnostic`), and for text that comes from outside (the filesystem, serde).
- A broken compiler invariant is an `InternalError`, never a user-facing error.
- Unit tests match the variant; integration tests assert the text, since that is the public contract.

## Panics

- No `unwrap`, `panic!`, `todo!`, `unimplemented!` or `dbg!` outside tests **(lint)**. Use `?`, or `expect("…")` that states the invariant making it impossible.
- No `as` casts **(lint)**. Use `From`, `TryFrom` or `checked_*`.
- No `unsafe` **(lint)**.
- Every `#[allow]` and `#[expect]` gives a `reason` **(lint)**.

## Imports

- No glob imports outside tests, and no `use Enum::*` **(lint)**. Enum variants are always written qualified: `Opcode::Drop`, `ParseError::Missing`.
- Types are imported by name; functions are called through their module: `constants::evaluate(...)`.
- Paths longer than two segments are imported, not written inline **(lint)**.
- `super::` within a top-level module, `crate::` across modules.
- Groups, separated by a blank line: `std`, external crates, then `crate`.

## Comments

The code should explain itself. A comment is the exception:

- **Keep a comment only if a reader new to the code learns something not in the signature and the next few lines.** That means a non-obvious why, an invariant other code relies on, a trap that looks like a bug but is not, or an external rule (a VM, consensus or arkd limit).
- Delete a comment that restates the code. Do not shorten it into a riddle either.
- History and design justification go in the commit message or the PR, not the file.
- **Every module starts with a `//!` header** saying what it takes and what it guarantees, in a few lines.
- A known simplification is tagged `LIMITATION:` and names the condition that would justify replacing it.
- `pub` API keeps its doc comments. A private item gets one only for an invariant, a unit or an ordering contract.
- At most about 10% of the lines a change adds are comments.

## Tests

- A bug fix lands with a failing regression test first.
- Non-trivial logic gets the smallest runnable check that would fail if it broke.
- Assert the affected spend group, covenant, leaves, witness shape and critical opcodes when code generation changes.
- Normalize or ignore `updatedAt` when comparing artifacts.
