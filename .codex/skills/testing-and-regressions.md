---
name: testing-and-regressions
description: Activate this skill for any test authoring or debugging request, including new contract fixtures, opcode assertions, CLI parity checks, or regression coverage for parser/compiler behavior.
prerequisites: cargo test, rustfmt
---

# Testing and Regressions

<purpose>
Create durable regression tests for compiler behavior, with clear expectations for ABI fields, dual variants, and emitted ASM.
</purpose>

<context>
Testing is integration-heavy under `tests/*.rs`. Typical pattern:
- Build in-memory Arkade contract string
- Call `arkade_compiler::compile`
- Assert contract metadata + function variants + opcode sequence
Some tests also execute CLI binary via `env!("CARGO_BIN_EXE_arkadec")`.
</context>

<procedure>
1. Pick test style:
- Compiler behavior -> integration test using `compile(...)`
- CLI parity -> integration test invoking binary and comparing JSON
2. Write minimal contract fixture inline in test.
3. Assert key behavior:
- Function count and names
- `server_variant` true/false behavior
- Opcode sequence or required opcodes
4. For CLI JSON comparisons, normalize timestamp fields by removing `updatedAt`.
5. Run targeted tests: `cargo test --test <file>`.
6. Run global suite: `cargo test`.
7. Keep tests deterministic (no wall-clock assertions).
</procedure>

<patterns>
<do>
- Use `.find(|f| f.name == "..." && f.server_variant)` for precise variant selection.
- Assert opcodes with constants from `arkade_compiler::opcodes` when available.
- Cover at least one negative/edge branch for new parser features.
</do>
<dont>
- Do not compare full JSON strings containing dynamic `updatedAt` without normalization.
- Do not assert every opcode if behavior can be validated with stable critical subsequences.
- Do not place new behavior without corresponding regression tests.
</dont>
</patterns>

<examples>
Example: CLI parity check skeleton
```rust
let status = std::process::Command::new(env!("CARGO_BIN_EXE_arkadec"))
    .arg(input_path)
    .arg("-o")
    .arg(output_path)
    .status()?;
assert!(status.success());
```
</examples>

<troubleshooting>
| Symptom | Cause | Fix |
|---|---|---|
| Test passes locally, fails in CI on formatting | `cargo fmt` not run | Run `cargo fmt` before commit |
| JSON mismatch only on timestamp field | Dynamic `updatedAt` | Remove `updatedAt` from both JSON objects before compare |
| CLI test cannot find binary | Wrong test context or env macro misuse | Use `env!("CARGO_BIN_EXE_arkadec")` in integration tests |
</troubleshooting>

<references>
- `tests/htlc_test.rs`: compile assertions + CLI parity comparison
- `tests/new_opcodes_test.rs`: opcode-focused feature regression style
- `tests/group_properties_test.rs`: broader semantic assertion patterns
</references>
