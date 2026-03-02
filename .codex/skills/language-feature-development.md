---
name: language-feature-development
description: Activate this skill whenever Arkade language syntax, grammar precedence, AST variants, opcode emission, or ABI semantics change. Use it for any request mentioning new keywords, operators, expressions, require forms, or function generation behavior.
prerequisites: Rust toolchain with cargo; familiarity with parser/compiler/model modules
---

# Language Feature Development

<purpose>
Implement language/compiler features safely by enforcing synchronized edits across grammar, parser, AST models, opcode emission, and integration tests.
</purpose>

<context>
This project is a single Rust crate. Core feature pipeline:
1. Grammar (`src/parser/grammar.pest`)
2. Parser mapping (`src/parser/mod.rs`)
3. AST/ABI models (`src/models/mod.rs`)
4. ASM emission (`src/compiler/mod.rs`)
5. Integration coverage (`tests/*.rs`)

Non-internal functions emit dual variants. Introspection paths have special exit behavior (N-of-N fallback), so feature edits can impact both variants.
</context>

<procedure>
1. Classify the feature:
- Syntax-only (parse and preserve)
- Semantic (changes emitted ASM/requirements)
- ABI-shape (changes `ContractJson`/`FunctionInput`)
2. Update `src/models/mod.rs` first when new AST variants are needed.
3. Update grammar in `src/parser/grammar.pest` with careful PEG ordering.
4. Map new rules in `src/parser/mod.rs` via explicit `parse_*` function paths.
5. Implement emission in `src/compiler/mod.rs`:
- Requirement generation (`require` metadata)
- Expression/statement ASM emission
- Dual-path behavior when relevant
6. Add integration tests in `tests/`:
- Happy path
- Edge condition
- Variant expectations (`serverVariant` true/false)
7. Run validation: `cargo fmt --check && cargo test`.
8. If examples should demonstrate the feature, update `examples/*.ark` and regenerate playground contracts.
</procedure>

<patterns>
<do>
- Keep one-to-one mapping between grammar alternatives and parser branches.
- Add minimal helper functions rather than growing one giant match arm.
- Assert exact opcodes in tests for semantic features.
- Test both parser success and output shape when changing AST.
</do>
<dont>
- Do not add grammar rules without parser handling -> use explicit parse branch instead.
- Do not change `Expression`/`Requirement` enums without compiler emission support.
- Do not rely on README examples as behavior source -> use code/tests.
</dont>
</patterns>

<examples>
Example: Add new transaction property check
```rust
// 1) models: add Expression variant if needed
// 2) grammar: add token to tx_introspection rule
// 3) parser: map rule -> Expression::TxIntrospection { property }
// 4) compiler: map property -> OP_INSPECT* opcode in emit_tx_introspection_asm
// 5) test: assert opcode exists in server variant ASM
```
</examples>

<troubleshooting>
| Symptom | Cause | Fix |
|---|---|---|
| `Parse error: Unexpected rule` | Grammar added but parser match missing | Add parser branch and conversion function |
| Feature parses but ASM unchanged | Compiler emission path not wired | Update `generate_expression_asm`/`emit_expression_asm` or requirement mapping |
| Only one variant behaves correctly | Dual-path logic not handled | Inspect `generate_function` and add variant-specific tests |
</troubleshooting>

<references>
- `src/parser/grammar.pest`: language grammar and operator precedence
- `src/parser/mod.rs`: parse functions and AST construction
- `src/models/mod.rs`: AST/ABI type definitions
- `src/compiler/mod.rs`: requirement + ASM generation
- `tests/new_opcodes_test.rs`: feature-style regression examples
</references>
