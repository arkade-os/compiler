---
name: compiler-debugging
description: Activate this skill for parse failures, incorrect opcode output, variant mismatches, or unclear compiler behavior. Use it aggressively when bug reports include `Parse error`, wrong ASM, or failing integration tests.
prerequisites: cargo, familiarity with parser/compiler paths
---

# Compiler Debugging

<purpose>
Diagnose compiler defects quickly by isolating stage failures and tracing data flow from grammar to AST to emitted ASM.
</purpose>

<context>
The compiler path is deterministic:
- Parse source into AST (`src/parser/mod.rs`)
- Convert AST statements/requirements into ABI and ASM (`src/compiler/mod.rs`)
Most production defects are one of:
1. Grammar/parser mismatch
2. AST variant emitted incorrectly
3. Covenant/leaf grouping or tapscript emission mismatch
</context>

<procedure>
1. Reproduce with smallest contract snippet that still fails.
2. Identify failure stage:
- `Parse error:` prefix -> parser/grammar
- Compilation succeeds but wrong ASM -> compiler emission
- CLI-only failure -> `src/main.rs` I/O/arg handling
3. Add or update a targeted integration test before patching.
4. Trace affected path:
- Grammar rule -> parser `parse_*` function
- AST variant -> `emit_expression_asm` / `generate_requirement_asm`
- ABI grouping -> `build_function_groups` / default leaf synthesis
5. Implement minimal fix and run:
- `cargo fmt --check`
- `cargo test --test <focused_file>`
- `cargo test`
6. Keep the reproducer test as regression coverage.
</procedure>

<patterns>
<do>
- Classify bug by stage before editing code.
- Use opcode string joins in tests when full vector matching is brittle.
- Validate the affected `arkade` covenant and all relevant tapleaves when fixing semantic bugs.
</do>
<dont>
- Do not patch compiler first when parser is failing to build AST.
- Do not remove tests to make suite pass.
- Do not ignore warnings that indicate dead paths for newly added variants.
</dont>
</patterns>

<examples>
Example: parse-vs-emit triage
```text
If error starts with "Parse error:", fix grammar/parser.
If test compiles but ASM misses expected opcode, fix compiler emission branch.
If only CLI path fails, inspect file extension/output path logic in src/main.rs.
```
</examples>

<troubleshooting>
| Symptom | Cause | Fix |
|---|---|---|
| `Parse error: ...` for valid-looking syntax | PEG rule order mismatch | Reorder grammar alternatives and parser mapping |
| Tapleaf unexpectedly uses introspection ops | Covenant-only expression reached tapscript emission | Inspect tapscript validation and grouping |
| Function inputs unexpectedly expanded | Array flattening behavior | Check `DEFAULT_ARRAY_LENGTH` handling in compiler |
</troubleshooting>

<references>
- `src/parser/grammar.pest`: parse surface area
- `src/parser/mod.rs`: parser implementation
- `src/compiler/mod.rs`: covenant and opcode emission logic
- `src/main.rs`: CLI argument/file handling
- `tests/*.rs`: behavior contracts and regression signals
</references>
