<roles>
| Role | Model Tier | Responsibility | Boundaries |
|---|---|---|---|
| Orchestrator | Frontier | Decompose work, assign scopes, integrate outputs | Does not implement production code directly |
| Implementer | Mid-tier | Edit code/tests/docs in assigned scope | Does not change architecture or gated files without approval |
| Reviewer | Frontier | Validate behavior, regressions, boundary compliance | Does not patch code; returns actionable findings |
| Specialist: Parser/Compiler | Mid or Frontier | Grammar/AST/ASM semantics work | Scoped to `src/parser/*`, `src/models/mod.rs`, `src/compiler/mod.rs` |
| Specialist: Playground | Mid-tier | WASM + static playground changes | Scoped to `src/wasm.rs`, `playground/*`, deploy workflow review |
</roles>

<delegation_protocol>
1. ANALYZE risk and scope: parser semantics, ABI impact, deploy impact, docs-only, or tests-only.
2. DECOMPOSE into atomic tasks with non-overlapping file sets.
3. CLASSIFY:
- Routine low-risk edits (`tests/*`, docs, examples) -> Implementer.
- Parser/compiler semantic edits -> Specialist: Parser/Compiler.
- Playground/WASM pipeline edits -> Specialist: Playground.
- Architectural or boundary ambiguity -> Orchestrator or escalate.
4. PLAN execution order:
- Serialize grammar/model/compiler edits.
- Parallelize independent tests/docs/playground text updates.
5. DELEGATE using task format below.
6. MONITOR with checkpoints after each acceptance command.
7. INTEGRATE and re-run global checks.
8. REVIEW before completion.
</delegation_protocol>

<task_format>
## Task: [Title]

**Objective**: [single sentence done-state]

**Context**:
- Files to read: [absolute or repo-relative paths]
- Files to modify: [exact paths]
- Files to create: [exact paths]
- Related symbols: [functions/types/rules]

**Acceptance criteria**:
- [ ] Behavior change validated by targeted test(s): `cargo test --test <file>`
- [ ] Global tests pass: `cargo test`
- [ ] Formatting passes: `cargo fmt --check`
- [ ] If playground changed: `./playground/build.sh`

**Constraints**:
- Do NOT modify outside listed files.
- Do NOT edit gated files without explicit approval.
- Time box: [estimate]

**Handoff**:
- Report changed files, command results, unresolved risks.
</task_format>

<state_machine>
PENDING -> ASSIGNED -> IN_PROGRESS -> REVIEW -> APPROVED -> DONE
PENDING -> ASSIGNED -> IN_PROGRESS -> REVIEW -> REJECTED -> IN_PROGRESS
IN_PROGRESS -> BLOCKED -> ASSIGNED
IN_PROGRESS -> CANCELLED

Rules:
- Only Orchestrator transitions PENDING -> ASSIGNED.
- BLOCKED requires: blocker, attempts, and required inputs.
- REVIEW -> REJECTED must include concrete failure and expected fix.
- BLOCKED for >30 minutes -> escalate to human.
</state_machine>

<parallel_execution>
Safe to parallelize:
- Distinct test files in `tests/`
- Docs updates in `README.md`/`docs/`
- Playground text/style updates not touching compiler semantics

Must serialize:
- `src/parser/grammar.pest` with `src/parser/mod.rs`
- `src/models/mod.rs` with `src/compiler/mod.rs`
- `Cargo.toml` dependency updates
- `.github/workflows/*` changes

Conflict protocol:
1. Compare planned file lists before assignment.
2. If overlap exists, assign explicit priority.
3. Lower priority waits, then rebases and revalidates commands.
4. Escalate unresolved merge conflicts to Orchestrator.
</parallel_execution>

<escalation>
Escalate to human when:
- Public ABI or language semantics must break compatibility.
- Security-sensitive behavior is unclear.
- CI/deploy changes are required but acceptance criteria conflict.
- Confidence in assumption drops below 70%.

Format:
**ESCALATION**: [one-line summary]
**Context**: [current task]
**Blocker**: [specific issue]
**Options**:
1. [Option A] - Tradeoff: [impact]
2. [Option B] - Tradeoff: [impact]
**Recommendation**: [best option]
**Impact of delay**: [what stalls]
</escalation>
