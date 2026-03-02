<identity>
Arkade Compiler compiles `.ark` contracts into JSON ABI + script assembly via Rust library, CLI (`arkadec`), and optional WASM bindings.
</identity>

<stack>
| Layer | Technology | Version | Notes |
|---|---|---|---|
| Runtime | Rust toolchain | stable [verify] | Local validation used `rustc 1.91.1` on 2026-03-02 |
| Language | Rust | Edition 2021 | Set in `Cargo.toml` |
| Parser | `pest`, `pest_derive` | `^2.7.8` (`2.8.6` resolved [verify]) | Grammar in `src/parser/grammar.pest` |
| CLI | `clap` | `^4.5.3` | Entry point `src/main.rs` |
| Serialization | `serde`, `serde_json` | `^1.0` | ABI/output models in `src/models/mod.rs` |
| Time metadata | `chrono` | `^0.4.34` | Generates `updatedAt` |
| WASM bridge | `wasm-bindgen` | `0.2` (optional) | Enabled by `--features wasm` |
| Package manager | Cargo | bundled | No workspace; single crate |
| Test framework | Cargo integration tests | n/a | Test suite in `tests/*.rs` |
| Playground runtime | Browser JS + Node + Python | [verify] | Node used by `playground/generate_contracts.sh`; Python serves static files |
| CI/CD | GitHub Actions | [verify] | Build/test + GitHub Pages deploy on `master` |
</stack>

<structure>
project-root/
- `src/` # Compiler crate source [agent: autonomous except gated files]
- `src/main.rs` # CLI entrypoint (`arkadec`) [autonomous]
- `src/lib.rs` # Public library API (`compile`) [autonomous]
- `src/parser/` # Pest grammar + AST parser [autonomous except `grammar.pest` gated]
- `src/compiler/mod.rs` # AST -> ABI/ASM generation [gated]
- `src/models/mod.rs` # AST and JSON ABI data model [gated]
- `src/opcodes/mod.rs` # Opcode constants [autonomous]
- `src/wasm.rs` # WASM exports behind feature flag [autonomous]
- `tests/` # Integration tests and CLI parity checks [autonomous]
- `examples/` # `.ark` fixtures and generated `.json`/`.hack` artifacts [autonomous]
- `docs/` # Language/design references [autonomous]
- `playground/` # Static web playground + build scripts [autonomous]
- `scripts/pre-commit` # Local formatting hook [gated]
- `.github/workflows/` # CI and pages deploy [gated]
- `Cargo.toml` # crate metadata + dependency constraints [gated]
- `README.md` # user-facing docs (can drift; verify against source) [autonomous]
- `.codex/skills/` # project skill catalog [forbidden without explicit instruction]
- `CLAUDE.md`, `agents.md` # agent context configs [forbidden without explicit instruction]
</structure>

<commands>
| Task | Command | Notes |
|---|---|---|
| Fetch dependencies | `cargo fetch` | Use after dependency edits |
| Build compiler | `cargo build` | Primary compile validation |
| Run all tests | `cargo test` | Includes integration and CLI tests |
| Run one test file | `cargo test --test htlc_test` | Fast iteration on one contract scenario |
| Format check | `cargo fmt --check` | Required by CI |
| Format fix | `cargo fmt` | Also used by `scripts/pre-commit` |
| Run CLI | `cargo run -- examples/htlc.ark -o /tmp/htlc.json` | Real args are only `<file>` and optional `-o/--output` |
| Build WASM package | `wasm-pack build --target web --out-dir playground/pkg --features wasm` | Requires `wasm-pack` + wasm target |
| Generate playground contracts | `./playground/generate_contracts.sh` | Regenerates `playground/contracts.js` from `examples/*.ark` |
| Full playground build | `./playground/build.sh` | Generate contracts + wasm-pack + cleanup |
| Serve playground | `./playground/serve.sh 8080` | Uses Python HTTP server |
</commands>

<conventions>
  <code_style>
    Rust naming: `snake_case` for functions/variables, `PascalCase` for enums/structs, `SCREAMING_SNAKE_CASE` for opcode constants.
    Keep module boundaries strict: grammar in `src/parser/grammar.pest`, parse logic in `src/parser/mod.rs`, emit logic in `src/compiler/mod.rs`.
    Prefer explicit `Result<_, String>` in parser/compiler internals; map to richer error in public API (`src/lib.rs`) and CLI (`src/main.rs`).
    Always run `cargo fmt` after source edits.
  </code_style>

  <patterns>
    <do>
      - Update `models` + `parser` + `compiler` together for any language feature change.
      - Add integration tests in `tests/` for every new syntax/opcode path.
      - Validate both function variants (`serverVariant=true/false`) for non-internal functions.
      - Strip or ignore `updatedAt` when comparing expected vs actual JSON in tests.
      - Keep placeholder format `<name>` in emitted ASM.
    </do>
    <dont>
      - Do not trust README CLI flags blindly; source of truth is `src/main.rs` clap args.
      - Do not edit generated playground artifacts manually (`playground/contracts.js`, `playground/pkg/*`); regenerate.
      - Do not change grammar ordering casually; PEG alternative order changes parse behavior.
      - Do not add new Expression/Requirement variants without compiler emission and tests.
    </dont>
  </patterns>

  <commit_conventions>
    Prefer conventional prefixes used in repo history: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`.
    Keep branch targets aligned with `master` workflow triggers [verify].
  </commit_conventions>
</conventions>

<workflows>
  <bug_fix>
    1. Reproduce with smallest `.ark` snippet or existing failing test.
    2. Classify failure stage: parser (`Parse error:`) vs compiler/ASM vs CLI I/O.
    3. Patch only the responsible module (`parser`, `compiler`, `main`, or tests).
    4. Add/adjust regression test in `tests/`.
    5. Run `cargo fmt --check`.
    6. Run targeted test file, then `cargo test`.
    7. If output JSON is asserted, normalize `updatedAt` first.
  </bug_fix>

  <new_language_feature>
    1. Add/adjust grammar rules in `src/parser/grammar.pest` (gated).
    2. Add AST representation in `src/models/mod.rs` (gated).
    3. Parse rule to AST in `src/parser/mod.rs`.
    4. Emit requirements/ASM in `src/compiler/mod.rs` (gated).
    5. If semantics affect dual-path logic, verify `generate_function` behavior for both variants.
    6. Add tests in `tests/` covering happy path + edge conditions.
    7. Run `cargo fmt --check` and `cargo test`.
    8. If playground examples depend on feature, update `examples/*.ark` and regenerate `playground/contracts.js`.
  </new_language_feature>

  <playground_change>
    1. Update static files in `playground/` and/or compiler WASM interface (`src/wasm.rs`).
    2. Run `./playground/generate_contracts.sh` if examples changed.
    3. Run `./playground/build.sh`.
    4. Validate local browser flow via `./playground/serve.sh`.
    5. Confirm deploy workflow assumptions in `.github/workflows/deploy-playground.yml`.
  </playground_change>
</workflows>

<boundaries>
  <zone_map>
    | Path | Zone | Rule |
    |---|---|---|
    | `src/parser/grammar.pest` | supervised | Language grammar changes require human approval before merge |
    | `src/models/mod.rs` | supervised | AST/ABI contract changes require approval |
    | `src/compiler/mod.rs` | supervised | Script-generation semantics are high impact |
    | `Cargo.toml` | supervised | Dependency/version/public metadata changes require approval |
    | `.github/workflows/*` | supervised | CI/CD behavior changes require approval |
    | `scripts/pre-commit` | supervised | Team hook behavior changes require approval |
    | `src/**` (except above), `tests/**`, `examples/**`, `docs/**`, `playground/**`, `README.md` | autonomous | Safe coding/testing/docs zone |
    | `.env`, `.env.*`, `*.key`, `*.pem`, secrets files | forbidden | Credentials/secrets never read or modified |
    | `.git/**` internals | forbidden | Never edit git internals |
    | `CLAUDE.md`, `agents.md`, `.codex/skills/**` | forbidden | Modify only on explicit user request |
  </zone_map>

  <safety_checks>
    Before any destructive change (deletes, bulk overwrite, migration-like rewrite):
    1. State exact files to change.
    2. State rollback plan.
    3. Wait for explicit confirmation.
  </safety_checks>
</boundaries>

<troubleshooting>
  <known_issues>
    | Symptom | Cause | Fix |
    |---|---|---|
    | `Input file must have .ark extension` | CLI validates extension in `src/main.rs` | Use `.ark` input path |
    | `Parse error: ...` | Grammar/parser mismatch | Update both `src/parser/grammar.pest` and `src/parser/mod.rs`; add regression test |
    | `wasm-pack: command not found` | Missing local wasm tool | `cargo install wasm-pack` and ensure PATH |
    | JSON equality test fails but contracts look same | `updatedAt` timestamp differs | Remove/ignore `updatedAt` before assertions |
    | CI format check fails | Rust code not formatted | Run `cargo fmt` then re-run `cargo fmt --check` |
  </known_issues>

  <recovery_patterns>
    1. Re-run failing command with full output (`cargo test --test <file>`).
    2. Confirm referenced grammar rule/expression variant exists in parser + models + compiler.
    3. Run `cargo fmt --check` and `cargo test` from clean working tree.
    4. If parser behavior is unclear, isolate a minimal `.ark` contract and inspect parse path.
    5. Escalate with exact error, failing file, and command if still blocked.
  </recovery_patterns>
</troubleshooting>

<skills>
Canonical skills directory: `.codex/skills/`.
Compatibility symlinks: `.claude/skills -> ../.codex/skills`, `.agents/skills -> ../.codex/skills`.

Available project skills:
- `language-feature-development.md`: Add or change Arkade syntax/AST/compiler semantics safely.
- `testing-and-regressions.md`: Author and maintain integration/CLI regression tests.
- `wasm-playground-workflow.md`: Build/debug/deploy playground and WASM bridge.
- `compiler-debugging.md`: Diagnose parse/compiler/ASM mismatches quickly.

Load only the skill required for the active task domain.
</skills>

<memory>
  <project_decisions>
    - [2026-03-02] Non-internal functions emit two ABI variants (`serverVariant=true/false`) - supports cooperative and exit paths.
    - [2026-03-02] Introspection exit paths use N-of-N CHECKSIG fallback - avoids introspection opcodes in unilateral path.
    - [2026-03-02] `options.server` is treated as a boolean capability flag, not a constructor parameter binding.
    - [2026-03-02] Array parameters are flattened with `DEFAULT_ARRAY_LENGTH=3` in ABI/function input generation.
  </project_decisions>

  <lessons_learned>
    - README examples may drift; verify behavior against `src/main.rs`, parser, and tests.
    - Grammar alternative order in PEG materially changes parse results.
    - Reliable feature work requires synchronized changes across `models`, `parser`, `compiler`, and `tests`.
  </lessons_learned>
</memory>
