---
name: wasm-playground-workflow
description: Activate this skill whenever work touches WASM bindings, playground UI behavior, example contract generation, or GitHub Pages deployment for the browser playground.
prerequisites: cargo, wasm-pack, node, python3
---

# WASM Playground Workflow

<purpose>
Safely modify and validate the browser playground pipeline that wraps the Rust compiler as WebAssembly and serves static demo assets.
</purpose>

<context>
Playground stack is static HTML/CSS/JS in `playground/` plus Rust WASM exports in `src/wasm.rs`.
Build flow:
1. `playground/generate_contracts.sh` creates `playground/contracts.js` from `examples/*.ark`.
2. `wasm-pack build --features wasm` outputs package to `playground/pkg`.
3. Deploy workflow publishes `playground/` to GitHub Pages.
</context>

<procedure>
1. If compiler surface changed for web usage, update `src/wasm.rs` first.
2. If example list/content changed, run `./playground/generate_contracts.sh`.
3. Run full build: `./playground/build.sh`.
4. Serve locally: `./playground/serve.sh 8080` and verify browser compile flow.
5. If deploy behavior changed, verify `.github/workflows/deploy-playground.yml` assumptions.
6. Re-run `cargo test` if compiler logic changed.
</procedure>

<patterns>
<do>
- Keep WASM exports string-based for browser ergonomics (`compile` returns JSON string).
- Treat `playground/contracts.js` as generated output.
- Keep playground self-contained (no package manager assumptions).
</do>
<dont>
- Do not hand-edit `playground/pkg/*` artifacts -> regenerate via wasm-pack.
- Do not require npm/yarn setup; current scripts rely only on Node runtime.
- Do not change deploy workflow without explicit approval.
</dont>
</patterns>

<examples>
Example: full local verification
```bash
./playground/generate_contracts.sh
./playground/build.sh
./playground/serve.sh 8080
```
</examples>

<troubleshooting>
| Symptom | Cause | Fix |
|---|---|---|
| `wasm-pack: command not found` | Missing tool | `cargo install wasm-pack` |
| Playground loads but compile fails | WASM package missing or stale | Re-run `./playground/build.sh` |
| New example not in dropdown | `contracts.js` not regenerated | Run `./playground/generate_contracts.sh` |
</troubleshooting>

<references>
- `src/wasm.rs`: wasm-bindgen exports
- `playground/build.sh`: build orchestration
- `playground/generate_contracts.sh`: generated contracts module
- `.github/workflows/deploy-playground.yml`: pages deploy pipeline
</references>
