export function load(): Promise<Pick<typeof import("../dist/wasm/arkade_compiler.js"), "compile_sources_with_diagnostics" | "check_sources" | "symbol_at" | "completions_at" | "version">>;
