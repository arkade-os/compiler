// ponytail: the glue keeps one instance per module, so after a trap this realm reuses the broken
// instance and a new worker or page recovers; wasm-bindgen's --experimental-reset-state-function
// would allow an in-place reset if wasm-pack could pass it.
export async function load() {
    const wasm = await import('./wasm/arkade_compiler.js');
    await wasm.default({ module_or_path: new URL('./wasm/arkade_compiler_bg.wasm', import.meta.url) });
    return wasm;
}
