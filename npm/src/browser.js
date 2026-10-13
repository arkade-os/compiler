export async function load() {
    const wasm = await import('./wasm/arkade_compiler.js');
    await wasm.default({ module_or_path: new URL('./wasm/arkade_compiler_bg.wasm', import.meta.url) });
    return wasm;
}
