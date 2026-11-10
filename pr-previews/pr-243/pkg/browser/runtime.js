// Static, since a browser caches a failed dynamic import; only the WASM fetch is lazy.
import init, * as wasm from '../wasm/arkade_compiler.js';

// ponytail: the glue keeps one instance per module, so after a trap this page reuses the broken
// instance until it reloads; wasm-bindgen's --experimental-reset-state-function would allow an
// in-place reset if wasm-pack could pass it.
export async function load() {
    await init({ module_or_path: new URL('../wasm/arkade_compiler_bg.wasm', import.meta.url) });
    return wasm;
}
