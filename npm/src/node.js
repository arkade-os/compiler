import { readFileSync } from 'node:fs';

let instances = 0;

// Each load imports the glue under a new URL for a fresh instance, so a trap is recoverable.
export async function load() {
    const wasm = await import(`../wasm/arkade_compiler.js?instance=${++instances}`);
    wasm.initSync({ module: readFileSync(new URL('../wasm/arkade_compiler_bg.wasm', import.meta.url)) });
    return wasm;
}
