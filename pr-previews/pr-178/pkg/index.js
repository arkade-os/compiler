import { load } from "./runtime.js";
let initialization;
function initialize() {
    return initialization ??= load().catch(error => {
        initialization = undefined;
        throw error;
    });
}
function serializeInput(input) {
    if (!input || typeof input !== "object" || Array.isArray(input)
        || typeof input.entry !== "string"
        || !input.files || typeof input.files !== "object" || Array.isArray(input.files)) {
        throw new TypeError("Expected { entry: string, files: Record<string, string> }");
    }
    const entry = input.entry;
    const files = Object.entries(input.files);
    if (files.some(([, source]) => typeof source !== "string")) {
        throw new TypeError("Every source file must contain a string");
    }
    return { entry, files: JSON.stringify(Object.fromEntries(files)) };
}
/** Compile a virtual source project using the installed compiler. */
export async function compile(input, options) {
    const { entry, files } = serializeInput(input);
    const optimize = options?.optimize;
    if (options !== undefined && (!options || typeof options !== "object" || Array.isArray(options)
        || (optimize !== undefined && typeof optimize !== "boolean"))) {
        throw new TypeError("Compile options must be { optimize?: boolean }");
    }
    const wasm = await initialize();
    let result;
    try {
        result = wasm.compile_sources_with_diagnostics(entry, files, optimize);
    }
    catch (error) {
        throw error instanceof Error ? error : new Error(String(error));
    }
    const { artifact, warnings } = JSON.parse(result);
    return { ...JSON.parse(artifact), warnings };
}
/** Parse declarations for editor tooling, including directly imported symbols. */
export async function symbols(input) {
    const { entry, files } = serializeInput(input);
    const wasm = await initialize();
    try {
        return JSON.parse(wasm.symbols(entry, files));
    }
    catch (error) {
        throw error instanceof Error ? error : new Error(String(error));
    }
}
/** Check source without generating an artifact; source errors are returned as data. */
export async function check(input) {
    const { entry, files } = serializeInput(input);
    const wasm = await initialize();
    try {
        return JSON.parse(wasm.check(entry, files));
    }
    catch (error) {
        throw error instanceof Error ? error : new Error(String(error));
    }
}
/** Read the version from the installed WASM compiler. */
export async function version() {
    return (await initialize()).version();
}
