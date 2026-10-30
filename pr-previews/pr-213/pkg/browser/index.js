import { load } from "./runtime.js";
let initialization;
function initialize() {
    return initialization ??= load().catch(error => {
        initialization = undefined;
        throw error;
    });
}
// The compiler validates the files it parses from this JSON.
function serializeInput(input) {
    return { entry: input.entry, files: JSON.stringify(input.files) };
}
function serializePosition(position) {
    const line = position?.line;
    const column = position?.column;
    // The WASM exports take wasm32 `usize`, which wraps larger numbers.
    if (!Number.isInteger(line) || !Number.isInteger(column) || line < 1 || column < 1
        || line > 0xFFFFFFFF || column > 0xFFFFFFFF) {
        throw new TypeError("Expected { line: number, column: number } with 1-based 32-bit integers");
    }
    return [line, column];
}
async function call(method) {
    const loading = initialize();
    const wasm = await loading;
    let output;
    try {
        output = method(wasm);
    }
    catch (error) {
        // Compiler errors are strings; anything else is a trap that left the instance unusable.
        if (typeof error === "string")
            throw new Error(error);
        if (initialization === loading)
            initialization = undefined;
        throw error;
    }
    return JSON.parse(output);
}
/** Compile a virtual source project using the installed compiler. */
export async function compile(input, options) {
    const { entry, files } = serializeInput(input);
    const optimize = options?.optimize;
    const { artifact, debug, diagnostics } = await call(wasm => wasm.compile_sources_with_diagnostics(entry, files, optimize));
    return artifact === null || debug === null
        ? { artifact: null, debug: null, diagnostics }
        : { artifact: JSON.parse(artifact), debug: JSON.parse(debug), diagnostics };
}
/** Every diagnostic of a project without generating an artifact; a library entry is not an error. */
export async function check(input, options) {
    const { entry, files } = serializeInput(input);
    const optimize = options?.optimize;
    return call(wasm => wasm.check_sources(entry, files, optimize));
}
/** The symbol at a position of the entry file, for hover, go to definition and highlighting. */
export async function symbolAt(input, position) {
    const { entry, files } = serializeInput(input);
    const [line, column] = serializePosition(position);
    return call(wasm => wasm.symbol_at(entry, files, line, column));
}
/** The names usable at a position of the entry file, for completion. */
export async function completionsAt(input, position) {
    const { entry, files } = serializeInput(input);
    const [line, column] = serializePosition(position);
    return call(wasm => wasm.completions_at(entry, files, line, column));
}
/** Read the version from the installed WASM compiler. */
export async function version() {
    return (await initialize()).version();
}
