import { load } from "./runtime.js";
let initialization;
function initialize() {
    return initialization ??= load().catch(error => {
        initialization = undefined;
        throw error;
    });
}
function serializeInput(input) {
    const entry = input?.entry;
    const sources = input?.files;
    if (!input || typeof input !== "object" || Array.isArray(input)
        || typeof entry !== "string"
        || !sources || typeof sources !== "object" || Array.isArray(sources)) {
        throw new TypeError("Expected { entry: string, files: Record<string, string> }");
    }
    const files = Object.entries(sources);
    if (files.some(([, source]) => typeof source !== "string")) {
        throw new TypeError("Every source file must contain a string");
    }
    return { entry, files: JSON.stringify(Object.fromEntries(files)) };
}
function optimization(options) {
    const optimize = options?.optimize;
    if (options !== undefined && (!options || typeof options !== "object" || Array.isArray(options)
        || (optimize !== undefined && typeof optimize !== "boolean"))) {
        throw new TypeError("Compile options must be { optimize?: boolean }");
    }
    return optimize;
}
function serializePosition(position) {
    const line = position?.line;
    const column = position?.column;
    if (!Number.isInteger(line) || !Number.isInteger(column) || line < 1 || column < 1) {
        throw new TypeError("Expected { line: number, column: number } with 1-based integers");
    }
    return [line, column];
}
async function call(method) {
    const wasm = await initialize();
    try {
        return JSON.parse(method(wasm));
    }
    catch (error) {
        throw error instanceof Error ? error : new Error(String(error));
    }
}
/** Compile a virtual source project using the installed compiler. */
export async function compile(input, options) {
    const { entry, files } = serializeInput(input);
    const optimize = optimization(options);
    const { artifact, debug, diagnostics } = await call(wasm => wasm.compile_sources_with_diagnostics(entry, files, optimize));
    return artifact === null || debug === null
        ? { artifact: null, debug: null, diagnostics }
        : { artifact: JSON.parse(artifact), debug: JSON.parse(debug), diagnostics };
}
/** Every diagnostic of a project without generating an artifact; a library entry is not an error. */
export async function check(input, options) {
    const { entry, files } = serializeInput(input);
    const optimize = optimization(options);
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
