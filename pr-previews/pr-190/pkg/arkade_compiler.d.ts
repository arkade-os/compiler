/* tslint:disable */
/* eslint-disable */

/**
 * The diagnostics of a virtual project, in the form `compile_sources_with_diagnostics` gives
 * them, without an artifact; a library entry gets its own diagnostics, not the error compiling
 * it as an entry would give. For diagnosing sources while they are edited.
 */
export function check_sources(entry: string, files: string, optimize?: boolean | null): string;

/**
 * Compile Arkade Script source code to JSON
 *
 * # Arguments
 * * `source` - The Arkade Script source code
 *
 * # Returns
 * A JSON string containing the compiled contract, or an error message
 */
export function compile(source: string): string;

/**
 * Compile a virtual project. `files` is a JSON object mapping relative .ark paths to source text.
 * `optimize` defaults to true when omitted.
 */
export function compile_sources(entry: string, files: string, optimize?: boolean | null): string;

/**
 * Compile a virtual project and report every diagnostic with its position. Compilation
 * errors are diagnostics, not a thrown error: the result is
 * `{ artifact: string | null, debug: string | null, warnings: string[], diagnostics: Diagnostic[] }`,
 * where `debug` is the debug file JSON (`ContractJson::debug_info`) and each
 * diagnostic has `severity`, `code`, `message`, `file` and, when located, 1-based `start` and
 * `end` `{ line, column }` with columns counted in UTF-16 units, as editors count them.
 */
export function compile_sources_with_diagnostics(entry: string, files: string, optimize?: boolean | null): string;

/**
 * The names usable at 1-based `line` and UTF-16 `column` of `entry`, for completion:
 * `{ symbols, structs, members }`, where `members` lists a library's or contract's names
 * under its own, and `structs` gives each visible struct's fields.
 */
export function completions_at(entry: string, files: string, line: number, column: number): string;

/**
 * Initialize panic hook for better error messages in the browser console
 */
export function init(): void;

/**
 * The symbol at 1-based `line` and UTF-16 `column` of `entry`, for hover, go to definition
 * and highlighting: `{ name, kind, type, at, definition, references }`, each location
 * `{ file, start, end }`, or `null` when no name is there.
 */
export function symbol_at(entry: string, files: string, line: number, column: number): string;

/**
 * Validate Arkade Script source code without generating output
 *
 * # Arguments
 * * `source` - The Arkade Script source code
 *
 * # Returns
 * `true` if the source is valid, otherwise returns an error message
 */
export function validate(source: string): boolean;

/**
 * Get the compiler version
 */
export function version(): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly check_sources: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly compile: (a: number, b: number) => [number, number, number, number];
    readonly compile_sources: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly compile_sources_with_diagnostics: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly completions_at: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly symbol_at: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly validate: (a: number, b: number) => [number, number, number];
    readonly version: () => [number, number];
    readonly init: () => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
