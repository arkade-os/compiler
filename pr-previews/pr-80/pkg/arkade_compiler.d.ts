/* tslint:disable */
/* eslint-disable */

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
 * Initialize panic hook for better error messages in the browser console
 */
export function init(): void;

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
    readonly compile: (a: number, b: number) => [number, number, number, number];
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
