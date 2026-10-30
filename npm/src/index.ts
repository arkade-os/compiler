import { load } from "./runtime.js";

export interface CompileInput {
    entry: string;
    files: Record<string, string>;
}

export interface CompileOptions {
    optimize?: boolean;
}

/** A 1-based line and column, with columns in UTF-16 code units as editors count them. */
export interface Position {
    line: number;
    column: number;
}

export interface Diagnostic {
    severity: "error" | "warning";
    /** The pass that raised it, such as `"validation"` or `"type"`; `null` for parse and import errors. */
    code: string | null;
    message: string;
    file: string;
    start: Position | null;
    end: Position | null;
}

export interface Parameter {
    name: string;
    type: string;
}

export interface StructDefinition {
    name: string;
    fields: Parameter[];
}

export type SymbolKind = "contract" | "library" | "struct" | "constant" | "function" | "tapscript" | "parameter" | "variable" | "field";

export interface Location {
    file: string;
    start: Position | null;
    end: Position | null;
}

export interface SymbolInfo {
    name: string;
    kind: SymbolKind;
    type: string | null;
    /** The name under the position. */
    at: Location;
    definition: Location;
    references: Location[];
}

export interface CompletionSymbol {
    name: string;
    kind: SymbolKind;
    type: string | null;
}

export interface Completions {
    symbols: CompletionSymbol[];
    /** Fields of every analyzed struct, since a field's type can name a struct the entry does not see. */
    structs: { name: string; fields: { name: string; type: string | null }[] }[];
    /** A library's or contract's names under its own. */
    members: Record<string, CompletionSymbol[]>;
}

export interface WitnessElement extends Parameter {
    encoding: string;
    injected?: boolean;
}

export interface ArkadeCovenant {
    inputs: Parameter[];
    asm: string[];
}

export interface TapLeaf {
    name: string;
    witness: WitnessElement[];
    asm: string[];
}

export interface SpendGroup {
    name: string;
    arkade?: ArkadeCovenant;
    leaves: TapLeaf[];
}

export interface SourceBundle {
    entry: string;
    files: Record<string, string>;
}

export interface CompilerInfo {
    name: string;
    version: string;
    options?: { optimize: boolean };
}

export interface CompilerArtifact {
    formatVersion?: number;
    contractName: string;
    structs?: StructDefinition[];
    constructorInputs: Parameter[];
    functions: SpendGroup[];
    source?: SourceBundle;
    compiler?: CompilerInfo;
    updatedAt?: string;
    fingerprint?: string;
}

export interface SourceRange {
    /** Half-open range of indexes into the covenant's `asm`. */
    asm: [number, number];
    /** 1-based `[line, column]` in the artifact's entry file, with UTF-16 columns. */
    start: [number, number];
    end: [number, number];
    message?: string;
}

/** Covenant source maps, linked to their artifact by its fingerprint. */
export interface DebugInfo {
    formatVersion: number;
    artifactFingerprint?: string;
    functions: Record<string, { sourceMap: SourceRange[] }>;
}

/**
 * Source errors are diagnostics with a `null` artifact, not a rejection. `diagnostics` lists every
 * error and warning, warnings included on success.
 */
export type CompileResult =
    | { artifact: CompilerArtifact; debug: DebugInfo; diagnostics: Diagnostic[] }
    | { artifact: null; debug: null; diagnostics: Diagnostic[] };

let initialization: ReturnType<typeof load> | undefined;

function initialize(): ReturnType<typeof load> {
    return initialization ??= load().catch(error => {
        initialization = undefined;
        throw error;
    });
}

function serializeInput(input: CompileInput): { entry: string; files: string } {
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

function optimization(options?: CompileOptions): boolean | undefined {
    const optimize = options?.optimize;
    if (options !== undefined && (!options || typeof options !== "object" || Array.isArray(options)
        || (optimize !== undefined && typeof optimize !== "boolean"))) {
        throw new TypeError("Compile options must be { optimize?: boolean }");
    }
    return optimize;
}

function serializePosition(position: Position): [number, number] {
    const line = position?.line;
    const column = position?.column;
    // The WASM exports take wasm32 `usize`, which wraps larger numbers.
    if (!Number.isInteger(line) || !Number.isInteger(column) || line < 1 || column < 1
        || line > 0xFFFFFFFF || column > 0xFFFFFFFF) {
        throw new TypeError("Expected { line: number, column: number } with 1-based 32-bit integers");
    }
    return [line, column];
}

async function call<T>(method: (wasm: Awaited<ReturnType<typeof load>>) => string): Promise<T> {
    const loading = initialize();
    const wasm = await loading;
    let output: string;
    try {
        output = method(wasm);
    } catch (error) {
        // Compiler errors are strings; anything else is a trap that left the instance unusable.
        if (typeof error === "string") throw new Error(error);
        if (initialization === loading) initialization = undefined;
        throw error;
    }
    return JSON.parse(output);
}

/** Compile a virtual source project using the installed compiler. */
export async function compile(input: CompileInput, options?: CompileOptions): Promise<CompileResult> {
    const { entry, files } = serializeInput(input);
    const optimize = optimization(options);
    const { artifact, debug, diagnostics } = await call<{ artifact: string | null; debug: string | null; diagnostics: Diagnostic[] }>(
        wasm => wasm.compile_sources_with_diagnostics(entry, files, optimize));
    return artifact === null || debug === null
        ? { artifact: null, debug: null, diagnostics }
        : { artifact: JSON.parse(artifact), debug: JSON.parse(debug), diagnostics };
}

/** Every diagnostic of a project without generating an artifact; a library entry is not an error. */
export async function check(input: CompileInput, options?: CompileOptions): Promise<Diagnostic[]> {
    const { entry, files } = serializeInput(input);
    const optimize = optimization(options);
    return call(wasm => wasm.check_sources(entry, files, optimize));
}

/** The symbol at a position of the entry file, for hover, go to definition and highlighting. */
export async function symbolAt(input: CompileInput, position: Position): Promise<SymbolInfo | null> {
    const { entry, files } = serializeInput(input);
    const [line, column] = serializePosition(position);
    return call(wasm => wasm.symbol_at(entry, files, line, column));
}

/** The names usable at a position of the entry file, for completion. */
export async function completionsAt(input: CompileInput, position: Position): Promise<Completions> {
    const { entry, files } = serializeInput(input);
    const [line, column] = serializePosition(position);
    return call(wasm => wasm.completions_at(entry, files, line, column));
}

/** Read the version from the installed WASM compiler. */
export async function version(): Promise<string> {
    return (await initialize()).version();
}
