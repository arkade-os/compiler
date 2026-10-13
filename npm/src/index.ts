import { load } from "./runtime.js";

export interface CompileInput {
    entry: string;
    files: Record<string, string>;
}

export interface CompileOptions {
    optimize?: boolean;
}

export interface Parameter {
    name: string;
    type: string;
}

export interface StructDefinition {
    name: string;
    fields: Parameter[];
}

export interface SourceSymbol {
    name: string;
    kind: string;
    type?: string;
    position: [number, number];
    scope?: [number, number];
    file?: string;
}

export interface SourceSymbols {
    symbols: SourceSymbol[];
    structs: StructDefinition[];
    members: Record<string, SourceSymbol[]>;
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
    /** Diagnostics retained by the wrapper; excluded from the artifact fingerprint. */
    warnings: string[];
}

let initialization: ReturnType<typeof load> | undefined;

function initialize(): ReturnType<typeof load> {
    return initialization ??= load().catch(error => {
        initialization = undefined;
        throw error;
    });
}

function serializeInput(input: CompileInput): { entry: string; files: string } {
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
export async function compile(input: CompileInput, options?: CompileOptions): Promise<CompilerArtifact> {
    const { entry, files } = serializeInput(input);
    const optimize = options?.optimize;
    if (options !== undefined && (!options || typeof options !== "object" || Array.isArray(options)
        || (optimize !== undefined && typeof optimize !== "boolean"))) {
        throw new TypeError("Compile options must be { optimize?: boolean }");
    }
    const wasm = await initialize();
    let result: string;
    try {
        result = wasm.compile_sources_with_diagnostics(entry, files, optimize);
    } catch (error) {
        throw error instanceof Error ? error : new Error(String(error));
    }
    const { artifact, warnings } = JSON.parse(result);
    return { ...JSON.parse(artifact), warnings };
}

/** Parse declarations for editor tooling, including directly imported symbols. */
export async function symbols(input: CompileInput): Promise<SourceSymbols> {
    const { entry, files } = serializeInput(input);
    const wasm = await initialize();
    try {
        return JSON.parse(wasm.symbols(entry, files));
    } catch (error) {
        throw error instanceof Error ? error : new Error(String(error));
    }
}

/** Read the version from the installed WASM compiler. */
export async function version(): Promise<string> {
    return (await initialize()).version();
}
