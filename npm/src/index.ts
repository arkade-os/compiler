import { load } from "./runtime.js";

export interface CompileInput {
    entry: string;
    files: Record<string, string>;
}

export interface Parameter {
    name: string;
    type: string;
}

export interface StructDefinition {
    name: string;
    fields: Parameter[];
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

/** Compile a virtual source project using the installed compiler. */
export async function compile(input: CompileInput): Promise<CompilerArtifact> {
    if (!input || typeof input !== "object" || Array.isArray(input)
        || typeof input.entry !== "string"
        || !input.files || typeof input.files !== "object" || Array.isArray(input.files)) {
        throw new TypeError("compile expects { entry: string, files: Record<string, string> }");
    }
    const entry = input.entry;
    const files = Object.entries(input.files);
    if (files.some(([, source]) => typeof source !== "string")) {
        throw new TypeError("Every source file must contain a string");
    }
    const serialized = JSON.stringify(Object.fromEntries(files));
    const wasm = await initialize();
    let result: string;
    try {
        result = wasm.compile_sources_with_diagnostics(entry, serialized);
    } catch (error) {
        throw error instanceof Error ? error : new Error(String(error));
    }
    const { artifact, warnings } = JSON.parse(result);
    return { ...JSON.parse(artifact), warnings };
}

/** Read the version from the installed WASM compiler. */
export async function version(): Promise<string> {
    return (await initialize()).version();
}
