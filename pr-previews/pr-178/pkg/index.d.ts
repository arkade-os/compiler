export interface CompileInput {
    entry: string;
    files: Record<string, string>;
}
export interface CompileOptions {
    optimize?: boolean;
}
export interface Diagnostic {
    severity: "error" | "warning";
    message: string;
    file: string;
    code?: string;
    /** UTF-8 byte offsets into the diagnostic's source file. */
    span?: {
        start: number;
        end: number;
    };
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
    options?: {
        optimize: boolean;
    };
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
/** Compile a virtual source project using the installed compiler. */
export declare function compile(input: CompileInput, options?: CompileOptions): Promise<CompilerArtifact>;
/** Parse declarations for editor tooling, including directly imported symbols. */
export declare function symbols(input: CompileInput): Promise<SourceSymbols>;
/** Check source without generating an artifact; source errors are returned as data. */
export declare function check(input: CompileInput): Promise<Diagnostic[]>;
/** Read the version from the installed WASM compiler. */
export declare function version(): Promise<string>;
