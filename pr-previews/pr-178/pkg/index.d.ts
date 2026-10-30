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
    structs: {
        name: string;
        fields: {
            name: string;
            type: string | null;
        }[];
    }[];
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
    functions: Record<string, {
        sourceMap: SourceRange[];
    }>;
}
/**
 * Source errors are diagnostics with a `null` artifact, not a rejection. `diagnostics` lists every
 * error and warning, warnings included on success.
 */
export type CompileResult = {
    artifact: CompilerArtifact;
    debug: DebugInfo;
    diagnostics: Diagnostic[];
} | {
    artifact: null;
    debug: null;
    diagnostics: Diagnostic[];
};
/** Compile a virtual source project using the installed compiler. */
export declare function compile(input: CompileInput, options?: CompileOptions): Promise<CompileResult>;
/** Every diagnostic of a project without generating an artifact; a library entry is not an error. */
export declare function check(input: CompileInput, options?: CompileOptions): Promise<Diagnostic[]>;
/** The symbol at a position of the entry file, for hover, go to definition and highlighting. */
export declare function symbolAt(input: CompileInput, position: Position): Promise<SymbolInfo | null>;
/** The names usable at a position of the entry file, for completion. */
export declare function completionsAt(input: CompileInput, position: Position): Promise<Completions>;
/** Read the version from the installed WASM compiler. */
export declare function version(): Promise<string>;
