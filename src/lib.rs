// Compilation entry points, data models, and opcode constants are public.
// Pipeline stages are crate-internal.
mod builtins;
mod compiler;
pub mod diagnostics;
pub mod errors;
mod imports;
pub mod lint;
pub mod models;
pub mod opcodes;
mod operators;
mod parser;
mod properties;
pub mod symbols;
mod types;
mod validator;

#[cfg(feature = "wasm")]
pub mod wasm;

pub use diagnostics::{Diagnostic, Severity, Span};
pub use imports::Analysis;
pub use models::{
    Contract, ContractJson, Expression, Function, Parameter, StructDefinition, WitnessElement,
};
pub use types::ArkType;

/// Per-call compiler settings. Optimizations are enabled by default. Outside this crate, start
/// from `CompileOptions::default()` and set the fields to change. A field missing from
/// deserialized options takes its default.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct CompileOptions {
    /// Fold constant expressions, remove static branches, and optimize Arkade assembly.
    pub optimize: bool,
}

impl Default for CompileOptions {
    fn default() -> Self {
        Self { optimize: true }
    }
}

/// A failed `compile*` call, which displays the error located in its file.
#[derive(Clone)]
pub struct Error(String);

/// The message's `Debug`, as a `main` returning `Box<dyn std::error::Error>` prints it.
impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// Compile Arkade Language source code to a JSON-serializable structure
///
/// This function takes Arkade Language source code as input, parses it into an AST,
/// and then compiles it into a ContractJson structure that can be serialized to JSON.
///
/// The output includes:
/// - Contract name
/// - Parameters
/// - Spend groups with optional Arkade Scripts and L1 tapleaves
///
/// # Arguments
///
/// * `source_code` - The Arkade Language source code as a string
///
/// # Returns
///
/// A Result containing either the ContractJson structure or an error
///
/// # Example
///
/// ```ignore
/// use arkade_compiler::compile;
///
/// let source_code = r#"
/// contract Example(pubkey owner, int exit) {
///     function spend(signature ownerSig) {
///         require(checkSig(ownerSig, owner));
///     }
///
///     function unilateral(signature ownerSig) tapscript {
///         require(older(exit));
///         require(checkSig(ownerSig, owner));
///     }
/// }"#;
///
/// let result = compile(source_code);
/// assert!(result.is_ok());
///
/// // Serialize to JSON
/// let json = serde_json::to_string_pretty(&result.unwrap()).unwrap();
/// println!("{}", json);
/// ```
pub fn compile(source_code: &str) -> Result<ContractJson, Error> {
    compiler::compile(source_code).map_err(Error)
}

/// Compile an entry file and its relative imports from the filesystem.
pub fn compile_file(path: impl AsRef<std::path::Path>) -> Result<ContractJson, Error> {
    compile_file_with_options(path, CompileOptions::default())
}

/// Compile an entry file and its relative imports with per-call options.
pub fn compile_file_with_options(
    path: impl AsRef<std::path::Path>,
    options: CompileOptions,
) -> Result<ContractJson, Error> {
    imports::compile_file(path.as_ref(), options).map_err(Error)
}

/// Compile an entry file from an in-memory map of relative paths to source text.
pub fn compile_sources(
    entry: &str,
    files: &std::collections::BTreeMap<String, String>,
) -> Result<ContractJson, Error> {
    imports::compile_sources(entry, files, CompileOptions::default()).map_err(Error)
}

/// Compile in-memory sources with per-call options.
pub fn compile_sources_with_options(
    entry: &str,
    files: &std::collections::BTreeMap<String, String>,
    options: CompileOptions,
) -> Result<ContractJson, Error> {
    imports::compile_sources(entry, files, options).map_err(Error)
}

/// Parse, resolve imports, type and validate `entry` from an in-memory map of
/// relative paths to source text, without generating code. Its diagnostics,
/// typed AST and artifact all come from this one analysis.
///
/// ```
/// let files = std::collections::BTreeMap::from([(
///     "main.ark".to_string(),
///     "contract C(pubkey owner) { function spend(signature s) { require(checkSig(s, owner)); } }"
///         .to_string(),
/// )]);
/// let analysis = arkade_compiler::analyze("main.ark", &files);
/// assert!(analysis.diagnostics().is_empty());
/// assert_eq!(analysis.contract().unwrap().name, "C");
/// let artifact = analysis.compile(Default::default()).unwrap();
/// assert_eq!(artifact.name, "C");
/// ```
pub fn analyze(entry: &str, files: &std::collections::BTreeMap<String, String>) -> Analysis {
    imports::analyze(entry, files, true)
}

/// [`analyze`] for an entry file and its relative imports on the filesystem; diagnostics name
/// files by absolute path.
pub fn analyze_file(path: impl AsRef<std::path::Path>) -> Analysis {
    imports::analyze_file(path.as_ref(), true)
}

/// Every parse, validation and type diagnostic for `entry`, without writing
/// an artifact. Unlike the `compile_*` functions, this does not stop at the
/// first error: independent problems in `entry` each get their own entry.
/// Code generation, which runs only when those pass, reports its first error.
/// Diagnostics from imports name the imported file. `entry` may be a library
/// file.
pub fn check(entry: &str, files: &std::collections::BTreeMap<String, String>) -> Vec<Diagnostic> {
    imports::check_sources(entry, files)
}

/// Every builtin function and `tx`/`this` member as JSON: its parameters, its result or type,
/// and its docs. Builtins and properties come from the tables the compiler itself reads.
pub fn builtin_docs() -> String {
    builtins::docs()
}
