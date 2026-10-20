//! WASM bindings for the Arkade Compiler
//!
//! This module provides WebAssembly bindings for the compiler,
//! allowing it to be used in web browsers.

use wasm_bindgen::prelude::*;

/// Initialize panic hook for better error messages in the browser console
#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(feature = "wasm")]
    console_error_panic_hook::set_once();
}

/// Compile Arkade Script source code to JSON
///
/// # Arguments
/// * `source` - The Arkade Script source code
///
/// # Returns
/// A JSON string containing the compiled contract, or an error message
#[wasm_bindgen]
pub fn compile(source: &str) -> Result<String, String> {
    match crate::compiler::compile(source) {
        Ok(contract_json) => serde_json::to_string_pretty(&contract_json)
            .map_err(|e| format!("Serialization error: {e}")),
        Err(e) => Err(e),
    }
}

/// Get the compiler version
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Validate Arkade Script source code without generating output
///
/// # Arguments
/// * `source` - The Arkade Script source code
///
/// # Returns
/// `true` if the source is valid, otherwise returns an error message
#[wasm_bindgen]
pub fn validate(source: &str) -> Result<bool, String> {
    match crate::compile(source) {
        Ok(_) => Ok(true),
        Err(e) => Err(e.to_string()),
    }
}

/// Compile a virtual project. `files` is a JSON object mapping relative .ark paths to source text.
/// `optimize` defaults to true when omitted.
#[wasm_bindgen]
pub fn compile_sources(entry: &str, files: &str, optimize: Option<bool>) -> Result<String, String> {
    let output = compile_project(entry, files, optimize)?;
    serde_json::to_string_pretty(&output).map_err(|e| format!("Serialization error: {e}"))
}

/// Compile a virtual project and report every diagnostic with its position. Compilation
/// errors are diagnostics, not a thrown error: the result is
/// `{ artifact: string | null, warnings: string[], diagnostics: Diagnostic[] }`, where each
/// diagnostic has `severity`, `code`, `message`, `file` and, when located, 1-based `start` and
/// `end` `{ line, column }` with columns counted in UTF-16 units, as editors count them.
#[wasm_bindgen]
pub fn compile_sources_with_diagnostics(
    entry: &str,
    files: &str,
    optimize: Option<bool>,
) -> Result<String, String> {
    let files: std::collections::BTreeMap<String, String> =
        serde_json::from_str(files).map_err(|e| format!("Invalid source files: {e}"))?;
    let options = crate::CompileOptions {
        optimize: optimize.unwrap_or(true),
    };
    let analysis = crate::analyze(entry, &files);
    let mut diagnostics = analysis.diagnostics();
    let mut artifact = None;
    let mut warnings = Vec::new();
    if analysis.contract().is_some() {
        match analysis.compile(options) {
            Ok(output) => {
                warnings = output.warnings.clone();
                artifact = Some(
                    serde_json::to_string_pretty(&output)
                        .map_err(|e| format!("Serialization error: {e}"))?,
                );
            }
            Err(errors) => diagnostics.extend(errors),
        }
    }
    let diagnostics: Vec<_> = diagnostics
        .iter()
        .map(|diagnostic| located(diagnostic, &files))
        .collect();
    serde_json::to_string(&serde_json::json!({
        "artifact": artifact,
        "warnings": warnings,
        "diagnostics": diagnostics,
    }))
    .map_err(|e| format!("Serialization error: {e}"))
}

fn located(
    diagnostic: &crate::Diagnostic,
    files: &std::collections::BTreeMap<String, String>,
) -> serde_json::Value {
    let source = files
        .iter()
        .find(|(path, _)| {
            crate::imports::relative_path(path).is_ok_and(|path| path == diagnostic.file)
        })
        .map(|(_, source)| source.as_str());
    let position = |offset: usize| {
        let (line, column) = crate::diagnostics::position(source?, offset)?;
        Some(serde_json::json!({ "line": line, "column": column }))
    };
    let span = diagnostic.span;
    serde_json::json!({
        "severity": match diagnostic.severity {
            crate::Severity::Error => "error",
            crate::Severity::Warning => "warning",
        },
        "code": diagnostic.code,
        "message": diagnostic.message,
        "file": diagnostic.file,
        "start": span.and_then(|span| position(span.start)),
        "end": span.and_then(|span| position(span.end)),
    })
}

fn compile_project(
    entry: &str,
    files: &str,
    optimize: Option<bool>,
) -> Result<crate::ContractJson, String> {
    let files = serde_json::from_str(files).map_err(|e| format!("Invalid source files: {e}"))?;
    let options = crate::CompileOptions {
        optimize: optimize.unwrap_or(true),
    };
    crate::imports::compile_sources(entry, &files, options)
}

/// Completion symbols for `entry` in a virtual project. `files` is a JSON object
/// mapping relative .ark paths to source text.
#[wasm_bindgen]
pub fn symbols(entry: &str, files: &str) -> Result<String, String> {
    let files = serde_json::from_str(files).map_err(|e| format!("Invalid source files: {e}"))?;
    Ok(crate::imports::source_symbols(entry, &files)?.to_string())
}
