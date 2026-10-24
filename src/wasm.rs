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
/// `{ artifact: string | null, debug: string | null, warnings: string[], diagnostics: Diagnostic[] }`,
/// where `debug` is the debug file JSON (`ContractJson::debug_info`) and each
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
    let analysis = crate::imports::analyze(entry, &files, false);
    let mut diagnostics = analysis.diagnostics();
    let mut artifact = None;
    let mut debug = None;
    let mut warnings = Vec::new();
    if analysis.contract().is_some() {
        match analysis.compile(options) {
            Ok(output) => {
                warnings = output.warnings.clone();
                artifact = Some(
                    serde_json::to_string_pretty(&output)
                        .map_err(|e| format!("Serialization error: {e}"))?,
                );
                debug = Some(output.debug_info().to_string());
            }
            Err(errors) => diagnostics.extend(errors),
        }
    }
    let diagnostics: Vec<_> = diagnostics
        .iter()
        .map(|d| crate::diagnostics::to_json(d, analysis.source(&d.file)))
        .collect();
    serde_json::to_string(&serde_json::json!({
        "artifact": artifact,
        "debug": debug,
        "warnings": warnings,
        "diagnostics": diagnostics,
    }))
    .map_err(|e| format!("Serialization error: {e}"))
}

/// The diagnostics of a virtual project, in the form `compile_sources_with_diagnostics` gives
/// them, without an artifact; a library entry gets its own diagnostics, not the error compiling
/// it as an entry would give. For diagnosing sources while they are edited.
#[wasm_bindgen]
pub fn check_sources(entry: &str, files: &str, optimize: Option<bool>) -> Result<String, String> {
    let files: std::collections::BTreeMap<String, String> =
        serde_json::from_str(files).map_err(|e| format!("Invalid source files: {e}"))?;
    let options = crate::CompileOptions {
        optimize: optimize.unwrap_or(true),
    };
    let analysis = crate::imports::analyze(entry, &files, false);
    let diagnostics: Vec<_> = analysis
        .check(options)
        .iter()
        .map(|d| crate::diagnostics::to_json(d, analysis.source(&d.file)))
        .collect();
    serde_json::to_string(&diagnostics).map_err(|e| format!("Serialization error: {e}"))
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

/// The analysis of `entry`, made relative, in the `files` JSON, kept while both stay the same.
fn analyzed(entry: &str, files: &str) -> Result<(String, std::rc::Rc<crate::Analysis>), String> {
    thread_local! {
        /// The entry and files JSON last analyzed, and their analysis.
        // ponytail: one project, the open one every lookup asks about, analyzed again apart from the
        // lint; returning the symbol table from `check_sources` would share the lint's analysis.
        static ANALYZED: std::cell::RefCell<Option<(String, String, std::rc::Rc<crate::Analysis>)>> =
            Default::default();
    }
    let entry = crate::imports::relative_path(entry)?;
    let analysis = ANALYZED.with_borrow_mut(|analyzed| match analyzed {
        Some((e, f, analysis)) if *e == entry && f == files => Ok(analysis.clone()),
        _ => {
            let parsed =
                serde_json::from_str(files).map_err(|e| format!("Invalid source files: {e}"))?;
            let analysis = std::rc::Rc::new(crate::analyze(&entry, &parsed));
            *analyzed = Some((entry.clone(), files.to_string(), analysis.clone()));
            Ok::<_, String>(analysis)
        }
    })?;
    Ok((entry, analysis))
}

/// The symbol at 1-based `line` and UTF-16 `column` of `entry`, for hover, go to definition
/// and highlighting: `{ name, kind, type, at, definition, references }`, each location
/// `{ file, start, end }`, or `null` when no name is there.
#[wasm_bindgen]
pub fn symbol_at(entry: &str, files: &str, line: usize, column: usize) -> Result<String, String> {
    let (entry, analysis) = analyzed(entry, files)?;
    let symbols = analysis.symbols();
    let offset = analysis
        .source(&entry)
        .and_then(|source| crate::diagnostics::offset(source, line, column));
    let Some(definition) = offset.and_then(|offset| symbols.definition_at(&entry, offset)) else {
        return Ok("null".to_string());
    };
    let location = |file: &str, span: crate::diagnostics::Span| {
        let position = |offset| {
            let (line, column) = crate::diagnostics::position(analysis.source(file)?, offset)?;
            Some(serde_json::json!({ "line": line, "column": column }))
        };
        serde_json::json!({ "file": file, "start": position(span.start), "end": position(span.end) })
    };
    let index = symbols
        .definitions()
        .iter()
        .position(|candidate| std::ptr::eq(candidate, definition));
    let references: Vec<_> = symbols
        .references()
        .iter()
        .filter(|reference| Some(reference.definition) == index)
        .collect();
    let offset = offset.expect("a definition was found at it");
    let at = references
        .iter()
        .find(|r| r.file == entry && r.span.start <= offset && offset <= r.span.end)
        .map_or(definition.span, |reference| reference.span);
    Ok(serde_json::json!({
        "name": definition.name,
        "kind": format!("{:?}", definition.kind).to_lowercase(),
        "type": definition.ty.as_ref().map(ToString::to_string),
        "at": location(&entry, at),
        "definition": location(&definition.file, definition.span),
        "references": references
            .iter()
            .map(|reference| location(&reference.file, reference.span))
            .collect::<Vec<_>>(),
    })
    .to_string())
}

/// The names usable at 1-based `line` and UTF-16 `column` of `entry`, for completion:
/// `{ symbols, structs, members }`, where `members` lists a library's or contract's names
/// under its own, and `structs` gives the fields of every struct analyzed, since a field's type
/// can name a struct the entry does not see.
#[wasm_bindgen]
pub fn completions_at(
    entry: &str,
    files: &str,
    line: usize,
    column: usize,
) -> Result<String, String> {
    use crate::symbols::SymbolKind;
    let (entry, analysis) = analyzed(entry, files)?;
    let symbols = analysis.symbols();
    let offset = analysis
        .source(&entry)
        .and_then(|source| crate::diagnostics::offset(source, line, column))
        .unwrap_or_default();
    let mut names = Vec::new();
    let mut members: std::collections::BTreeMap<&str, Vec<serde_json::Value>> = Default::default();
    for (name, definition) in symbols.visible_at(&entry, offset) {
        if definition.kind == SymbolKind::Tapscript {
            continue;
        }
        let item = serde_json::json!({
            "name": definition.name,
            "kind": format!("{:?}", definition.kind).to_lowercase(),
            "type": definition.ty.as_ref().map(ToString::to_string),
        });
        match name.split_once('.') {
            Some((owner, _)) => members.entry(owner).or_default().push(item),
            None => names.push(item),
        }
    }
    let definitions = symbols.definitions();
    let structs: Vec<_> = definitions
        .iter()
        .filter(|definition| definition.kind == SymbolKind::Struct)
        .map(|definition| {
            let fields: Vec<_> = definitions
                .iter()
                .filter(|field| {
                    field.owner.as_deref() == Some(definition.name.as_str())
                        && field.file == definition.file
                })
                .map(|field| {
                    let ty = field.ty.as_ref().map(ToString::to_string);
                    serde_json::json!({ "name": field.name, "type": ty })
                })
                .collect();
            serde_json::json!({ "name": definition.name, "fields": fields })
        })
        .collect();
    Ok(serde_json::json!({ "symbols": names, "structs": structs, "members": members }).to_string())
}
