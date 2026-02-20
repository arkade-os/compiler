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
            .map_err(|e| format!("Serialization error: {}", e)),
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
