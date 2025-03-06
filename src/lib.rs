pub mod models;
pub mod parser;
pub mod compiler;
pub mod interpreter;

pub use models::{Contract, Function, Parameter, Requirement, Expression, ContractJson};

/// Compile TapLang source code to a JSON-serializable structure
///
/// This function takes TapLang source code as input, parses it into an AST,
/// and then compiles it into a ContractJson structure that can be serialized to JSON.
///
/// The output includes:
/// - Contract name
/// - Parameters
/// - Functions with their inputs, requirements, and assembly code
///
/// Each function includes a serverVariant flag. When using the function:
/// - If serverVariant is true, the function requires a server signature
/// - If serverVariant is false, the function requires an exit timelock
///
/// # Arguments
///
/// * `source_code` - The TapLang source code as a string
///
/// # Returns
///
/// A Result containing either the ContractJson structure or an error
///
/// # Example
///
/// ```
/// use taplang::compile;
///
/// let source_code = r#"
/// // Contract configuration options
/// options {
///   // Server key parameter from contract parameters
///   server = server;
///   
///   // Exit timelock: 24 hours (144 blocks)
///   exit = 144;
/// }
/// 
/// contract Example(pubkey owner, pubkey server) {
///     function spend(signature ownerSig) {
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
pub fn compile(source_code: &str) -> Result<ContractJson, Box<dyn std::error::Error>> {
    match compiler::compile(source_code) {
        Ok(output) => Ok(output),
        Err(err) => Err(err.into()),
    }
}

use std::fs;
use std::path::Path;

pub fn compile_file(input_path: &str, output_path: &str) -> Result<(), String> {
    // Read the input file
    let source_code = fs::read_to_string(input_path)
        .map_err(|e| format!("Failed to read input file: {}", e))?;
    
    // Compile the source code
    let contract_json = compiler::compile(&source_code)?;
    
    // Serialize to JSON
    let json_string = serde_json::to_string_pretty(&contract_json)
        .map_err(|e| format!("Failed to serialize to JSON: {}", e))?;
    
    // Write to the output file
    fs::write(output_path, json_string)
        .map_err(|e| format!("Failed to write output file: {}", e))?;
    
    Ok(())
}

pub fn compile_to_json(source_code: &str) -> Result<String, String> {
    let contract_json = compiler::compile(source_code)?;
    
    serde_json::to_string_pretty(&contract_json)
        .map_err(|e| format!("Failed to serialize to JSON: {}", e))
} 