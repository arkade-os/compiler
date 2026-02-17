pub mod compiler;
pub mod models;
pub mod parser;

pub use models::{Contract, ContractJson, Expression, Function, Parameter, Requirement};

/// Compile Arkade Script source code to a JSON-serializable structure
///
/// This function takes Arkade Script source code as input, parses it into an AST,
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
/// * `source_code` - The Arkade Script source code as a string
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
