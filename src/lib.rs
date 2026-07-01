pub mod compiler;
pub mod models;
pub mod opcodes;
pub mod parser;
pub mod typechecker;
pub mod validator;

#[cfg(feature = "wasm")]
pub mod wasm;

pub use models::{
    Contract, ContractJson, Expression, Function, Parameter, Requirement, WitnessElement,
    DEFAULT_ARRAY_LENGTH,
};
pub use typechecker::{ArkType, TypeError};

/// Compile Arkade Script source code to a JSON-serializable structure
///
/// This function takes Arkade Script source code as input, parses it into an AST,
/// and then compiles it into a ContractJson structure that can be serialized to JSON.
///
/// The output includes:
/// - Contract name
/// - Parameters
/// - Spend groups with optional arkade covenants and L1 tapleaves
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
pub fn compile(source_code: &str) -> Result<ContractJson, Box<dyn std::error::Error>> {
    match compiler::compile(source_code) {
        Ok(output) => Ok(output),
        Err(err) => Err(err.into()),
    }
}
