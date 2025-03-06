use serde::{Serialize, Deserialize};

// Export the opcodes module
pub mod opcodes;
pub use opcodes::Opcode;

/// JSON output structures
/// 
/// These structures are used to represent the compiled contract in a format
/// that can be serialized to JSON.

/// Parameter in a contract or function
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Parameter {
    /// Parameter name
    pub name: String,
    /// Parameter type (pubkey, signature, bytes32, int, bool, asset, value)
    #[serde(rename = "type")]
    pub param_type: String,
}

/// Function input parameter
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FunctionInput {
    /// Parameter name
    pub name: String,
    /// Parameter type
    #[serde(rename = "type")]
    pub param_type: String,
}

/// Requirement for a function
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RequireStatement {
    /// Requirement type
    #[serde(rename = "type")]
    pub req_type: String,
    /// Custom message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Function definition in the ABI
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AbiFunction {
    /// Function name
    pub name: String,
    /// Function inputs
    #[serde(rename = "functionInputs")]
    pub function_inputs: Vec<FunctionInput>,
    /// Whether this is a server variant
    #[serde(rename = "serverVariant")]
    pub server_variant: bool,
    /// Requirements
    pub require: Vec<RequireStatement>,
    /// Assembly instructions
    pub asm: Vec<String>,
}

/// Script path for a function
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Operation {
    pub op: String,
    pub data: Option<String>,
}

/// Script path for a function
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScriptPath {
    /// Function name
    pub function: String,
    /// Whether this is a server variant
    #[serde(rename = "serverVariant")]
    pub server_variant: bool,
    /// Bitcoin script operations
    pub operations: Vec<Operation>,
}

/// JSON output for a contract
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ContractJson {
    #[serde(rename = "contractName")]
    pub name: String,
    #[serde(rename = "constructorInputs")]
    pub parameters: Vec<Parameter>,
    pub functions: Vec<AbiFunction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiler: Option<CompilerInfo>,
    #[serde(rename = "updatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// Compiler information
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CompilerInfo {
    pub name: String,
    pub version: String,
}

/// AST structures
/// 
/// These structures represent the parsed abstract syntax tree (AST)
/// of a TapLang contract.

/// Contract AST
#[derive(Debug, Clone)]
pub struct Contract {
    /// Contract name
    pub name: String,
    /// Contract parameters
    pub parameters: Vec<Parameter>,
    /// Ark-specific renewal timelock (in blocks)
    pub renewal_timelock: Option<u64>,
    /// Ark-specific exit timelock (in blocks, typically 48 hours worth of blocks)
    pub exit_timelock: Option<u64>,
    /// Ark-specific server key parameter name
    pub server_key_param: Option<String>,
    /// Contract functions
    pub functions: Vec<Function>,
}

/// Function AST
#[derive(Debug, Clone)]
pub struct Function {
    /// Function name
    pub name: String,
    /// Function arguments
    pub parameters: Vec<Parameter>,
    /// Function requirements
    pub requirements: Vec<Requirement>,
    /// Whether this is an internal function
    pub is_internal: bool,
}

/// Requirement AST
#[derive(Debug, Clone)]
pub enum Requirement {
    /// Check signature requirement
    CheckSig { signature: String, pubkey: String },
    /// Check multisig requirement
    CheckMultisig { signatures: Vec<String>, pubkeys: Vec<String> },
    /// After requirement
    After { blocks: u64, timelock_var: Option<String> },
    /// Hash equal requirement
    HashEqual { preimage: String, hash: String },
    /// Comparison requirement
    Comparison { left: Expression, op: String, right: Expression },
}

/// Expression AST
#[derive(Debug, Clone)]
pub enum Expression {
    /// Variable reference
    Variable(String),
    /// Literal value
    Literal(String),
    /// Property access (e.g., tx.time)
    Property(String),
    /// SHA256 hash function
    Sha256(String),
    /// Current input access (tx.input.current)
    CurrentInput(Option<String>),
} 