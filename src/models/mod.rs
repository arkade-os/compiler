use serde::{Serialize, Deserialize};

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
/// of an Arkade Script contract.

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

/// Source of an asset lookup (input or output)
#[derive(Debug, Clone, PartialEq)]
pub enum AssetLookupSource {
    /// tx.inputs[i]
    Input,
    /// tx.outputs[o]
    Output,
}

/// Source of an asset group sum (inputs or outputs)
#[derive(Debug, Clone, PartialEq)]
pub enum GroupSumSource {
    /// sumInputs (source=0)
    Inputs,
    /// sumOutputs (source=1)
    Outputs,
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
    /// Current input access (tx.input.current)
    CurrentInput(Option<String>),
    /// Asset lookup: tx.inputs[i].assets.lookup(assetId) or tx.outputs[o].assets.lookup(assetId)
    AssetLookup {
        source: AssetLookupSource,
        index: Box<Expression>,
        asset_id: String,
    },
    /// Binary arithmetic operation (a + b, a - b, a * b, a / b)
    BinaryOp {
        left: Box<Expression>,
        op: String,
        right: Box<Expression>,
    },
    /// Asset group find: tx.assetGroups.find(assetId) → csn index
    GroupFind {
        asset_id: String,
    },
    /// Asset group property: group.sumInputs, group.delta, etc.
    GroupProperty {
        group: String,
        property: String,
    },
    /// Asset groups length: tx.assetGroups.length → csn
    AssetGroupsLength,
    /// Asset group sum with explicit index: tx.assetGroups[k].sumInputs/sumOutputs
    GroupSum {
        index: Box<Expression>,
        source: GroupSumSource,
    },
} 