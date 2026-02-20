use serde::{Deserialize, Serialize};

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
    /// Whether this contract uses the Arkade operator key for the cooperative path.
    /// The operator key is always injected externally — it is never a constructor parameter.
    pub has_server_key: bool,
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
    /// Function body statements (replaces requirements for Commits 4-6)
    pub statements: Vec<Statement>,
    /// Whether this is an internal function
    pub is_internal: bool,
}

/// Statement AST - represents any executable statement in a function body
#[derive(Debug, Clone)]
pub enum Statement {
    /// require(expr, "message");
    Require(Requirement),
    /// let name = expr;
    LetBinding { name: String, value: Expression },
    /// name = expr; (variable reassignment)
    VarAssign { name: String, value: Expression },
    /// if (condition) { then_body } else { else_body }
    IfElse {
        condition: Expression,
        then_body: Vec<Statement>,
        else_body: Option<Vec<Statement>>,
    },
    /// for (index_var, value_var) in iterable { body }
    ForIn {
        index_var: String,
        value_var: String,
        iterable: Expression,
        body: Vec<Statement>,
    },
}

/// Requirement AST
#[derive(Debug, Clone)]
pub enum Requirement {
    /// Check signature requirement
    CheckSig { signature: String, pubkey: String },
    /// Check signature from stack requirement (signature verified against a message)
    CheckSigFromStack {
        signature: String,
        pubkey: String,
        message: String,
    },
    /// Check multisig requirement
    CheckMultisig {
        signatures: Vec<String>,
        pubkeys: Vec<String>,
        threshold: u16,
    },
    /// After requirement
    After {
        blocks: u64,
        timelock_var: Option<String>,
    },
    /// Hash equal requirement
    HashEqual { preimage: String, hash: String },
    /// Comparison requirement
    Comparison {
        left: Expression,
        op: String,
        right: Expression,
    },
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

/// Source for per-group input/output access
#[derive(Debug, Clone, PartialEq)]
pub enum GroupIOSource {
    /// inputs (source=0)
    Inputs,
    /// outputs (source=1)
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
    /// Asset count: tx.inputs[i].assets.length or tx.outputs[o].assets.length
    AssetCount {
        source: AssetLookupSource,
        index: Box<Expression>,
    },
    /// Indexed asset access: tx.inputs[i].assets[t].assetId or tx.outputs[o].assets[t].amount
    AssetAt {
        source: AssetLookupSource,
        io_index: Box<Expression>,
        asset_index: Box<Expression>,
        property: String, // "assetId" or "amount"
    },
    /// Transaction introspection: tx.version, tx.locktime, tx.numInputs, tx.numOutputs, tx.weight
    TxIntrospection { property: String },
    /// Input introspection: tx.inputs[i].value, scriptPubKey, sequence, outpoint, issuance
    InputIntrospection {
        index: Box<Expression>,
        property: String,
    },
    /// Output introspection: tx.outputs[o].value, scriptPubKey, nonce
    OutputIntrospection {
        index: Box<Expression>,
        property: String,
    },
    /// Binary operation (e.g., a + b, x >= y)
    BinaryOp {
        left: Box<Expression>,
        op: String,
        right: Box<Expression>,
    },
    /// Asset group find: tx.assetGroups.find(assetId) → csn index
    GroupFind { asset_id: String },
    /// Asset group property: group.sumInputs, group.delta, etc.
    GroupProperty { group: String, property: String },
    /// Asset groups length: tx.assetGroups.length → csn
    AssetGroupsLength,
    /// Asset group sum with explicit index: tx.assetGroups[k].sumInputs/sumOutputs
    GroupSum {
        index: Box<Expression>,
        source: GroupSumSource,
    },
    /// Asset group input/output count: tx.assetGroups[k].numInputs/numOutputs
    GroupNumIO {
        index: Box<Expression>,
        source: GroupIOSource,
    },
    /// Per-group input/output access: tx.assetGroups[k].inputs[j] or tx.assetGroups[k].outputs[j]
    /// Returns: type_u8, data..., amount_u64 based on input/output type
    GroupIOAccess {
        group_index: Box<Expression>,
        io_index: Box<Expression>,
        source: GroupIOSource,
        property: Option<String>, // Optional property like "amount", "type", "inputIndex", "outputIndex"
    },
    /// Array indexing (e.g., arr[i])
    ArrayIndex {
        array: Box<Expression>,
        index: Box<Expression>,
    },
    /// Array/collection length (e.g., arr.length)
    ArrayLength(String),
    /// CheckSig expression result (for use in if conditions)
    CheckSigExpr { signature: String, pubkey: String },
    /// CheckSigFromStack expression result
    CheckSigFromStackExpr {
        signature: String,
        pubkey: String,
        message: String,
    },
    // ─── Streaming SHA256 ──────────────────────────────────────────────
    /// Streaming SHA256 initialize: sha256Initialize(data)
    Sha256Initialize { data: Box<Expression> },
    /// Streaming SHA256 update: sha256Update(ctx, chunk)
    Sha256Update {
        context: Box<Expression>,
        chunk: Box<Expression>,
    },
    /// Streaming SHA256 finalize: sha256Finalize(ctx, lastChunk)
    Sha256Finalize {
        context: Box<Expression>,
        last_chunk: Box<Expression>,
    },
    // ─── Conversion & Arithmetic ───────────────────────────────────────
    /// Negate 64-bit value: neg64(value)
    Neg64 { value: Box<Expression> },
    /// Convert LE64 to script number: le64ToScriptNum(value)
    Le64ToScriptNum { value: Box<Expression> },
    /// Convert LE32 to LE64: le32ToLe64(value)
    Le32ToLe64 { value: Box<Expression> },
    // ─── Crypto Opcodes ────────────────────────────────────────────────
    /// EC scalar multiplication verify: ecMulScalarVerify(k, P, Q)
    EcMulScalarVerify {
        scalar: Box<Expression>,
        point_p: Box<Expression>,
        point_q: Box<Expression>,
    },
    /// Tweak verification: tweakVerify(P, k, Q)
    TweakVerify {
        point_p: Box<Expression>,
        tweak: Box<Expression>,
        point_q: Box<Expression>,
    },
    /// CheckSigFromStack with verify: checkSigFromStackVerify(sig, pubkey, msg)
    CheckSigFromStackVerify {
        signature: String,
        pubkey: String,
        message: String,
    },
}
