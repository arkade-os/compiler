use serde::{Deserialize, Serialize};

/// The number of elements that array-typed parameters (e.g. `pubkey[]`) are
/// flattened into throughout the pipeline.
///
/// This single constant governs:
/// - Constructor / function input flattening in the compiler
/// - Witness schema generation (`pubkey_0 … pubkey_N`)
/// - Compile-time loop unrolling (`for (k, v) in arr`)
/// - Scope expansion in the type checker
///
/// Raising this value increases the size of every compiled tapscript that
/// uses array parameters; lower it to tighten script sizes when contracts
/// only need fewer elements.
pub const DEFAULT_ARRAY_LENGTH: usize = 3;

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

/// A single element in the tapscript witness stack.
///
/// `witnessSchema` lists every value the caller must supply at spend time,
/// in the order they appear as `<name>` placeholders in the `asm` array
/// (constructor parameters, which are baked into the script, are excluded).
///
/// The `encoding` field is a stable identifier that code generators
/// (TypeScript, Go, …) can switch on to pick the correct serializer:
///
/// | encoding        | description                                   |
/// |-----------------|-----------------------------------------------|
/// | `compressed-33` | 33-byte SEC-compressed secp256k1 public key  |
/// | `schnorr-64`    | 64-byte Schnorr signature (BIP-340)           |
/// | `raw`           | arbitrary byte array (caller decides length)  |
/// | `raw-20`        | 20-byte array (e.g., HASH160)                 |
/// | `raw-32`        | 32-byte array (e.g., SHA256, txid)            |
/// | `scriptnum`     | Bitcoin CScriptNum (variable-length LE)       |
/// | `le64`          | 8-byte unsigned little-endian int64           |
/// | `le32`          | 4-byte unsigned little-endian int32           |
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WitnessElement {
    /// Parameter name (matches an `<name>` placeholder in `asm`)
    pub name: String,
    /// Arkade Script type string (e.g., `"pubkey"`, `"signature"`, `"bytes32"`)
    #[serde(rename = "type")]
    pub elem_type: String,
    /// Wire-encoding descriptor for client stub generators
    pub encoding: String,
}

/// Function definition in the ABI
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AbiFunction {
    /// Function name
    pub name: String,
    /// Function inputs (parameter names + declared types)
    #[serde(rename = "functionInputs")]
    pub function_inputs: Vec<FunctionInput>,
    /// Ordered witness stack elements the caller must supply at spend time.
    ///
    /// Includes all function inputs plus any server/exit-path signatures.
    /// Constructor parameters are **not** listed here — they are baked into
    /// the tapscript leaf and not part of the witness.
    #[serde(rename = "witnessSchema")]
    pub witness_schema: Vec<WitnessElement>,
    /// Whether this is a server variant
    #[serde(rename = "serverVariant")]
    pub server_variant: bool,
    /// Requirements
    pub require: Vec<RequireStatement>,
    /// Assembly instructions
    pub asm: Vec<String>,
}

/// The emulator-run covenant for a function-backed spend group.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ArkadeCovenant {
    /// Covenant inputs (function parameters, array-expanded). No server/emulator sigs.
    pub inputs: Vec<FunctionInput>,
    /// Covenant assembly.
    pub asm: Vec<String>,
}

/// One L1 tapleaf within a spend group.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AbiLeaf {
    /// Leaf name (source tapscript name, or covenant name for a synthesized default).
    pub name: String,
    /// Ordered witness stack the caller supplies at spend time.
    pub witness: Vec<WitnessElement>,
    /// Tapleaf assembly (pubkeys + ops; signatures live in `witness`).
    pub asm: Vec<String>,
}

/// A spend group: an optional covenant plus its L1 leaves.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AbiFunctionGroup {
    /// Group name (covenant function name, or a standalone leaf's own name).
    pub name: String,
    /// Emulator covenant; absent for groups containing only standalone leaves.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arkade: Option<ArkadeCovenant>,
    /// L1 tapleaves grouped under this entry.
    pub leaves: Vec<AbiLeaf>,
}

/// JSON output for a contract
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ContractJson {
    #[serde(rename = "contractName")]
    pub name: String,
    #[serde(rename = "constructorInputs")]
    pub parameters: Vec<Parameter>,
    pub functions: Vec<AbiFunctionGroup>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiler: Option<CompilerInfo>,
    #[serde(rename = "updatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub warnings: Vec<String>,
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
    /// Contract functions
    pub functions: Vec<Function>,
    /// Tapscript (L1 leaf) declarations, parsed from `function … tapscript { }`.
    pub tapscripts: Vec<NamedTapscript>,
    /// Imported contract file paths (declared via `import "path.ark";`)
    pub imports: Vec<String>,
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

/// Hash function used in a tapscript condition prefix (`hashFn(x) == h`).
#[derive(Debug, Clone, PartialEq)]
pub enum HashFn {
    Sha256,
    Hash160,
    Hash256,
    Ripemd160,
}

impl HashFn {
    /// The Bitcoin opcode string this hash function emits.
    pub fn opcode(&self) -> &'static str {
        match self {
            HashFn::Sha256 => "OP_SHA256",
            HashFn::Hash160 => "OP_HASH160",
            HashFn::Hash256 => "OP_HASH256",
            HashFn::Ripemd160 => "OP_RIPEMD160",
        }
    }

    /// Parse a hash function name; returns None for unknown names.
    pub fn parse(name: &str) -> Option<HashFn> {
        match name {
            "sha256" => Some(HashFn::Sha256),
            "hash160" => Some(HashFn::Hash160),
            "hash256" => Some(HashFn::Hash256),
            "ripemd160" => Some(HashFn::Ripemd160),
            _ => None,
        }
    }
}

/// A key operand in a tapscript `checkSig`/`checkMultisig`.
#[derive(Debug, Clone, PartialEq)]
pub enum KeyExpr {
    /// A bare pubkey identifier: a reserved role (`server`, `emulator`) or any
    /// pubkey in scope (constructor pubkey, etc.).
    Ident(String),
    /// `tweak(emulator, func)`: the emulator key tweaked by `func`'s covenant hash.
    Tweak { func: String },
}

/// One ordered component of a tapscript leaf body. Source order must follow the
/// closure template: condition? · timelock? · multisig (validated in Context::Tapscript).
#[derive(Debug, Clone)]
pub enum TapItem {
    /// `hashFn(preimage) == hash` → condition prefix.
    Hash {
        hash_fn: HashFn,
        preimage: String,
        hash: String,
    },
    /// `older(n)` → CSV (relative timelock, exit class). `value` is a literal or param name.
    Older { value: String },
    /// `after(n)` or `tx.time >= n` → CLTV (absolute timelock, forfeit class).
    After { value: String },
    /// `checkSig`/`checkMultisig` → multisig suffix. `threshold == None` means N-of-N.
    Sig {
        keys: Vec<KeyExpr>,
        sigs: Vec<String>,
        threshold: Option<u16>,
    },
}

/// A `tapscript`-modified function declaration: an L1 tapleaf source member.
#[derive(Debug, Clone)]
pub struct NamedTapscript {
    /// Declared name (decides function-binding by exact match).
    pub name: String,
    /// Declared witness inputs (signatures, preimages, …), in source order.
    pub inputs: Vec<Parameter>,
    /// Ordered closure components.
    pub items: Vec<TapItem>,
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
    /// Asset lookup: tx.inputs[i].assets.lookup(txid, gidx) or
    /// tx.outputs[o].assets.lookup(txid, gidx). Asserts the asset is present
    /// (consumes the opcode success flag with OP_VERIFY) and leaves its amount.
    AssetLookup {
        source: AssetLookupSource,
        index: Box<Expression>,
        asset_txid: Box<Expression>, // bytes32 reference
        asset_gidx: Box<Expression>, // int reference or literal (0..65535)
    },
    /// Asset presence predicate: tx.inputs[i].assets.has(txid, gidx) or
    /// tx.outputs[o].assets.has(txid, gidx). Boolean — true when the asset is
    /// present, false when absent (keeps the opcode success flag, drops amount).
    AssetHas {
        source: AssetLookupSource,
        index: Box<Expression>,
        asset_txid: Box<Expression>,
        asset_gidx: Box<Expression>,
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
    /// Asset group find: tx.assetGroups.find(txid, gidx) → resolved packet
    /// position k. Asserts existence (consumes the success flag with OP_VERIFY).
    GroupFind {
        asset_txid: Box<Expression>,
        asset_gidx: Box<Expression>,
    },
    /// Asset group presence predicate: tx.assetGroups.has(txid, gidx). Boolean —
    /// true when a group with that Asset ID exists, false otherwise.
    GroupHas {
        asset_txid: Box<Expression>,
        asset_gidx: Box<Expression>,
    },
    /// Asset group property: group.sumInputs, group.delta, etc.
    GroupProperty { group: String, property: String },
    /// Boolean equality over the complete canonical control Asset ID:
    /// group.controlIs(txid, gidx). False when control is absent or either
    /// component differs. `group.hasControl` (presence only) is modeled as a
    /// plain `GroupProperty { property: "hasControl" }`.
    GroupControlIs {
        group: String,
        asset_txid: Box<Expression>,
        asset_gidx: Box<Expression>,
    },
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
    // ─── Byte-string operations ────────────────────────────────────────
    /// Byte-string concatenation: produced by the rewrite pass when `+`
    /// has at least one bytes-like operand. `coerce_left` / `coerce_right`
    /// tell the emitter to insert `OP_SCRIPTNUMTOLE64` on a side that is
    /// an integer (mixed `bytes + int` writes the int as fixed 8-byte LE
    /// before OP_CAT, so off-chain hashing matches deterministically).
    Concat {
        left: Box<Expression>,
        right: Box<Expression>,
        coerce_left: bool,
        coerce_right: bool,
    },
    /// One-shot SHA256: sha256(data) → 32-byte digest. Used for small
    /// fixed messages where streaming would be overkill.
    Sha256 { data: Box<Expression> },
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
    /// Contract instantiation: new ContractName(arg1, arg2, ...)
    ///
    /// Resolves to the Taproot scriptPubKey of the named contract instantiated
    /// with the given arguments. Options (server key, exit timelock) are
    /// inherited from the enclosing contract. Used for recursion enforcement
    /// via output introspection: `tx.outputs[0].scriptPubKey == new Foo(x)`
    ContractInstance {
        /// Name of the contract to instantiate
        contract_name: String,
        /// Constructor arguments (typically Variable or Literal)
        args: Vec<Expression>,
    },
}
