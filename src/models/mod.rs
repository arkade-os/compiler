use serde::{Deserialize, Serialize};

fn is_false(value: &bool) -> bool {
    !*value
}

/// Split a declared type string into element type and length when it is an
/// array type (`"pubkey[3]"` → `("pubkey", 3)`), otherwise `None`.
///
/// Array lengths are static and always present: the grammar has no unsized
/// array type.
pub fn array_type_parts(declared_type: &str) -> Option<(&str, usize)> {
    let (element, length) = declared_type.strip_suffix(']')?.split_once('[')?;
    Some((element, length.parse().ok()?))
}

pub fn is_builtin_type(declared_type: &str) -> bool {
    matches!(
        declared_type,
        "pubkey" | "signature" | "bytes" | "bytes20" | "bytes32" | "int" | "bool" | "asset"
    )
}

// JSON output structures.
// These represent the compiled contract in a serializable format.
/// Parameter in a contract or function
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Parameter {
    /// Parameter name
    pub name: String,
    /// Parameter type (pubkey, signature, bytes32, int, bool, asset, value)
    #[serde(rename = "type")]
    pub param_type: String,
}

/// A named, statically laid-out source type.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StructDefinition {
    pub name: String,
    pub fields: Vec<Parameter>,
}

/// One scalar leaf in a recursively flattened parameter layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeLeaf {
    /// Source path used by expressions, such as `policy.owner.key`.
    pub access_name: String,
    /// Artifact and placeholder name, such as `policy_owner_key`.
    pub emitted_name: String,
    pub leaf_type: String,
}

pub fn flatten_parameter(
    parameter: &Parameter,
    structs: &[StructDefinition],
) -> Result<Vec<TypeLeaf>, String> {
    let mut leaves = Vec::new();
    flatten_type(
        &parameter.name,
        &parameter.name,
        &parameter.param_type,
        structs,
        &mut Vec::new(),
        &mut leaves,
    )?;
    Ok(leaves)
}

fn flatten_type(
    access_name: &str,
    emitted_name: &str,
    declared_type: &str,
    structs: &[StructDefinition],
    stack: &mut Vec<String>,
    leaves: &mut Vec<TypeLeaf>,
) -> Result<(), String> {
    if let Some((element_type, length)) = array_type_parts(declared_type) {
        if !is_builtin_type(element_type) {
            return Err(format!(
                "arrays of structs are not supported: '{declared_type}'"
            ));
        }
        for index in 0..length {
            leaves.push(TypeLeaf {
                access_name: format!("{access_name}[{index}]"),
                emitted_name: format!("{emitted_name}_{index}"),
                leaf_type: element_type.to_string(),
            });
        }
        return Ok(());
    }
    if is_builtin_type(declared_type) {
        leaves.push(TypeLeaf {
            access_name: access_name.to_string(),
            emitted_name: emitted_name.to_string(),
            leaf_type: declared_type.to_string(),
        });
        return Ok(());
    }

    let definition = structs
        .iter()
        .find(|definition| definition.name == declared_type)
        .ok_or_else(|| format!("unknown type '{declared_type}'"))?;
    if stack.iter().any(|name| name == declared_type) {
        return Err(format!("recursive struct layout: {declared_type}"));
    }
    stack.push(declared_type.to_string());
    for field in &definition.fields {
        flatten_type(
            &format!("{access_name}.{}", field.name),
            &format!("{emitted_name}_{}", field.name),
            &field.param_type,
            structs,
            stack,
            leaves,
        )?;
    }
    stack.pop();
    Ok(())
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

/// A single element in a tapleaf's `witness` array.
///
/// Each leaf's `witness` lists every value the caller must supply at spend time,
/// in source-declared order (constructor parameters, which are baked into the
/// script, are excluded).
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
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WitnessElement {
    /// Parameter name (matches an `<name>` placeholder in `asm`)
    pub name: String,
    /// Arkade Script type string (e.g., `"pubkey"`, `"signature"`, `"bytes32"`)
    #[serde(rename = "type")]
    pub elem_type: String,
    /// Wire-encoding descriptor for client stub generators
    pub encoding: String,
    /// True when Arkade infrastructure supplies this witness field.
    #[serde(default, skip_serializing_if = "is_false")]
    pub injected: bool,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub structs: Vec<StructDefinition>,
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

// AST structures.
// These represent the parsed abstract syntax tree of an Arkade Script contract.

/// Contract AST
#[derive(Debug, Clone)]
pub struct Contract {
    /// Contract name
    pub name: String,
    /// Struct types declared before this contract.
    pub structs: Vec<StructDefinition>,
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
    /// Function body statements.
    pub statements: Vec<Statement>,
    /// Whether this is an internal function
    pub is_internal: bool,
}

/// Statement AST - represents any executable statement in a function body
#[derive(Debug, Clone)]
pub enum Statement {
    /// require(expr, "message");
    Require(Requirement),
    /// let name = expr; or type name = expr;
    LetBinding {
        name: String,
        declared_type: Option<String>,
        value: Expression,
    },
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
    /// Expression that must evaluate to true
    Expression(Expression),
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
        signatures: Vec<String>,
        threshold: u16,
    },
    /// After requirement
    After {
        blocks: u64,
        timelock_var: Option<String>,
    },
    /// Hash equal requirement
    HashEqual {
        hash_fn: HashFn,
        preimage: String,
        hash: String,
    },
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
        use crate::opcodes::{OP_HASH160, OP_HASH256, OP_RIPEMD160, OP_SHA256};
        match self {
            HashFn::Sha256 => OP_SHA256,
            HashFn::Hash160 => OP_HASH160,
            HashFn::Hash256 => OP_HASH256,
            HashFn::Ripemd160 => OP_RIPEMD160,
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

impl KeyExpr {
    /// The reserved arkd-operator role.
    pub fn is_server(&self) -> bool {
        matches!(self, KeyExpr::Ident(id) if id == "server")
    }

    /// A bare (implicitly-tweaked) emulator role.
    pub fn is_emulator(&self) -> bool {
        matches!(self, KeyExpr::Ident(id) if id == "emulator")
    }

    /// An infra-injected co-signer whose signature is generated, not user pubkey:
    /// `server`, bare `emulator`, or an explicit `tweak(emulator, …)`.
    pub fn is_cosigner(&self) -> bool {
        self.is_server() || self.is_emulator() || matches!(self, KeyExpr::Tweak { .. })
    }
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
    /// Array literal; only valid as the initializer of an array declaration.
    ArrayLiteral(Vec<Expression>),
    /// Array element selected by an integer expression.
    ArrayIndex {
        array: String,
        index: Box<Expression>,
    },
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
    /// Input introspection: tx.inputs[i].value, scriptPubKey, sequence, outpoint
    InputIntrospection {
        index: Box<Expression>,
        property: String,
    },
    /// Output introspection: tx.outputs[o].value, scriptPubKey
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
    /// CheckSig expression result (for use in if conditions)
    CheckSigExpr { signature: String, pubkey: String },
    /// CheckSigFromStack expression result
    CheckSigFromStackExpr {
        signature: String,
        pubkey: String,
        message: String,
    },
    // ─── Byte-string operations ────────────────────────────────────────
    /// Byte-string concatenation: produced by the rewrite pass when `+` has at
    /// least one bytes-like operand. Both operands must already be bytes; a
    /// numeric operand is a compile error telling the author to convert it with
    /// `num2bin(value, width)`. The compiler never picks a width on its own,
    /// because the width and byte order are consensus-visible: they decide what
    /// an off-chain signer must hash to match.
    Concat {
        left: Box<Expression>,
        right: Box<Expression>,
    },
    // ─── Streaming SHA256 ──────────────────────────────────────────────
    /// Plain SHA256: sha256(data) → emits `<data> OP_SHA256`.
    /// One-shot hashing of byte-string expressions like substr; used for
    /// small fixed messages where streaming would be overkill.
    Sha256 { data: Box<Expression> },
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
    /// Signature hash for the current input under the selected hash type.
    Sighash { hash_type: Box<Expression> },
    /// Digest selected at runtime. The result is 20 or 32 bytes depending on the hash type.
    Digest {
        data: Box<Expression>,
        hash_type: Box<Expression>,
    },
    // ─── Arithmetic ────────────────────────────────────────────────────
    /// Negate a BigNum value: negate(value)
    Negate { value: Box<Expression> },
    /// Modular exponentiation: modExp(base, exponent, modulus)
    ModExp {
        base: Box<Expression>,
        exponent: Box<Expression>,
        modulus: Box<Expression>,
    },
    // ─── Crypto Opcodes ────────────────────────────────────────────────
    /// EC point addition. Produces x and y as two stack items.
    ///
    /// TODO(asset-id-struct): like `group.assetId`, a two-item result has no
    /// representation — `let` binds one name and `==` would only see y. The
    /// result is unusable until the composite return type lands; the emission
    /// is correct and ready for it.
    EcAdd {
        x1: Box<Expression>,
        y1: Box<Expression>,
        x2: Box<Expression>,
        y2: Box<Expression>,
        curve_id: Box<Expression>,
    },
    /// EC scalar multiplication. Produces x and y as two stack items.
    ///
    /// TODO(asset-id-struct): same two-item limitation as `EcAdd`.
    EcMul {
        x: Box<Expression>,
        y: Box<Expression>,
        scalar: Box<Expression>,
        curve_id: Box<Expression>,
    },
    /// One-pair pairing check. Tuple support can generalize this to multiple pairs.
    EcPairing {
        g1_x: Box<Expression>,
        g1_y: Box<Expression>,
        g2_x_c1: Box<Expression>,
        g2_x_c0: Box<Expression>,
        g2_y_c1: Box<Expression>,
        g2_y_c0: Box<Expression>,
        curve_id: Box<Expression>,
    },
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
    // ─── Byte-string Manipulation (introspector extensions) ────────────
    /// Substring extraction: substr(data, offset, size) → OP_SUBSTR
    Substr {
        data: Box<Expression>,
        offset: Box<Expression>,
        size: Box<Expression>,
    },
    /// Byte concatenation: cat(a, b) → OP_CAT
    Cat {
        left: Box<Expression>,
        right: Box<Expression>,
    },
    /// Bytes-to-number (little-endian, leading-zero-stripped BigNum): bin2num(bytes) → OP_BIN2NUM
    Bin2Num { data: Box<Expression> },
    /// Number-to-bytes (little-endian, zero-padded): num2bin(num, size) → OP_NUM2BIN
    Num2Bin {
        value: Box<Expression>,
        size: Box<Expression>,
    },
    /// Reverse a byte string: reverseBytes(data) → OP_REVERSEBYTES
    ReverseBytes { data: Box<Expression> },
    /// Byte-string length: size(bytes) → OP_SIZE OP_NIP
    SizeOf { data: Box<Expression> },
    // ─── Packet Introspection ──────────────────────────────────────────
    /// Current-tx packet content: tx.packet(packetType)
    /// Emits the raw packet bytes and asserts presence via OP_INSPECTPACKET's
    /// bool flag. Compiles to `<packetType> OP_INSPECTPACKET OP_1 OP_EQUALVERIFY`.
    PacketInspect { packet_type: Box<Expression> },
    /// Previous Ark-tx packet via input i: tx.inputs[i].packet(packetType)
    /// Compiles to `<packetType> <i> OP_INSPECTINPUTPACKET OP_1 OP_EQUALVERIFY`.
    InputPacketInspect {
        index: Box<Expression>,
        packet_type: Box<Expression>,
    },
}
