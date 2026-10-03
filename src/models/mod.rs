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

/// Native struct fields in source order; producing opcodes push the first field deepest.
pub fn builtin_struct_fields(
    declared_type: &str,
) -> Option<&'static [(&'static str, &'static str)]> {
    match declared_type {
        "AssetId" => Some(&[("txid", "bytes32"), ("gidx", "int")]),
        "Outpoint" => Some(&[("txid", "bytes32"), ("vout", "int")]),
        "ECPoint" => Some(&[("x", "int"), ("y", "int")]),
        // alt_bn128 G2 point; each coordinate is an Fp2 element `c1 * i + c0`.
        "G2Point" => Some(&[
            ("xC1", "int"),
            ("xC0", "int"),
            ("yC1", "int"),
            ("yC0", "int"),
        ]),
        _ => None,
    }
}

pub fn is_builtin_struct(declared_type: &str) -> bool {
    builtin_struct_fields(declared_type).is_some()
}

// JSON output structures.
// These represent the compiled contract in a serializable format.
pub const ARTIFACT_FORMAT_VERSION: u32 = 1;

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
    /// Artifact and placeholder name, such as `policy.owner.key`.
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
        for index in 0..length {
            flatten_type(
                &format!("{access_name}[{index}]"),
                &format!("{emitted_name}.{index}"),
                element_type,
                structs,
                stack,
                leaves,
            )?;
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
    if let Some(fields) = builtin_struct_fields(declared_type) {
        for (field_name, field_type) in fields {
            flatten_type(
                &format!("{access_name}.{field_name}"),
                &format!("{emitted_name}.{field_name}"),
                field_type,
                structs,
                stack,
                leaves,
            )?;
        }
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
            &format!("{emitted_name}.{}", field.name),
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
    #[serde(rename = "formatVersion", skip_serializing_if = "Option::is_none")]
    pub format_version: Option<u32>,
    #[serde(rename = "contractName")]
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub structs: Vec<StructDefinition>,
    #[serde(rename = "constructorInputs")]
    pub parameters: Vec<Parameter>,
    pub functions: Vec<AbiFunctionGroup>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceBundle>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiler: Option<CompilerInfo>,
    #[serde(rename = "updatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing, default)]
    pub warnings: Vec<String>,
}

/// Original files needed to reproduce a compilation without filesystem access.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SourceBundle {
    pub entry: String,
    pub files: std::collections::BTreeMap<String, String>,
}

/// Compiler information
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CompilerInfo {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<crate::CompileOptions>,
}

// AST structures.
// These represent the parsed abstract syntax tree of an Arkade Script contract.

/// Contract AST
#[derive(Debug, Clone)]
pub struct Contract {
    /// Contract or library name; empty for a source file containing only structs.
    pub name: String,
    /// Whether this declaration is a library rather than an instantiable contract.
    pub is_library: bool,
    /// Struct types available to this contract.
    pub structs: Vec<StructDefinition>,
    /// Contract parameters
    pub parameters: Vec<Parameter>,
    /// Contract functions
    pub functions: Vec<Function>,
    /// Tapscript (L1 leaf) declarations, parsed from `function … tapscript { }`.
    pub tapscripts: Vec<NamedTapscript>,
    /// Imported source file paths (declared via `import "path.ark";`)
    pub imports: Vec<String>,
    /// Compile-time constants declared in the contract body.
    pub constants: Vec<Constant>,
}

/// A compile-time constant, folded into every use site before validation.
#[derive(Debug, Clone)]
pub struct Constant {
    pub name: String,
    pub const_type: String,
    pub value: Expression,
}

/// Function AST
#[derive(Debug, Clone)]
pub struct Function {
    /// Function name
    pub name: String,
    /// Function arguments
    pub parameters: Vec<Parameter>,
    /// Byte range of the function name.
    pub span: crate::diagnostics::Span,
    /// Function body statements.
    pub statements: Vec<LocatedStatement>,
    /// Whether this is a callable helper rather than a transaction entrypoint.
    pub is_private: bool,
    /// Whether this helper cannot see constructor state.
    pub is_static: bool,
    /// Whether this helper can be called from a directly importing file.
    pub is_exported: bool,
    /// Explicit result type; None means the function returns no value.
    pub return_type: Option<String>,
}

impl Function {
    // Qualified helpers have already been checked in their defining file's scope.
    pub(crate) fn is_imported(&self) -> bool {
        self.name.contains('.')
    }
}

/// A statement with the byte range of its source text.
#[derive(Debug, Clone)]
pub struct LocatedStatement {
    pub span: crate::diagnostics::Span,
    pub statement: Statement,
}

/// Statement AST - represents any executable statement in a function body
#[derive(Debug, Clone)]
pub enum Statement {
    /// A void private function call.
    Call(Expression),
    /// Return from a private function.
    Return(Option<Expression>),
    /// require(expr, "message");
    Require(Requirement),
    /// let name = expr; or type name = expr;
    LetBinding {
        name: String,
        declared_type: Option<String>,
        value: Expression,
    },
    /// name = expr; or name[index] = expr; (variable reassignment)
    VarAssign {
        target: AssignmentTarget,
        value: Expression,
    },
    /// if (condition) { then_body } else { else_body }
    IfElse {
        condition: Expression,
        then_body: Vec<LocatedStatement>,
        else_body: Option<Vec<LocatedStatement>>,
    },
    /// for (index_var, value_var) in iterable { body }
    ForIn {
        index_var: String,
        value_var: String,
        iterable: Expression,
        body: Vec<LocatedStatement>,
    },
    /// for (count) { body }
    ForCount {
        count: Expression,
        body: Vec<LocatedStatement>,
    },
}

/// A binding or array element on the left-hand side of an assignment.
#[derive(Debug, Clone)]
pub enum AssignmentTarget {
    Access(Box<Expression>),
    Binding(String),
    ArrayIndex {
        array: String,
        index: Box<Expression>,
    },
}

/// Requirement AST
#[derive(Debug, Clone)]
pub enum Requirement {
    /// Expression that must evaluate to true
    Expression(Expression),
    /// Check signature requirement
    CheckSig {
        signature: Expression,
        pubkey: Expression,
    },
    /// Check signature from stack requirement (signature verified against a message)
    CheckSigFromStack {
        signature: Expression,
        pubkey: Expression,
        message: Expression,
    },
    /// Check multisig requirement
    CheckMultisig {
        pubkeys: Vec<Expression>,
        signatures: Vec<Expression>,
        threshold: u16,
    },
    /// Hash equal requirement
    HashEqual {
        hash_fn: HashFn,
        preimage: Expression,
        hash: Expression,
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

    /// Source name of the hash function, e.g. `hash160`.
    pub fn name(&self) -> &'static str {
        match self {
            HashFn::Sha256 => "sha256",
            HashFn::Hash160 => "hash160",
            HashFn::Hash256 => "hash256",
            HashFn::Ripemd160 => "ripemd160",
        }
    }

    /// Type name of the digest this hash function produces.
    pub fn digest_type(&self) -> &'static str {
        match self {
            HashFn::Sha256 | HashFn::Hash256 => "bytes32",
            HashFn::Hash160 | HashFn::Ripemd160 => "bytes20",
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
    /// `tweak(base, func)`: `base` tweaked by `func`'s covenant hash.
    /// `base` is `emulator` or a constructor pubkey (a second enclave).
    Tweak { base: String, func: String },
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
    /// `tweak` of a constructor pubkey is that key's own signature.
    pub fn is_cosigner(&self) -> bool {
        self.is_server()
            || self.is_emulator()
            || matches!(self, KeyExpr::Tweak { base, .. } if base == "emulator")
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
    /// `after(n)` → CLTV (absolute timelock, forfeit class).
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
    /// A private function call; the declared result type is resolved before validation.
    Call {
        name: String,
        args: Vec<Expression>,
        return_type: Option<String>,
    },
    /// Variable reference
    Variable(String),
    /// Decimal integer, boolean, or 0x-prefixed byte data (including empty 0x).
    Literal(String),
    /// Property access (e.g., tx.time)
    Property(String),
    /// Whether the emulator's clock has reached a Unix timestamp.
    CheckTime { timestamp: Box<Expression> },
    /// Query a hex-encoded UTF-8 intent path; presence-only queries return bool.
    IntentInspect { path: String, presence_only: bool },
    /// Continue the current input at an output; policy order is script, value, assets.
    Tunnel {
        output_index: Box<Expression>,
        policy: Box<[Expression; 3]>,
        exceptions: Vec<Expression>,
    },
    /// Array literal; only valid as the initializer of an array declaration.
    ArrayLiteral(Vec<Expression>),
    /// Named struct literal; only valid as the initializer of a typed declaration.
    StructLiteral(Vec<(String, Expression)>),
    /// A field of a statically laid-out value.
    FieldAccess {
        value: Box<Expression>,
        field: String,
    },
    /// An array nested inside an indexed value.
    IndexAccess {
        value: Box<Expression>,
        index: Box<Expression>,
    },
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
        property: Option<String>, // "amount" or "type"; None returns the raw type/data/amount tuple
    },
    /// CheckSig expression result (for use in if conditions)
    CheckSigExpr {
        signature: Box<Expression>,
        pubkey: Box<Expression>,
    },
    /// CheckSigFromStack expression result
    CheckSigFromStackExpr {
        signature: Box<Expression>,
        pubkey: Box<Expression>,
        message: Box<Expression>,
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
    /// Arithmetic negation: -value
    Negate { value: Box<Expression> },
    /// Boolean negation: !value
    Not { value: Box<Expression> },
    /// Modular exponentiation: modExp(base, exponent, modulus)
    ModExp {
        base: Box<Expression>,
        exponent: Box<Expression>,
        modulus: Box<Expression>,
    },
    // ─── Crypto Opcodes ────────────────────────────────────────────────
    /// EC point addition: ecAdd(P, Q, curveId). Produces an `ECPoint`.
    EcAdd {
        point_p: Box<Expression>,
        point_q: Box<Expression>,
        curve_id: Box<Expression>,
    },
    /// EC scalar multiplication: ecMul(P, scalar, curveId). Produces an `ECPoint`.
    EcMul {
        point: Box<Expression>,
        scalar: Box<Expression>,
        curve_id: Box<Expression>,
    },
    /// Pairing-product check over aligned `ECPoint[n]` and `G2Point[n]` arrays.
    EcPairing {
        g1: Box<Expression>,
        g2: Box<Expression>,
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
        signature: Box<Expression>,
        pubkey: Box<Expression>,
        message: Box<Expression>,
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
    /// Narrowing cast from bytes: pubkey(x), signature(x), bytes20(x), bytes32(x)
    Cast {
        target: String,
        data: Box<Expression>,
    },
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

/// Native struct returned by a fixed-width multi-item expression.
pub fn expression_result_struct(expression: &Expression) -> Option<&'static str> {
    match expression {
        Expression::EcAdd { .. } | Expression::EcMul { .. } => Some("ECPoint"),
        Expression::AssetAt { property, .. } if property == "assetId" => Some("AssetId"),
        Expression::GroupProperty { property, .. }
            if matches!(property.as_str(), "assetId" | "controlAssetId") =>
        {
            Some("AssetId")
        }
        Expression::CurrentInput(Some(property))
        | Expression::InputIntrospection { property, .. }
            if property == "outpoint" =>
        {
            Some("Outpoint")
        }
        _ => None,
    }
}

pub(crate) fn child_exprs_mut(expr: &mut Expression) -> Vec<&mut Expression> {
    match expr {
        // Leaf nodes: no nested expressions.
        Expression::Variable(_)
        | Expression::Literal(_)
        | Expression::Property(_)
        | Expression::CurrentInput(_)
        | Expression::TxIntrospection { .. }
        | Expression::IntentInspect { .. }
        | Expression::GroupProperty { .. }
        | Expression::AssetGroupsLength => vec![],

        Expression::CheckSigExpr { signature, pubkey } => vec![signature, pubkey],
        Expression::CheckSigFromStackExpr {
            signature,
            pubkey,
            message,
        }
        | Expression::CheckSigFromStackVerify {
            signature,
            pubkey,
            message,
        } => vec![signature, pubkey, message],

        Expression::FieldAccess { value, .. } => vec![value],
        Expression::IndexAccess { value, index } => vec![value, index],
        Expression::ArrayIndex { index, .. } => vec![index],

        Expression::ArrayLiteral(elements) | Expression::Call { args: elements, .. } => {
            elements.iter_mut().collect()
        }
        Expression::StructLiteral(fields) => fields.iter_mut().map(|(_, value)| value).collect(),

        Expression::AssetLookup {
            index,
            asset_txid,
            asset_gidx,
            ..
        }
        | Expression::AssetHas {
            index,
            asset_txid,
            asset_gidx,
            ..
        } => vec![index, asset_txid, asset_gidx],
        Expression::AssetCount { index, .. }
        | Expression::InputIntrospection { index, .. }
        | Expression::OutputIntrospection { index, .. }
        | Expression::GroupSum { index, .. }
        | Expression::GroupNumIO { index, .. } => vec![index],
        Expression::AssetAt {
            io_index,
            asset_index,
            ..
        } => vec![io_index, asset_index],
        Expression::BinaryOp { left, right, .. } | Expression::Concat { left, right, .. } => {
            vec![left, right]
        }
        Expression::GroupFind {
            asset_txid,
            asset_gidx,
        }
        | Expression::GroupHas {
            asset_txid,
            asset_gidx,
        } => vec![asset_txid, asset_gidx],
        Expression::GroupControlIs {
            asset_txid,
            asset_gidx,
            ..
        } => vec![asset_txid, asset_gidx],
        Expression::GroupIOAccess {
            group_index,
            io_index,
            ..
        } => vec![group_index, io_index],
        Expression::Sha256 { data } | Expression::Sha256Initialize { data } => vec![data],
        Expression::Sha256Update { context, chunk } => vec![context, chunk],
        Expression::Sha256Finalize {
            context,
            last_chunk,
        } => vec![context, last_chunk],
        Expression::Sighash { hash_type } => vec![hash_type],
        Expression::Digest { data, hash_type } => vec![data, hash_type],
        Expression::Negate { value } | Expression::Not { value } => vec![value],
        Expression::CheckTime { timestamp } => vec![timestamp],
        Expression::Tunnel {
            output_index,
            policy,
            exceptions,
        } => std::iter::once(output_index.as_mut())
            .chain(policy.iter_mut())
            .chain(exceptions.iter_mut())
            .collect(),
        Expression::ModExp {
            base,
            exponent,
            modulus,
        } => vec![base, exponent, modulus],
        Expression::EcAdd {
            point_p,
            point_q,
            curve_id,
        } => vec![point_p, point_q, curve_id],
        Expression::EcMul {
            point,
            scalar,
            curve_id,
        } => vec![point, scalar, curve_id],
        Expression::EcPairing { g1, g2, curve_id } => vec![g1, g2, curve_id],
        Expression::EcMulScalarVerify {
            scalar,
            point_p,
            point_q,
        } => vec![scalar, point_p, point_q],
        Expression::TweakVerify {
            point_p,
            tweak,
            point_q,
        } => vec![point_p, tweak, point_q],
        Expression::ContractInstance { args, .. } => args.iter_mut().collect(),
        Expression::Substr { data, offset, size } => vec![data, offset, size],
        Expression::Cat { left, right } => vec![left, right],
        Expression::Bin2Num { data }
        | Expression::ReverseBytes { data }
        | Expression::SizeOf { data }
        | Expression::Cast { data, .. } => vec![data],
        Expression::Num2Bin { value, size } => vec![value, size],
        Expression::PacketInspect { packet_type } => vec![packet_type],
        Expression::InputPacketInspect { index, packet_type } => vec![index, packet_type],
    }
}

impl Expression {
    /// Resolve the layout path, using element zero for runtime indexes.
    pub(crate) fn binding_path(&self) -> Option<String> {
        self.access_path(&|index| match index {
            Self::Literal(index) if index.parse::<usize>().is_ok() => index.clone(),
            _ => "0".to_string(),
        })
    }

    /// Spell an operand as written, for diagnostics.
    pub(crate) fn source_text(&self) -> String {
        match self {
            Self::Literal(value) => value.clone(),
            Self::BinaryOp { left, op, right } => {
                format!("{} {op} {}", left.source_text(), right.source_text())
            }
            _ => self
                .access_path(&Self::source_text)
                .unwrap_or_else(|| "<expr>".to_string()),
        }
    }

    fn access_path(&self, index_text: &dyn Fn(&Self) -> String) -> Option<String> {
        match self {
            Self::Variable(name) | Self::Property(name) => Some(name.clone()),
            Self::ArrayIndex { array, index } => Some(format!("{array}[{}]", index_text(index))),
            Self::IndexAccess { value, index } => Some(format!(
                "{}[{}]",
                value.access_path(index_text)?,
                index_text(index)
            )),
            Self::FieldAccess { value, field } => {
                Some(format!("{}.{field}", value.access_path(index_text)?))
            }
            _ => None,
        }
    }
}
