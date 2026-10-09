//! The abstract syntax tree of an Arkade Script contract.

use super::*;

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

impl Requirement {
    pub(crate) fn expressions_mut(&mut self) -> Vec<&mut Expression> {
        match self {
            Requirement::Expression(expression) => vec![expression],
            Requirement::Comparison { left, right, .. } => vec![left, right],
        }
    }
}

/// Requirement AST
#[derive(Debug, Clone)]
pub enum Requirement {
    /// Expression that must evaluate to true
    Expression(Expression),
    /// Comparison requirement
    Comparison {
        left: Expression,
        op: crate::operators::BinaryOperator,
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
    /// `older(n)` → CSV (relative timelock, exit class). `value` is a literal,
    /// constant, parameter, or `serverExitDelay`; without a unit it is the raw
    /// BIP68 sequence.
    Older {
        value: String,
        unit: Option<TimeUnit>,
    },
    /// `after(n)` → CLTV (absolute timelock, forfeit class). Without a unit
    /// `value` is the raw nLockTime.
    After {
        value: String,
        unit: Option<TimeUnit>,
    },
    /// `checkSig`/`checkMultisig` → multisig suffix. `threshold == None` means N-of-N.
    Sig {
        keys: Vec<KeyExpr>,
        sigs: Vec<String>,
        threshold: Option<u16>,
    },
}

/// The unit of a `blocks(n)` or `seconds(n)` timelock operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeUnit {
    Blocks,
    Seconds,
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

/// Source for per-group input/output access
#[derive(Debug, Clone, PartialEq)]
pub enum GroupIOSource {
    /// inputs (source=0)
    Inputs,
    /// outputs (source=1)
    Outputs,
}

/// An expression with the byte range of the source text it came from.
/// Nodes the compiler builds in place of another keep that node's span.
#[derive(Debug, Clone)]
pub struct Expression {
    pub kind: ExprKind,
    pub span: crate::diagnostics::Span,
    /// Set by `types::annotate`; `Unknown` until then.
    pub(crate) ty: crate::types::ArkType,
}

impl Expression {
    pub fn new(kind: ExprKind, span: crate::diagnostics::Span) -> Self {
        Self {
            kind,
            span,
            ty: crate::types::ArkType::Unknown,
        }
    }

    /// A node replacing this one, at the same source position.
    pub(crate) fn with_kind(&self, kind: ExprKind) -> Self {
        Self::new(kind, self.span)
    }
}

#[cfg(test)]
impl From<ExprKind> for Expression {
    fn from(kind: ExprKind) -> Self {
        Self::new(kind, crate::diagnostics::Span { start: 0, end: 0 })
    }
}

/// Expression AST
#[derive(Debug, Clone)]
pub enum ExprKind {
    /// A private function call; the declared result type is resolved before validation.
    Call {
        name: String,
        args: Vec<Expression>,
        return_type: Option<String>,
    },
    /// A builtin function call; its arguments are in parameter order.
    Builtin {
        builtin: &'static crate::builtins::Builtin,
        args: Vec<Expression>,
    },
    /// Variable reference
    Variable(String),
    /// Decimal integer, boolean, or 0x-prefixed byte data (including empty 0x).
    Literal(String),
    /// Property access
    Property(String),
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
    /// `this.activeInputIndex`, `this.expiry`
    This(crate::properties::ThisProperty),
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
        property: crate::properties::AssetProperty,
    },
    /// Transaction introspection: tx.version, tx.locktime, tx.numInputs, tx.numOutputs, tx.weight
    TxIntrospection {
        property: crate::properties::TxProperty,
    },
    /// Input introspection: tx.inputs[i].value, scriptPubKey, sequence, outpoint;
    /// tx.input.current.* indexes it with this.activeInputIndex
    InputIntrospection {
        index: Box<Expression>,
        property: crate::properties::InputProperty,
    },
    /// Output introspection: tx.outputs[o].value, scriptPubKey
    OutputIntrospection {
        index: Box<Expression>,
        property: crate::properties::OutputProperty,
    },
    /// Binary operation (e.g., a + b, x >= y)
    BinaryOp {
        left: Box<Expression>,
        op: crate::operators::BinaryOperator,
        right: Box<Expression>,
    },
    /// Asset group find: tx.assetGroups.find(txid, gidx) → the `AssetGroup` with
    /// that Asset ID. Asserts existence (consumes the success flag with OP_VERIFY).
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
    /// The `AssetGroup` at packet position k: tx.assetGroups[k].
    AssetGroupAt { index: Box<Expression> },
    /// Asset group property: group.sumInputs, group.delta, etc.
    GroupProperty {
        group: Box<Expression>,
        property: crate::properties::GroupProperty,
    },
    /// Boolean equality over the complete canonical control Asset ID:
    /// group.controlIs(txid, gidx). False when control is absent or either
    /// component differs. `group.hasControl` (presence only) is modeled as a
    /// plain `GroupProperty { property: "hasControl" }`.
    GroupControlIs {
        group: Box<Expression>,
        asset_txid: Box<Expression>,
        asset_gidx: Box<Expression>,
    },
    /// Asset groups length: tx.assetGroups.length → csn
    AssetGroupsLength,
    /// Per-group input/output access: group.inputs[j] or group.outputs[j]
    /// Returns: type_u8, data..., amount_u64 based on input/output type
    GroupIOAccess {
        group: Box<Expression>,
        io_index: Box<Expression>,
        source: GroupIOSource,
        property: Option<crate::properties::GroupIoProperty>, // "amount" or "type"; None returns the raw type/data/amount tuple
    },
    // ─── Arithmetic ────────────────────────────────────────────────────
    /// Prefix operator: -value, !value or ~value
    Unary {
        op: crate::operators::UnaryOperator,
        value: Box<Expression>,
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
    /// Narrowing cast from bytes: pubkey(x), signature(x), bytes20(x), bytes32(x);
    /// or a scalar conversion: int(bool), bool(int)
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
    match &expression.kind {
        ExprKind::Builtin { builtin, .. } => builtin.result,
        ExprKind::AssetAt { property, .. } => Some(property.value_type()),
        ExprKind::GroupProperty { property, .. } => Some(property.value_type()),
        ExprKind::InputIntrospection { property, .. } => Some(property.value_type()),
        _ => None,
    }
    .filter(|result| builtin_struct_fields(result).is_some())
}

/// Generates the shared and mutable traversals from one list of each variant's
/// direct sub-expressions, so the two cannot drift apart. The match has no `_`
/// arm: a new variant does not compile until its children are declared here.
macro_rules! expression_children {
    ($name:ident, $expr:ty, ($($borrow:tt)*), $iter:ident, $as_box:ident) => {
        pub(crate) fn $name(expr: $expr) -> Vec<$expr> {
            match $($borrow)* expr.kind {
                // Leaf nodes: no nested expressions.
                ExprKind::Variable(_)
                | ExprKind::Literal(_)
                | ExprKind::Property(_)
                | ExprKind::This(_)
                | ExprKind::TxIntrospection { .. }
                | ExprKind::IntentInspect { .. }
                | ExprKind::AssetGroupsLength => vec![],

                ExprKind::FieldAccess { value, .. } => vec![value],
                ExprKind::IndexAccess { value, index } => vec![value, index],
                ExprKind::ArrayIndex { index, .. } => vec![index],

                ExprKind::ArrayLiteral(elements)
                | ExprKind::Call { args: elements, .. }
                | ExprKind::Builtin { args: elements, .. } => elements.$iter().collect(),
                ExprKind::StructLiteral(fields) => fields.$iter().map(|(_, value)| value).collect(),

                ExprKind::AssetLookup {
                    index,
                    asset_txid,
                    asset_gidx,
                    ..
                }
                | ExprKind::AssetHas {
                    index,
                    asset_txid,
                    asset_gidx,
                    ..
                } => vec![index, asset_txid, asset_gidx],
                ExprKind::AssetCount { index, .. }
                | ExprKind::InputIntrospection { index, .. }
                | ExprKind::OutputIntrospection { index, .. }
                | ExprKind::AssetGroupAt { index }
                | ExprKind::GroupProperty { group: index, .. } => vec![index],
                ExprKind::AssetAt {
                    io_index,
                    asset_index,
                    ..
                } => vec![io_index, asset_index],
                ExprKind::BinaryOp { left, right, .. } => {
                    vec![left, right]
                }
                ExprKind::GroupFind {
                    asset_txid,
                    asset_gidx,
                }
                | ExprKind::GroupHas {
                    asset_txid,
                    asset_gidx,
                } => vec![asset_txid, asset_gidx],
                ExprKind::GroupControlIs {
                    group,
                    asset_txid,
                    asset_gidx,
                } => vec![group, asset_txid, asset_gidx],
                ExprKind::GroupIOAccess {
                    group, io_index, ..
                } => vec![group, io_index],
                ExprKind::Unary { value, .. } => vec![value],
                ExprKind::Tunnel {
                    output_index,
                    policy,
                    exceptions,
                } => std::iter::once(output_index.$as_box())
                    .chain(policy.$iter())
                    .chain(exceptions.$iter())
                    .collect(),
                ExprKind::ContractInstance { args, .. } => args.$iter().collect(),
                ExprKind::Cast { data, .. } => vec![data],
                ExprKind::PacketInspect { packet_type } => vec![packet_type],
                ExprKind::InputPacketInspect { index, packet_type } => vec![index, packet_type],
            }
        }
    };
}

expression_children!(child_exprs, &Expression, (&), iter, as_ref);
expression_children!(child_exprs_mut, &mut Expression, (&mut), iter_mut, as_mut);

impl Expression {
    /// Resolve the layout path, using element zero for runtime indexes.
    pub(crate) fn binding_path(&self) -> Option<String> {
        self.access_path(&|index| match &index.kind {
            ExprKind::Literal(index) if index.parse::<usize>().is_ok() => index.clone(),
            _ => "0".to_string(),
        })
    }

    /// Spell an operand for diagnostics, using canonical names for aliases.
    pub(crate) fn source_text(&self) -> String {
        match &self.kind {
            ExprKind::Literal(value) => value.clone(),
            ExprKind::This(property) => format!("this.{}", property.name()),
            ExprKind::TxIntrospection { property } => format!("tx.{}", property.name()),
            ExprKind::InputIntrospection { index, property } => {
                format!("tx.inputs[{}].{}", index.source_text(), property.name())
            }
            ExprKind::BinaryOp { left, op, right } => {
                format!("{} {op} {}", left.source_text(), right.source_text())
            }
            _ => self
                .access_path(&Self::source_text)
                .unwrap_or_else(|| "<expr>".to_string()),
        }
    }

    fn access_path(&self, index_text: &dyn Fn(&Self) -> String) -> Option<String> {
        match &self.kind {
            ExprKind::Variable(name) | ExprKind::Property(name) => Some(name.clone()),
            ExprKind::ArrayIndex { array, index } => {
                Some(format!("{array}[{}]", index_text(index)))
            }
            ExprKind::IndexAccess { value, index } => Some(format!(
                "{}[{}]",
                value.access_path(index_text)?,
                index_text(index)
            )),
            ExprKind::FieldAccess { value, field } => {
                Some(format!("{}.{field}", value.access_path(index_text)?))
            }
            _ => None,
        }
    }
}
