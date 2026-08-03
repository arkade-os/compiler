/// Type system for Arkade Script.
///
/// Provides:
/// - `ArkType`: the canonical type enum for all Arkade Script values,
///   including wire-encoding metadata used by client stub generators
/// - `infer_type`: expression-level type inference
/// - `check_contract` / `check_function`: requirement-level type checking
///   that returns a list of `TypeError`s (currently non-fatal — the caller
///   decides how to surface them)
use std::collections::HashMap;

use crate::models::{Contract, Expression, Function, Requirement, Statement, DEFAULT_ARRAY_LENGTH};

// ─── Type Enum ────────────────────────────────────────────────────────────────

/// All possible types in Arkade Script.
///
/// Declared types map directly to the grammar's `data_type` rule.
/// Internal types are produced by introspection expressions; they never appear
/// in user-written type annotations.
#[derive(Debug, Clone, PartialEq)]
pub enum ArkType {
    // ── Declared types (match grammar data_type rule) ──────────────────────
    /// 33-byte compressed secp256k1 public key
    Pubkey,
    /// 64-byte Schnorr signature
    Signature,
    /// Arbitrary-length byte array
    Bytes,
    /// 20-byte array (e.g., HASH160 output)
    Bytes20,
    /// 32-byte array (e.g., SHA256 output, txid)
    Bytes32,
    /// Standard Bitcoin script integer (CScriptNum, variable-length LE)
    Int,
    /// Boolean (0x00 = false, 0x01 = true as CScriptNum)
    Bool,
    /// Taproot Asset identifier
    Asset,

    // ── Internal / introspection types ─────────────────────────────────────

    // ── Composite ──────────────────────────────────────────────────────────
    /// Homogeneous array (e.g., `pubkey[]`)
    Array(Box<ArkType>),

    /// Type could not be resolved (variable not in scope, etc.)
    Unknown,
}

impl ArkType {
    /// Parse from a grammar `data_type` string (e.g., `"pubkey"`, `"bytes32[]"`).
    pub fn parse(s: &str) -> ArkType {
        if let Some(inner) = s.strip_suffix("[]") {
            return ArkType::Array(Box::new(ArkType::parse(inner)));
        }
        match s {
            "pubkey" => ArkType::Pubkey,
            "signature" => ArkType::Signature,
            "bytes" => ArkType::Bytes,
            "bytes20" => ArkType::Bytes20,
            "bytes32" => ArkType::Bytes32,
            "int" => ArkType::Int,
            "bool" => ArkType::Bool,
            "asset" => ArkType::Asset,
            _ => ArkType::Unknown,
        }
    }

    /// Wire-encoding descriptor used in leaf `witness` / client stub output.
    ///
    /// These strings are stable identifiers; downstream code generators
    /// (TypeScript, Go, etc.) can switch on them to pick the right serializer.
    pub fn encoding(&self) -> &'static str {
        match self {
            ArkType::Pubkey => "compressed-33",
            ArkType::Signature => "schnorr-64",
            ArkType::Bytes => "raw",
            ArkType::Bytes20 => "raw-20",
            ArkType::Bytes32 => "raw-32",
            ArkType::Int => "scriptnum",
            ArkType::Bool => "scriptnum",
            ArkType::Asset => "raw-32",
            ArkType::Array(_) => "array",
            ArkType::Unknown => "unknown",
        }
    }

    /// Canonical string form matching Arkade Script syntax.
    pub fn as_str(&self) -> String {
        match self {
            ArkType::Pubkey => "pubkey".to_string(),
            ArkType::Signature => "signature".to_string(),
            ArkType::Bytes => "bytes".to_string(),
            ArkType::Bytes20 => "bytes20".to_string(),
            ArkType::Bytes32 => "bytes32".to_string(),
            ArkType::Int => "int".to_string(),
            ArkType::Bool => "bool".to_string(),
            ArkType::Asset => "asset".to_string(),
            ArkType::Array(inner) => format!("{}[]", inner.as_str()),
            ArkType::Unknown => "unknown".to_string(),
        }
    }
}

// ─── Type Errors ──────────────────────────────────────────────────────────────

/// A type error emitted by the checker.
#[derive(Debug, Clone)]
pub struct TypeError {
    /// Human-readable description of the problem.
    pub message: String,
}

impl TypeError {
    fn new(msg: impl Into<String>) -> Self {
        TypeError {
            message: msg.into(),
        }
    }
}

// ─── Scope ────────────────────────────────────────────────────────────────────

pub type Scope = HashMap<String, ArkType>;

pub fn build_scope(params: &[crate::models::Parameter]) -> Scope {
    let mut scope = Scope::new();
    for p in params {
        if let Some(base) = p.param_type.strip_suffix("[]") {
            let elem_type = ArkType::parse(base);
            // Register the bare name as the array type, plus each indexed
            // element. The count must match
            // DEFAULT_ARRAY_LENGTH so the type checker and compiler agree.
            scope.insert(p.name.clone(), ArkType::Array(Box::new(elem_type.clone())));
            for i in 0..DEFAULT_ARRAY_LENGTH {
                scope.insert(format!("{}[{}]", p.name, i), elem_type.clone());
            }
        } else {
            scope.insert(p.name.clone(), ArkType::parse(&p.param_type));
        }
    }
    scope
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Type-check an entire contract.
///
/// Returns all type errors found across all functions.
/// Currently non-fatal — the compiler emits these as warnings.
pub fn check_contract(contract: &Contract) -> Vec<TypeError> {
    let constructor_scope = build_scope(&contract.parameters);
    contract
        .functions
        .iter()
        .flat_map(|f| check_function(f, &constructor_scope))
        .collect()
}

fn check_function(function: &Function, constructor_scope: &Scope) -> Vec<TypeError> {
    let mut scope = constructor_scope.clone();
    // Merge function parameters into scope
    scope.extend(build_scope(&function.parameters));

    let mut errors = Vec::new();
    check_statements(
        &function.statements,
        &mut scope,
        &mut errors,
        &function.name,
    );
    errors
}

fn check_statements(
    stmts: &[Statement],
    scope: &mut Scope,
    errors: &mut Vec<TypeError>,
    fn_name: &str,
) {
    for stmt in stmts {
        check_statement(stmt, scope, errors, fn_name);
    }
}

fn check_statement(
    stmt: &Statement,
    scope: &mut Scope,
    errors: &mut Vec<TypeError>,
    fn_name: &str,
) {
    match stmt {
        Statement::Require(req) => {
            check_requirement(req, scope, errors, fn_name);
        }
        Statement::LetBinding {
            name,
            declared_type,
            value,
        } => {
            check_expression(value, scope, errors, fn_name);
            let inferred = infer_type(value, scope);
            let t = declared_type
                .as_deref()
                .map(ArkType::parse)
                .unwrap_or(inferred);
            // Seed the scope so downstream uses of `name` get the inferred type.
            scope.insert(name.clone(), t);
        }
        Statement::VarAssign { name, value } => {
            let original_type = scope.get(name.as_str()).cloned();
            if original_type.is_none() {
                errors.push(TypeError::new(format!(
                    "fn {}: assignment to undeclared variable '{}'",
                    fn_name, name
                )));
            }
            check_expression(value, scope, errors, fn_name);
            let assigned_type = infer_type(value, scope);
            if let Some(original_type) = original_type {
                if original_type != ArkType::Unknown
                    && assigned_type != ArkType::Unknown
                    && original_type != assigned_type
                {
                    errors.push(TypeError::new(format!(
                        "fn {}: assignment to '{}' changes its type from '{}' to '{}'",
                        fn_name,
                        name,
                        original_type.as_str(),
                        assigned_type.as_str()
                    )));
                }
            }
        }
        Statement::IfElse {
            condition,
            then_body,
            else_body,
        } => {
            check_expression(condition, scope, errors, fn_name);
            let cond_type = infer_type(condition, scope);
            if cond_type != ArkType::Bool && cond_type != ArkType::Unknown {
                errors.push(TypeError::new(format!(
                    "fn {}: if condition has type '{}', expected bool",
                    fn_name,
                    cond_type.as_str()
                )));
            }
            // Use cloned child scopes so LetBindings inside branches don't
            // leak into the parent scope.
            check_statements(then_body, &mut scope.clone(), errors, fn_name);
            if let Some(else_stmts) = else_body {
                check_statements(else_stmts, &mut scope.clone(), errors, fn_name);
            }
        }
        Statement::ForIn {
            index_var,
            value_var,
            iterable,
            body,
        } => {
            check_expression(iterable, scope, errors, fn_name);
            // Use a cloned child scope so loop variables don't leak out.
            let mut loop_scope = scope.clone();
            loop_scope.insert(index_var.clone(), ArkType::Int);
            loop_scope.insert(value_var.clone(), ArkType::Unknown);
            check_statements(body, &mut loop_scope, errors, fn_name);
        }
    }
}

fn check_requirement(req: &Requirement, scope: &Scope, errors: &mut Vec<TypeError>, fn_name: &str) {
    match req {
        Requirement::Expression(expr) => {
            check_expression(expr, scope, errors, fn_name);
            let condition_type = infer_type(expr, scope);
            if condition_type != ArkType::Bool && condition_type != ArkType::Unknown {
                errors.push(TypeError::new(format!(
                    "fn {}: require condition has type '{}', expected bool",
                    fn_name,
                    condition_type.as_str()
                )));
            }
        }
        Requirement::CheckSig { signature, pubkey } => {
            check_signature_expression(signature, pubkey, "checkSig", scope, errors, fn_name);
        }
        Requirement::CheckSigFromStack {
            signature, pubkey, ..
        } => {
            check_signature_expression(
                signature,
                pubkey,
                "checkSigFromStack",
                scope,
                errors,
                fn_name,
            );
        }
        Requirement::CheckMultisig {
            pubkeys,
            signatures,
            ..
        } => {
            for pk in pubkeys {
                expect_type(
                    scope,
                    pk,
                    &ArkType::Pubkey,
                    errors,
                    fn_name,
                    &format!("checkMultisig() pubkey '{}'", pk),
                );
            }
            for signature in signatures {
                expect_type(
                    scope,
                    signature,
                    &ArkType::Signature,
                    errors,
                    fn_name,
                    &format!("checkMultisig() signature '{}'", signature),
                );
            }
        }
        Requirement::HashEqual { hash, .. } => {
            // The hash value should be bytes32.
            if let Some(t) = scope.get(hash.as_str()) {
                if *t != ArkType::Bytes32 && *t != ArkType::Bytes && *t != ArkType::Unknown {
                    errors.push(TypeError::new(format!(
                        "fn {}: sha256 comparison: '{}' has type '{}', expected bytes32",
                        fn_name,
                        hash,
                        t.as_str()
                    )));
                }
            }
        }
        Requirement::Comparison { left, op, right } => {
            check_expression(left, scope, errors, fn_name);
            check_expression(right, scope, errors, fn_name);
            check_comparison(left, op, right, scope, errors, fn_name);
        }
        Requirement::After { .. } => {} // No type checking needed
    }
}

fn check_expression(expr: &Expression, scope: &Scope, errors: &mut Vec<TypeError>, fn_name: &str) {
    match expr {
        Expression::BinaryOp { left, op, right } => {
            check_expression(left, scope, errors, fn_name);
            check_expression(right, scope, errors, fn_name);
            if matches!(op.as_str(), "==" | "!=" | ">" | ">=" | "<" | "<=") {
                check_comparison(left, op, right, scope, errors, fn_name);
            }
        }
        Expression::CheckSigExpr { signature, pubkey } => {
            check_signature_expression(signature, pubkey, "checkSig", scope, errors, fn_name);
        }
        Expression::CheckSigFromStackExpr {
            signature, pubkey, ..
        }
        | Expression::CheckSigFromStackVerify {
            signature, pubkey, ..
        } => {
            check_signature_expression(
                signature,
                pubkey,
                "checkSigFromStack",
                scope,
                errors,
                fn_name,
            );
        }
        _ => {}
    }
}

fn check_signature_expression(
    signature: &str,
    pubkey: &str,
    call: &str,
    scope: &Scope,
    errors: &mut Vec<TypeError>,
    fn_name: &str,
) {
    if scope.get(signature) == Some(&ArkType::Pubkey)
        && scope.get(pubkey) == Some(&ArkType::Signature)
    {
        errors.push(TypeError::new(format!(
            "fn {}: {}({}, {}) — arguments appear swapped: expected (signature, pubkey)",
            fn_name, call, signature, pubkey
        )));
        return;
    }
    expect_type(
        scope,
        signature,
        &ArkType::Signature,
        errors,
        fn_name,
        &format!("{call}() arg 1 '{signature}'"),
    );
    expect_type(
        scope,
        pubkey,
        &ArkType::Pubkey,
        errors,
        fn_name,
        &format!("{call}() arg 2 '{pubkey}'"),
    );
}

fn check_comparison(
    left: &Expression,
    op: &str,
    right: &Expression,
    scope: &Scope,
    errors: &mut Vec<TypeError>,
    fn_name: &str,
) {
    let left_type = infer_type(left, scope);
    let right_type = infer_type(right, scope);
    if left_type == ArkType::Unknown || right_type == ArkType::Unknown {
        return;
    }
    if matches!(left_type, ArkType::Array(_)) || matches!(right_type, ArkType::Array(_)) {
        errors.push(TypeError::new(format!(
            "fn {}: array comparison '{}' is not supported",
            fn_name, op
        )));
        return;
    }

    let compatible = match op {
        "==" | "!=" => {
            left_type == right_type
                || (is_bytes_like(&left_type) && is_bytes_like(&right_type))
                || (is_numeric(&left_type) && is_numeric(&right_type))
        }
        ">" | ">=" | "<" | "<=" => is_numeric(&left_type) && is_numeric(&right_type),
        _ => true,
    };

    if !compatible {
        errors.push(TypeError::new(format!(
            "fn {}: comparison '{}' is not defined between '{}' and '{}'",
            fn_name,
            op,
            left_type.as_str(),
            right_type.as_str()
        )));
    }
}

fn is_numeric(t: &ArkType) -> bool {
    matches!(t, ArkType::Int)
}

fn expect_type(
    scope: &Scope,
    name: &str,
    expected: &ArkType,
    errors: &mut Vec<TypeError>,
    fn_name: &str,
    label: &str,
) {
    if let Some(actual) = scope.get(name) {
        if actual != expected && *actual != ArkType::Unknown {
            errors.push(TypeError::new(format!(
                "fn {}: {} has type '{}', expected '{}'",
                fn_name,
                label,
                actual.as_str(),
                expected.as_str()
            )));
        }
    }
}

// ─── Type Inference ───────────────────────────────────────────────────────────

/// Infer the `ArkType` of an expression given the current variable scope.
///
/// Returns `ArkType::Unknown` for expressions whose type cannot be determined
/// statically (e.g., unresolved variables, not-yet-implemented forms).
pub fn infer_type(expr: &Expression, scope: &Scope) -> ArkType {
    match expr {
        Expression::Variable(name) => scope
            .get(name.as_str())
            .cloned()
            .unwrap_or(ArkType::Unknown),
        Expression::Literal(value) if matches!(value.as_str(), "true" | "false") => ArkType::Bool,
        Expression::Literal(_) => ArkType::Int,
        Expression::Property(property) => scope
            .get(property.trim())
            .cloned()
            .or_else(|| {
                let (array, index) = property.strip_suffix(']')?.split_once('[')?;
                if index.parse::<usize>().is_ok() {
                    return None;
                }
                match scope.get(array)? {
                    ArkType::Array(element) => Some((**element).clone()),
                    _ => None,
                }
            })
            .unwrap_or(match property.trim() {
                "tx.time" | "this.activeInputIndex" => ArkType::Int,
                "this.activeBytecode" => ArkType::Bytes,
                _ => ArkType::Unknown,
            }),

        // tx.input.current.*
        Expression::CurrentInput(prop) => match prop.as_deref() {
            Some("value") => ArkType::Int,
            Some("scriptPubKey") => ArkType::Bytes,
            Some("sequence") => ArkType::Int,
            Some("outpoint") => ArkType::Bytes32,
            _ => ArkType::Unknown,
        },

        // tx-level introspection
        Expression::TxIntrospection { property } => match property.as_str() {
            "version" | "locktime" => ArkType::Int,
            "numInputs" | "numOutputs" | "weight" => ArkType::Int,
            "id" => ArkType::Bytes32,
            _ => ArkType::Unknown,
        },

        // tx.inputs[i].*
        Expression::InputIntrospection { property, .. } => match property.as_str() {
            "value" => ArkType::Int,
            "scriptPubKey" => ArkType::Bytes,
            "sequence" => ArkType::Int,
            "outpoint" => ArkType::Bytes32,
            "arkadeScriptHash" | "arkadeWitnessHash" => ArkType::Bytes32,
            _ => ArkType::Unknown,
        },

        // tx.outputs[o].*
        Expression::OutputIntrospection { property, .. } => match property.as_str() {
            "value" => ArkType::Int,
            "scriptPubKey" => ArkType::Bytes,
            _ => ArkType::Unknown,
        },

        // Asset introspection
        Expression::AssetLookup { .. } => ArkType::Int,
        Expression::AssetHas { .. } => ArkType::Bool,
        Expression::AssetCount { .. } => ArkType::Int,
        Expression::AssetAt { property, .. } => match property.as_str() {
            "amount" => ArkType::Int,
            // TODO(asset-id-struct): `.assetId` is really a two-item canonical
            // Asset ID (asset_txid, asset_gidx), NOT a single bytes32. Typed as
            // Bytes32 only as a stopgap until the composite `AssetId` struct
            // return type lands (separate PR).
            "assetId" => ArkType::Bytes32,
            _ => ArkType::Unknown,
        },

        // Asset group introspection
        Expression::GroupFind { .. } => ArkType::Int,
        Expression::GroupHas { .. } => ArkType::Bool,
        Expression::GroupControlIs { .. } => ArkType::Bool,
        Expression::GroupSum { .. } => ArkType::Int,
        Expression::GroupNumIO { .. } => ArkType::Int,
        Expression::AssetGroupsLength => ArkType::Int,
        Expression::GroupProperty { property, .. } => match property.as_str() {
            "sumInputs" | "sumOutputs" | "delta" => ArkType::Int,
            "numInputs" | "numOutputs" => ArkType::Int,
            // TODO(asset-id-struct): `assetId` is really a two-item canonical
            // Asset ID (asset_txid, asset_gidx), not a single bytes32; typed
            // Bytes32 only as a stopgap until the composite `AssetId` struct
            // lands, so `==` over it is unsound until then. `metadataHash`
            // is genuinely a 32-byte hash and is correct.
            "metadataHash" | "assetId" => ArkType::Bytes32,
            "isFresh" | "hasControl" => ArkType::Bool,
            _ => ArkType::Unknown,
        },
        Expression::GroupIOAccess { property, .. } => match property.as_deref() {
            Some("amount") => ArkType::Int,
            Some("type") => ArkType::Int,
            _ => ArkType::Unknown,
        },

        // SHA256 — all produce a 32-byte digest or midstate
        Expression::Sha256 { .. }
        | Expression::Sha256Initialize { .. }
        | Expression::Sha256Update { .. }
        | Expression::Sha256Finalize { .. }
        | Expression::Sighash { .. } => ArkType::Bytes32,

        // Byte-string ops
        Expression::Concat { .. } | Expression::Digest { .. } => ArkType::Bytes,

        // Arithmetic
        Expression::Negate { .. } | Expression::ModExp { .. } => ArkType::Int,

        // Crypto expressions
        Expression::CheckSigExpr { .. }
        | Expression::CheckSigFromStackExpr { .. }
        | Expression::CheckSigFromStackVerify { .. }
        | Expression::EcPairing { .. }
        | Expression::EcMulScalarVerify { .. }
        | Expression::TweakVerify { .. } => ArkType::Bool,
        Expression::EcAdd { .. } | Expression::EcMul { .. } => ArkType::Unknown,

        // Contract instantiation resolves to a scriptPubKey bytes value.
        Expression::ContractInstance { .. } => ArkType::Bytes,

        // Byte-string manipulation (introspector extensions)
        Expression::Substr { .. } => ArkType::Bytes,
        Expression::Cat { .. } => ArkType::Bytes,
        Expression::Bin2Num { .. } => ArkType::Int,
        Expression::Num2Bin { .. } => ArkType::Bytes,
        Expression::ReverseBytes { .. } => ArkType::Bytes,
        Expression::SizeOf { .. } => ArkType::Int,

        // Packet introspection — returns raw packet bytes.
        Expression::PacketInspect { .. } => ArkType::Bytes,
        Expression::InputPacketInspect { .. } => ArkType::Bytes,

        // Binary operations — type is determined by operand types and operator.
        Expression::BinaryOp { left, op, right } => {
            let lt = infer_type(left, scope);
            let rt = infer_type(right, scope);
            match op.as_str() {
                "+" => {
                    // bytes-like on either side → concatenation (result Bytes).
                    if is_bytes_like(&lt) || is_bytes_like(&rt) {
                        ArkType::Bytes
                    } else {
                        ArkType::Int
                    }
                }
                "-" | "*" | "/" => ArkType::Int,
                "==" | "!=" | ">=" | "<=" | ">" | "<" => ArkType::Bool,
                _ => ArkType::Unknown,
            }
        }
    }
}

/// Returns true when the type is a raw byte string (eligible as a `+`
/// operand for concatenation via OP_CAT).
pub fn is_bytes_like(t: &ArkType) -> bool {
    matches!(t, ArkType::Bytes | ArkType::Bytes20 | ArkType::Bytes32)
}
