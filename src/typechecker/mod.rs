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
/// Internal types are produced by introspection expressions and 64-bit
/// arithmetic; they never appear in user-written type annotations.
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
    /// 8-byte little-endian unsigned 64-bit integer.
    /// Produced by: asset amounts, UTXO values, group sums.
    /// Requires OP_ADD64/OP_SUB64/etc. for arithmetic; cannot mix with Int.
    Uint64Le,
    /// 4-byte little-endian unsigned 32-bit integer.
    /// Produced by: tx.version, tx.locktime.
    Uint32Le,

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

    /// Wire-encoding descriptor used in `witnessSchema` / client stub output.
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
            ArkType::Uint64Le => "le64",
            ArkType::Uint32Le => "le32",
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
            ArkType::Uint64Le => "uint64le".to_string(),
            ArkType::Uint32Le => "uint32le".to_string(),
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

type Scope = HashMap<String, ArkType>;

fn build_scope(params: &[crate::models::Parameter]) -> Scope {
    params
        .iter()
        .flat_map(|p| {
            if p.param_type.ends_with("[]") {
                let base = p.param_type.trim_end_matches("[]");
                let elem_type = ArkType::parse(base);
                // Register the bare name as the array type, plus each flattened
                // index form (name_0 … name_{N-1}).  The count must match
                // DEFAULT_ARRAY_LENGTH so the type checker and the compiler
                // always agree on how many elements exist.
                let mut entries = vec![(
                    p.name.clone(),
                    ArkType::Array(Box::new(elem_type.clone())),
                )];
                for i in 0..DEFAULT_ARRAY_LENGTH {
                    entries.push((format!("{}_{}", p.name, i), elem_type.clone()));
                }
                entries
            } else {
                vec![(p.name.clone(), ArkType::parse(&p.param_type))]
            }
        })
        .collect()
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
    check_statements(&function.statements, &mut scope, &mut errors, &function.name);
    errors
}

fn check_statements(stmts: &[Statement], scope: &mut Scope, errors: &mut Vec<TypeError>, fn_name: &str) {
    for stmt in stmts {
        check_statement(stmt, scope, errors, fn_name);
    }
}

fn check_statement(stmt: &Statement, scope: &mut Scope, errors: &mut Vec<TypeError>, fn_name: &str) {
    match stmt {
        Statement::Require(req) => {
            check_requirement(req, scope, errors, fn_name);
        }
        Statement::LetBinding { name, value } => {
            let t = infer_type(value, scope);
            // Seed the scope so downstream uses of `name` get the inferred type.
            scope.insert(name.clone(), t);
        }
        Statement::VarAssign { name, value } => {
            if !scope.contains_key(name.as_str()) {
                errors.push(TypeError::new(format!(
                    "fn {}: assignment to undeclared variable '{}'",
                    fn_name, name
                )));
            }
            let t = infer_type(value, scope);
            // Update scope with the new type in case it changed.
            scope.insert(name.clone(), t);
        }
        Statement::IfElse {
            condition,
            then_body,
            else_body,
        } => {
            let cond_type = infer_type(condition, scope);
            if cond_type != ArkType::Bool && cond_type != ArkType::Unknown {
                errors.push(TypeError::new(format!(
                    "fn {}: if condition has type '{}', expected bool",
                    fn_name,
                    cond_type.as_str()
                )));
            }
            // Note: we don't fork scope into branches — LetBindings in branches
            // are not visible outside them, but we don't enforce that here yet.
            check_statements(then_body, scope, errors, fn_name);
            if let Some(else_stmts) = else_body {
                check_statements(else_stmts, scope, errors, fn_name);
            }
        }
        Statement::ForIn {
            index_var,
            value_var,
            iterable,
            body,
        } => {
            let _ = infer_type(iterable, scope);
            // Seed the loop variables with placeholder types for body checking.
            scope.insert(index_var.clone(), ArkType::Int);
            scope.insert(value_var.clone(), ArkType::Unknown);
            check_statements(body, scope, errors, fn_name);
        }
    }
}

fn check_requirement(req: &Requirement, scope: &Scope, errors: &mut Vec<TypeError>, fn_name: &str) {
    match req {
        Requirement::CheckSig { signature, pubkey } => {
            // Detect swapped arguments first (more actionable message).
            let sig_t = scope.get(signature.as_str());
            let pk_t = scope.get(pubkey.as_str());
            if sig_t == Some(&ArkType::Pubkey) && pk_t == Some(&ArkType::Signature) {
                errors.push(TypeError::new(format!(
                    "fn {}: checkSig({}, {}) — arguments appear swapped: expected (signature, pubkey)",
                    fn_name, signature, pubkey
                )));
                return;
            }
            expect_type(scope, signature, &ArkType::Signature, errors, fn_name,
                &format!("checkSig() arg 1 '{}'", signature));
            expect_type(scope, pubkey, &ArkType::Pubkey, errors, fn_name,
                &format!("checkSig() arg 2 '{}'", pubkey));
        }
        Requirement::CheckSigFromStack {
            signature,
            pubkey,
            message,
        } => {
            let sig_t = scope.get(signature.as_str());
            let pk_t = scope.get(pubkey.as_str());
            if sig_t == Some(&ArkType::Pubkey) && pk_t == Some(&ArkType::Signature) {
                errors.push(TypeError::new(format!(
                    "fn {}: checkSigFromStack({}, {}, {}) — first two arguments appear swapped",
                    fn_name, signature, pubkey, message
                )));
                return;
            }
            expect_type(scope, signature, &ArkType::Signature, errors, fn_name,
                &format!("checkSigFromStack() arg 1 '{}'", signature));
            expect_type(scope, pubkey, &ArkType::Pubkey, errors, fn_name,
                &format!("checkSigFromStack() arg 2 '{}'", pubkey));
        }
        Requirement::CheckMultisig { signatures, pubkeys } => {
            for sig in signatures {
                expect_type(scope, sig, &ArkType::Signature, errors, fn_name,
                    &format!("checkMultisig() signature '{}'", sig));
            }
            for pk in pubkeys {
                expect_type(scope, pk, &ArkType::Pubkey, errors, fn_name,
                    &format!("checkMultisig() pubkey '{}'", pk));
            }
        }
        Requirement::HashEqual { hash, .. } => {
            // The hash value should be bytes32.
            if let Some(t) = scope.get(hash.as_str()) {
                if *t != ArkType::Bytes32 && *t != ArkType::Bytes && *t != ArkType::Unknown {
                    errors.push(TypeError::new(format!(
                        "fn {}: sha256 comparison: '{}' has type '{}', expected bytes32",
                        fn_name, hash, t.as_str()
                    )));
                }
            }
        }
        Requirement::Comparison { left, op, right } => {
            let lt = infer_type(left, scope);
            let rt = infer_type(right, scope);
            // Warn when one side is Uint64Le and the other is a plain Int —
            // these require explicit conversion opcodes (OP_SCRIPTNUMTOLE64 /
            // OP_LE64TOSCRIPTNUM) and the compiler inserts them automatically,
            // but it's good to flag the mismatch for contract authors.
            if lt != ArkType::Unknown && rt != ArkType::Unknown {
                let left_64 = lt == ArkType::Uint64Le;
                let right_64 = rt == ArkType::Uint64Le;
                if left_64 != right_64 {
                    errors.push(TypeError::new(format!(
                        "fn {}: comparison '{}' mixes uint64le ('{}') with scriptnum ('{}') — \
                         implicit conversion applied; use le64ToScriptNum() for explicit control",
                        fn_name, op, lt.as_str(), rt.as_str()
                    )));
                }
            }
        }
        Requirement::After { .. } => {} // No type checking needed
    }
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
        Expression::Variable(name) => {
            scope.get(name.as_str()).cloned().unwrap_or(ArkType::Unknown)
        }
        Expression::Literal(_) => ArkType::Int,
        Expression::Property(_) => ArkType::Unknown,

        // tx.input.current.*
        Expression::CurrentInput(prop) => match prop.as_deref() {
            Some("value") => ArkType::Uint64Le,
            Some("scriptPubKey") => ArkType::Bytes,
            Some("sequence") => ArkType::Uint32Le,
            Some("outpoint") => ArkType::Bytes32,
            _ => ArkType::Unknown,
        },

        // tx-level introspection
        Expression::TxIntrospection { property } => match property.as_str() {
            "version" | "locktime" => ArkType::Uint32Le,
            "numInputs" | "numOutputs" | "weight" => ArkType::Int,
            _ => ArkType::Unknown,
        },

        // tx.inputs[i].*
        Expression::InputIntrospection { property, .. } => match property.as_str() {
            "value" => ArkType::Uint64Le,
            "scriptPubKey" => ArkType::Bytes,
            "sequence" => ArkType::Uint32Le,
            "outpoint" => ArkType::Bytes32,
            "issuance" => ArkType::Bytes,
            _ => ArkType::Unknown,
        },

        // tx.outputs[o].*
        Expression::OutputIntrospection { property, .. } => match property.as_str() {
            "value" => ArkType::Uint64Le,
            "scriptPubKey" => ArkType::Bytes,
            "nonce" => ArkType::Bytes32,
            _ => ArkType::Unknown,
        },

        // Asset introspection
        Expression::AssetLookup { .. } => ArkType::Uint64Le,
        Expression::AssetCount { .. } => ArkType::Int,
        Expression::AssetAt { property, .. } => match property.as_str() {
            "amount" => ArkType::Uint64Le,
            "assetId" => ArkType::Bytes32,
            _ => ArkType::Unknown,
        },

        // Asset group introspection
        Expression::GroupFind { .. } => ArkType::Int,
        Expression::GroupSum { .. } => ArkType::Uint64Le,
        Expression::GroupNumIO { .. } => ArkType::Int,
        Expression::AssetGroupsLength => ArkType::Int,
        Expression::GroupProperty { property, .. } => match property.as_str() {
            "sumInputs" | "sumOutputs" | "delta" => ArkType::Uint64Le,
            "numInputs" | "numOutputs" => ArkType::Int,
            "control" | "metadataHash" | "assetId" => ArkType::Bytes32,
            "isFresh" => ArkType::Bool,
            _ => ArkType::Unknown,
        },
        Expression::GroupIOAccess { property, .. } => match property.as_deref() {
            Some("amount") => ArkType::Uint64Le,
            Some("type") => ArkType::Int,
            _ => ArkType::Unknown,
        },

        // Streaming SHA256 — all produce a 32-byte digest or midstate
        Expression::Sha256Initialize { .. }
        | Expression::Sha256Update { .. }
        | Expression::Sha256Finalize { .. } => ArkType::Bytes32,

        // Conversion and arithmetic
        Expression::Neg64 { .. } => ArkType::Uint64Le,
        Expression::Le64ToScriptNum { .. } => ArkType::Int,
        Expression::Le32ToLe64 { .. } => ArkType::Uint64Le,

        // Crypto expressions
        Expression::CheckSigExpr { .. }
        | Expression::CheckSigFromStackExpr { .. }
        | Expression::CheckSigFromStackVerify { .. }
        | Expression::EcMulScalarVerify { .. }
        | Expression::TweakVerify { .. } => ArkType::Bool,

        // Array operations
        Expression::ArrayIndex { array, .. } => {
            // The element type is the array's inner type.
            if let ArkType::Array(inner) = infer_type(array, scope) {
                *inner
            } else {
                ArkType::Unknown
            }
        }
        Expression::ArrayLength(_) => ArkType::Int,

        // Binary operations — type is determined by operand types and operator.
        Expression::BinaryOp { left, op, right } => {
            let lt = infer_type(left, scope);
            let rt = infer_type(right, scope);
            match op.as_str() {
                "+" | "-" | "*" | "/" => {
                    // If either side is 64-bit, the result is 64-bit.
                    if lt == ArkType::Uint64Le || rt == ArkType::Uint64Le {
                        ArkType::Uint64Le
                    } else {
                        ArkType::Int
                    }
                }
                "==" | "!=" | ">=" | "<=" | ">" | "<" => ArkType::Bool,
                _ => ArkType::Unknown,
            }
        }
    }
}
