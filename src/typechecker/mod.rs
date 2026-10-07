/// Type system for Arkade Script.
///
/// Provides:
/// - `ArkType`: the canonical type enum for all Arkade Script values,
///   including wire-encoding metadata used by client stub generators
/// - `annotate`: stores every expression's type on it before validation;
///   the validator and code generation read `Expression::ty`
/// - `infer_type`: the inference rule `annotate` applies to each node
use std::collections::HashMap;

use crate::models::{
    AssignmentTarget, Contract, ExprKind, Expression, LocatedStatement, Requirement, Statement,
};
use crate::operators::{BinaryOperator, OperatorClass, UnaryOperator};

pub(crate) mod builtins;

// ─── Type Enum ────────────────────────────────────────────────────────────────

/// All possible types in Arkade Script.
///
/// Declared types map directly to the grammar's `data_type` rule.
/// Internal types are produced by introspection expressions; they never appear
/// in user-written type annotations.
#[derive(Debug, Clone, PartialEq)]
pub enum ArkType {
    // ── Declared types (match grammar data_type rule) ──────────────────────
    /// 64-byte Schnorr signature
    Signature,
    /// Arbitrary-length byte array; `pubkey` is an alias
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
    /// Position of an asset group in the transaction's asset packet
    AssetGroup,

    // ── Internal / introspection types ─────────────────────────────────────

    // ── Composite ──────────────────────────────────────────────────────────
    /// Homogeneous fixed-size array (e.g., `pubkey[3]`)
    Array(Box<ArkType>, usize),
    /// Named user-defined struct.
    Struct(String),

    /// Type could not be resolved (variable not in scope, etc.)
    Unknown,
}

impl ArkType {
    /// Parse from a grammar `data_type` string (e.g., `"pubkey"`, `"bytes32[4]"`).
    pub fn parse(s: &str) -> ArkType {
        if let Some((element, length)) = crate::models::array_type_parts(s) {
            return ArkType::Array(Box::new(ArkType::parse(element)), length);
        }
        match s {
            "signature" => ArkType::Signature,
            "bytes" | "pubkey" => ArkType::Bytes,
            "bytes20" => ArkType::Bytes20,
            "bytes32" => ArkType::Bytes32,
            "int" => ArkType::Int,
            "bool" => ArkType::Bool,
            "asset" => ArkType::Asset,
            "AssetGroup" => ArkType::AssetGroup,
            _ if !s.is_empty() => ArkType::Struct(s.to_string()),
            _ => ArkType::Unknown,
        }
    }

    /// Wire-encoding descriptor used in leaf `witness` / client stub output.
    ///
    /// These strings are stable identifiers; downstream code generators
    /// (TypeScript, Go, etc.) can switch on them to pick the right serializer.
    pub fn encoding(&self) -> &'static str {
        match self {
            ArkType::Signature => "schnorr-64",
            ArkType::Bytes => "raw",
            ArkType::Bytes20 => "raw-20",
            ArkType::Bytes32 => "raw-32",
            ArkType::Int => "scriptnum",
            ArkType::Bool => "scriptnum",
            ArkType::Asset => "raw-32",
            ArkType::AssetGroup => "scriptnum",
            ArkType::Array(..) => "array",
            ArkType::Struct(..) => "struct",
            ArkType::Unknown => "unknown",
        }
    }

    /// Canonical string form matching Arkade Script syntax.
    pub fn as_str(&self) -> String {
        match self {
            ArkType::Signature => "signature".to_string(),
            ArkType::Bytes => "bytes".to_string(),
            ArkType::Bytes20 => "bytes20".to_string(),
            ArkType::Bytes32 => "bytes32".to_string(),
            ArkType::Int => "int".to_string(),
            ArkType::Bool => "bool".to_string(),
            ArkType::Asset => "asset".to_string(),
            ArkType::AssetGroup => "AssetGroup".to_string(),
            ArkType::Array(inner, length) => format!("{}[{length}]", inner.as_str()),
            ArkType::Struct(name) => name.clone(),
            ArkType::Unknown => "unknown".to_string(),
        }
    }
}

// ─── Scope ────────────────────────────────────────────────────────────────────

pub type Scope = HashMap<String, ArkType>;

pub fn build_scope_with_structs(
    params: &[crate::models::Parameter],
    structs: &[crate::models::StructDefinition],
) -> Scope {
    let mut scope = Scope::new();
    for p in params {
        insert_type_bindings(&mut scope, &p.name, &p.param_type, structs, &mut Vec::new());
    }
    scope
}

fn insert_type_bindings(
    scope: &mut Scope,
    name: &str,
    declared_type: &str,
    structs: &[crate::models::StructDefinition],
    stack: &mut Vec<String>,
) {
    if let Some((base, length)) = crate::models::array_type_parts(declared_type) {
        let element_type = ArkType::parse(base);
        scope.insert(
            name.to_string(),
            ArkType::Array(Box::new(element_type.clone()), length),
        );
        for index in 0..length {
            insert_type_bindings(scope, &format!("{name}[{index}]"), base, structs, stack);
        }
        return;
    }
    if let Some(fields) = crate::models::builtin_struct_fields(declared_type) {
        scope.insert(name.to_string(), ArkType::Struct(declared_type.to_string()));
        for (field_name, field_type) in fields {
            insert_type_bindings(
                scope,
                &format!("{name}.{field_name}"),
                field_type,
                structs,
                stack,
            );
        }
        return;
    }
    if let Some(definition) = structs
        .iter()
        .find(|definition| definition.name == declared_type)
    {
        scope.insert(name.to_string(), ArkType::Struct(declared_type.to_string()));
        if stack.iter().any(|name| name == declared_type) {
            return;
        }
        stack.push(declared_type.to_string());
        for field in &definition.fields {
            insert_type_bindings(
                scope,
                &format!("{name}.{}", field.name),
                &field.param_type,
                structs,
                stack,
            );
        }
        stack.pop();
        return;
    }
    scope.insert(name.to_string(), ArkType::parse(declared_type));
}

pub(crate) fn bind_local_type(
    scope: &mut Scope,
    name: &str,
    declared_type: Option<&str>,
    inferred: ArkType,
    structs: &[crate::models::StructDefinition],
) {
    let expanded = match declared_type {
        Some(declared_type) => Some(declared_type.to_string()),
        None if matches!(inferred, ArkType::Struct(_) | ArkType::Array(..)) => {
            Some(inferred.as_str())
        }
        None => None,
    };
    match expanded {
        Some(declared_type) => {
            insert_type_bindings(scope, name, &declared_type, structs, &mut Vec::new())
        }
        None => {
            scope.insert(name.to_string(), inferred);
        }
    }
}

/// Type every expression of the contract's own functions.
pub(crate) fn annotate(contract: &mut Contract) {
    let constructor = build_scope_with_structs(&contract.parameters, &contract.structs);
    for function in contract.functions.iter_mut().filter(|f| !f.is_imported()) {
        let mut scope = constructor.clone();
        scope.extend(build_scope_with_structs(
            &function.parameters,
            &contract.structs,
        ));
        annotate_statements(&mut function.statements, &mut scope, &contract.structs);
    }
}

/// Type `statements`, binding their locals into `scope`.
pub(crate) fn annotate_statements(
    statements: &mut [LocatedStatement],
    scope: &mut Scope,
    structs: &[crate::models::StructDefinition],
) {
    for statement in statements {
        match &mut statement.statement {
            Statement::Call(value) | Statement::Return(Some(value)) => {
                annotate_expression(value, scope)
            }
            Statement::Return(None) => {}
            Statement::Require(requirement) => {
                for value in requirement.expressions_mut() {
                    annotate_expression(value, scope);
                }
            }
            Statement::LetBinding {
                name,
                declared_type,
                value,
            } => {
                annotate_expression(value, scope);
                let ty = declared_type
                    .as_deref()
                    .map(ArkType::parse)
                    .unwrap_or_else(|| value.ty.clone());
                bind_local_type(scope, name, declared_type.as_deref(), ty, structs);
            }
            Statement::VarAssign { target, value } => {
                if let AssignmentTarget::Access(index)
                | AssignmentTarget::ArrayIndex { index, .. } = target
                {
                    annotate_expression(index, scope);
                }
                annotate_expression(value, scope);
            }
            Statement::IfElse {
                condition,
                then_body,
                else_body,
            } => {
                annotate_expression(condition, scope);
                annotate_statements(then_body, &mut scope.clone(), structs);
                if let Some(else_body) = else_body {
                    annotate_statements(else_body, &mut scope.clone(), structs);
                }
            }
            Statement::ForIn {
                index_var,
                value_var,
                iterable,
                body,
            } => {
                annotate_expression(iterable, scope);
                let mut body_scope = scope.clone();
                body_scope.insert(index_var.clone(), ArkType::Int);
                let element = match &iterable.ty {
                    ArkType::Array(element, _) => (**element).clone(),
                    _ => ArkType::Unknown,
                };
                bind_local_type(&mut body_scope, value_var, None, element, structs);
                annotate_statements(body, &mut body_scope, structs);
            }
            Statement::ForCount { count, body } => {
                annotate_expression(count, scope);
                annotate_statements(body, &mut scope.clone(), structs);
            }
        }
    }
}

fn annotate_expression(expression: &mut Expression, scope: &Scope) {
    for child in crate::models::child_exprs_mut(expression) {
        annotate_expression(child, scope);
    }
    expression.ty = infer_type(expression, scope);
}

pub(crate) fn resolve_group_properties(contract: &mut Contract) {
    let constructor_scope = build_scope_with_structs(&contract.parameters, &contract.structs);
    let returns = contract
        .functions
        .iter()
        .map(|f| (f.name.clone(), f.return_type.clone()))
        .collect();
    for function in contract.functions.iter_mut().filter(|f| !f.is_imported()) {
        let mut scope = constructor_scope.clone();
        scope.extend(build_scope_with_structs(
            &function.parameters,
            &contract.structs,
        ));
        resolve_statements(
            &mut function.statements,
            &mut scope,
            &contract.structs,
            &returns,
        );
    }
}

fn resolve_statements(
    statements: &mut [LocatedStatement],
    scope: &mut Scope,
    structs: &[crate::models::StructDefinition],
    returns: &HashMap<String, Option<String>>,
) {
    for statement in statements {
        match &mut statement.statement {
            Statement::Call(expression) | Statement::Return(Some(expression)) => {
                resolve_expression(expression, scope, returns)
            }
            Statement::Return(None) => {}
            Statement::Require(requirement) => match requirement {
                Requirement::Expression(expression) => {
                    resolve_expression(expression, scope, returns)
                }
                Requirement::Comparison { left, right, .. } => {
                    resolve_expression(left, scope, returns);
                    resolve_expression(right, scope, returns);
                }
                _ => {}
            },
            Statement::LetBinding {
                name,
                declared_type,
                value,
            } => {
                resolve_expression(value, scope, returns);
                let binding_type = declared_type
                    .as_deref()
                    .map(ArkType::parse)
                    .unwrap_or_else(|| infer_type(value, scope));
                bind_local_type(scope, name, declared_type.as_deref(), binding_type, structs);
            }
            Statement::VarAssign { target, value } => {
                if let AssignmentTarget::ArrayIndex { index, .. }
                | AssignmentTarget::Access(index) = target
                {
                    resolve_expression(index, scope, returns);
                }
                resolve_expression(value, scope, returns);
            }
            Statement::IfElse {
                condition,
                then_body,
                else_body,
            } => {
                resolve_expression(condition, scope, returns);
                resolve_statements(then_body, &mut scope.clone(), structs, returns);
                if let Some(else_body) = else_body {
                    resolve_statements(else_body, &mut scope.clone(), structs, returns);
                }
            }
            Statement::ForIn {
                index_var,
                value_var,
                iterable,
                body,
            } => {
                resolve_expression(iterable, scope, returns);
                let element_type = match infer_type(iterable, scope) {
                    ArkType::Array(element, _) => *element,
                    _ => ArkType::Unknown,
                };
                let mut loop_scope = scope.clone();
                loop_scope.insert(index_var.clone(), ArkType::Int);
                bind_local_type(&mut loop_scope, value_var, None, element_type, structs);
                resolve_statements(body, &mut loop_scope, structs, returns);
            }
            Statement::ForCount { count, body } => {
                resolve_expression(count, scope, returns);
                resolve_statements(body, &mut scope.clone(), structs, returns);
            }
        }
    }
}

fn resolve_expression(
    expression: &mut Expression,
    scope: &Scope,
    returns: &HashMap<String, Option<String>>,
) {
    for child in crate::models::child_exprs_mut(expression) {
        resolve_expression(child, scope, returns);
    }
    if let ExprKind::Call {
        name, return_type, ..
    } = &mut expression.kind
    {
        *return_type = returns.get(name).cloned().flatten();
    }

    let resolved = match &expression.kind {
        // `g.delta`, `s.group.delta`
        ExprKind::Property(path) => path.rsplit_once('.').and_then(|(base, property)| {
            Some(ExprKind::GroupProperty {
                group: Box::new(group_binding(base, expression, scope)?),
                property: GROUP_PROPERTIES
                    .contains(&property)
                    .then(|| property.to_string())?,
            })
        }),
        // `g.inputs[j]`
        ExprKind::ArrayIndex { array, index } => {
            array.rsplit_once('.').and_then(|(base, source)| {
                Some(ExprKind::GroupIOAccess {
                    group: Box::new(group_binding(base, expression, scope)?),
                    io_index: index.clone(),
                    source: group_io_source(source)?,
                    property: None,
                })
            })
        }
        // `gs[i].inputs[j]`
        ExprKind::IndexAccess { value, index } => match &value.as_ref().kind {
            ExprKind::FieldAccess {
                value: group,
                field,
            } if !is_struct(group, scope) => {
                group_io_source(field).map(|source| ExprKind::GroupIOAccess {
                    group: group.clone(),
                    io_index: index.clone(),
                    source,
                    property: None,
                })
            }
            _ => None,
        },
        // `g.inputs[j].amount`, `gs[i].delta`
        ExprKind::FieldAccess { value, field } => match &value.as_ref().kind {
            ExprKind::GroupIOAccess {
                group,
                io_index,
                source,
                property: None,
            } if matches!(field.as_str(), "amount" | "type") => Some(ExprKind::GroupIOAccess {
                group: group.clone(),
                io_index: io_index.clone(),
                source: source.clone(),
                property: Some(field.clone()),
            }),
            _ if GROUP_PROPERTIES.contains(&field.as_str()) && !is_struct(value, scope) => {
                Some(ExprKind::GroupProperty {
                    group: value.clone(),
                    property: field.clone(),
                })
            }
            _ => None,
        },
        _ => None,
    };
    if let Some(resolved) = resolved {
        expression.kind = resolved;
    }
}

/// Each entry also needs an `asset_group_property` grammar alternative and an
/// `emit_group_property_asm` arm.
pub(crate) const GROUP_PROPERTIES: [&str; 10] = [
    "numInputs",
    "numOutputs",
    "sumInputs",
    "sumOutputs",
    "delta",
    "hasControl",
    "controlAssetId",
    "metadataHash",
    "assetId",
    "isFresh",
];

/// Group members apply to any non-struct value; the builtin table rejects
/// operands that aren't `AssetGroup`, while struct fields keep their names.
fn is_struct(value: &Expression, scope: &Scope) -> bool {
    matches!(infer_type(value, scope), ArkType::Struct(_))
}

/// The binding named by `path`, when a group member can apply to it; it takes
/// the span of the access `at`, which has none narrower for the binding alone.
fn group_binding(path: &str, at: &Expression, scope: &Scope) -> Option<Expression> {
    (!matches!(scope.get(path), Some(ArkType::Struct(_)))).then(|| {
        at.with_kind(if path.contains('.') {
            ExprKind::Property(path.to_string())
        } else {
            ExprKind::Variable(path.to_string())
        })
    })
}

pub(crate) fn group_io_source(name: &str) -> Option<crate::models::GroupIOSource> {
    match name {
        "inputs" => Some(crate::models::GroupIOSource::Inputs),
        "outputs" => Some(crate::models::GroupIOSource::Outputs),
        _ => None,
    }
}

pub(crate) fn literal_index(mut expression: &Expression) -> Option<(bool, &str)> {
    let mut negative = false;
    while let ExprKind::Unary {
        op: UnaryOperator::Neg,
        value,
    } = &expression.kind
    {
        negative = !negative;
        expression = value;
    }
    match &expression.kind {
        ExprKind::Literal(value) => Some(match value.strip_prefix('-') {
            Some(magnitude) => (!negative, magnitude),
            None => (negative, value),
        }),
        _ => None,
    }
}

/// Whether a value of type `t` can be compared with `hash_fn`'s digest.
pub(crate) fn digest_accepts(hash_fn: &crate::models::HashFn, t: &ArkType) -> bool {
    matches!(t, ArkType::Bytes | ArkType::Unknown) || *t == ArkType::parse(hash_fn.digest_type())
}

// ─── Type Inference ───────────────────────────────────────────────────────────

/// Infer the `ArkType` of an expression given the current variable scope.
///
/// Returns `ArkType::Unknown` for expressions whose type cannot be determined
/// statically (e.g., unresolved variables, not-yet-implemented forms).
pub fn infer_type(expr: &Expression, scope: &Scope) -> ArkType {
    match &expr.kind {
        ExprKind::Call { return_type, .. } => return_type
            .as_deref()
            .map(ArkType::parse)
            .unwrap_or(ArkType::Unknown),
        ExprKind::Variable(name) => scope
            .get(name.as_str())
            .cloned()
            .unwrap_or(ArkType::Unknown),
        ExprKind::Literal(value) if matches!(value.as_str(), "true" | "false") => ArkType::Bool,
        ExprKind::Literal(value) if value.starts_with("0x") => ArkType::Bytes,
        ExprKind::Literal(_) => ArkType::Int,
        ExprKind::ArrayLiteral(elements) => ArkType::Array(
            Box::new(
                elements
                    .first()
                    .map(|element| infer_type(element, scope))
                    .unwrap_or(ArkType::Unknown),
            ),
            elements.len(),
        ),
        ExprKind::StructLiteral(_) => ArkType::Unknown,
        ExprKind::FieldAccess { .. } => expr
            .binding_path()
            .map(|name| infer_type(&expr.with_kind(ExprKind::Property(name)), scope))
            .unwrap_or(ArkType::Unknown),
        ExprKind::IndexAccess { value, .. } => match infer_type(value, scope) {
            ArkType::Array(element, _) => *element,
            _ => ArkType::Unknown,
        },
        ExprKind::ArrayIndex { array, .. } => match scope.get(array) {
            Some(ArkType::Array(element, _)) => (**element).clone(),
            _ => ArkType::Unknown,
        },
        ExprKind::Property(property) => scope
            .get(property.trim())
            .cloned()
            .or_else(|| {
                let array = property.trim().strip_suffix(".length")?;
                matches!(scope.get(array)?, ArkType::Array(..)).then_some(ArkType::Int)
            })
            .or_else(|| {
                let (array, index) = property.strip_suffix(']')?.split_once('[')?;
                if index.parse::<usize>().is_ok() {
                    return None;
                }
                match scope.get(array)? {
                    ArkType::Array(element, _) => Some((**element).clone()),
                    _ => None,
                }
            })
            .unwrap_or(match property.trim() {
                "tx.time" | "this.activeInputIndex" | "this.expiry" => ArkType::Int,
                "this.activeBytecode" => ArkType::Bytes,
                _ => ArkType::Unknown,
            }),

        // tx.input.current.*
        ExprKind::CurrentInput(prop) => match prop.as_deref() {
            Some("value") => ArkType::Int,
            Some("scriptPubKey") => ArkType::Bytes,
            Some("sequence") | Some("witnessVersion") => ArkType::Int,
            Some("outpoint") => ArkType::Struct("Outpoint".to_string()),
            Some("arkadeScriptHash") | Some("arkadeWitnessHash") => ArkType::Bytes32,
            _ => ArkType::Unknown,
        },

        // tx-level introspection
        ExprKind::TxIntrospection { property } => match property.as_str() {
            "version" | "locktime" => ArkType::Int,
            "numInputs" | "numOutputs" | "weight" => ArkType::Int,
            "id" => ArkType::Bytes32,
            _ => ArkType::Unknown,
        },

        // tx.inputs[i].*
        ExprKind::InputIntrospection { property, .. } => match property.as_str() {
            "value" => ArkType::Int,
            "scriptPubKey" => ArkType::Bytes,
            "sequence" | "witnessVersion" => ArkType::Int,
            "outpoint" => ArkType::Struct("Outpoint".to_string()),
            "arkadeScriptHash" | "arkadeWitnessHash" => ArkType::Bytes32,
            _ => ArkType::Unknown,
        },

        // tx.outputs[o].*
        ExprKind::OutputIntrospection { property, .. } => match property.as_str() {
            "value" | "witnessVersion" => ArkType::Int,
            "scriptPubKey" => ArkType::Bytes,
            _ => ArkType::Unknown,
        },

        // Asset introspection
        ExprKind::AssetLookup { .. } => ArkType::Int,
        ExprKind::AssetHas { .. } => ArkType::Bool,
        ExprKind::AssetCount { .. } => ArkType::Int,
        ExprKind::AssetAt { property, .. } => match property.as_str() {
            "amount" => ArkType::Int,
            "assetId" => ArkType::Struct("AssetId".to_string()),
            _ => ArkType::Unknown,
        },

        // Asset group introspection
        ExprKind::GroupFind { .. } | ExprKind::AssetGroupAt { .. } => ArkType::AssetGroup,
        ExprKind::GroupHas { .. } => ArkType::Bool,
        ExprKind::GroupControlIs { .. } => ArkType::Bool,
        ExprKind::AssetGroupsLength => ArkType::Int,
        ExprKind::GroupProperty { property, .. } => match property.as_str() {
            "sumInputs" | "sumOutputs" | "delta" => ArkType::Int,
            "numInputs" | "numOutputs" => ArkType::Int,
            "metadataHash" => ArkType::Bytes32,
            "assetId" | "controlAssetId" => ArkType::Struct("AssetId".to_string()),
            "isFresh" | "hasControl" => ArkType::Bool,
            _ => ArkType::Unknown,
        },
        ExprKind::GroupIOAccess { property, .. } => match property.as_deref() {
            Some("amount") => ArkType::Int,
            Some("type") => ArkType::Int,
            _ => ArkType::Unknown,
        },

        ExprKind::Builtin { builtin, .. } => builtin.result.map_or(ArkType::Bool, ArkType::parse),

        // Byte-string ops
        ExprKind::Concat { .. } => ArkType::Bytes,

        // Arithmetic
        ExprKind::Unary {
            op: UnaryOperator::Invert,
            ..
        } => bytes_of_width(static_byte_width(expr, scope)),
        ExprKind::Unary { op, .. } => ArkType::parse(op.operand_type()),
        ExprKind::Tunnel { .. } => ArkType::Bool,

        // Crypto expressions
        ExprKind::CheckSigExpr { .. }
        | ExprKind::CheckSigFromStackExpr { .. }
        | ExprKind::CheckSigFromStackVerify { .. } => ArkType::Bool,

        // Contract instantiation resolves to a scriptPubKey bytes value.
        ExprKind::ContractInstance { .. } => ArkType::Bytes,

        ExprKind::Cast { target, .. } => ArkType::parse(target),

        // Packet introspection — returns raw packet bytes.
        ExprKind::PacketInspect { .. } => ArkType::Bytes,
        ExprKind::IntentInspect { presence_only, .. } => {
            if *presence_only {
                ArkType::Bool
            } else {
                ArkType::Bytes
            }
        }
        ExprKind::InputPacketInspect { .. } => ArkType::Bytes,

        // Binary operations — type is determined by operand types and operator.
        ExprKind::BinaryOp { left, op, right } => {
            let lt = infer_type(left, scope);
            let rt = infer_type(right, scope);
            match op.class() {
                // bytes-like on either side → concatenation (result Bytes).
                OperatorClass::Arithmetic
                    if *op == BinaryOperator::Add && (is_bytes_like(&lt) || is_bytes_like(&rt)) =>
                {
                    ArkType::Bytes
                }
                OperatorClass::Arithmetic | OperatorClass::Shift => ArkType::Int,
                OperatorClass::Bytewise => bytes_of_width(static_byte_width(expr, scope)),
                OperatorClass::Ordering | OperatorClass::Equality | OperatorClass::Logical => {
                    ArkType::Bool
                }
            }
        }
    }
}

/// Byte length of `expr` when it is known at compile time.
pub(crate) fn static_byte_width(expr: &Expression, scope: &Scope) -> Option<usize> {
    match &expr.kind {
        ExprKind::Literal(value) if value.starts_with("0x") => Some((value.len() - 2) / 2),
        // Bytewise operands share one length, so either side's known width is the result's.
        ExprKind::BinaryOp { left, op, right } if op.class() == OperatorClass::Bytewise => {
            static_byte_width(left, scope).or_else(|| static_byte_width(right, scope))
        }
        ExprKind::Unary {
            op: UnaryOperator::Invert,
            value,
        } => static_byte_width(value, scope),
        _ => match infer_type(expr, scope) {
            ArkType::Bytes20 => Some(20),
            ArkType::Bytes32 => Some(32),
            _ => None,
        },
    }
}

fn bytes_of_width(width: Option<usize>) -> ArkType {
    match width {
        Some(20) => ArkType::Bytes20,
        Some(32) => ArkType::Bytes32,
        _ => ArkType::Bytes,
    }
}

/// Returns true when the type widens to `bytes`: it can be concatenated with
/// `+` and compared or bound to `bytes`, but never to another sized type.
pub fn is_bytes_like(t: &ArkType) -> bool {
    matches!(
        t,
        ArkType::Bytes | ArkType::Bytes20 | ArkType::Bytes32 | ArkType::Signature
    )
}
