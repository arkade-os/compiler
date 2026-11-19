/// Type system for Arkade Script.
///
/// Provides:
/// - `ArkType`: the canonical type enum for all Arkade Script values,
///   including wire-encoding metadata used by client stub generators
/// - `annotate`: stores every expression's type on it before validation;
///   the validator and code generation read `Expression::ty`
use std::collections::HashMap;

use crate::models::{
    AssignmentTarget, Contract, ExprKind, Expression, LocatedStatement, Path, Statement, TypeName,
};
use crate::operators::{BinaryOperator, OperatorClass, UnaryOperator};
use crate::properties::{GroupIoProperty, GroupProperty};

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
    /// Boolean: empty is false and 0x01 is true, the only encodings a witness may use
    Bool,
    /// Position of an asset group in the transaction's asset packet
    AssetGroup,

    // ── Internal / introspection types ─────────────────────────────────────

    // ── Composite ──────────────────────────────────────────────────────────
    /// Homogeneous fixed-size array (e.g., `pubkey[3]`)
    Array(Box<ArkType>, usize),
    /// Named user-defined struct.
    Struct(String),

    /// No stack value: a call to a function without a result.
    Void,

    /// Type could not be resolved (variable not in scope, etc.)
    Unknown,
}

impl ArkType {
    /// Parse from a grammar `data_type` string (e.g., `"pubkey"`, `"bytes32[4]"`).
    pub fn parse(s: &str) -> ArkType {
        crate::models::TypeName::parse(s).ark_type()
    }

    /// The type a builtin or struct name denotes.
    pub(crate) fn named(s: &str) -> ArkType {
        match s {
            "signature" => ArkType::Signature,
            "bytes" | "pubkey" => ArkType::Bytes,
            "bytes20" => ArkType::Bytes20,
            "bytes32" => ArkType::Bytes32,
            "int" => ArkType::Int,
            "bool" => ArkType::Bool,
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
            ArkType::AssetGroup => "scriptnum",
            ArkType::Array(..) => "array",
            ArkType::Struct(..) => "struct",
            ArkType::Void => "void",
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
            ArkType::AssetGroup => "AssetGroup".to_string(),
            ArkType::Array(inner, length) => format!("{}[{length}]", inner.as_str()),
            ArkType::Struct(name) => name.clone(),
            ArkType::Void => "void".to_string(),
            ArkType::Unknown => "unknown".to_string(),
        }
    }
}

impl From<&ArkType> for TypeName {
    fn from(ty: &ArkType) -> Self {
        match ty {
            ArkType::Array(element, length) => TypeName::array((&**element).into(), *length),
            _ => TypeName::Named(ty.as_str()),
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
    declared_type: &TypeName,
    structs: &[crate::models::StructDefinition],
    stack: &mut Vec<String>,
) {
    if let Some((base, length)) = declared_type.array_parts() {
        scope.insert(
            name.to_string(),
            ArkType::Array(Box::new(base.ark_type()), length),
        );
        for index in 0..length {
            insert_type_bindings(scope, &format!("{name}[{index}]"), base, structs, stack);
        }
        return;
    }
    let type_name = declared_type.name().unwrap_or_default();
    if let Some(fields) = crate::models::builtin_struct_fields(type_name) {
        scope.insert(name.to_string(), ArkType::Struct(type_name.to_string()));
        for (field_name, field_type) in fields {
            insert_type_bindings(
                scope,
                &format!("{name}.{field_name}"),
                &TypeName::parse(field_type),
                structs,
                stack,
            );
        }
        return;
    }
    if let Some(definition) = structs
        .iter()
        .find(|definition| definition.name == type_name)
    {
        scope.insert(name.to_string(), ArkType::Struct(type_name.to_string()));
        if stack.iter().any(|name| name == type_name) {
            return;
        }
        stack.push(type_name.to_string());
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
    scope.insert(name.to_string(), declared_type.ark_type());
}

pub(crate) fn bind_local_type(
    scope: &mut Scope,
    name: &str,
    declared_type: Option<&TypeName>,
    inferred: ArkType,
    structs: &[crate::models::StructDefinition],
) {
    let expanded = match declared_type {
        Some(declared_type) => Some(declared_type.clone()),
        None if matches!(inferred, ArkType::Struct(_) | ArkType::Array(..)) => {
            Some(TypeName::from(&inferred))
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

/// Type every expression of the contract's own functions, first resolving
/// call return types and asset-group members, which depend on the types.
pub(crate) fn annotate(contract: &mut Contract) {
    let constructor = build_scope_with_structs(&contract.parameters, &contract.structs);
    let signatures: HashMap<_, _> = contract
        .functions
        .iter()
        .map(|f| {
            let parameters = f.parameters.iter().map(|p| p.param_type.clone()).collect();
            (f.name.clone(), (parameters, f.return_type.clone()))
        })
        .collect();
    for function in contract.functions.iter_mut().filter(|f| !f.is_imported()) {
        let mut scope = constructor.clone();
        scope.extend(build_scope_with_structs(
            &function.parameters,
            &contract.structs,
        ));
        Typing {
            structs: &contract.structs,
            signatures: Some(&signatures),
            result: function.return_type.as_ref(),
        }
        .statements(&mut function.statements, &mut scope);
    }
}

/// Type `statements`, binding their locals into `scope`. For code built from
/// already annotated code, such as an unrolled loop body.
pub(crate) fn annotate_statements(
    statements: &mut [LocatedStatement],
    scope: &mut Scope,
    structs: &[crate::models::StructDefinition],
) {
    Typing {
        structs,
        signatures: None,
        result: None,
    }
    .statements(statements, scope);
}

/// Type one expression of code that has not been annotated.
pub(crate) fn annotate_expression(expression: &mut Expression, scope: &Scope) {
    Typing {
        structs: &[],
        signatures: None,
        result: None,
    }
    .expression(expression, scope);
}

/// Each function's parameter and result types, by name.
type Signatures = HashMap<String, (Vec<TypeName>, Option<TypeName>)>;

struct Typing<'a> {
    structs: &'a [crate::models::StructDefinition],
    /// Present on the first pass, which also resolves names.
    signatures: Option<&'a Signatures>,
    /// The result type of the function being typed.
    result: Option<&'a TypeName>,
}

impl Typing<'_> {
    fn statements(&self, statements: &mut [LocatedStatement], scope: &mut Scope) {
        for statement in statements {
            match &mut statement.statement {
                Statement::Call(value) | Statement::Require(value) => self.expression(value, scope),
                Statement::Return(Some(value)) => {
                    self.expression(value, scope);
                    if let Some(result) = self.result {
                        self.expect(value, &result.ark_type());
                    }
                }
                Statement::Return(None) => {}
                Statement::Declaration {
                    name,
                    declared_type,
                } => {
                    bind_local_type(
                        scope,
                        name,
                        Some(declared_type),
                        declared_type.ark_type(),
                        self.structs,
                    );
                }
                Statement::LetBinding {
                    name,
                    declared_type,
                    value,
                } => {
                    self.expression(value, scope);
                    if let Some(declared_type) = declared_type {
                        self.expect(value, &declared_type.ark_type());
                    }
                    // A binding holds a value, so one of a void initializer has no type.
                    let ty = match (declared_type.as_ref(), &value.ty) {
                        (Some(declared_type), _) => declared_type.ark_type(),
                        (None, ArkType::Void) => ArkType::Unknown,
                        (None, ty) => ty.clone(),
                    };
                    bind_local_type(scope, name, declared_type.as_ref(), ty, self.structs);
                }
                Statement::VarAssign { target, value } => {
                    if let AssignmentTarget::Access(index)
                    | AssignmentTarget::ArrayIndex { index, .. } = target
                    {
                        self.expression(index, scope);
                    }
                    self.expression(value, scope);
                    let target = match target {
                        AssignmentTarget::Binding(path) => scope.get(&path.key()).cloned(),
                        AssignmentTarget::ArrayIndex { array, .. } => match scope.get(&array.key())
                        {
                            Some(ArkType::Array(element, _)) => Some((**element).clone()),
                            _ => None,
                        },
                        AssignmentTarget::Access(access) => Some(access.ty.clone()),
                    };
                    if let Some(target) = target {
                        self.expect(value, &target);
                    }
                }
                Statement::IfElse {
                    condition,
                    then_body,
                    else_body,
                } => {
                    self.expression(condition, scope);
                    self.statements(then_body, &mut scope.clone());
                    if let Some(else_body) = else_body {
                        self.statements(else_body, &mut scope.clone());
                    }
                }
                Statement::ForIn {
                    index_var,
                    value_var,
                    iterable,
                    body,
                } => {
                    self.expression(iterable, scope);
                    // A literal's elements after the first take the first's type.
                    self.expect(iterable, &iterable.ty.clone());
                    let mut body_scope = scope.clone();
                    body_scope.insert(index_var.clone(), ArkType::Int);
                    let element = match &iterable.ty {
                        ArkType::Array(element, _) => (**element).clone(),
                        _ => ArkType::Unknown,
                    };
                    bind_local_type(&mut body_scope, value_var, None, element, self.structs);
                    self.statements(body, &mut body_scope);
                }
                Statement::ForCount { count, body } => {
                    self.expression(count, scope);
                    self.statements(body, &mut scope.clone());
                }
            }
        }
    }

    fn expression(&self, expression: &mut Expression, scope: &Scope) {
        for child in crate::models::child_exprs_mut(expression) {
            self.expression(child, scope);
        }
        if let ExprKind::BinaryOp { left, op, right } = &mut expression.kind {
            self.type_compared_literal(left, *op, right);
        }
        if let Some(signatures) = self.signatures {
            if let ExprKind::Call {
                name,
                args,
                return_type,
            } = &mut expression.kind
            {
                let (parameters, result) = signatures.get(name).cloned().unzip();
                *return_type = result.flatten();
                for (arg, parameter) in args.iter_mut().zip(parameters.unwrap_or_default()) {
                    self.expect(arg, &parameter.ark_type());
                }
            }
            resolve_length(expression, scope);
            resolve_group_member(expression, scope);
        }
        self.expect_operands(expression);
        expression.ty = match &expression.kind {
            // An unknown function, which validation reports, has no result type.
            ExprKind::Call { name, .. }
                if self
                    .signatures
                    .is_some_and(|known| !known.contains_key(name)) =>
            {
                ArkType::Unknown
            }
            // A computed value's member, or one whose path an out-of-range constant index leaves
            // unbound, is typed as the same member of a binding of its type.
            // TODO(ir): scopes key types by binding path, hence the made-up name `$`.
            ExprKind::FieldAccess { value, field }
                if expression
                    .binding_path()
                    .is_none_or(|path| !scope.contains_key(&path.key())) =>
            {
                let mut members = Scope::new();
                bind_local_type(&mut members, "$", None, value.ty.clone(), self.structs);
                let member = expression.with_kind(ExprKind::Name(Path::new("$").field(field)));
                infer_type(&member, &members)
            }
            _ => infer_type(expression, scope),
        };
        // A named literal's own type types its nested literals.
        if matches!(
            expression.kind,
            ExprKind::StructLiteral { name: Some(_), .. }
        ) {
            self.expect(expression, &expression.ty.clone());
        }
    }

    /// Types the literal operands of a builtin or an asset lookup from its signature.
    fn expect_operands(&self, expression: &mut Expression) {
        match &mut expression.kind {
            ExprKind::Builtin { builtin, args } => {
                for (arg, (_, parameter)) in args.iter_mut().zip(builtin.params) {
                    // `T[]` takes its length from the operand.
                    let ty = match parameter.strip_suffix("[]") {
                        Some(element) => ArkType::Array(Box::new(ArkType::parse(element)), 0),
                        None => ArkType::parse(parameter),
                    };
                    self.expect(arg, &ty);
                }
            }
            ExprKind::AssetLookup { asset_id, .. }
            | ExprKind::AssetHas { asset_id, .. }
            | ExprKind::AssetTryLookup { asset_id, .. }
            | ExprKind::GroupLookup { asset_id }
            | ExprKind::GroupHas { asset_id }
            | ExprKind::GroupControlIs { asset_id, .. } => {
                self.expect(asset_id, &ArkType::Struct("AssetId".to_string()))
            }
            _ => {}
        }
    }

    /// Gives an unnamed struct literal or an array literal `ty`, the type it is checked
    /// against, and the literals nested in it their field or element types; an array
    /// literal already typed from its first element keeps that type.
    fn expect(&self, value: &mut Expression, ty: &ArkType) {
        match (&mut value.kind, ty) {
            (ExprKind::ArrayLiteral(elements), ArkType::Array(element, _)) => {
                for value in elements.iter_mut() {
                    self.expect(value, element);
                }
                if !resolved(&value.ty) {
                    value.ty = ArkType::Array(element.clone(), elements.len());
                }
            }
            (ExprKind::StructLiteral { name, fields }, ArkType::Struct(_)) => {
                // A named literal's fields follow its own name.
                let own = name.as_ref().map(|name| ArkType::Struct(name.clone()));
                let mut members = Scope::new();
                let struct_type = own.unwrap_or_else(|| ty.clone());
                bind_local_type(&mut members, "$", None, struct_type, self.structs);
                for (field, value) in fields {
                    if let Some(ty) = members.get(&format!("$.{field}")) {
                        self.expect(value, ty);
                    }
                }
                if value.ty == ArkType::Unknown {
                    value.ty = ty.clone();
                }
            }
            _ => {}
        }
    }

    /// An unnamed struct literal or an array literal takes the resolved type of the
    /// value it is tested for equality with, as an initializer takes its declared
    /// type, while an array literal keeps its length; the validator checks the
    /// literal against that type. Two literals keep their own types, as typing one
    /// from the other would depend on operand order.
    fn type_compared_literal(
        &self,
        left: &mut Expression,
        op: BinaryOperator,
        right: &mut Expression,
    ) {
        if op.class() != OperatorClass::Equality {
            return;
        }
        let literal = |e: &Expression| {
            matches!(
                e.kind,
                ExprKind::ArrayLiteral(_) | ExprKind::StructLiteral { .. }
            )
        };
        let typed_by = |value: &Expression, peer: &Expression| match (&value.kind, &peer.ty) {
            _ if literal(peer) || !resolved(&peer.ty) => None,
            (ExprKind::ArrayLiteral(elements), ArkType::Array(element, _)) => {
                Some(ArkType::Array(element.clone(), elements.len()))
            }
            (ExprKind::StructLiteral { name: None, .. }, ArkType::Struct(_)) => {
                Some(peer.ty.clone())
            }
            _ => None,
        };
        if let Some(ty) = typed_by(left, right) {
            left.ty = ty.clone();
            self.expect(left, &ty);
        } else if let Some(ty) = typed_by(right, left) {
            right.ty = ty.clone();
            self.expect(right, &ty);
        }
    }
}

/// A member of an `AssetGroup` value is the group opcode that computes it;
/// every other value keeps its own fields.
fn resolve_group_member(expression: &mut Expression, scope: &Scope) {
    let resolved = match &expression.kind {
        // `g.delta`, `s.group.delta`
        ExprKind::Name(path) => path.split_last().and_then(|(base, property)| {
            Some(ExprKind::GroupProperty {
                group: Box::new(group_binding(base, expression, scope)?),
                property: GroupProperty::from_name(property)?,
            })
        }),
        // `g.inputs[j]`
        ExprKind::ArrayIndex { array, index } => array.split_last().and_then(|(base, source)| {
            Some(ExprKind::GroupIOAccess {
                group: Box::new(group_binding(base, expression, scope)?),
                io_index: index.clone(),
                source: group_io_source(source)?,
                property: None,
            })
        }),
        // `gs[i].inputs[j]`
        ExprKind::IndexAccess { value, index } => match &value.as_ref().kind {
            ExprKind::FieldAccess {
                value: group,
                field,
            } if group.ty == ArkType::AssetGroup => {
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
            } if GroupIoProperty::from_name(field).is_some() => Some(ExprKind::GroupIOAccess {
                group: group.clone(),
                io_index: io_index.clone(),
                source: source.clone(),
                property: GroupIoProperty::from_name(field),
            }),
            _ if value.ty == ArkType::AssetGroup => {
                GroupProperty::from_name(field).map(|property| ExprKind::GroupProperty {
                    group: value.clone(),
                    property,
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

/// `.length` of a bytes-like value is `size(value)`, and of a group's `inputs` or
/// `outputs` its `numInputs` or `numOutputs`; an array's stays its static length.
fn resolve_length(expression: &mut Expression, scope: &Scope) {
    let value = match &expression.kind {
        ExprKind::Name(path) => match path.split_last() {
            Some((base, "length")) => {
                let mut value = expression.with_kind(ExprKind::Name(base));
                value.ty = infer_type(&value, scope);
                value
            }
            _ => return,
        },
        ExprKind::FieldAccess { value, field } if field == "length" => (**value).clone(),
        _ => return,
    };
    let count = |source: &str| match source {
        "inputs" => Some(GroupProperty::NumInputs),
        "outputs" => Some(GroupProperty::NumOutputs),
        _ => None,
    };
    let resolved = match value.kind {
        _ if is_bytes_like(&value.ty) => Some(ExprKind::Builtin {
            builtin: crate::builtins::find("size").expect("size is a builtin"),
            args: vec![value],
        }),
        // `g.inputs.length`
        ExprKind::Name(path) => path.split_last().and_then(|(base, source)| {
            Some(ExprKind::GroupProperty {
                group: Box::new(group_binding(base, expression, scope)?),
                property: count(source)?,
            })
        }),
        // `tx.assetGroups[k].inputs.length`
        ExprKind::FieldAccess {
            value: group,
            field,
        } if group.ty == ArkType::AssetGroup => {
            count(&field).map(|property| ExprKind::GroupProperty { group, property })
        }
        _ => None,
    };
    if let Some(resolved) = resolved {
        expression.kind = resolved;
    }
}

/// The binding named by `path`, when it is an `AssetGroup`; it takes the span
/// of the access `at`, which has none narrower for the binding alone.
fn group_binding(path: Path, at: &Expression, scope: &Scope) -> Option<Expression> {
    let mut binding = at.with_kind(ExprKind::Name(path));
    binding.ty = infer_type(&binding, scope);
    (binding.ty == ArkType::AssetGroup).then_some(binding)
}

pub(crate) fn group_io_source(name: &str) -> Option<crate::models::GroupIOSource> {
    match name {
        "inputs" => Some(crate::models::GroupIOSource::Inputs),
        "outputs" => Some(crate::models::GroupIOSource::Outputs),
        _ => None,
    }
}

/// Whether a value of type `t` can be compared with `hash_fn`'s digest.
pub(crate) fn digest_accepts(hash_fn: &crate::models::HashFn, t: &ArkType) -> bool {
    *t == ArkType::Bytes || *t == ArkType::parse(hash_fn.digest_type())
}

// ─── Type Inference ───────────────────────────────────────────────────────────

/// Infer the `ArkType` of an expression given the current variable scope and
/// the types already stored on its children.
///
/// Returns `ArkType::Unknown` for expressions whose type cannot be determined
/// statically (e.g., unresolved variables, not-yet-implemented forms).
fn infer_type(expr: &Expression, scope: &Scope) -> ArkType {
    match &expr.kind {
        ExprKind::Call { return_type, .. } => return_type
            .as_ref()
            .map_or(ArkType::Void, TypeName::ark_type),
        ExprKind::Literal(value) if matches!(value.as_str(), "true" | "false") => ArkType::Bool,
        ExprKind::Literal(value) if value.starts_with("0x") => {
            bytes_of_width(static_byte_width(expr))
        }
        ExprKind::Literal(_) => ArkType::Int,
        ExprKind::ArrayLiteral(elements) => ArkType::Array(
            Box::new(
                elements
                    .first()
                    .map(|element| element.ty.clone())
                    .unwrap_or(ArkType::Unknown),
            ),
            elements.len(),
        ),
        // An unnamed literal keeps the type it is checked against.
        ExprKind::StructLiteral { name, .. } => name
            .as_ref()
            .map_or_else(|| expr.ty.clone(), |name| ArkType::Struct(name.clone())),
        ExprKind::FieldAccess { .. } => expr
            .binding_path()
            .map(|path| infer_type(&expr.with_kind(ExprKind::Name(path)), scope))
            .unwrap_or(ArkType::Unknown),
        ExprKind::IndexAccess { value, .. } => match &value.ty {
            ArkType::Array(element, _) => (**element).clone(),
            _ => ArkType::Unknown,
        },
        ExprKind::ArrayIndex { array, .. } => match scope.get(&array.key()) {
            Some(ArkType::Array(element, _)) => (**element).clone(),
            _ => ArkType::Unknown,
        },
        ExprKind::Name(path) => scope
            .get(&path.key())
            .cloned()
            .or_else(|| {
                let (array, field) = path.split_last()?;
                (field == "length" && matches!(scope.get(&array.key())?, ArkType::Array(..)))
                    .then_some(ArkType::Int)
            })
            .unwrap_or(ArkType::Unknown),

        ExprKind::This(property) => ArkType::parse(property.value_type()),
        // Extraction keeps the extracted value's type on the node.
        ExprKind::Extracted(_) => expr.ty.clone(),
        ExprKind::TxIntrospection { property } => ArkType::parse(property.value_type()),
        ExprKind::InputIntrospection { property, .. } => ArkType::parse(property.value_type()),
        ExprKind::OutputIntrospection { property, .. } => ArkType::parse(property.value_type()),

        // Asset introspection
        ExprKind::AssetLookup { .. } => ArkType::Int,
        ExprKind::AssetHas { .. } => ArkType::Bool,
        ExprKind::AssetCount { .. } => ArkType::Int,
        ExprKind::AssetTryLookup { .. } => ArkType::Struct("AssetLookup".to_string()),
        ExprKind::AssetAt { property, .. } => {
            ArkType::parse(property.map_or("AssetEntry", |p| p.value_type()))
        }

        // Asset group introspection
        ExprKind::GroupLookup { .. } | ExprKind::AssetGroupAt { .. } => ArkType::AssetGroup,
        ExprKind::GroupHas { .. } => ArkType::Bool,
        ExprKind::GroupControlIs { .. } => ArkType::Bool,
        ExprKind::AssetGroupsLength => ArkType::Int,
        ExprKind::GroupProperty { property, .. } => ArkType::parse(property.value_type()),
        ExprKind::GroupIOAccess {
            source, property, ..
        } => ArkType::parse(property.map_or(source.record_type(), |p| p.value_type())),

        ExprKind::Builtin { builtin, .. } => ArkType::parse(builtin.result),

        // Arithmetic
        ExprKind::Unary {
            op: UnaryOperator::Invert,
            ..
        } => bytes_of_width(static_byte_width(expr)),
        ExprKind::Unary { op, .. } => ArkType::parse(op.operand_type()),
        ExprKind::Tunnel { .. } => ArkType::Bool,

        // Contract instantiation includes the Taproot witness version.
        ExprKind::ContractInstance { .. } => ArkType::Struct("ScriptPubKey".to_string()),

        ExprKind::Cast { target, .. } => ArkType::parse(target),

        // Packet introspection — returns raw packet bytes.
        ExprKind::PacketInspect { presence_only, .. }
        | ExprKind::InputPacketInspect { presence_only, .. } => {
            if *presence_only {
                ArkType::Bool
            } else {
                ArkType::Bytes
            }
        }
        ExprKind::IntentInspect { presence_only, .. } => {
            if *presence_only {
                ArkType::Bool
            } else {
                ArkType::Bytes
            }
        }

        // Binary operations — type is determined by operand types and operator.
        ExprKind::BinaryOp { left, op, right } => {
            match op.class() {
                // bytes-like on either side → concatenation (result Bytes).
                OperatorClass::Arithmetic
                    if *op == BinaryOperator::Add
                        && (is_bytes_like(&left.ty) || is_bytes_like(&right.ty)) =>
                {
                    ArkType::Bytes
                }
                OperatorClass::Arithmetic | OperatorClass::Shift => ArkType::Int,
                OperatorClass::Bytewise => bytes_of_width(static_byte_width(expr)),
                OperatorClass::Ordering | OperatorClass::Equality | OperatorClass::Logical => {
                    ArkType::Bool
                }
            }
        }
    }
}

/// Byte length of `expr` when it is known at compile time.
pub(crate) fn static_byte_width(expr: &Expression) -> Option<usize> {
    match &expr.kind {
        ExprKind::Literal(value) if value.starts_with("0x") => Some((value.len() - 2) / 2),
        // Bytewise operands share one length, so either side's known width is the result's.
        ExprKind::BinaryOp { left, op, right } if op.class() == OperatorClass::Bytewise => {
            static_byte_width(left).or_else(|| static_byte_width(right))
        }
        ExprKind::Unary {
            op: UnaryOperator::Invert,
            value,
        } => static_byte_width(value),
        _ => match expr.ty {
            ArkType::Bytes20 => Some(20),
            ArkType::Bytes32 => Some(32),
            _ => None,
        },
    }
}

pub(crate) fn bytes_of_width(width: Option<usize>) -> ArkType {
    match width {
        Some(20) => ArkType::Bytes20,
        Some(32) => ArkType::Bytes32,
        _ => ArkType::Bytes,
    }
}

/// Whether the type is known down to its array elements.
pub(crate) fn resolved(ty: &ArkType) -> bool {
    match ty {
        ArkType::Array(element, _) => resolved(element),
        ty => *ty != ArkType::Unknown,
    }
}

/// Whether values of the type are script numbers.
pub(crate) fn is_numeric(t: &ArkType) -> bool {
    t.encoding() == "scriptnum"
}

/// Returns true when the type widens to `bytes`: it can be concatenated with
/// `+` and compared or bound to `bytes`, but never to another sized type.
pub fn is_bytes_like(t: &ArkType) -> bool {
    matches!(
        t,
        ArkType::Bytes | ArkType::Bytes20 | ArkType::Bytes32 | ArkType::Signature
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_asset_groups_have_group_members() {
        let mut contract = crate::parser::parse(
            "struct S { int delta; }
            contract V(AssetGroup g, int x, S s, bytes b) {
                function spend() { let p = g.delta; let q = x.delta; let r = s.delta; let t = (b + b).delta; }
            }",
        )
        .expect("parses");
        annotate(&mut contract);
        let members: Vec<_> = contract.functions[0]
            .statements
            .iter()
            .map(|statement| match &statement.statement {
                Statement::LetBinding { value, .. } => {
                    matches!(value.kind, ExprKind::GroupProperty { .. })
                }
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(members, [true, false, false, false]);
    }
}
