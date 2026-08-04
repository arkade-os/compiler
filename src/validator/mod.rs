//! Semantic validation for Arkade Script contracts.
//!
//! This module provides two validation passes:
//!
//! 1. **AST validation** (`validate_ast`) — runs after parsing, before compilation.
//!    Catches semantic errors that the PEG grammar cannot express, such as duplicate
//!    names, reserved tapscript roles, and invalid Asset ID operands.
//!    Also performs CashScript-style require-guard checks (warn when a function has
//!    no `require()` statements — it would trivially pass all spends).
//!
//! 2. **Output validation** (`validate_output`) — runs after compilation.
//!    Asserts structural invariants on the emitted `ContractJson`, catching compiler
//!    bugs before the output reaches callers: every spend group has at least one
//!    leaf, each leaf has non-empty `asm`, each present `arkade` covenant has
//!    non-empty `asm`, and no leaf `asm` carries a signature placeholder
//!    (signatures are witness-only). Tapscript-source-level operand scope checks
//!    live in `compiler::tapscript::validate_arkd_rules`.
//!
//! Issues are returned as a `Vec<ValidationIssue>`.  Use [`has_errors`] to check
//! whether any are fatal.

use crate::models::{Contract, ContractJson, Expression, Requirement, Statement};
use crate::typechecker::{build_scope_with_structs, infer_type, ArkType, Scope};
use std::collections::{HashMap, HashSet};

// ─── Issue types ──────────────────────────────────────────────────────────────

/// Severity of a validation issue.
#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    /// Compilation must halt; the contract cannot be safely emitted.
    Error,
    /// Non-fatal; compilation continues but the caller should surface this.
    /// Retained for the output-invariant warning path (compiler::compile);
    /// no validator check currently emits one.
    #[allow(dead_code)]
    Warning,
}

/// A single validation finding.
#[derive(Debug, Clone)]
pub struct ValidationIssue {
    pub severity: Severity,
    pub message: String,
}

impl ValidationIssue {
    fn error(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            message: message.into(),
        }
    }

    #[allow(dead_code)]
    fn warning(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            message: message.into(),
        }
    }
}

/// Returns `true` if any issue in the slice is [`Severity::Error`].
pub fn has_errors(issues: &[ValidationIssue]) -> bool {
    issues.iter().any(|i| matches!(i.severity, Severity::Error))
}

// ─── AST validation ───────────────────────────────────────────────────────────

/// Validate the parsed [`Contract`] AST for semantic errors before compilation.
///
/// Checks performed:
/// - Contract name is non-empty.
/// - At least one non-internal function is declared.
/// - Function names are unique within the contract.
/// - Tapscript names are unique within the contract.
/// - Constructor parameter names are unique.
/// - Each function's parameter names are unique within that function.
/// - Tapscript inputs do not collide with reserved key roles.
/// - Asset ID operands have the expected txid/gidx types.
pub fn validate_ast(contract: &Contract) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();

    check_struct_definitions(contract, &mut issues);

    // ── Contract name ──────────────────────────────────────────────────────
    if contract.name.is_empty() {
        issues.push(ValidationIssue::error("contract name must not be empty"));
    }

    // ── At least one non-internal function or tapscript ──────────────────
    let non_internal_count = contract.functions.iter().filter(|f| !f.is_internal).count();
    if non_internal_count == 0 && contract.tapscripts.is_empty() {
        issues.push(ValidationIssue::error(
            "contract must declare at least one non-internal function",
        ));
    }

    // ── Unique function names ──────────────────────────────────────────────
    {
        let mut seen: HashSet<&str> = HashSet::new();
        for func in &contract.functions {
            if !seen.insert(func.name.as_str()) {
                issues.push(ValidationIssue::error(format!(
                    "duplicate function name '{}'; each function must have a unique name",
                    func.name
                )));
            }
        }
    }

    // ── Unique constructor parameter names ────────────────────────────────
    {
        let mut seen: HashSet<&str> = HashSet::new();
        for param in &contract.parameters {
            validate_source_identifier(&param.name, "constructor parameter", &mut issues);
            if !seen.insert(param.name.as_str()) {
                issues.push(ValidationIssue::error(format!(
                    "duplicate constructor parameter '{}'",
                    param.name
                )));
            }
        }
    }

    // ── Unique parameter names within each function ────────────────────────
    for func in &contract.functions {
        let mut seen: HashSet<&str> = HashSet::new();
        for param in &func.parameters {
            validate_source_identifier(
                &param.name,
                &format!("parameter in function '{}'", func.name),
                &mut issues,
            );
            if !seen.insert(param.name.as_str()) {
                issues.push(ValidationIssue::error(format!(
                    "duplicate parameter '{}' in function '{}'",
                    param.name, func.name
                )));
            }
        }
    }

    // ── Require-guard check ────────────────────────────
    // Every execution path through a covenant function must hit at least one
    // require(). Each require() fails fast via OP_VERIFY and the covenant
    // terminates with OP_1, so a path that reaches the end with no require()
    // would pass any spend on that path — almost certainly a security bug.
    for func in contract.functions.iter().filter(|f| !f.is_internal) {
        if !block_guarantees_require(&func.statements) {
            issues.push(ValidationIssue::error(format!(
                "function '{}' has a spend path with no require(); \
                 every branch must enforce at least one condition",
                func.name
            )));
        }
    }

    // ── Tapscript reserved-name + duplicate checks ────────────────────────
    {
        let mut seen: HashSet<&str> = HashSet::new();
        for ts in &contract.tapscripts {
            if !seen.insert(ts.name.as_str()) {
                issues.push(ValidationIssue::error(format!(
                    "duplicate tapscript name '{}'; each tapscript must have a unique name",
                    ts.name
                )));
            }
        }
    }

    // Reserved key roles may only appear as key operands inside a tapscript's
    // checkSig/checkMultisig — never as constructor parameters.
    for p in &contract.parameters {
        if p.name == "server" || p.name == "emulator" {
            issues.push(ValidationIssue::error(format!(
                "constructor parameter '{}' collides with a reserved key role",
                p.name
            )));
        }
    }

    for ts in &contract.tapscripts {
        for p in &ts.inputs {
            validate_source_identifier(
                &p.name,
                &format!("input in tapscript '{}'", ts.name),
                &mut issues,
            );
            if p.name == "server" || p.name == "emulator" {
                issues.push(ValidationIssue::error(format!(
                    "tapscript '{}' input '{}' collides with a reserved key role",
                    ts.name, p.name
                )));
            }
            if crate::models::array_type_parts(&p.param_type).is_some() {
                issues.push(ValidationIssue::error(format!(
                    "tapscript '{}' input '{}' has array type '{}'; array witnesses are not \
                     supported in tapscript functions",
                    ts.name, p.name, p.param_type
                )));
            }
            if contract
                .structs
                .iter()
                .any(|definition| definition.name == p.param_type)
            {
                issues.push(ValidationIssue::error(format!(
                    "tapscript '{}' input '{}' has struct type '{}'; struct witnesses are not supported in tapscript functions",
                    ts.name, p.name, p.param_type
                )));
            }
        }
        // Duplicate input names within a tapscript.
        let mut seen = std::collections::HashSet::new();
        for p in &ts.inputs {
            if !seen.insert(p.name.as_str()) {
                issues.push(ValidationIssue::error(format!(
                    "duplicate input '{}' in tapscript '{}'",
                    p.name, ts.name
                )));
            }
        }
    }

    check_shadowing(contract, &mut issues);
    check_expanded_namespace(contract, &mut issues);
    check_binding_semantics(contract, &mut issues);
    check_asset_id_operands(contract, &mut issues);

    issues
}

fn check_struct_definitions(contract: &Contract, issues: &mut Vec<ValidationIssue>) {
    let mut names = HashSet::new();
    for definition in &contract.structs {
        if crate::models::is_builtin_type(&definition.name) {
            issues.push(ValidationIssue::error(format!(
                "struct '{}' collides with a built-in type",
                definition.name
            )));
        }
        if !names.insert(definition.name.as_str()) {
            issues.push(ValidationIssue::error(format!(
                "duplicate struct definition '{}'",
                definition.name
            )));
        }
        let mut fields = HashSet::new();
        for field in &definition.fields {
            if !fields.insert(field.name.as_str()) {
                issues.push(ValidationIssue::error(format!(
                    "duplicate field '{}' in struct '{}'",
                    field.name, definition.name
                )));
            }
        }
    }

    let definitions = contract
        .structs
        .iter()
        .map(|definition| (definition.name.as_str(), definition))
        .collect::<HashMap<_, _>>();
    for definition in &contract.structs {
        validate_struct_fields(definition, &definitions, &mut Vec::new(), issues);
    }
    for parameter in contract
        .parameters
        .iter()
        .chain(
            contract
                .functions
                .iter()
                .flat_map(|function| &function.parameters),
        )
        .chain(
            contract
                .tapscripts
                .iter()
                .flat_map(|tapscript| &tapscript.inputs),
        )
    {
        validate_declared_type(&parameter.param_type, "parameter", &definitions, issues);
    }
    for function in &contract.functions {
        validate_local_types(&function.statements, &function.name, &definitions, issues);
    }
}

fn validate_local_types(
    statements: &[Statement],
    function_name: &str,
    definitions: &HashMap<&str, &crate::models::StructDefinition>,
    issues: &mut Vec<ValidationIssue>,
) {
    for statement in statements {
        match statement {
            Statement::LetBinding {
                declared_type: Some(declared_type),
                ..
            } => validate_declared_type(
                declared_type,
                &format!("local declaration in function '{function_name}'"),
                definitions,
                issues,
            ),
            Statement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                validate_local_types(then_body, function_name, definitions, issues);
                if let Some(else_body) = else_body {
                    validate_local_types(else_body, function_name, definitions, issues);
                }
            }
            Statement::ForIn { body, .. } => {
                validate_local_types(body, function_name, definitions, issues);
            }
            _ => {}
        }
    }
}

fn validate_struct_fields<'a>(
    definition: &'a crate::models::StructDefinition,
    definitions: &HashMap<&'a str, &'a crate::models::StructDefinition>,
    stack: &mut Vec<&'a str>,
    issues: &mut Vec<ValidationIssue>,
) {
    if stack.contains(&definition.name.as_str()) {
        let mut cycle = stack.join(" -> ");
        if !cycle.is_empty() {
            cycle.push_str(" -> ");
        }
        cycle.push_str(&definition.name);
        issues.push(ValidationIssue::error(format!(
            "recursive struct layout: {cycle}"
        )));
        return;
    }
    stack.push(&definition.name);
    for field in &definition.fields {
        validate_declared_type(
            &field.param_type,
            &format!("field '{}.{}'", definition.name, field.name),
            definitions,
            issues,
        );
        let (base, is_array) = crate::models::array_type_parts(&field.param_type)
            .map(|(base, _)| (base, true))
            .unwrap_or((field.param_type.as_str(), false));
        if let Some(nested) = definitions.get(base) {
            if is_array {
                issues.push(ValidationIssue::error(format!(
                    "field '{}.{}' is an array of structs; arrays of structs are not supported",
                    definition.name, field.name
                )));
            } else {
                validate_struct_fields(nested, definitions, stack, issues);
            }
        }
    }
    stack.pop();
}

fn validate_declared_type(
    declared_type: &str,
    context: &str,
    definitions: &HashMap<&str, &crate::models::StructDefinition>,
    issues: &mut Vec<ValidationIssue>,
) {
    let array = crate::models::array_type_parts(declared_type);
    let base = array.map(|(base, _)| base).unwrap_or(declared_type);
    if !crate::models::is_builtin_type(base) && !definitions.contains_key(base) {
        issues.push(ValidationIssue::error(format!(
            "{context} uses unknown type '{base}'"
        )));
    }
    if array.is_some() && definitions.contains_key(base) {
        issues.push(ValidationIssue::error(format!(
            "{context} uses an array of structs; arrays of structs are not supported"
        )));
    }
}

fn validate_source_identifier(name: &str, context: &str, issues: &mut Vec<ValidationIssue>) {
    if name == "SERVER_KEY" {
        issues.push(ValidationIssue::error(format!(
            "{context} '{name}' uses a compiler-reserved placeholder name"
        )));
    }
}

// ─── Asset ID operand validation (fatal) ───────────────────────────────────────

/// Reject malformed canonical Asset ID operands at compile time instead of
/// relying on the emulator's runtime `popAssetID` check. For every
/// `lookup`/`find`/`has`/`controlIs` operand:
/// - `asset_txid` must resolve to `Bytes32` (rejects `Unknown`/swapped types),
/// - `asset_gidx` must resolve to `Int` (rejects `Unknown`); a numeric literal
///   must additionally be in `0..=65535`.
///
/// Scope-aware: seeds constructor + function params, infers `let`/assignment
/// values, binds a `for` loop's index variable as `Int`. The loop value
/// variable stays `Unknown` (no iterable-element typing yet) and is therefore
/// not accepted as an Asset ID component.
fn check_asset_id_operands(contract: &Contract, issues: &mut Vec<ValidationIssue>) {
    let ctor_scope = build_scope_with_structs(&contract.parameters, &contract.structs);
    for func in &contract.functions {
        let mut scope = ctor_scope.clone();
        scope.extend(build_scope_with_structs(
            &func.parameters,
            &contract.structs,
        ));
        walk_asset_id_stmts(&func.statements, &mut scope, &func.name, issues);
    }
}

fn walk_asset_id_stmts(
    stmts: &[Statement],
    scope: &mut Scope,
    fname: &str,
    issues: &mut Vec<ValidationIssue>,
) {
    for stmt in stmts {
        match stmt {
            Statement::Require(req) => match req {
                Requirement::Expression(expr) => {
                    check_asset_id_expr(expr, scope, fname, issues);
                }
                Requirement::Comparison { left, right, .. } => {
                    check_asset_id_expr(left, scope, fname, issues);
                    check_asset_id_expr(right, scope, fname, issues);
                }
                _ => {}
            },
            Statement::LetBinding { name, value, .. } => {
                check_asset_id_expr(value, scope, fname, issues);
                let t = infer_type(value, scope);
                scope.insert(name.clone(), t);
            }
            Statement::VarAssign { name, value } => {
                check_asset_id_expr(value, scope, fname, issues);
                let t = infer_type(value, scope);
                scope.insert(name.clone(), t);
            }
            Statement::IfElse {
                condition,
                then_body,
                else_body,
            } => {
                check_asset_id_expr(condition, scope, fname, issues);
                walk_asset_id_stmts(then_body, &mut scope.clone(), fname, issues);
                if let Some(eb) = else_body {
                    walk_asset_id_stmts(eb, &mut scope.clone(), fname, issues);
                }
            }
            Statement::ForIn {
                index_var,
                value_var,
                body,
                ..
            } => {
                let mut loop_scope = scope.clone();
                loop_scope.insert(index_var.clone(), ArkType::Int);
                loop_scope.insert(value_var.clone(), ArkType::Unknown);
                walk_asset_id_stmts(body, &mut loop_scope, fname, issues);
            }
        }
    }
}

/// Walk an expression, validating the operands of every Asset ID construct and
/// recursing through every sub-expression that can nest one.
///
/// Traversal and validation are deliberately split: this function validates the
/// Asset ID operands of the constructs that carry them, then recurses into *all*
/// direct sub-expressions via [`child_exprs`]. Because `child_exprs` is an
/// exhaustive match with no wildcard, any future `Expression` variant forces a
/// decision there and can never silently bypass this validation by falling
/// through a catch-all.
fn check_asset_id_expr(
    expr: &Expression,
    scope: &Scope,
    fname: &str,
    issues: &mut Vec<ValidationIssue>,
) {
    // Variant-specific Asset ID operand validation.
    match expr {
        Expression::AssetLookup {
            asset_txid,
            asset_gidx,
            ..
        }
        | Expression::AssetHas {
            asset_txid,
            asset_gidx,
            ..
        }
        | Expression::GroupFind {
            asset_txid,
            asset_gidx,
        }
        | Expression::GroupHas {
            asset_txid,
            asset_gidx,
        }
        | Expression::GroupControlIs {
            asset_txid,
            asset_gidx,
            ..
        } => {
            validate_asset_id(asset_txid, asset_gidx, scope, fname, issues);
        }
        _ => {}
    }

    // Generic recursion through every sub-expression.
    for child in child_exprs(expr) {
        check_asset_id_expr(child, scope, fname, issues);
    }
}

/// Return the direct sub-expressions of `expr`.
///
/// This is the single source of truth for expression-tree traversal in the
/// validator. The match is intentionally exhaustive (no `_` arm): adding a new
/// [`Expression`] variant will fail to compile here until its nested
/// expressions — if any — are declared, guaranteeing that walkers built on top
/// of this (e.g. [`check_asset_id_expr`]) cover every new construct.
fn child_exprs(expr: &Expression) -> Vec<&Expression> {
    match expr {
        // Leaf nodes: no nested expressions.
        Expression::Variable(_)
        | Expression::Literal(_)
        | Expression::Property(_)
        | Expression::CurrentInput(_)
        | Expression::TxIntrospection { .. }
        | Expression::GroupProperty { .. }
        | Expression::AssetGroupsLength
        | Expression::CheckSigExpr { .. }
        | Expression::CheckSigFromStackExpr { .. }
        | Expression::CheckSigFromStackVerify { .. } => vec![],

        Expression::ArrayIndex { index, .. } => vec![index],

        Expression::ArrayLiteral(elements) => elements.iter().collect(),

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
        Expression::Negate { value } => vec![value],
        Expression::ModExp {
            base,
            exponent,
            modulus,
        } => vec![base, exponent, modulus],
        Expression::EcAdd {
            x1,
            y1,
            x2,
            y2,
            curve_id,
        } => vec![x1, y1, x2, y2, curve_id],
        Expression::EcMul {
            x,
            y,
            scalar,
            curve_id,
        } => vec![x, y, scalar, curve_id],
        Expression::EcPairing {
            g1_x,
            g1_y,
            g2_x_c1,
            g2_x_c0,
            g2_y_c1,
            g2_y_c0,
            curve_id,
        } => vec![g1_x, g1_y, g2_x_c1, g2_x_c0, g2_y_c1, g2_y_c0, curve_id],
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
        Expression::ContractInstance { args, .. } => args.iter().collect(),
        Expression::Substr { data, offset, size } => vec![data, offset, size],
        Expression::Cat { left, right } => vec![left, right],
        Expression::Bin2Num { data }
        | Expression::ReverseBytes { data }
        | Expression::SizeOf { data } => vec![data],
        Expression::Num2Bin { value, size } => vec![value, size],
        Expression::PacketInspect { packet_type } => vec![packet_type],
        Expression::InputPacketInspect { index, packet_type } => vec![index, packet_type],
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BindingSource {
    Constructor,
    FunctionInput,
    Local,
    Loop,
}

#[derive(Clone, Debug)]
struct BindingInfo {
    binding_type: ArkType,
    source: BindingSource,
}

type BindingScopes = Vec<HashMap<String, BindingInfo>>;

fn insert_parameters(
    frame: &mut HashMap<String, BindingInfo>,
    parameters: &[crate::models::Parameter],
    source: BindingSource,
    structs: &[crate::models::StructDefinition],
) {
    let types = build_scope_with_structs(parameters, structs);
    for (name, binding_type) in types {
        frame.insert(
            name,
            BindingInfo {
                binding_type,
                source,
            },
        );
    }
}

fn find_binding<'a>(scopes: &'a BindingScopes, name: &str) -> Option<&'a BindingInfo> {
    if let Some((array, index)) = name.strip_suffix(']').and_then(|name| name.split_once('[')) {
        if index.parse::<usize>().is_err() {
            let first_element = format!("{array}[0]");
            return scopes
                .iter()
                .rev()
                .find_map(|frame| frame.get(&first_element));
        }
    }
    scopes.iter().rev().find_map(|frame| frame.get(name))
}

fn flattened_types(scopes: &BindingScopes) -> Scope {
    let mut result = Scope::new();
    for frame in scopes {
        result.extend(
            frame
                .iter()
                .map(|(name, info)| (name.clone(), info.binding_type.clone())),
        );
    }
    result
}

fn resolved_expression_type(expression: &Expression, scopes: &BindingScopes) -> ArkType {
    match expression {
        Expression::Variable(name) | Expression::Property(name) => find_binding(scopes, name)
            .map(|binding| binding.binding_type.clone())
            .unwrap_or_else(|| infer_type(expression, &flattened_types(scopes))),
        _ => infer_type(expression, &flattened_types(scopes)),
    }
}

fn binding_types_compatible(expected: &ArkType, actual: &ArkType) -> bool {
    expected == actual
        || matches!(
            (expected, actual),
            (ArkType::Bytes, ArkType::Bytes20 | ArkType::Bytes32)
        )
}

fn check_binding_semantics(contract: &Contract, issues: &mut Vec<ValidationIssue>) {
    for function in &contract.functions {
        let mut root = HashMap::new();
        insert_parameters(
            &mut root,
            &contract.parameters,
            BindingSource::Constructor,
            &contract.structs,
        );
        insert_parameters(
            &mut root,
            &function.parameters,
            BindingSource::FunctionInput,
            &contract.structs,
        );
        let mut scopes = vec![root];
        validate_binding_statements(&function.statements, &function.name, &mut scopes, issues);
    }
}

fn validate_binding_statements(
    statements: &[Statement],
    function_name: &str,
    scopes: &mut BindingScopes,
    issues: &mut Vec<ValidationIssue>,
) {
    for statement in statements {
        match statement {
            Statement::Require(requirement) => {
                validate_binding_requirement(requirement, function_name, scopes, issues);
            }
            Statement::LetBinding {
                name,
                declared_type,
                value,
            } => {
                // Array literals are the one composite value allowed in a value
                // position, and only here; validate their elements instead.
                match value {
                    Expression::ArrayLiteral(elements) => {
                        for element in elements {
                            validate_binding_expression(
                                element,
                                function_name,
                                scopes,
                                issues,
                                true,
                            );
                        }
                    }
                    _ => validate_binding_expression(value, function_name, scopes, issues, true),
                }
                let inferred = resolved_expression_type(value, scopes);
                let binding_type = declared_type
                    .as_deref()
                    .map(ArkType::parse)
                    .unwrap_or_else(|| inferred.clone());
                // The inferred array type only carries the first element's type,
                // so check every element against the declared element type.
                if let (Expression::ArrayLiteral(elements), ArkType::Array(element_type, _)) =
                    (value, &binding_type)
                {
                    for (index, element) in elements.iter().enumerate() {
                        let actual = resolved_expression_type(element, scopes);
                        if actual != ArkType::Unknown
                            && !binding_types_compatible(element_type, &actual)
                        {
                            issues.push(ValidationIssue::error(format!(
                                "function '{}': element {} of array '{}' has type '{}', expected '{}'",
                                function_name,
                                index,
                                name,
                                actual.as_str(),
                                element_type.as_str()
                            )));
                        }
                    }
                }
                if declared_type.is_some()
                    && inferred != ArkType::Unknown
                    && !binding_types_compatible(&binding_type, &inferred)
                {
                    issues.push(ValidationIssue::error(format!(
                        "function '{}': binding '{}' declares type '{}' but initializer has type '{}'",
                        function_name,
                        name,
                        binding_type.as_str(),
                        inferred.as_str()
                    )));
                }
                if matches!(value, Expression::ArrayLiteral(_))
                    && declared_type
                        .as_deref()
                        .and_then(crate::models::array_type_parts)
                        .is_none()
                {
                    issues.push(ValidationIssue::error(format!(
                        "function '{}': array literal needs a declared array type, as in 'int[2] {} = …'",
                        function_name, name
                    )));
                }
                let frame = scopes
                    .last_mut()
                    .expect("binding validation always has a scope");
                if let ArkType::Array(element, length) = &binding_type {
                    for index in 0..*length {
                        frame.insert(
                            format!("{name}[{index}]"),
                            BindingInfo {
                                binding_type: (**element).clone(),
                                source: BindingSource::Local,
                            },
                        );
                    }
                }
                frame.insert(
                    name.clone(),
                    BindingInfo {
                        binding_type,
                        source: BindingSource::Local,
                    },
                );
            }
            Statement::VarAssign { name, value } => {
                validate_binding_expression(value, function_name, scopes, issues, true);
                let inferred = resolved_expression_type(value, scopes);
                match find_binding(scopes, name) {
                    None => issues.push(ValidationIssue::error(format!(
                        "function '{}': assignment to undeclared variable '{}'",
                        function_name, name
                    ))),
                    Some(binding) if binding.source == BindingSource::Constructor => {
                        // The existing shadowing walk owns the constructor-mutation diagnostic.
                    }
                    Some(binding) if binding.source == BindingSource::Loop => {
                        issues.push(ValidationIssue::error(format!(
                            "function '{}': cannot assign to compile-time loop variable '{}'",
                            function_name, name
                        )));
                    }
                    Some(binding)
                        if inferred != ArkType::Unknown
                            && binding.binding_type != ArkType::Unknown
                            && !binding_types_compatible(&binding.binding_type, &inferred) =>
                    {
                        issues.push(ValidationIssue::error(format!(
                            "function '{}': assignment to '{}' changes its type from '{}' to '{}'",
                            function_name,
                            name,
                            binding.binding_type.as_str(),
                            inferred.as_str()
                        )));
                    }
                    Some(_) => {}
                }
            }
            Statement::IfElse {
                condition,
                then_body,
                else_body,
            } => {
                validate_binding_expression(condition, function_name, scopes, issues, true);
                let condition_type = resolved_expression_type(condition, scopes);
                if condition_type != ArkType::Bool {
                    issues.push(ValidationIssue::error(format!(
                        "function '{}': if condition has type '{}', expected bool; use an explicit comparison",
                        function_name,
                        condition_type.as_str()
                    )));
                }
                scopes.push(HashMap::new());
                validate_binding_statements(then_body, function_name, scopes, issues);
                scopes.pop();
                if let Some(else_body) = else_body {
                    scopes.push(HashMap::new());
                    validate_binding_statements(else_body, function_name, scopes, issues);
                    scopes.pop();
                }
            }
            Statement::ForIn {
                index_var,
                value_var,
                iterable,
                body,
            } => {
                let element_type = match iterable {
                    Expression::Variable(name) | Expression::Property(name)
                        if name.trim() != "tx.assetGroups" =>
                    {
                        match find_binding(scopes, name) {
                            Some(BindingInfo {
                                binding_type: ArkType::Array(element, _),
                                ..
                            }) => (**element).clone(),
                            Some(binding) => {
                                issues.push(ValidationIssue::error(format!(
                                "function '{}': loop iterable '{}' has type '{}', expected array",
                                function_name,
                                name,
                                binding.binding_type.as_str()
                            )));
                                ArkType::Unknown
                            }
                            None => {
                                issues.push(ValidationIssue::error(format!(
                                    "function '{}': loop iterable '{}' is undefined",
                                    function_name, name
                                )));
                                ArkType::Unknown
                            }
                        }
                    }
                    Expression::Property(property) if property.trim() == "tx.assetGroups" => {
                        issues.push(ValidationIssue::error(format!(
                            "function '{}': cannot iterate 'tx.assetGroups'; the group count is \
                             not known at compile time. Iterate a declared array of group \
                             indices instead",
                            function_name
                        )));
                        ArkType::Unknown
                    }
                    _ => {
                        issues.push(ValidationIssue::error(format!(
                            "function '{}': unsupported loop iterable",
                            function_name
                        )));
                        ArkType::Unknown
                    }
                };
                let mut frame = HashMap::new();
                for (name, binding_type) in [(index_var, ArkType::Int), (value_var, element_type)] {
                    frame.insert(
                        name.clone(),
                        BindingInfo {
                            binding_type,
                            source: BindingSource::Loop,
                        },
                    );
                }
                scopes.push(frame);
                validate_binding_statements(body, function_name, scopes, issues);
                scopes.pop();
            }
        }
    }
}

fn validate_named_binding(
    name: &str,
    expected: Option<ArkType>,
    label: &str,
    function_name: &str,
    scopes: &BindingScopes,
    issues: &mut Vec<ValidationIssue>,
) {
    if let Some((_, index)) = name.strip_suffix(']').and_then(|name| name.split_once('[')) {
        if index.parse::<usize>().is_err() {
            match find_binding(scopes, index) {
                None => issues.push(ValidationIssue::error(format!(
                    "function '{}': array index '{}' is undefined",
                    function_name, index
                ))),
                Some(binding) if binding.binding_type != ArkType::Int => {
                    issues.push(ValidationIssue::error(format!(
                        "function '{}': array index '{}' has type '{}', expected 'int'",
                        function_name,
                        index,
                        binding.binding_type.as_str()
                    )));
                }
                Some(_) => {}
            }
        }
    }

    match find_binding(scopes, name) {
        None => issues.push(ValidationIssue::error(format!(
            "function '{}': {} '{}' is undefined",
            function_name, label, name
        ))),
        Some(binding)
            if expected.as_ref().is_some_and(|expected| {
                binding.binding_type != *expected && binding.binding_type != ArkType::Unknown
            }) =>
        {
            issues.push(ValidationIssue::error(format!(
                "function '{}': {} '{}' has type '{}', expected '{}'",
                function_name,
                label,
                name,
                binding.binding_type.as_str(),
                expected.expect("checked above").as_str()
            )));
        }
        Some(_) => {}
    }
}

fn validate_binding_requirement(
    requirement: &Requirement,
    function_name: &str,
    scopes: &BindingScopes,
    issues: &mut Vec<ValidationIssue>,
) {
    match requirement {
        Requirement::Expression(expression) => {
            let produces_value = !matches!(
                expression,
                Expression::CheckSigFromStackVerify { .. }
                    | Expression::EcMulScalarVerify { .. }
                    | Expression::TweakVerify { .. }
            );
            validate_binding_expression(expression, function_name, scopes, issues, produces_value);
        }
        Requirement::CheckSig { signature, pubkey } => {
            validate_named_binding(
                signature,
                Some(ArkType::Signature),
                "signature",
                function_name,
                scopes,
                issues,
            );
            validate_named_binding(
                pubkey,
                Some(ArkType::Pubkey),
                "public key",
                function_name,
                scopes,
                issues,
            );
        }
        Requirement::CheckSigFromStack {
            signature,
            pubkey,
            message,
        } => {
            validate_named_binding(
                signature,
                Some(ArkType::Signature),
                "signature",
                function_name,
                scopes,
                issues,
            );
            validate_named_binding(
                pubkey,
                Some(ArkType::Pubkey),
                "public key",
                function_name,
                scopes,
                issues,
            );
            validate_named_binding(message, None, "message", function_name, scopes, issues);
        }
        Requirement::CheckMultisig {
            pubkeys,
            signatures,
            ..
        } => {
            if pubkeys.len() != signatures.len() {
                issues.push(ValidationIssue::error(format!(
                    "function '{}': checkMultisig key and signature counts must match",
                    function_name
                )));
            }
            for pubkey in pubkeys {
                validate_named_binding(
                    pubkey,
                    Some(ArkType::Pubkey),
                    "multisig public key",
                    function_name,
                    scopes,
                    issues,
                );
            }
            for signature in signatures {
                validate_named_binding(
                    signature,
                    Some(ArkType::Signature),
                    "multisig signature",
                    function_name,
                    scopes,
                    issues,
                );
            }
        }
        Requirement::After {
            timelock_var: Some(name),
            ..
        } => validate_named_binding(
            name,
            Some(ArkType::Int),
            "timelock",
            function_name,
            scopes,
            issues,
        ),
        Requirement::After { .. } => {}
        Requirement::HashEqual { preimage, hash, .. } => {
            validate_named_binding(preimage, None, "preimage", function_name, scopes, issues);
            validate_named_binding(hash, None, "hash", function_name, scopes, issues);
        }
        Requirement::Comparison { left, right, .. } => {
            validate_binding_expression(left, function_name, scopes, issues, true);
            validate_binding_expression(right, function_name, scopes, issues, true);
        }
    }
}

fn validate_binding_expression(
    expression: &Expression,
    function_name: &str,
    scopes: &BindingScopes,
    issues: &mut Vec<ValidationIssue>,
    value_position: bool,
) {
    let expression_type = resolved_expression_type(expression, scopes);
    if value_position && matches!(expression_type, ArkType::Array(..) | ArkType::Struct(..)) {
        let kind = if matches!(expression_type, ArkType::Struct(..)) {
            "struct"
        } else {
            "array"
        };
        issues.push(ValidationIssue::error(format!(
            "function '{}': {kind} expressions are composite values and cannot be used here",
            function_name,
        )));
    }
    if value_position
        && (matches!(
            expression,
            Expression::EcAdd { .. } | Expression::EcMul { .. }
        ) || matches!(
            expression,
            Expression::AssetAt { property, .. } if property == "assetId"
        ))
    {
        issues.push(ValidationIssue::error(format!(
            "function '{}': expression produces 2 stack items; composite values are not supported",
            function_name
        )));
    }
    if value_position
        && matches!(
            expression,
            Expression::GroupProperty { property, .. } if property == "assetId"
        )
    {
        issues.push(ValidationIssue::error(format!(
            "function '{}': expression produces 2 stack items; composite values are not supported",
            function_name
        )));
    }
    if value_position
        && matches!(
            expression,
            Expression::GroupIOAccess { property: None, .. }
                | Expression::EcMulScalarVerify { .. }
                | Expression::TweakVerify { .. }
                | Expression::CheckSigFromStackVerify { .. }
        )
    {
        issues.push(ValidationIssue::error(format!(
            "function '{}': expression does not produce one stack item",
            function_name
        )));
    }
    if value_position
        && (matches!(
            expression,
            Expression::CurrentInput(Some(property)) if property == "outpoint"
        ) || matches!(
            expression,
            Expression::InputIntrospection { property, .. } if property == "outpoint"
        ))
    {
        issues.push(ValidationIssue::error(format!(
            "function '{}': outpoint inspection produces 2 stack items; composite values are not supported",
            function_name
        )));
    }
    if value_position
        && matches!(
            expression,
            Expression::GroupIOAccess {
                source: crate::models::GroupIOSource::Inputs,
                ..
            }
        )
    {
        issues.push(ValidationIssue::error(format!(
            "function '{}': asset-group input inspection has a variable-width result and cannot be used as a value",
            function_name
        )));
    }

    match expression {
        Expression::Variable(name) => {
            validate_named_binding(name, None, "binding", function_name, scopes, issues);
        }
        Expression::ArrayIndex { array, index } => {
            let mut length = None;
            match find_binding(scopes, array) {
                None => issues.push(ValidationIssue::error(format!(
                    "function '{}': array '{}' is undefined",
                    function_name, array
                ))),
                Some(BindingInfo {
                    binding_type: ArkType::Array(_, declared_length),
                    ..
                }) => length = Some(*declared_length),
                Some(_) => {
                    issues.push(ValidationIssue::error(format!(
                        "function '{}': binding '{}' is not an array",
                        function_name, array
                    )));
                }
            }
            let index_type = resolved_expression_type(index, scopes);
            if !matches!(index_type, ArkType::Int | ArkType::Unknown) {
                issues.push(ValidationIssue::error(format!(
                    "function '{}': array index has type '{}', expected 'int'",
                    function_name,
                    index_type.as_str()
                )));
            }
            if let (Expression::Literal(index), Some(length)) = (index.as_ref(), length) {
                if index.parse::<usize>().map_or(true, |i| i >= length) {
                    issues.push(ValidationIssue::error(format!(
                        "function '{}': array index '{}' is out of range for '{}[{}]'",
                        function_name, index, array, length
                    )));
                }
            }
        }
        Expression::Property(name) if name.contains('[') => {
            validate_named_binding(name, None, "binding", function_name, scopes, issues);
        }
        Expression::Property(name) if name.ends_with(".length") => {
            let array = name.trim_end_matches(".length");
            if !matches!(
                find_binding(scopes, array).map(|binding| &binding.binding_type),
                Some(ArkType::Array(..))
            ) {
                issues.push(ValidationIssue::error(format!(
                    "function '{}': '{}' is not an array; '.length' is undefined",
                    function_name, array
                )));
            }
        }
        Expression::Property(name) => {
            let root = name.split('.').next().unwrap_or(name);
            if matches!(
                find_binding(scopes, root).map(|binding| &binding.binding_type),
                Some(ArkType::Struct(..))
            ) {
                validate_named_binding(name, None, "field", function_name, scopes, issues);
            }
        }
        Expression::GroupProperty { group, .. } | Expression::GroupControlIs { group, .. }
            if group.parse::<usize>().is_err() =>
        {
            validate_named_binding(
                group,
                Some(ArkType::Int),
                "asset group",
                function_name,
                scopes,
                issues,
            );
        }
        Expression::CheckSigExpr { signature, pubkey } => {
            validate_named_binding(
                signature,
                Some(ArkType::Signature),
                "signature",
                function_name,
                scopes,
                issues,
            );
            validate_named_binding(
                pubkey,
                Some(ArkType::Pubkey),
                "public key",
                function_name,
                scopes,
                issues,
            );
        }
        Expression::CheckSigFromStackExpr {
            signature,
            pubkey,
            message,
        }
        | Expression::CheckSigFromStackVerify {
            signature,
            pubkey,
            message,
        } => {
            validate_named_binding(
                signature,
                Some(ArkType::Signature),
                "signature",
                function_name,
                scopes,
                issues,
            );
            validate_named_binding(
                pubkey,
                Some(ArkType::Pubkey),
                "public key",
                function_name,
                scopes,
                issues,
            );
            validate_named_binding(message, None, "message", function_name, scopes, issues);
        }
        Expression::ContractInstance { args, .. } => {
            for argument in args {
                match argument {
                    Expression::Variable(name) => {
                        if let Some(binding) = find_binding(scopes, name) {
                            if !matches!(binding.source, BindingSource::Constructor) {
                                issues.push(ValidationIssue::error(format!(
                                    "function '{}': contract instance argument '{}' is a runtime value; only constructor parameters and literals are supported",
                                function_name, name
                            )));
                            }
                        }
                    }
                    Expression::Literal(_) => {}
                    _ => issues.push(ValidationIssue::error(format!(
                        "function '{}': computed contract arguments are not supported",
                        function_name
                    ))),
                }
            }
        }
        _ => {}
    }

    for child in child_exprs(expression) {
        validate_binding_expression(
            child,
            function_name,
            scopes,
            issues,
            !matches!(expression, Expression::ContractInstance { .. }),
        );
    }
}

/// Validate one `(asset_txid, asset_gidx)` pair.
fn validate_asset_id(
    asset_txid: &Expression,
    asset_gidx: &Expression,
    scope: &Scope,
    fname: &str,
    issues: &mut Vec<ValidationIssue>,
) {
    let txid_type = infer_type(asset_txid, scope);
    if txid_type != ArkType::Bytes32 {
        issues.push(ValidationIssue::error(format!(
            "function '{}': asset id txid operand {} must be bytes32, got {}",
            fname,
            describe_operand(asset_txid),
            txid_type.as_str()
        )));
    }

    // gidx: a numeric literal is range-checked directly; anything else must
    // resolve to Int through the scope.
    if let Expression::Literal(lit) = asset_gidx {
        match lit.parse::<i64>() {
            Ok(v) if (0..=65535).contains(&v) => {}
            Ok(v) => issues.push(ValidationIssue::error(format!(
                "function '{}': asset id gidx literal {} is out of range 0..65535",
                fname, v
            ))),
            Err(_) => issues.push(ValidationIssue::error(format!(
                "function '{}': asset id gidx literal '{}' is not a valid integer",
                fname, lit
            ))),
        }
    } else {
        let gidx_type = infer_type(asset_gidx, scope);
        if gidx_type != ArkType::Int {
            issues.push(ValidationIssue::error(format!(
                "function '{}': asset id gidx operand {} must be int (0..65535), got {}",
                fname,
                describe_operand(asset_gidx),
                gidx_type.as_str()
            )));
        }
    }
}

fn describe_operand(expr: &Expression) -> String {
    match expr {
        Expression::Variable(v) => format!("'{}'", v),
        Expression::Literal(l) => format!("'{}'", l),
        _ => "<expr>".to_string(),
    }
}

// ─── AST helpers ─────────────────────────────────────────────────────────────

/// Returns `true` if every execution path through the block hits at least one
/// `require()`. A block guarantees a require when any of its (sequential)
/// statements does; an if/else guarantees one only when both branches do (so a
/// missing `else` is a bare path); a loop body's guarantee counts because the
/// unroller always emits at least one iteration.
fn block_guarantees_require(stmts: &[Statement]) -> bool {
    stmts.iter().any(statement_guarantees_require)
}

fn statement_guarantees_require(stmt: &Statement) -> bool {
    match stmt {
        Statement::Require(_) => true,
        Statement::LetBinding { .. } | Statement::VarAssign { .. } => false,
        Statement::IfElse {
            then_body,
            else_body,
            ..
        } => {
            block_guarantees_require(then_body)
                && else_body
                    .as_ref()
                    .is_some_and(|b| block_guarantees_require(b))
        }
        Statement::ForIn { body, .. } => block_guarantees_require(body),
    }
}

/// Check 1: reject any binding that shadows a name still live in an enclosing
/// scope, plus `for (x, x)`. Function parameters are compared against
/// constructor parameters explicitly before seeding (a collapsed set would
/// silently swallow the duplicate).
fn check_shadowing(contract: &Contract, issues: &mut Vec<ValidationIssue>) {
    let ctor_names: HashSet<&str> = contract
        .parameters
        .iter()
        .map(|p| p.name.as_str())
        .collect();

    for func in &contract.functions {
        // Seed frame: constructor params + this function's params.
        let mut seed: HashSet<String> = ctor_names.iter().map(|s| s.to_string()).collect();
        for param in &func.parameters {
            if ctor_names.contains(param.name.as_str()) {
                issues.push(ValidationIssue::error(format!(
                    "parameter '{}' in function '{}' shadows constructor parameter '{}'",
                    param.name, func.name, param.name
                )));
            }
            seed.insert(param.name.clone());
        }

        let mut stack: Vec<HashSet<String>> = vec![seed];
        walk_scope(&func.statements, &func.name, &mut stack, issues);

        check_ctor_assignment(&func.statements, &func.name, &ctor_names, issues);
    }
}

/// Reject `name = expr;` where `name` is a constructor parameter; constructor
/// parameters are immutable. Recurses into branch and loop bodies.
fn check_ctor_assignment(
    stmts: &[Statement],
    fname: &str,
    ctor_names: &HashSet<&str>,
    issues: &mut Vec<ValidationIssue>,
) {
    for stmt in stmts {
        match stmt {
            Statement::VarAssign { name, .. } => {
                if ctor_names.contains(name.as_str()) {
                    issues.push(ValidationIssue::error(format!(
                        "cannot assign to constructor parameter '{}' in function '{}'; \
                         constructor parameters are immutable",
                        name, fname
                    )));
                }
            }
            Statement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                check_ctor_assignment(then_body, fname, ctor_names, issues);
                if let Some(eb) = else_body {
                    check_ctor_assignment(eb, fname, ctor_names, issues);
                }
            }
            Statement::ForIn { body, .. } => {
                check_ctor_assignment(body, fname, ctor_names, issues);
            }
            Statement::LetBinding { .. } | Statement::Require(_) => {}
        }
    }
}

/// Returns true if `name` is bound in any frame currently on the stack.
fn in_scope(stack: &[HashSet<String>], name: &str) -> bool {
    stack.iter().any(|frame| frame.contains(name))
}

/// Walk statements maintaining a lexical scope stack. Each block (`for` body,
/// `if`/`else` branch) is a pushed frame, so sibling blocks do not conflict.
fn walk_scope(
    stmts: &[Statement],
    fname: &str,
    stack: &mut Vec<HashSet<String>>,
    issues: &mut Vec<ValidationIssue>,
) {
    for stmt in stmts {
        match stmt {
            Statement::LetBinding { name, .. } => {
                validate_source_identifier(name, &format!("binding in function '{fname}'"), issues);
                if in_scope(stack, name) {
                    issues.push(ValidationIssue::error(format!(
                        "binding '{}' in function '{}' shadows an in-scope binding",
                        name, fname
                    )));
                } else {
                    stack
                        .last_mut()
                        .expect("non-empty scope stack")
                        .insert(name.clone());
                }
            }
            Statement::ForIn {
                index_var,
                value_var,
                body,
                ..
            } => {
                validate_source_identifier(
                    index_var,
                    &format!("loop variable in function '{fname}'"),
                    issues,
                );
                validate_source_identifier(
                    value_var,
                    &format!("loop variable in function '{fname}'"),
                    issues,
                );
                if index_var == value_var {
                    issues.push(ValidationIssue::error(format!(
                        "loop variables in function '{}' must differ; both are named '{}'",
                        fname, index_var
                    )));
                }
                for v in [index_var, value_var] {
                    if in_scope(stack, v) {
                        issues.push(ValidationIssue::error(format!(
                            "loop variable '{}' in function '{}' shadows an in-scope binding",
                            v, fname
                        )));
                    }
                }
                let mut frame = HashSet::new();
                frame.insert(index_var.clone());
                frame.insert(value_var.clone());
                stack.push(frame);
                walk_scope(body, fname, stack, issues);
                stack.pop();
            }
            Statement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                stack.push(HashSet::new());
                walk_scope(then_body, fname, stack, issues);
                stack.pop();
                if let Some(eb) = else_body {
                    stack.push(HashSet::new());
                    walk_scope(eb, fname, stack, issues);
                    stack.pop();
                }
            }
            // Reassignment is handled separately; requires introduce no bindings.
            Statement::VarAssign { .. } | Statement::Require(_) => {}
        }
    }
}

/// Check 2: the names a function's parameters and the constructor's parameters
/// contribute to the *emitted* placeholder namespace after array flattening
/// must be unique. Distinct source names can
/// still collide here (e.g. `int[] xs` vs `int xs_0`).
fn check_expanded_namespace(contract: &Contract, issues: &mut Vec<ValidationIssue>) {
    // Constructor params expanded exactly as the emitter expands them (array flattening).
    let ctor_expanded =
        match crate::compiler::expanded_placeholder_params(&contract.parameters, &contract.structs)
        {
            Ok(parameters) => parameters,
            Err(error) => {
                issues.push(ValidationIssue::error(error));
                return;
            }
        };

    for func in contract.functions.iter().filter(|f| !f.is_internal) {
        let mut seen: HashSet<String> = HashSet::new();

        for p in &ctor_expanded {
            record_name(
                p.name.clone(),
                &format!("function '{}'", func.name),
                &mut seen,
                issues,
            );
        }

        let expanded =
            match crate::compiler::expanded_placeholder_params(&func.parameters, &contract.structs)
            {
                Ok(parameters) => parameters,
                Err(error) => {
                    issues.push(ValidationIssue::error(error));
                    continue;
                }
            };
        for p in expanded {
            record_name(
                p.name,
                &format!("function '{}'", func.name),
                &mut seen,
                issues,
            );
        }
    }

    for tapscript in &contract.tapscripts {
        let mut seen: HashSet<String> = HashSet::new();
        for p in &ctor_expanded {
            record_name(
                p.name.clone(),
                &format!("tapscript '{}'", tapscript.name),
                &mut seen,
                issues,
            );
        }
        let expanded = match crate::compiler::expanded_placeholder_params(
            &tapscript.inputs,
            &contract.structs,
        ) {
            Ok(parameters) => parameters,
            Err(error) => {
                issues.push(ValidationIssue::error(error));
                continue;
            }
        };
        for p in expanded {
            record_name(
                p.name,
                &format!("tapscript '{}'", tapscript.name),
                &mut seen,
                issues,
            );
        }
    }
}

/// Insert an emitted name; on the first duplicate, record a collision error.
fn record_name(
    name: String,
    context: &str,
    seen: &mut HashSet<String>,
    issues: &mut Vec<ValidationIssue>,
) {
    if !seen.insert(name.clone()) {
        issues.push(ValidationIssue::error(format!(
            "parameters in {context} collide in the emitted namespace as '{name}'"
        )));
    }
}

// ─── Output validation ────────────────────────────────────────────────────────

/// Validate the compiled [`ContractJson`] output for structural invariants.
///
/// This pass acts as a compiler self-check: a valid source contract should always
/// produce output that satisfies these invariants. Any error here indicates a
/// compiler bug rather than a user error.
pub fn validate_output(output: &ContractJson) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();

    if output.functions.is_empty() {
        issues.push(ValidationIssue::error("contract produced no spend groups"));
    }

    for group in &output.functions {
        if group.leaves.is_empty() {
            issues.push(ValidationIssue::error(format!(
                "spend group '{}' has no leaves (compiler bug)",
                group.name
            )));
        }
        if let Some(arkade) = &group.arkade {
            if arkade.asm.is_empty() {
                issues.push(ValidationIssue::error(format!(
                    "group '{}' arkade covenant has empty asm",
                    group.name
                )));
            }
            // The ABI keeps one entry per source parameter; the prologue pushes
            // one placeholder per array element, so compare against the
            // flattened namespace.
            let expected_prologue = match crate::compiler::expanded_placeholder_params(
                &output.parameters,
                &output.structs,
            ) {
                Ok(parameters) => parameters
                    .iter()
                    .rev()
                    .map(|parameter| format!("<{}>", parameter.name))
                    .collect::<Vec<_>>(),
                Err(error) => {
                    issues.push(ValidationIssue::error(format!(
                        "group '{}' has an invalid type layout: {error}",
                        group.name
                    )));
                    continue;
                }
            };
            if !arkade.asm.starts_with(&expected_prologue) {
                issues.push(ValidationIssue::error(format!(
                    "group '{}' arkade covenant has an invalid constructor prologue",
                    group.name
                )));
            }
            if arkade.asm[expected_prologue.len().min(arkade.asm.len())..]
                .iter()
                .any(|token| {
                    token.starts_with('<') && token.ends_with('>') && !token.starts_with("<VTXO:")
                })
            {
                issues.push(ValidationIssue::error(format!(
                    "group '{}' arkade covenant has a placeholder outside its constructor prologue",
                    group.name
                )));
            }
        }
        for leaf in &group.leaves {
            if leaf.asm.is_empty() {
                issues.push(ValidationIssue::error(format!(
                    "leaf '{}' in group '{}' has empty asm",
                    leaf.name, group.name
                )));
            }
            // Leaf ASM must not carry signature placeholders (sigs are witness).
            // Case-insensitive: a leaked placeholder may be named `<sig>`,
            // `<ownersig>`, or `<serverSig>` depending on the source naming —
            // all must trip this compiler-bug self-check.
            if leaf
                .asm
                .iter()
                .filter_map(|token| token.strip_prefix('<')?.strip_suffix('>'))
                .any(|name| {
                    name.chars()
                        .all(|character| character.is_ascii_alphanumeric() || character == '_')
                        && name.to_ascii_lowercase().ends_with("sig")
                })
            {
                issues.push(ValidationIssue::error(format!(
                    "leaf '{}' in group '{}' has a signature in asm (must be witness-only)",
                    leaf.name, group.name
                )));
            }
        }
    }

    issues
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AbiFunctionGroup, AbiLeaf, Contract, Function, Parameter, WitnessElement};

    fn make_contract(name: &str) -> Contract {
        Contract {
            name: name.to_string(),
            structs: vec![],
            parameters: vec![Parameter {
                name: "owner".to_string(),
                param_type: "pubkey".to_string(),
            }],
            functions: vec![Function {
                name: "spend".to_string(),
                parameters: vec![
                    Parameter {
                        name: "ownerSig".to_string(),
                        param_type: "signature".to_string(),
                    },
                    Parameter {
                        name: "flag".to_string(),
                        param_type: "bool".to_string(),
                    },
                ],
                statements: vec![Statement::Require(Requirement::CheckSig {
                    signature: "ownerSig".to_string(),
                    pubkey: "owner".to_string(),
                })],
                is_internal: false,
            }],
            tapscripts: Vec::new(),
            imports: vec![],
        }
    }

    #[test]
    fn valid_contract_has_no_issues() {
        let contract = make_contract("Simple");
        let issues = validate_ast(&contract);
        assert!(!has_errors(&issues));
    }

    #[test]
    fn require_only_in_one_branch_is_error() {
        // An if with a require in the then-branch but no else leaves the
        // "condition false" path with no require() → a trivially-passing spend.
        let mut contract = make_contract("BarePath");
        contract.functions[0].statements = vec![Statement::IfElse {
            condition: Expression::Variable("flag".to_string()),
            then_body: vec![Statement::Require(Requirement::CheckSig {
                signature: "ownerSig".to_string(),
                pubkey: "owner".to_string(),
            })],
            else_body: None,
        }];
        let issues = validate_ast(&contract);
        assert!(has_errors(&issues));
        assert!(issues
            .iter()
            .any(|i| i.message.contains("spend path with no require()")));
    }

    #[test]
    fn require_in_both_branches_is_ok() {
        let mut contract = make_contract("BothPaths");
        let req = || {
            Statement::Require(Requirement::CheckSig {
                signature: "ownerSig".to_string(),
                pubkey: "owner".to_string(),
            })
        };
        contract.functions[0].statements = vec![Statement::IfElse {
            condition: Expression::Variable("flag".to_string()),
            then_body: vec![req()],
            else_body: Some(vec![req()]),
        }];
        assert!(!has_errors(&validate_ast(&contract)));
    }

    #[test]
    fn empty_contract_name_is_error() {
        let contract = make_contract("");
        let issues = validate_ast(&contract);
        assert!(has_errors(&issues));
        assert!(issues.iter().any(|i| i.message.contains("name")));
    }

    #[test]
    fn no_functions_is_error() {
        let mut contract = make_contract("Empty");
        contract.functions.clear();
        let issues = validate_ast(&contract);
        assert!(has_errors(&issues));
        assert!(issues
            .iter()
            .any(|i| i.message.contains("non-internal function")));
    }

    #[test]
    fn only_internal_functions_is_error() {
        let mut contract = make_contract("AllInternal");
        contract.functions[0].is_internal = true;
        let issues = validate_ast(&contract);
        assert!(has_errors(&issues));
    }

    #[test]
    fn duplicate_function_name_is_error() {
        let mut contract = make_contract("Dup");
        contract.functions.push(contract.functions[0].clone());
        let issues = validate_ast(&contract);
        assert!(has_errors(&issues));
        assert!(issues.iter().any(|i| i.message.contains("spend")));
    }

    #[test]
    fn duplicate_constructor_param_is_error() {
        let mut contract = make_contract("Dup");
        contract.parameters.push(contract.parameters[0].clone());
        let issues = validate_ast(&contract);
        assert!(has_errors(&issues));
    }

    fn make_output(name: &str) -> ContractJson {
        let witness = vec![WitnessElement {
            name: "sig".to_string(),
            elem_type: "signature".to_string(),
            encoding: "schnorr-64".to_string(),
            injected: false,
        }];
        ContractJson {
            name: name.to_string(),
            structs: vec![],
            parameters: vec![],
            functions: vec![AbiFunctionGroup {
                name: "spend".to_string(),
                arkade: None,
                leaves: vec![AbiLeaf {
                    name: "spend".to_string(),
                    witness,
                    asm: vec!["OP_CHECKSIG".to_string()],
                }],
            }],
            source: None,
            compiler: None,
            updated_at: None,
            warnings: vec![],
        }
    }

    #[test]
    fn valid_output_has_no_errors() {
        let output = make_output("Simple");
        let issues = validate_output(&output);
        assert!(!has_errors(&issues));
    }

    #[test]
    fn empty_asm_is_output_error() {
        let mut output = make_output("Bad");
        output.functions[0].leaves[0].asm.clear();
        let issues = validate_output(&output);
        assert!(has_errors(&issues));
        assert!(issues.iter().any(|i| i.message.contains("empty asm")));
    }

    #[test]
    fn signature_placeholder_in_leaf_asm_is_output_error() {
        // The sig-leak self-check must fire regardless of placeholder casing:
        // <serverSig>, <ownersig>, and <sig> are all signature placeholders.
        for leaked in ["<serverSig>", "<ownersig>", "<sig>"] {
            let mut output = make_output("Leak");
            output.functions[0].leaves[0].asm = vec![leaked.to_string()];
            let issues = validate_output(&output);
            assert!(
                has_errors(&issues),
                "leaked placeholder {} must be an output error",
                leaked
            );
            assert!(
                issues
                    .iter()
                    .any(|i| i.message.contains("signature in asm")),
                "expected sig-leak message for {}",
                leaked
            );
        }
    }
}
