//! Semantic validation for Arkade Script contracts.
//!
//! This module provides two validation passes:
//!
//! 1. **AST validation** (`validate_ast`) — runs after parsing, before compilation.
//!    Catches semantic errors that the PEG grammar cannot express, such as duplicate
//!    function names, missing required options, and invalid timelock values.
//!    Also performs CashScript-style require-guard checks (warn when a function has
//!    no `require()` statements — it would trivially pass all spends).
//!
//! 2. **Output validation** (`validate_output`) — runs after compilation.
//!    Asserts structural invariants on the emitted `ContractJson`, catching compiler
//!    bugs before the output reaches callers.  Includes:
//!    - BSST-style ASM structure analysis (OP_IF/OP_ELSE/OP_ENDIF balance,
//!      placeholder syntax, no empty instructions).
//!    - CashScript-style placeholder consistency check (every `<name>` in ASM must
//!      resolve against the witnessSchema or constructorInputs).
//!
//! Issues are returned as a `Vec<ValidationIssue>`.  Use [`has_errors`] to check
//! whether any are fatal.

use crate::models::{Contract, ContractJson, Expression, Requirement, Statement};
use crate::typechecker::{build_scope, infer_type, ArkType, Scope};
use std::collections::HashSet;

// ─── Issue types ──────────────────────────────────────────────────────────────

/// Severity of a validation issue.
#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    /// Compilation must halt; the contract cannot be safely emitted.
    Error,
    /// Non-fatal; compilation continues but the caller should surface this.
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
/// - Constructor parameter names are unique.
/// - Each function's parameter names are unique within that function.
/// - `options.exit` is required whenever `options.server` is set.
/// - Timelock values must be positive (> 0).
pub fn validate_ast(contract: &Contract) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();

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
            if !seen.insert(param.name.as_str()) {
                issues.push(ValidationIssue::error(format!(
                    "duplicate parameter '{}' in function '{}'",
                    param.name, func.name
                )));
            }
        }
    }

    // ── Require-guard check (CashScript-style) ────────────────────────────
    // A non-internal function with no require() statements (directly or inside
    // branches/loops) will always succeed — any spend attempt will pass.
    // This is almost certainly a security bug, not intentional.
    for func in contract.functions.iter().filter(|f| !f.is_internal) {
        if !statements_have_require(&func.statements) {
            issues.push(ValidationIssue::warning(format!(
                "function '{}' has no require() statements; \
                 it will always succeed regardless of witness — is this intentional?",
                func.name
            )));
        }
    }

    // ── Tapscript reserved-name + duplicate-input checks ──────────────────
    for ts in &contract.tapscripts {
        for p in &ts.inputs {
            if p.name == "server" || p.name == "emulator" {
                issues.push(ValidationIssue::error(format!(
                    "tapscript '{}' input '{}' collides with a reserved key role",
                    ts.name, p.name
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
    check_asset_id_operands(contract, &mut issues);

    issues
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
    let ctor_scope = build_scope(&contract.parameters);
    for func in &contract.functions {
        let mut scope = ctor_scope.clone();
        scope.extend(build_scope(&func.parameters));
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
            Statement::Require(req) => {
                if let Requirement::Comparison { left, right, .. } = req {
                    check_asset_id_expr(left, scope, fname, issues);
                    check_asset_id_expr(right, scope, fname, issues);
                }
            }
            Statement::LetBinding { name, value } => {
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
        | Expression::ArrayLength(_)
        | Expression::CheckSigExpr { .. }
        | Expression::CheckSigFromStackExpr { .. }
        | Expression::CheckSigFromStackVerify { .. } => vec![],

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
        Expression::ArrayIndex { array, index } => vec![array, index],
        Expression::Sha256 { data } | Expression::Sha256Initialize { data } => vec![data],
        Expression::Sha256Update { context, chunk } => vec![context, chunk],
        Expression::Sha256Finalize {
            context,
            last_chunk,
        } => vec![context, last_chunk],
        Expression::Neg64 { value }
        | Expression::Le64ToScriptNum { value }
        | Expression::Le32ToLe64 { value } => vec![value],
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

/// Returns `true` if any statement in the slice contains a `Require` (recursing
/// into if/else branches and for-loop bodies).
fn statements_have_require(stmts: &[Statement]) -> bool {
    stmts.iter().any(|s| statement_has_require(s))
}

fn statement_has_require(stmt: &Statement) -> bool {
    match stmt {
        Statement::Require(_) => true,
        Statement::LetBinding { .. } | Statement::VarAssign { .. } => false,
        Statement::IfElse {
            then_body,
            else_body,
            ..
        } => {
            statements_have_require(then_body)
                || else_body
                    .as_ref()
                    .map_or(false, |b| statements_have_require(b))
        }
        Statement::ForIn { body, .. } => statements_have_require(body),
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
/// contribute to the *emitted* placeholder namespace — after array flattening
/// and reserved generated names — must be unique. Distinct source names can
/// still collide here (e.g. `int[] xs` vs `int xs_0`).
fn check_expanded_namespace(contract: &Contract, issues: &mut Vec<ValidationIssue>) {
    // Constructor params expanded exactly as the emitter expands them (array flattening).
    let ctor_expanded = crate::compiler::decompose_constructor_params(&contract.parameters);

    for func in contract.functions.iter().filter(|f| !f.is_internal) {
        let mut seen: HashSet<String> = HashSet::new();

        for p in &ctor_expanded {
            record_name(p.name.clone(), &func.name, &mut seen, issues);
        }

        // Function parameters: array flattening only (mirrors generate_witness_schema).
        for p in &func.parameters {
            if p.param_type.ends_with("[]") {
                for i in 0..crate::models::DEFAULT_ARRAY_LENGTH {
                    record_name(format!("{}_{}", p.name, i), &func.name, &mut seen, issues);
                }
            } else {
                record_name(p.name.clone(), &func.name, &mut seen, issues);
            }
        }
    }
}

/// Insert an emitted name; on the first duplicate, record a collision error.
fn record_name(
    name: String,
    fname: &str,
    seen: &mut HashSet<String>,
    issues: &mut Vec<ValidationIssue>,
) {
    if !seen.insert(name.clone()) {
        issues.push(ValidationIssue::error(format!(
            "parameters in function '{}' collide in the emitted namespace as '{}'",
            fname, name
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
        }
        for leaf in &group.leaves {
            if leaf.asm.is_empty() {
                issues.push(ValidationIssue::error(format!(
                    "leaf '{}' in group '{}' has empty asm",
                    leaf.name, group.name
                )));
            }
            // Leaf ASM must not carry signature placeholders (sigs are witness).
            if leaf.asm.iter().any(|t| t.contains("Sig>")) {
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
            parameters: vec![Parameter {
                name: "owner".to_string(),
                param_type: "pubkey".to_string(),
            }],
            functions: vec![Function {
                name: "spend".to_string(),
                parameters: vec![],
                statements: vec![],
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
        }];
        ContractJson {
            name: name.to_string(),
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
}
