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
use crate::typechecker::{build_scope, infer_type, ArkType, Scope};
use std::collections::HashSet;

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
        Expression::Sha256 { data } | Expression::Sha256Initialize { data } => vec![data],
        Expression::Sha256Update { context, chunk } => vec![context, chunk],
        Expression::Sha256Finalize {
            context,
            last_chunk,
        } => vec![context, last_chunk],
        Expression::Negate { value } => vec![value],
        Expression::ModExp {
            base,
            exponent,
            modulus,
        } => vec![base, exponent, modulus],
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
    let ctor_expanded = crate::compiler::expand_abi_params(&contract.parameters);

    for func in contract.functions.iter().filter(|f| !f.is_internal) {
        let mut seen: HashSet<String> = HashSet::new();

        for p in &ctor_expanded {
            record_name(p.name.clone(), &func.name, &mut seen, issues);
        }

        for p in crate::compiler::expand_abi_params(&func.parameters) {
            record_name(p.name, &func.name, &mut seen, issues);
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
            // Case-insensitive: a leaked placeholder may be named `<sig>`,
            // `<ownersig>`, or `<serverSig>` depending on the source naming —
            // all must trip this compiler-bug self-check.
            if leaf
                .asm
                .iter()
                .any(|t| t.to_ascii_lowercase().contains("sig>"))
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
            parameters: vec![Parameter {
                name: "owner".to_string(),
                param_type: "pubkey".to_string(),
            }],
            functions: vec![Function {
                name: "spend".to_string(),
                parameters: vec![],
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
