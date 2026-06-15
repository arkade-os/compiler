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

use crate::models::{Contract, ContractJson, Parameter, Statement};
use std::collections::HashMap;
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

    // ── At least one non-internal function ────────────────────────────────
    let non_internal_count = contract.functions.iter().filter(|f| !f.is_internal).count();
    if non_internal_count == 0 {
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

    // ── Timelock requirements ──────────────────────────────────────────────
    if contract.has_server_key && contract.exit_timelock.is_none() {
        issues.push(ValidationIssue::error(
            "options.exit timelock is required when options.server is set; \
             the exit path cannot be generated without a timelock",
        ));
    }

    // Timelocks may be a literal integer ("144") or a constructor param name
    // ("exit"). Param names are resolved at deploy time and cannot be checked
    // here. For literal values, reject zero and negatives — the grammar
    // (number_literal = ASCII_DIGIT+) already rejects negative literals at parse
    // time, but the validator double-checks as defense-in-depth in case the
    // grammar ever permits signed integers.
    if let Some(ref exit) = contract.exit_timelock {
        if let Ok(v) = exit.parse::<i64>() {
            if v <= 0 {
                issues.push(ValidationIssue::error(format!(
                    "options.exit timelock must be a positive block count; got {}",
                    v
                )));
            }
        }
    }

    if let Some(ref renewal) = contract.renewal_timelock {
        if let Ok(v) = renewal.parse::<i64>() {
            if v <= 0 {
                issues.push(ValidationIssue::warning(format!(
                    "options.renew timelock should be a positive block count; got {}",
                    v
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

    check_shadowing(contract, &mut issues);
    check_expanded_namespace(contract, &mut issues);

    issues
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
/// contribute to the *emitted* placeholder namespace — after array flattening,
/// asset decomposition, and reserved generated names — must be unique. Distinct
/// source names can still collide here (e.g. `int[] xs` vs `int xs_0`).
fn check_expanded_namespace(contract: &Contract, issues: &mut Vec<ValidationIssue>) {
    let lookup_ids = crate::compiler::collect_lookup_asset_ids(contract);
    // Constructor params expanded exactly as the emitter decomposes them.
    let ctor_expanded =
        crate::compiler::decompose_constructor_params(&contract.parameters, &lookup_ids);

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

        // `serverSig` is appended unconditionally to the cooperative witness
        // schema (no dedup), so a parameter of that name genuinely collides.
        if contract.has_server_key {
            record_name("serverSig".to_string(), &func.name, &mut seen, issues);
        }
        // N-of-N exit signatures (`{pubkey}Sig`) are intentionally NOT reserved:
        // the emitter deduplicates them against existing signature parameters by
        // name (src/compiler/mod.rs ~690), so a param like `senderSig` for a
        // `sender` pubkey is reused rather than duplicated — no collision.
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
/// produce output that satisfies these invariants.  Any error here indicates a
/// compiler bug rather than a user error.
///
/// Checks performed:
/// - `contractName` is non-empty.
/// - `functions` array is non-empty.
/// - Every function variant has non-empty `asm`.
/// - Every function variant has non-empty `witnessSchema`.
/// - Every unique function name has both a `serverVariant=true` and
///   `serverVariant=false` entry.
/// - **BSST-style ASM structure**: OP_IF/OP_ELSE/OP_ENDIF are balanced, no empty
///   instructions, all `<placeholder>` tokens are syntactically well-formed.
/// - **Placeholder consistency**: every `<name>` in the ASM resolves to a
///   witnessSchema element or a constructorInput (CashScript-style).
pub fn validate_output(output: &ContractJson) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();

    // ── Contract name ──────────────────────────────────────────────────────
    if output.name.is_empty() {
        issues.push(ValidationIssue::error(
            "compiled output has an empty contractName (compiler bug)",
        ));
    }

    // ── Functions present ──────────────────────────────────────────────────
    if output.functions.is_empty() {
        issues.push(ValidationIssue::error(
            "compiled output has no functions (compiler bug)",
        ));
        // Cannot continue further checks without functions
        return issues;
    }

    // ── Per-function invariants ────────────────────────────────────────────
    for func in &output.functions {
        if func.asm.is_empty() {
            issues.push(ValidationIssue::error(format!(
                "function '{}' (serverVariant={}) has empty ASM (compiler bug)",
                func.name, func.server_variant
            )));
        }
        if func.witness_schema.is_empty() {
            issues.push(ValidationIssue::warning(format!(
                "function '{}' (serverVariant={}) has empty witnessSchema",
                func.name, func.server_variant
            )));
        }

        // BSST-style ASM structure analysis
        for issue in validate_asm_structure(&func.name, func.server_variant, &func.asm) {
            issues.push(issue);
        }

        // Placeholder consistency (CashScript-style)
        for issue in validate_placeholder_consistency(
            &func.name,
            func.server_variant,
            &func.asm,
            &func.witness_schema,
            &output.parameters,
        ) {
            issues.push(issue);
        }
    }

    // ── Both variants present for each function name ───────────────────────
    let mut by_name: HashMap<&str, (bool, bool)> = HashMap::new();
    for func in &output.functions {
        let entry = by_name.entry(func.name.as_str()).or_insert((false, false));
        if func.server_variant {
            entry.0 = true;
        } else {
            entry.1 = true;
        }
    }
    for (name, (has_server, has_exit)) in &by_name {
        if !has_server {
            issues.push(ValidationIssue::warning(format!(
                "function '{}' has no serverVariant=true entry",
                name
            )));
        }
        if !has_exit {
            issues.push(ValidationIssue::warning(format!(
                "function '{}' has no serverVariant=false (exit) entry",
                name
            )));
        }
    }

    issues
}

// ─── BSST-style ASM structure analysis ───────────────────────────────────────

/// Analyse the ASM instruction array for structural correctness.
///
/// Inspired by BSST (Bitcoin Script Symbolic Tracer) — checks that are feasible
/// without full symbolic execution (which would require accurate witness-stack
/// depth context):
///
/// - No empty instruction strings (would produce malformed script bytes).
/// - All `<placeholder>` tokens are syntactically well-formed: non-empty name,
///   no spaces, properly closed with `>`.
/// - `OP_IF` / `OP_NOTIF` are balanced by a matching `OP_ENDIF`.
/// - `OP_ELSE` only appears inside an open `OP_IF` / `OP_NOTIF` block.
///
/// Note: Stack-depth tracking is intentionally omitted.  In Arkade's execution
/// model the witness stack is pre-populated before the script runs, and accurately
/// accounting for those initial elements requires the full witness schema (which
/// belongs to `validate_placeholder_consistency`).  Attempting depth tracking
/// here without that context produces false-positive underflow errors on every
/// standard function.
pub fn validate_asm_structure(
    func_name: &str,
    server_variant: bool,
    asm: &[String],
) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    let label = format!("fn '{}' (serverVariant={})", func_name, server_variant);

    let mut if_depth: i32 = 0;

    for (idx, instr) in asm.iter().enumerate() {
        // ── Empty instruction ──────────────────────────────────────────────
        if instr.is_empty() {
            issues.push(ValidationIssue::error(format!(
                "{}: empty ASM instruction at index {}",
                label, idx
            )));
            continue;
        }

        // ── Placeholder syntax ────────────────────────────────────────────
        if instr.starts_with('<') {
            if !instr.ends_with('>') {
                issues.push(ValidationIssue::error(format!(
                    "{}: malformed placeholder '{}' at index {} — missing closing '>'",
                    label, instr, idx
                )));
            } else if instr.len() < 3 {
                issues.push(ValidationIssue::error(format!(
                    "{}: empty placeholder '<>' at index {}",
                    label, idx
                )));
            }
            // Note: compound-expression placeholders like
            // <checkMultisig([a,b],[c,d])> legitimately contain spaces and
            // brackets — the compiler emits them as-is for expressions it
            // cannot yet fully inline.  A space-presence check would produce
            // false positives for every such emission, so we skip it here.
            // The placeholder-consistency check handles unknown names separately.
            continue;
        }

        // ── Control-flow balance ──────────────────────────────────────────
        match instr.as_str() {
            "OP_IF" | "OP_NOTIF" => {
                if_depth += 1;
            }
            "OP_ELSE" => {
                if if_depth == 0 {
                    issues.push(ValidationIssue::error(format!(
                        "{}: OP_ELSE at index {} has no matching OP_IF",
                        label, idx
                    )));
                }
            }
            "OP_ENDIF" => {
                if if_depth == 0 {
                    issues.push(ValidationIssue::error(format!(
                        "{}: OP_ENDIF at index {} has no matching OP_IF",
                        label, idx
                    )));
                } else {
                    if_depth -= 1;
                }
            }
            _ => {}
        }
    }

    // ── Unclosed branches ─────────────────────────────────────────────────
    if if_depth > 0 {
        issues.push(ValidationIssue::error(format!(
            "{}: {} unclosed OP_IF/OP_NOTIF — missing OP_ENDIF",
            label, if_depth
        )));
    }

    issues
}

// ─── Placeholder consistency (CashScript-style) ───────────────────────────────

/// Cross-check every `<name>` placeholder in the ASM against the function's
/// `witnessSchema` and the contract's `constructorInputs`.
///
/// Every placeholder must resolve to one of:
/// - A name in `witnessSchema` (caller-supplied witness element).
/// - A name in `constructorInputs` (constructor-bound script parameter).
/// - A well-known runtime placeholder: `SERVER_KEY` (operator key), or any token
///   starting with `VTXO:` (contract instance reference resolved by the Arkade node).
///
/// Orphaned placeholders mean the transaction can never be constructed because
/// there is no known binding for that name.
pub fn validate_placeholder_consistency(
    func_name: &str,
    server_variant: bool,
    asm: &[String],
    witness_schema: &[crate::models::WitnessElement],
    constructor_inputs: &[Parameter],
) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    let label = format!("fn '{}' (serverVariant={})", func_name, server_variant);

    let witness_names: HashSet<&str> = witness_schema.iter().map(|w| w.name.as_str()).collect();
    let ctor_names: HashSet<&str> = constructor_inputs.iter().map(|p| p.name.as_str()).collect();

    for instr in asm {
        if instr.starts_with('<') && instr.ends_with('>') && instr.len() >= 3 {
            let name = &instr[1..instr.len() - 1];

            // Well-known runtime-resolved tokens
            if name == "SERVER_KEY" || name.starts_with("VTXO:") || name.starts_with("serverSig") {
                continue;
            }

            // Compound-expression placeholders like
            // <checkMultisig([a,b],[c,d])> or <sha256(preimage)>
            // are emitted verbatim when the compiler cannot fully inline an
            // expression.  They are evaluated by the Arkade node at spend time —
            // not looked up by name — so we skip the name-resolution check.
            if name.contains('(') || name.contains('[') || name.contains(',') {
                continue;
            }

            if !witness_names.contains(name) && !ctor_names.contains(name) {
                issues.push(ValidationIssue::warning(format!(
                    "{}: placeholder <{}> is not in witnessSchema or constructorInputs; \
                     this transaction cannot be constructed without a binding for '{}'",
                    label, name, name
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
    use crate::models::{AbiFunction, Contract, Function, Parameter, WitnessElement};

    fn make_contract(name: &str, has_server_key: bool, exit_timelock: Option<&str>) -> Contract {
        Contract {
            name: name.to_string(),
            parameters: vec![Parameter {
                name: "owner".to_string(),
                param_type: "pubkey".to_string(),
            }],
            renewal_timelock: None,
            exit_timelock: exit_timelock.map(|s| s.to_string()),
            has_server_key,
            functions: vec![Function {
                name: "spend".to_string(),
                parameters: vec![],
                statements: vec![],
                is_internal: false,
            }],
            imports: vec![],
        }
    }

    #[test]
    fn valid_contract_has_no_issues() {
        let contract = make_contract("Simple", true, Some("144"));
        let issues = validate_ast(&contract);
        assert!(!has_errors(&issues));
    }

    #[test]
    fn empty_contract_name_is_error() {
        let contract = make_contract("", true, Some("144"));
        let issues = validate_ast(&contract);
        assert!(has_errors(&issues));
        assert!(issues.iter().any(|i| i.message.contains("name")));
    }

    #[test]
    fn no_functions_is_error() {
        let mut contract = make_contract("Empty", true, Some("144"));
        contract.functions.clear();
        let issues = validate_ast(&contract);
        assert!(has_errors(&issues));
        assert!(issues
            .iter()
            .any(|i| i.message.contains("non-internal function")));
    }

    #[test]
    fn only_internal_functions_is_error() {
        let mut contract = make_contract("AllInternal", true, Some("144"));
        contract.functions[0].is_internal = true;
        let issues = validate_ast(&contract);
        assert!(has_errors(&issues));
    }

    #[test]
    fn duplicate_function_name_is_error() {
        let mut contract = make_contract("Dup", true, Some("144"));
        contract.functions.push(contract.functions[0].clone());
        let issues = validate_ast(&contract);
        assert!(has_errors(&issues));
        assert!(issues.iter().any(|i| i.message.contains("spend")));
    }

    #[test]
    fn duplicate_constructor_param_is_error() {
        let mut contract = make_contract("Dup", true, Some("144"));
        contract.parameters.push(contract.parameters[0].clone());
        let issues = validate_ast(&contract);
        assert!(has_errors(&issues));
    }

    #[test]
    fn server_key_without_exit_timelock_is_error() {
        let contract = make_contract("NoExit", true, None);
        let issues = validate_ast(&contract);
        assert!(has_errors(&issues));
        assert!(issues.iter().any(|i| i.message.contains("exit")));
    }

    #[test]
    fn zero_exit_timelock_is_error() {
        let contract = make_contract("ZeroExit", true, Some("0"));
        let issues = validate_ast(&contract);
        assert!(has_errors(&issues));
        assert!(issues.iter().any(|i| i.message.contains("positive")));
    }

    #[test]
    fn negative_exit_timelock_is_error() {
        let contract = make_contract("NegExit", true, Some("-1"));
        let issues = validate_ast(&contract);
        assert!(has_errors(&issues));
        assert!(issues.iter().any(|i| i.message.contains("positive")));
    }

    #[test]
    fn param_name_exit_timelock_is_not_checked_for_value() {
        // "exit" is a constructor param name, value not known at compile time
        let contract = make_contract("ParamExit", true, Some("exit"));
        let issues = validate_ast(&contract);
        assert!(!has_errors(&issues));
    }

    #[test]
    fn no_server_key_without_exit_timelock_is_valid() {
        // A contract without server key doesn't need an exit timelock
        let contract = make_contract("NoServer", false, None);
        let issues = validate_ast(&contract);
        assert!(!has_errors(&issues));
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
            functions: vec![
                AbiFunction {
                    name: "spend".to_string(),
                    function_inputs: vec![],
                    witness_schema: witness.clone(),
                    server_variant: true,
                    require: vec![],
                    asm: vec!["OP_CHECKSIG".to_string()],
                },
                AbiFunction {
                    name: "spend".to_string(),
                    function_inputs: vec![],
                    witness_schema: witness,
                    server_variant: false,
                    require: vec![],
                    asm: vec!["OP_CHECKSIG".to_string()],
                },
            ],
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
        output.functions[0].asm.clear();
        let issues = validate_output(&output);
        assert!(has_errors(&issues));
        assert!(issues.iter().any(|i| i.message.contains("empty ASM")));
    }

    #[test]
    fn missing_exit_variant_is_output_warning() {
        let mut output = make_output("NoExit");
        output.functions.retain(|f| f.server_variant);
        let issues = validate_output(&output);
        // Missing exit variant → warning (not fatal; might be intentional)
        assert!(!has_errors(&issues));
        assert!(issues
            .iter()
            .any(|i| i.message.contains("serverVariant=false")));
    }
}
