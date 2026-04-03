//! Semantic validation for Arkade Script contracts.
//!
//! This module provides two validation passes:
//!
//! 1. **AST validation** (`validate_ast`) — runs after parsing, before compilation.
//!    Catches semantic errors that the PEG grammar cannot express, such as duplicate
//!    function names, missing required options, and invalid timelock values.
//!
//! 2. **Output validation** (`validate_output`) — runs after compilation.
//!    Asserts structural invariants on the emitted `ContractJson`, catching compiler
//!    bugs before the output reaches callers.
//!
//! Issues are returned as a `Vec<ValidationIssue>`.  Use [`has_errors`] to check
//! whether any are fatal.

use crate::models::{Contract, ContractJson};
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

    if let Some(exit) = contract.exit_timelock {
        if exit == 0 {
            issues.push(ValidationIssue::error(
                "options.exit timelock must be greater than 0",
            ));
        }
    }

    if let Some(renewal) = contract.renewal_timelock {
        if renewal == 0 {
            issues.push(ValidationIssue::warning(
                "options.renew timelock is 0; a positive block count is recommended",
            ));
        }
    }

    issues
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

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AbiFunction, Contract, Function, Parameter, WitnessElement};

    fn make_contract(name: &str, has_server_key: bool, exit_timelock: Option<u64>) -> Contract {
        Contract {
            name: name.to_string(),
            parameters: vec![Parameter {
                name: "owner".to_string(),
                param_type: "pubkey".to_string(),
            }],
            renewal_timelock: None,
            exit_timelock,
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
        let contract = make_contract("Simple", true, Some(144));
        let issues = validate_ast(&contract);
        assert!(!has_errors(&issues));
    }

    #[test]
    fn empty_contract_name_is_error() {
        let contract = make_contract("", true, Some(144));
        let issues = validate_ast(&contract);
        assert!(has_errors(&issues));
        assert!(issues.iter().any(|i| i.message.contains("name")));
    }

    #[test]
    fn no_functions_is_error() {
        let mut contract = make_contract("Empty", true, Some(144));
        contract.functions.clear();
        let issues = validate_ast(&contract);
        assert!(has_errors(&issues));
        assert!(issues
            .iter()
            .any(|i| i.message.contains("non-internal function")));
    }

    #[test]
    fn only_internal_functions_is_error() {
        let mut contract = make_contract("AllInternal", true, Some(144));
        contract.functions[0].is_internal = true;
        let issues = validate_ast(&contract);
        assert!(has_errors(&issues));
    }

    #[test]
    fn duplicate_function_name_is_error() {
        let mut contract = make_contract("Dup", true, Some(144));
        contract.functions.push(contract.functions[0].clone());
        let issues = validate_ast(&contract);
        assert!(has_errors(&issues));
        assert!(issues.iter().any(|i| i.message.contains("spend")));
    }

    #[test]
    fn duplicate_constructor_param_is_error() {
        let mut contract = make_contract("Dup", true, Some(144));
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
        let contract = make_contract("ZeroExit", true, Some(0));
        let issues = validate_ast(&contract);
        assert!(has_errors(&issues));
        assert!(issues.iter().any(|i| i.message.contains("greater than 0")));
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
