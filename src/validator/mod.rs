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

use crate::models::child_exprs;
use crate::models::{
    AssignmentTarget, Contract, ContractJson, ExprKind, Expression, KeyExpr, LocatedStatement,
    Requirement, Statement, TapItem,
};
use crate::operators::{BinaryOperator, OperatorClass};
use crate::types::{build_scope_with_structs, ArkType, Scope};
use std::collections::{HashMap, HashSet};

mod assets;
mod bindings;
mod expressions;
mod functions;
mod operands;
mod output;
pub(crate) mod references;
mod shadowing;

use assets::check_asset_id_operands;
use bindings::check_binding_semantics;
use shadowing::check_shadowing;

pub(crate) use bindings::binding_types_compatible;
pub(crate) use output::validate_output;

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
    /// Byte range of the expression, statement or function that caused it.
    pub span: Option<crate::diagnostics::Span>,
    /// Diagnostic code: `validation`, or `type` for operand type mismatches.
    pub code: &'static str,
}

impl ValidationIssue {
    fn error(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            message: message.into(),
            span: None,
            code: "validation",
        }
    }

    fn warning(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            message: message.into(),
            span: None,
            code: "validation",
        }
    }

    fn at(mut self, span: crate::diagnostics::Span) -> Self {
        self.span = Some(span);
        self
    }

    fn type_error(message: impl Into<String>) -> Self {
        Self {
            code: "type",
            ..Self::error(message)
        }
    }
}

/// Positions issues that a nested statement has not already positioned.
fn locate(issues: &mut [ValidationIssue], span: crate::diagnostics::Span) {
    for issue in issues {
        issue.span.get_or_insert(span);
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
/// - At least one public function is declared.
/// - Function names are unique within the contract.
/// - Tapscript names are unique within the contract.
/// - Constructor parameter names are unique.
/// - Each function's parameter names are unique within that function.
/// - Tapscript inputs do not collide with reserved arkd names.
/// - Asset ID operands have the expected txid/gidx types.
///
/// Reads `Expression::ty`, so `types::annotate` must run first; on an
/// unannotated contract every type is `Unknown` and type checks pass vacuously.
pub(crate) fn validate_ast(contract: &Contract, require_entrypoint: bool) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();

    check_struct_definitions(contract, &mut issues);

    // ── Contract name ──────────────────────────────────────────────────────
    if require_entrypoint && contract.name.is_empty() {
        issues.push(ValidationIssue::error("contract name must not be empty"));
    }

    // ── At least one public function or tapscript ──────────────────
    let public_count = contract.functions.iter().filter(|f| !f.is_private).count();
    if require_entrypoint && public_count == 0 && contract.tapscripts.is_empty() {
        issues.push(ValidationIssue::error(
            "contract must declare at least one public function",
        ));
    }

    // ── Unique function names ──────────────────────────────────────────────
    {
        let mut seen: HashSet<&str> = HashSet::new();
        for func in contract.functions.iter().filter(|f| !f.is_imported()) {
            if !seen.insert(func.name.as_str()) {
                issues.push(
                    ValidationIssue::error(format!(
                        "duplicate function name '{}'; each function must have a unique name",
                        func.name
                    ))
                    .at(func.span),
                );
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
    for func in contract.functions.iter().filter(|f| !f.is_imported()) {
        let first = issues.len();
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
        locate(&mut issues[first..], func.span);
    }

    functions::validate_functions(contract, &mut issues);

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

    // Reserved arkd names (`server`, `emulator`, `serverExitDelay`) are
    // supplied by the server, never by constructor parameters.
    for p in &contract.parameters {
        if crate::models::RESERVED_NAMES.contains(&p.name.as_str()) {
            issues.push(ValidationIssue::error(format!(
                "constructor parameter '{}' collides with a reserved arkd name",
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
            if crate::models::RESERVED_NAMES.contains(&p.name.as_str()) {
                issues.push(ValidationIssue::error(format!(
                    "tapscript '{}' input '{}' collides with a reserved arkd name",
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
            if crate::models::is_builtin_struct(&p.param_type)
                || contract
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
        // A literal or constant without blocks(n)/seconds(n) is pushed raw.
        for item in &ts.items {
            let (call, value, raw) = match item {
                TapItem::Older { value, unit: None } => ("older", value, "BIP68 sequence"),
                TapItem::After { value, unit: None } => ("after", value, "nLockTime"),
                _ => continue,
            };
            if value.parse::<i64>().is_ok() {
                issues.push(ValidationIssue::warning(format!(
                    "tapscript '{}': {call}({value}) is a raw {raw}; write blocks(n) or seconds(n) to state its unit",
                    ts.name
                )));
            }
        }
    }

    check_shadowing(contract, &mut issues);
    check_unused(contract, &mut issues);
    check_binding_semantics(contract, &mut issues);
    check_asset_id_operands(contract, &mut issues);

    issues
}

fn check_struct_definitions(contract: &Contract, issues: &mut Vec<ValidationIssue>) {
    let mut names = HashSet::new();
    for definition in &contract.structs {
        if crate::models::is_builtin_type(&definition.name)
            || crate::models::is_builtin_struct(&definition.name)
        {
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
    let mut validated = HashSet::new();
    for definition in &contract.structs {
        validate_struct_fields(
            definition,
            &definitions,
            &mut Vec::new(),
            &mut validated,
            issues,
        );
    }
    for parameter in contract.parameters.iter().chain(
        contract
            .tapscripts
            .iter()
            .flat_map(|tapscript| &tapscript.inputs),
    ) {
        validate_declared_type(&parameter.param_type, "parameter", &definitions, issues);
    }
    for function in &contract.functions {
        let first = issues.len();
        for parameter in &function.parameters {
            validate_declared_type(&parameter.param_type, "parameter", &definitions, issues);
        }
        // Imported helpers are positioned in their defining file.
        if !function.is_imported() {
            validate_local_types(&function.statements, &function.name, &definitions, issues);
            locate(&mut issues[first..], function.span);
        }
    }
}

fn validate_local_types(
    statements: &[LocatedStatement],
    function_name: &str,
    definitions: &HashMap<&str, &crate::models::StructDefinition>,
    issues: &mut Vec<ValidationIssue>,
) {
    for statement in statements {
        let first = issues.len();
        match &statement.statement {
            Statement::LetBinding {
                declared_type: Some(declared_type),
                ..
            } => {
                if !crate::models::is_builtin_struct(declared_type) {
                    validate_declared_type(
                        declared_type,
                        &format!("local declaration in function '{function_name}'"),
                        definitions,
                        issues,
                    );
                }
            }
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
            Statement::ForIn { body, .. } | Statement::ForCount { body, .. } => {
                validate_local_types(body, function_name, definitions, issues);
            }
            _ => {}
        }
        locate(&mut issues[first..], statement.span);
    }
}

fn validate_struct_fields<'a>(
    definition: &'a crate::models::StructDefinition,
    definitions: &HashMap<&'a str, &'a crate::models::StructDefinition>,
    stack: &mut Vec<&'a str>,
    validated: &mut HashSet<&'a str>,
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
    if !validated.insert(definition.name.as_str()) {
        return;
    }
    stack.push(&definition.name);
    for field in &definition.fields {
        if !crate::models::is_builtin_struct(&field.param_type) {
            validate_declared_type(
                &field.param_type,
                &format!("field '{}.{}'", definition.name, field.name),
                definitions,
                issues,
            );
        }
        let base = crate::models::array_type_parts(&field.param_type)
            .map(|(base, _)| base)
            .unwrap_or(&field.param_type);
        if let Some(nested) = definitions.get(base) {
            validate_struct_fields(nested, definitions, stack, validated, issues);
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
    if !crate::models::is_builtin_type(base)
        && !crate::models::is_builtin_struct(base)
        && !definitions.contains_key(base)
    {
        issues.push(ValidationIssue::error(format!(
            "{context} uses unknown type '{base}'"
        )));
    }
}

fn validate_source_identifier(name: &str, context: &str, issues: &mut Vec<ValidationIssue>) {
    if crate::models::RESERVED_PLACEHOLDERS.contains(&name) {
        issues.push(ValidationIssue::error(format!(
            "{context} '{name}' uses a compiler-reserved placeholder name"
        )));
    }
    const RESERVED: &[&str] = &[
        "int",
        "bool",
        "bytes",
        "bytes20",
        "bytes32",
        "pubkey",
        "signature",
        "asset",
        "contract",
        "library",
        "function",
        "struct",
        "require",
        "if",
        "else",
        "for",
        "in",
        "return",
        "const",
        "import",
        "pragma",
        "true",
        "false",
        "tapscript",
        "private",
        "public",
        "static",
        "tx",
        "this",
    ];
    if RESERVED.contains(&name) {
        issues.push(ValidationIssue::error(format!(
            "{context} '{name}' uses a reserved keyword or type name"
        )));
    }
}

/// Reject parameters, locals, and tapscript inputs that are never read: an
/// unread witness element is unchecked, so anyone relaying the spend could
/// replace it. An unread constructor parameter is only a warning because it is
/// pruned from the script and cannot be malleated.
fn check_unused(contract: &Contract, issues: &mut Vec<ValidationIssue>) {
    let mut contract_used: HashSet<&str> = HashSet::new();
    for tapscript in &contract.tapscripts {
        let mut used = HashSet::new();
        for item in &tapscript.items {
            match item {
                TapItem::Hash { preimage, hash, .. } => used.extend([preimage, hash]),
                TapItem::Older { value, .. } | TapItem::After { value, .. } => {
                    used.insert(value);
                }
                TapItem::Sig { keys, sigs, .. } => {
                    used.extend(keys.iter().map(|key| match key {
                        KeyExpr::Ident(name) | KeyExpr::Tweak { base: name, .. } => name,
                    }));
                    used.extend(sigs);
                }
            }
        }
        for input in tapscript.inputs.iter().filter(|i| !used.contains(&i.name)) {
            issues.push(ValidationIssue::error(format!(
                "input '{}' in tapscript '{}' is never used",
                input.name, tapscript.name
            )));
        }
        contract_used.extend(used.into_iter().map(String::as_str));
    }
    for function in contract.functions.iter().filter(|f| !f.is_imported()) {
        let used = references::referenced_parameters(&function.statements, &[]);
        for parameter in function
            .parameters
            .iter()
            .filter(|p| !used.contains(p.name.as_str()))
        {
            issues.push(
                ValidationIssue::error(format!(
                    "variable '{}' in function '{}' is never used",
                    parameter.name, function.name
                ))
                .at(function.span),
            );
        }
        check_unused_locals(&function.statements, &function.name, issues);
        contract_used.extend(used);
    }
    for parameter in contract
        .parameters
        .iter()
        .filter(|p| !contract_used.contains(p.name.as_str()))
    {
        issues.push(ValidationIssue::warning(format!(
            "constructor parameter '{}' is never used",
            parameter.name
        )));
    }
}

/// A local is read only by later statements in its own block, since shadowing
/// is rejected; sibling blocks may reuse the name for a separate binding.
// ponytail: rescans the rest of the block per binding, O(n²) in block length;
// index reads per binding in one pass if contract bodies ever grow large.
fn check_unused_locals(
    statements: &[LocatedStatement],
    function: &str,
    issues: &mut Vec<ValidationIssue>,
) {
    for (index, statement) in statements.iter().enumerate() {
        match &statement.statement {
            Statement::LetBinding { name, .. }
                if !references::referenced_parameters(&statements[index + 1..], &[])
                    .contains(name.as_str()) =>
            {
                issues.push(
                    ValidationIssue::error(format!(
                        "variable '{name}' in function '{function}' is never used"
                    ))
                    .at(statement.span),
                );
            }
            Statement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                check_unused_locals(then_body, function, issues);
                check_unused_locals(else_body.as_deref().unwrap_or_default(), function, issues);
            }
            Statement::ForIn { body, .. } | Statement::ForCount { body, .. } => {
                check_unused_locals(body, function, issues)
            }
            _ => {}
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AbiFunctionGroup, AbiLeaf, Contract, Function, Parameter, WitnessElement};

    #[test]
    fn output_validation_checks_filtered_constructor_layouts() {
        let output = crate::compile("contract C(int unused, int[2] values, int limit) { function spend() { require(values[0] > limit); } }").unwrap();
        for prologue in [
            vec!["<values.1>", "<values.0>", "<limit>"],
            vec!["<limit>", "<values.0>"],
            vec!["<limit>", "<limit>"],
            vec!["<unknown>"],
            vec!["OP_1", "<limit>"],
        ] {
            let mut invalid = output.clone();
            let asm = &mut invalid.functions[0].arkade.as_mut().unwrap().asm;
            asm.splice(..3, prologue.into_iter().map(String::from));
            assert!(
                has_errors(&validate_output(&invalid)),
                "{:?}",
                invalid.functions[0].arkade.as_ref().unwrap().asm
            );
        }
    }

    fn parse_and_validate(source: &str) -> Vec<ValidationIssue> {
        validate(&crate::parser::parse(source).expect("contract should parse"))
    }

    fn validate(contract: &Contract) -> Vec<ValidationIssue> {
        let mut contract = contract.clone();
        crate::types::annotate(&mut contract);
        validate_ast(&contract, true)
    }

    #[test]
    fn rejects_undefined_bindings_in_array_indices_once() {
        for statement in [
            "require(values[missing] == 1);",
            "require(values[missing + 1] == 1);",
            "values[missing] = 1;",
            "values[missing + 1] = 1;",
        ] {
            let issues = parse_and_validate(&format!(
                "contract C() {{ function spend(int[3] values) {{ {statement} require(true); }} }}"
            ));
            assert_eq!(
                issues
                    .iter()
                    .filter(|issue| issue.message.contains("'missing'"))
                    .count(),
                1,
                "{statement}: {issues:?}"
            );
            assert!(has_errors(&issues), "{issues:?}");
        }
    }

    #[test]
    fn validates_dynamic_array_assignment_target() {
        let issues = parse_and_validate(
            r#"
contract Demo() {
    function spend(int offset) {
        int[3] values = [1, 2, 3];
        values[offset + 1] = 4;
        require(values[0] == 1);
    }
}
"#,
        );
        assert!(!has_errors(&issues), "{issues:?}");
    }

    #[test]
    fn rejects_invalid_array_assignment_targets_once() {
        for (target, expected) in [
            ("value[0]", "binding 'value' is not an array"),
            ("missing[0]", "array 'missing' is undefined"),
            ("values[flag]", "array index has type 'bool'"),
            ("values[missing]", "binding 'missing' is undefined"),
            ("values[3]", "array index '3' is out of range"),
            ("values[-1]", "array index '-1' is out of range"),
        ] {
            let source = format!(
                r#"
contract Demo() {{
    function spend(bool flag) {{
        int value = 1;
        int[3] values = [1, 2, 3];
        {target} = 4;
        require(true);
    }}
}}
"#
            );
            let issues = parse_and_validate(&source);
            assert_eq!(
                issues
                    .iter()
                    .filter(|issue| issue.message.contains(expected))
                    .count(),
                1,
                "{issues:?}"
            );
        }
    }

    #[test]
    fn rejects_array_assignment_with_wrong_element_type() {
        let issues = parse_and_validate(
            r#"
contract Demo() {
    function spend() {
        int[2] values = [1, 2];
        values[0] = true;
        require(true);
    }
}
"#,
        );
        assert!(issues.iter().any(|issue| issue
            .message
            .contains("assignment to an element of 'values' changes its type")));
    }

    #[test]
    fn builtin_array_literals_report_each_fault_once() {
        for (call, expected) in [
            (
                "checkMultisig([1], [sig])",
                "checkMultisig '1' has type 'int', expected 'bytes'",
            ),
            (
                "checkMultisig([key], [1])",
                "checkMultisig '1' has type 'int', expected 'signature'",
            ),
            (
                "checkMultisig([key, 1], [sig, sig])",
                "checkMultisig '1' has type 'int', expected 'bytes'",
            ),
            (
                "checkMultisig([key], [sig, sig])",
                "checkMultisig operand has 2 elements, expected 1",
            ),
            (
                "checkMultisig([key], [signature(substr(1, 0, 64))])",
                "substr operand has type 'int', expected 'bytes'",
            ),
            ("checkMultisig([key], [missing])", "'missing' is undefined"),
        ] {
            let source = format!("contract C(pubkey key) {{ function spend(signature sig) {{ require(checkSig(sig, key)); require({call}); }} }}");
            let issues = parse_and_validate(&source);
            assert_eq!(issues.len(), 1, "{call}: {issues:?}");
            assert!(issues[0].message.contains(expected), "{call}: {issues:?}");
        }
    }

    fn located(statement: Statement) -> LocatedStatement {
        LocatedStatement {
            span: crate::diagnostics::Span { start: 0, end: 0 },
            statement,
        }
    }

    fn make_contract(name: &str) -> Contract {
        Contract {
            name: name.to_string(),
            is_library: false,
            structs: vec![],
            parameters: vec![Parameter {
                name: "owner".to_string(),
                param_type: "pubkey".to_string(),
            }],
            functions: vec![Function {
                name: "spend".to_string(),
                span: crate::diagnostics::Span { start: 0, end: 0 },
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
                statements: vec![located(Statement::Require(Requirement::Expression(
                    ExprKind::Builtin {
                        builtin: crate::builtins::find("checkSig").unwrap(),
                        args: vec![
                            ExprKind::Variable("ownerSig".to_string()).into(),
                            ExprKind::Variable("owner".to_string()).into(),
                        ],
                    }
                    .into(),
                )))],
                is_private: false,
                is_static: false,
                is_exported: false,
                return_type: None,
            }],
            tapscripts: Vec::new(),
            imports: vec![],
            constants: vec![],
        }
    }

    #[test]
    fn valid_contract_has_no_issues() {
        let mut contract = make_contract("Simple");
        // `flag` is only read by the branch tests.
        contract.functions[0].parameters.pop();
        let issues = validate(&contract);
        assert!(!has_errors(&issues));
    }

    #[test]
    fn require_only_in_one_branch_is_error() {
        // An if with a require in the then-branch but no else leaves the
        // "condition false" path with no require() → a trivially-passing spend.
        let mut contract = make_contract("BarePath");
        contract.functions[0].statements = vec![located(Statement::IfElse {
            condition: ExprKind::Variable("flag".to_string()).into(),
            then_body: vec![located(Statement::Require(Requirement::Expression(
                ExprKind::Builtin {
                    builtin: crate::builtins::find("checkSig").unwrap(),
                    args: vec![
                        ExprKind::Variable("ownerSig".to_string()).into(),
                        ExprKind::Variable("owner".to_string()).into(),
                    ],
                }
                .into(),
            )))],
            else_body: None,
        })];
        let issues = validate(&contract);
        assert!(has_errors(&issues));
        assert!(issues
            .iter()
            .any(|i| i.message.contains("spend path with no require()")));
    }

    #[test]
    fn require_in_both_branches_is_ok() {
        let mut contract = make_contract("BothPaths");
        let req = || {
            located(Statement::Require(Requirement::Expression(
                ExprKind::Builtin {
                    builtin: crate::builtins::find("checkSig").unwrap(),
                    args: vec![
                        ExprKind::Variable("ownerSig".to_string()).into(),
                        ExprKind::Variable("owner".to_string()).into(),
                    ],
                }
                .into(),
            )))
        };
        contract.functions[0].statements = vec![located(Statement::IfElse {
            condition: ExprKind::Variable("flag".to_string()).into(),
            then_body: vec![req()],
            else_body: Some(vec![req()]),
        })];
        assert!(!has_errors(&validate(&contract)));
    }

    #[test]
    fn empty_contract_name_is_error() {
        let contract = make_contract("");
        let issues = validate(&contract);
        assert!(has_errors(&issues));
        assert!(issues.iter().any(|i| i.message.contains("name")));
    }

    #[test]
    fn no_functions_is_error() {
        let mut contract = make_contract("Empty");
        contract.functions.clear();
        let issues = validate(&contract);
        assert!(has_errors(&issues));
        assert!(issues.iter().any(|i| i.message.contains("public function")));
    }

    #[test]
    fn only_private_functions_is_error() {
        let mut contract = make_contract("AllInternal");
        contract.functions[0].is_private = true;
        let issues = validate(&contract);
        assert!(has_errors(&issues));
    }

    #[test]
    fn duplicate_function_name_is_error() {
        let mut contract = make_contract("Dup");
        contract.functions.push(contract.functions[0].clone());
        let issues = validate(&contract);
        assert!(has_errors(&issues));
        assert!(issues.iter().any(|i| i.message.contains("spend")));
    }

    #[test]
    fn duplicate_constructor_param_is_error() {
        let mut contract = make_contract("Dup");
        contract.parameters.push(contract.parameters[0].clone());
        let issues = validate(&contract);
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
            format_version: None,
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
            fingerprint: None,
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
                "leaked placeholder {leaked} must be an output error"
            );
            assert!(
                issues
                    .iter()
                    .any(|i| i.message.contains("signature in asm")),
                "expected sig-leak message for {leaked}"
            );
        }
    }
}
