//! Semantic validation. [`validate_ast`] takes a typed [`Contract`] and reports the errors the
//! grammar cannot express; [`validate_output`] self-checks the emitted `ContractJson`. Code that
//! compiles but is likely wrong is a [`crate::lint`] warning instead.

use std::collections::{HashMap, HashSet};
use std::{fmt, iter};

use crate::diagnostics::Span;
use crate::lint::attributes;
use crate::models::{
    self, child_exprs, Contract, Expression, KeyExpr, LocatedStatement, NamedTapscript, Statement,
    StructDefinition, TapItem, TypeName, RESERVED_NAMES, RESERVED_PLACEHOLDERS,
};
use crate::parser;
use crate::types::ArkType;

mod assets;
mod bindings;
pub(crate) mod error;
mod expressions;
mod functions;
mod operands;
mod output;
pub(crate) mod references;
mod shadowing;

use assets::check_asset_id_operands;
use bindings::check_binding_semantics;
use error::Declared;
pub(crate) use error::ValidationError;
use shadowing::check_shadowing;

pub(crate) use functions::falls_through;
pub(crate) use output::validate_output;

#[derive(Debug, Clone)]
pub struct ValidationIssue {
    pub kind: ValidationError,
    /// Byte range of the expression, statement or function that caused it.
    pub span: Option<Span>,
    pub suggestion: Option<IssueSuggestion>,
}

#[derive(Debug, Clone)]
pub struct IssueSuggestion {
    pub replacement: String,
    /// The span it replaces, when not the issue's own.
    pub span: Option<Span>,
}

impl ValidationIssue {
    /// Suggesting `replacement` for `span`, or for the issue's own span once it is located.
    fn suggest(mut self, replacement: &str, span: Option<Span>) -> Self {
        self.suggestion = Some(IssueSuggestion {
            replacement: replacement.to_string(),
            span,
        });
        self
    }
}

impl From<ValidationError> for ValidationIssue {
    fn from(kind: ValidationError) -> Self {
        Self {
            kind,
            span: None,
            suggestion: None,
        }
    }
}

impl fmt::Display for ValidationIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(f)?;
        match &self.suggestion {
            Some(suggestion) => write!(f, "; did you mean '{}'?", suggestion.replacement),
            None => Ok(()),
        }
    }
}

/// Positions issues that a nested statement has not already positioned.
fn locate(issues: &mut [ValidationIssue], span: Span) {
    for issue in issues {
        issue.span.get_or_insert(span);
    }
}

/// Reads `Expression::ty`, so `types::annotate` must run first; an expression it
/// leaves `Unknown` is an error.
pub(crate) fn validate_ast(contract: &Contract, require_entrypoint: bool) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();

    check_struct_definitions(contract, &mut issues);

    if require_entrypoint && contract.name.is_empty() {
        issues.push(ValidationError::EmptyContractName.into());
    }

    let public_count = contract.functions.iter().filter(|f| !f.is_private).count();
    if require_entrypoint && public_count == 0 && contract.tapscripts.is_empty() {
        // A file with no contract has no name to locate this at.
        issues.push(ValidationIssue {
            span: (!contract.name.is_empty()).then_some(contract.span),
            ..ValidationError::NoEntrypoint.into()
        });
    }

    // Structs, parameters, inputs and locals are checked where they are walked.
    let kind = if contract.is_library {
        Declared::Library
    } else {
        Declared::Contract
    };
    let constants = contract.constants.iter().filter(|c| !c.name.contains('.'));
    let functions = contract.functions.iter().filter(|f| !f.is_imported());
    let tapscripts = contract.tapscripts.iter();
    let declarations = iter::once((kind, &contract.name, contract.span))
        .chain(constants.map(|c| (Declared::Constant, &c.name, c.span)))
        .chain(functions.map(|f| (Declared::Function, &f.name, f.span)))
        .chain(tapscripts.map(|t| (Declared::Tapscript, &t.name, t.span)));
    for (context, name, span) in declarations {
        let first = issues.len();
        let callable = matches!(context, Declared::Function | Declared::Tapscript);
        validate_source_identifier(name, context, &mut issues);
        if callable && parser::reserved_function_signature(name).is_some() {
            let name = name.clone();
            issues.push(ValidationError::ReservedFunctionName { name }.into());
        }
        locate(&mut issues[first..], span);
    }

    {
        let mut seen: HashSet<&str> = HashSet::new();
        for func in contract.functions.iter().filter(|f| !f.is_imported()) {
            if !seen.insert(func.name.as_str()) {
                let name = func.name.clone();
                issues.push(ValidationError::DuplicateFunction { name }.at(func.span));
            }
        }
    }

    {
        let mut seen: HashSet<&str> = HashSet::new();
        for param in &contract.parameters {
            let first = issues.len();
            validate_source_identifier(&param.name, Declared::ConstructorParameter, &mut issues);
            if !seen.insert(param.name.as_str()) {
                let name = param.name.clone();
                issues.push(ValidationError::DuplicateConstructorParameter { name }.into());
            }
            locate(&mut issues[first..], param.span);
        }
    }

    for func in contract.functions.iter().filter(|f| !f.is_imported()) {
        let first = issues.len();
        let mut seen: HashSet<&str> = HashSet::new();
        for param in &func.parameters {
            let function = func.name.clone();
            let context = Declared::FunctionParameter { function };
            validate_source_identifier(&param.name, context, &mut issues);
            if !seen.insert(param.name.as_str()) {
                issues.push(
                    ValidationError::DuplicateParameter {
                        name: param.name.clone(),
                        function: func.name.clone(),
                    }
                    .into(),
                );
            }
        }
        locate(&mut issues[first..], func.span);
    }

    functions::validate_functions(contract, &mut issues);

    {
        let mut seen: HashSet<&str> = HashSet::new();
        for ts in &contract.tapscripts {
            if !seen.insert(ts.name.as_str()) {
                let name = ts.name.clone();
                issues.push(ValidationError::DuplicateTapscript { name }.at(ts.span));
            }
        }
    }

    // The operator supplies the reserved names, so no constructor parameter may.
    for p in &contract.parameters {
        if RESERVED_NAMES.contains(&p.name.as_str()) {
            let name = p.name.clone();
            issues.push(ValidationError::ReservedConstructorParameter { name }.at(p.span));
        }
    }

    for ts in &contract.tapscripts {
        for p in &ts.inputs {
            let first = issues.len();
            let tapscript = ts.name.clone();
            validate_source_identifier(
                &p.name,
                Declared::TapscriptInput { tapscript },
                &mut issues,
            );
            let (tapscript, input, ty) = (ts.name.clone(), p.name.clone(), p.param_type.clone());
            if RESERVED_NAMES.contains(&p.name.as_str()) {
                let (tapscript, input) = (tapscript.clone(), input.clone());
                issues.push(ValidationError::ReservedTapscriptInput { tapscript, input }.into());
            }
            if p.param_type.array_parts().is_some() {
                let (tapscript, input, ty) = (tapscript.clone(), input.clone(), ty.clone());
                let error = ValidationError::ArrayTapscriptInput {
                    tapscript,
                    input,
                    ty,
                };
                issues.push(error.into());
            }
            if p.param_type.is_builtin_struct()
                || contract
                    .structs
                    .iter()
                    .any(|definition| p.param_type.name() == Some(&definition.name))
            {
                let error = ValidationError::StructTapscriptInput {
                    tapscript,
                    input,
                    ty,
                };
                issues.push(error.into());
            }
            locate(&mut issues[first..], p.span);
        }
        let mut seen = HashSet::new();
        for p in &ts.inputs {
            if !seen.insert(p.name.as_str()) {
                let (input, tapscript) = (p.name.clone(), ts.name.clone());
                issues
                    .push(ValidationError::DuplicateTapscriptInput { input, tapscript }.at(p.span));
            }
        }
    }

    check_shadowing(contract, &mut issues);
    check_unused(contract, &mut issues);
    check_binding_semantics(contract, &mut issues);
    check_asset_id_operands(contract, &mut issues);
    for (_, attributes) in contract.attributed() {
        for attribute in attributes {
            if let Some((error, span)) = attributes::error(attribute) {
                issues.push(error.at(span));
            }
        }
    }
    // Errors leave their expressions `Unknown`, so this backstop runs only on a clean contract.
    issues.retain(|issue| issue.kind != ValidationError::Reported);
    if issues.is_empty() {
        for function in contract.functions.iter().filter(|f| !f.is_imported()) {
            check_typed(&function.statements, &mut issues);
        }
    }

    issues
}

/// Reports each innermost expression `types::annotate` left `Unknown`; every type
/// check reads `Expression::ty`, so none of them may have passed over it.
fn check_typed(statements: &[LocatedStatement], issues: &mut Vec<ValidationIssue>) {
    fn visit(expression: &Expression, issues: &mut Vec<ValidationIssue>) {
        let children = child_exprs(expression);
        if expression.ty == ArkType::Unknown && children.iter().all(|c| c.ty != ArkType::Unknown) {
            let text = expression.source_text();
            issues.push(ValidationError::CannotInferType { text }.at(expression.span));
        }
        children.into_iter().for_each(|child| visit(child, issues));
    }
    for statement in statements {
        statement
            .statement
            .expressions()
            .into_iter()
            .for_each(|value| visit(value, issues));
        match &statement.statement {
            Statement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                check_typed(then_body, issues);
                check_typed(else_body.as_deref().unwrap_or_default(), issues);
            }
            Statement::ForIn { body, .. }
            | Statement::ForCount { body, .. }
            | Statement::ForRange { body, .. } => check_typed(body, issues),
            _ => {}
        }
    }
}

fn check_struct_definitions(contract: &Contract, issues: &mut Vec<ValidationIssue>) {
    let mut names = HashSet::new();
    for definition in &contract.structs {
        if models::is_builtin_type(&definition.name) || models::is_builtin_struct(&definition.name)
        {
            let name = definition.name.clone();
            issues.push(ValidationError::StructCollidesWithBuiltin { name }.at(definition.span));
        } else {
            let first = issues.len();
            validate_source_identifier(&definition.name, Declared::Struct, issues);
            locate(&mut issues[first..], definition.span);
        }
        if !names.insert(definition.name.as_str()) {
            let name = definition.name.clone();
            issues.push(ValidationError::DuplicateStruct { name }.into());
        }
        let mut fields = HashSet::new();
        for field in &definition.fields {
            let first = issues.len();
            let name = definition.name.clone();
            validate_source_identifier(&field.name, Declared::StructField { name }, issues);
            locate(&mut issues[first..], field.span);
            if !fields.insert(field.name.as_str()) {
                let error = ValidationError::DuplicateStructField {
                    field: field.name.clone(),
                    name: definition.name.clone(),
                };
                issues.push(error.at(field.span));
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
        validate_declared_type(
            &parameter.param_type,
            Declared::Parameter,
            &definitions,
            issues,
        );
    }
    for function in &contract.functions {
        let first = issues.len();
        for parameter in &function.parameters {
            validate_declared_type(
                &parameter.param_type,
                Declared::Parameter,
                &definitions,
                issues,
            );
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
    definitions: &HashMap<&str, &StructDefinition>,
    issues: &mut Vec<ValidationIssue>,
) {
    for statement in statements {
        let first = issues.len();
        match &statement.statement {
            Statement::Declaration { declared_type, .. }
            | Statement::LetBinding {
                declared_type: Some(declared_type),
                ..
            } => {
                if !declared_type.is_builtin_struct() {
                    let function = function_name.to_string();
                    let context = Declared::LocalDeclaration { function };
                    validate_declared_type(declared_type, context, definitions, issues);
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
            Statement::ForIn { body, .. }
            | Statement::ForCount { body, .. }
            | Statement::ForRange { body, .. } => {
                validate_local_types(body, function_name, definitions, issues);
            }
            _ => {}
        }
        locate(&mut issues[first..], statement.span);
    }
}

fn validate_struct_fields<'a>(
    definition: &'a StructDefinition,
    definitions: &HashMap<&'a str, &'a StructDefinition>,
    stack: &mut Vec<&'a str>,
    validated: &mut HashSet<&'a str>,
    issues: &mut Vec<ValidationIssue>,
) {
    if stack.contains(&definition.name.as_str()) {
        let cycle = stack.iter().copied().chain([definition.name.as_str()]);
        let cycle = cycle.map(str::to_string).collect();
        issues.push(ValidationError::RecursiveStruct { cycle }.at(definition.span));
        return;
    }
    if !validated.insert(definition.name.as_str()) {
        return;
    }
    stack.push(&definition.name);
    for field in &definition.fields {
        let base = field.param_type.base_name();
        // A built-in name keeps its built-in layout even where a struct reuses it.
        if models::is_builtin_type(base) || models::is_builtin_struct(base) {
            continue;
        }
        let context = Declared::Field {
            name: definition.name.clone(),
            field: field.name.clone(),
        };
        validate_declared_type(&field.param_type, context, definitions, issues);
        if let Some(nested) = definitions.get(base) {
            validate_struct_fields(nested, definitions, stack, validated, issues);
        }
    }
    stack.pop();
}

fn validate_declared_type(
    declared_type: &TypeName,
    context: Declared,
    definitions: &HashMap<&str, &StructDefinition>,
    issues: &mut Vec<ValidationIssue>,
) {
    let base = declared_type.base_name();
    if !models::is_builtin_type(base)
        && !models::is_builtin_struct(base)
        && !definitions.contains_key(base)
    {
        let base = base.to_string();
        issues.push(ValidationError::UnknownType { context, base }.into());
    }
}

fn validate_source_identifier(name: &str, context: Declared, issues: &mut Vec<ValidationIssue>) {
    if RESERVED_PLACEHOLDERS.contains(&name) {
        let (context, name) = (context.clone(), name.to_string());
        issues.push(ValidationError::PlaceholderName { context, name }.into());
    }
    const RESERVED: &[&str] = &[
        "int",
        "bool",
        "bytes",
        "bytes20",
        "bytes32",
        "pubkey",
        "signature",
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
        "let",
        "import",
        "pragma",
        "true",
        "false",
        "tapscript",
        "private",
        "static",
        "new",
        "tx",
        "this",
    ];
    if RESERVED.contains(&name) {
        let name = name.to_string();
        issues.push(ValidationError::ReservedName { context, name }.into());
    }
}

/// Reject parameters and tapscript inputs that are never read: an unread witness
/// element is unchecked, so anyone relaying the spend could replace it. A read by a
/// local or assignment nothing later reads does not count, since the script drops the
/// value. An unread constructor parameter or local is itself only a lint, since neither
/// can be malleated.
fn check_unused(contract: &Contract, issues: &mut Vec<ValidationIssue>) {
    for tapscript in &contract.tapscripts {
        let used = tapscript_reads(tapscript);
        for input in tapscript
            .inputs
            .iter()
            .filter(|i| !used.contains(i.name.as_str()))
        {
            let error = ValidationError::UnusedTapscriptInput {
                input: input.name.clone(),
                tapscript: tapscript.name.clone(),
            };
            issues.push(error.at(input.span));
        }
    }
    for function in contract.functions.iter().filter(|f| !f.is_imported()) {
        let (used, _) = references::live_reads(&function.statements);
        for parameter in function
            .parameters
            .iter()
            .filter(|p| !used.contains(p.name.as_str()))
        {
            let error = ValidationError::UnusedParameter {
                parameter: parameter.name.clone(),
                function: function.name.clone(),
            };
            issues.push(error.at(parameter.span));
        }
    }
}

/// The bindings a tapscript's items read: `guardians` for `guardians[0]`, `policy` for
/// `policy.owner`.
pub(crate) fn tapscript_reads(tapscript: &NamedTapscript) -> HashSet<&str> {
    let mut used = HashSet::new();
    for item in &tapscript.items {
        match item {
            TapItem::Hash { preimage, hash, .. } => {
                used.extend(iter::once(preimage).chain(hash.path()).map(|p| &*p.root));
            }
            TapItem::Older { value, .. } | TapItem::After { value, .. } => {
                used.extend(value.path().map(|p| &*p.root));
            }
            TapItem::Sig { keys, sigs, .. } => {
                used.extend(keys.iter().filter_map(|key| match key {
                    KeyExpr::Ident(path) => Some(&*path.root),
                    KeyExpr::Literal(_) => None,
                    KeyExpr::Tweak { base, .. } => Some(base.as_str()),
                }));
                used.extend(sigs.iter().map(|p| &*p.root));
            }
        }
    }
    used
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::diagnostics::Span;
    use crate::models::ContractJson;
    use crate::models::ExprKind;
    use crate::models::{self, ARTIFACT_FORMAT_VERSION};
    use crate::models::{AbiFunctionGroup, AbiLeaf, Contract, Function, Parameter, WitnessElement};
    use crate::{builtins, parser, types};

    #[test]
    fn output_validation_checks_constructor_placeholders() {
        let output = crate::compile("contract C(int unused, int[2] values, int limit) { function spend() { require(values[0] > limit); } }").unwrap();
        assert_eq!(
            output.functions[0].arkade.as_ref().unwrap().asm,
            ["<values.0>", "<limit>", "OP_GREATERTHAN"]
        );
        for (placeholders, valid) in [
            (["<values.0>", "<limit>"], true),
            (["<limit>", "<limit>"], false),
            (["<unknown>", "<limit>"], false),
        ] {
            let mut output = output.clone();
            let asm = &mut output.functions[0].arkade.as_mut().unwrap().asm;
            asm.splice(..2, placeholders.into_iter().map(String::from));
            assert_eq!(
                validate_output(&output).is_empty(),
                valid,
                "{placeholders:?}"
            );
        }
    }

    fn parse_and_validate(source: &str) -> Vec<ValidationIssue> {
        validate(&parser::parse(source).expect("contract should parse"))
    }

    fn validate(contract: &Contract) -> Vec<ValidationIssue> {
        let mut contract = contract.clone();
        types::annotate(&mut contract);
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
            let missing = ValidationError::UndefinedName {
                label: "binding",
                name: "missing".into(),
            };
            assert_eq!(
                issues.iter().filter(|issue| issue.kind == missing).count(),
                1,
                "{statement}: {issues:?}"
            );
            assert!(!issues.is_empty(), "{issues:?}");
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
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn rejects_invalid_array_assignment_targets_once() {
        let out_of_range = |value: &str| ValidationError::IndexOutOfRange {
            value: value.into(),
            array: "values[3]".into(),
        };
        for (target, expected) in [
            (
                "value[0]",
                ValidationError::NotAnArray {
                    binding: "value".into(),
                },
            ),
            (
                "missing[0]",
                ValidationError::UndefinedArray {
                    array: "missing".into(),
                },
            ),
            (
                "values[flag]",
                ValidationError::IndexType {
                    actual: "bool".into(),
                },
            ),
            (
                "values[missing]",
                ValidationError::UndefinedName {
                    label: "binding",
                    name: "missing".into(),
                },
            ),
            ("values[3]", out_of_range("3")),
            ("values[-1]", out_of_range("-1")),
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
                issues.iter().filter(|issue| issue.kind == expected).count(),
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
        assert!(issues.iter().any(|issue| matches!(
            &issue.kind,
            ValidationError::ElementAssignmentType { array, .. } if array.key() == "values"
        )));
    }

    #[test]
    fn builtin_array_literals_report_each_fault_once() {
        let element = |expected: &str| ValidationError::BuiltinElementType {
            builtin: "checkMultisig",
            value: "1".into(),
            actual: "int".into(),
            expected: expected.into(),
        };
        for (call, expected) in [
            ("checkMultisig([1], [sig])", element("bytes")),
            ("checkMultisig([key], [1])", element("signature")),
            ("checkMultisig([key, 1], [sig, sig])", element("bytes")),
            (
                "checkMultisig([key], [sig, sig])",
                ValidationError::BuiltinElementCount {
                    builtin: "checkMultisig",
                    got: 2,
                    expected: 1,
                },
            ),
            (
                "checkMultisig([key], [signature(substr(1, 0, 64))])",
                ValidationError::BuiltinOperandType {
                    builtin: "substr",
                    actual: "int".into(),
                    expected: "bytes".into(),
                },
            ),
            (
                "checkMultisig([key], [missing])",
                ValidationError::UndefinedName {
                    label: "binding",
                    name: "missing".into(),
                },
            ),
        ] {
            let source = format!("contract C(pubkey key) {{ function spend(signature sig) {{ require(checkSig(sig, key)); require({call}); }} }}");
            let issues = parse_and_validate(&source);
            assert_eq!(issues.len(), 1, "{call}: {issues:?}");
            assert_eq!(issues[0].kind, expected, "{call}");
        }
    }

    fn located(statement: Statement) -> LocatedStatement {
        LocatedStatement {
            message: None,
            names: Vec::new(),
            branches: Vec::new(),
            span: Span { start: 0, end: 0 },
            statement,
            attributes: Vec::new(),
        }
    }

    fn make_contract(name: &str) -> Contract {
        Contract {
            span: Default::default(),
            name: name.to_string(),
            is_library: false,
            declaration: Default::default(),
            attributes: vec![],
            structs: vec![],
            parameters: vec![Parameter {
                span: Default::default(),
                name: "owner".to_string(),
                param_type: "pubkey".into(),
            }],
            functions: vec![Function {
                declaration: Default::default(),
                name: "spend".to_string(),
                span: Span { start: 0, end: 0 },
                parameters: vec![
                    Parameter {
                        span: Default::default(),
                        name: "ownerSig".to_string(),
                        param_type: "signature".into(),
                    },
                    Parameter {
                        span: Default::default(),
                        name: "flag".to_string(),
                        param_type: "bool".into(),
                    },
                ],
                statements: vec![located(Statement::Require(
                    ExprKind::Builtin {
                        builtin: builtins::find("checkSig").unwrap(),
                        args: vec![
                            ExprKind::Name(models::Path::from_key("ownerSig")).into(),
                            ExprKind::Name(models::Path::from_key("owner")).into(),
                        ],
                    }
                    .into(),
                ))],
                is_private: false,
                is_static: false,
                is_exported: false,
                return_type: None,
                attributes: vec![],
            }],
            tapscripts: Vec::new(),
            imports: vec![],
            constants: vec![],
        }
    }

    #[test]
    fn valid_contract_has_no_issues() {
        let mut contract = make_contract("Simple");
        // This body never reads the `flag` parameter, so drop it to avoid an unused-input error.
        contract.functions[0].parameters.pop();
        let issues = validate(&contract);
        assert!(issues.is_empty());
    }

    #[test]
    fn require_only_in_one_branch_is_error() {
        // Without an else, the false path has no require() and the spend trivially passes.
        let mut contract = make_contract("BarePath");
        contract.functions[0].statements = vec![located(Statement::IfElse {
            condition: ExprKind::Name(models::Path::from_key("flag")).into(),
            then_body: vec![located(Statement::Require(
                ExprKind::Builtin {
                    builtin: builtins::find("checkSig").unwrap(),
                    args: vec![
                        ExprKind::Name(models::Path::from_key("ownerSig")).into(),
                        ExprKind::Name(models::Path::from_key("owner")).into(),
                    ],
                }
                .into(),
            ))],
            else_body: None,
        })];
        let issues = validate(&contract);
        assert!(!issues.is_empty());
        assert!(issues
            .iter()
            .any(|i| matches!(i.kind, ValidationError::UnenforcedPath { .. })));
    }

    #[test]
    fn require_in_both_branches_is_ok() {
        let mut contract = make_contract("BothPaths");
        let req = || {
            located(Statement::Require(
                ExprKind::Builtin {
                    builtin: builtins::find("checkSig").unwrap(),
                    args: vec![
                        ExprKind::Name(models::Path::from_key("ownerSig")).into(),
                        ExprKind::Name(models::Path::from_key("owner")).into(),
                    ],
                }
                .into(),
            ))
        };
        contract.functions[0].statements = vec![located(Statement::IfElse {
            condition: ExprKind::Name(models::Path::from_key("flag")).into(),
            then_body: vec![req()],
            else_body: Some(vec![req()]),
        })];
        assert!(validate(&contract).is_empty());
    }

    #[test]
    fn empty_contract_name_is_error() {
        let contract = make_contract("");
        let issues = validate(&contract);
        assert!(!issues.is_empty());
        assert!(issues
            .iter()
            .any(|i| i.kind == ValidationError::EmptyContractName));
    }

    #[test]
    fn no_functions_is_error() {
        let mut contract = make_contract("Empty");
        contract.functions.clear();
        let issues = validate(&contract);
        assert!(!issues.is_empty());
        assert!(issues
            .iter()
            .any(|i| i.kind == ValidationError::NoEntrypoint));
    }

    #[test]
    fn only_private_functions_is_error() {
        let mut contract = make_contract("AllInternal");
        contract.functions[0].is_private = true;
        let issues = validate(&contract);
        assert!(!issues.is_empty());
    }

    #[test]
    fn duplicate_function_name_is_error() {
        let mut contract = make_contract("Dup");
        contract.functions.push(contract.functions[0].clone());
        let issues = validate(&contract);
        assert!(!issues.is_empty());
        let duplicate = ValidationError::DuplicateFunction {
            name: "spend".into(),
        };
        assert!(issues.iter().any(|i| i.kind == duplicate));
    }

    #[test]
    fn duplicate_constructor_param_is_error() {
        let mut contract = make_contract("Dup");
        contract.parameters.push(contract.parameters[0].clone());
        let issues = validate(&contract);
        assert!(!issues.is_empty());
    }

    fn make_output(name: &str) -> ContractJson {
        let witness = vec![WitnessElement {
            name: "sig".to_string(),
            elem_type: "signature".to_string(),
            encoding: "schnorr-64".to_string(),
            injected: false,
        }];
        ContractJson {
            format_version: ARTIFACT_FORMAT_VERSION,
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
            contracts: Default::default(),
            code_hash: None,
            source: None,
            compiler: None,
            updated_at: None,
            fingerprint: None,
            warnings: vec![],
        }
    }

    #[test]
    fn examples_are_fully_typed_and_values_without_a_type_are_rejected() {
        fn ark_files(directory: &Path, paths: &mut Vec<PathBuf>) {
            for entry in fs::read_dir(directory).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    ark_files(&path, paths);
                } else if path.extension().is_some_and(|e| e == "ark") {
                    paths.push(path);
                }
            }
        }
        let mut paths = Vec::new();
        ark_files(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("examples"),
            &mut paths,
        );
        assert!(!paths.is_empty());
        for path in paths {
            let analysis = crate::analyze_file(&path);
            let contract = analysis
                .contract()
                .unwrap_or_else(|| panic!("{} does not compile", path.display()));
            let mut issues = Vec::new();
            for function in contract.functions.iter().filter(|f| !f.is_imported()) {
                check_typed(&function.statements, &mut issues);
            }
            assert!(issues.is_empty(), "{}: {issues:?}", path.display());
        }

        let group = "let g = tx.assetGroups.lookup(aid);";
        for (statement, message) in [
            (
                format!("{group} require(sha256(pk) == g.inputs[0]);"),
                "not defined between 'bytes32' and 'AssetGroupInput'",
            ),
            (
                format!("{group} S s = {{ a: 1 }}; s = g.outputs[0];"),
                "changes its type from 'S' to 'AssetGroupOutput'",
            ),
            (
                "require({ a: 1 } == { a: 2 });".to_string(),
                "struct literals may only initialize typed struct declarations",
            ),
            (
                "require(check(pk));".to_string(),
                "function 'check' does not return a value",
            ),
        ] {
            let source = format!(
                "struct S {{ int a; }} contract C(pubkey pk, AssetId aid) {{ \
                 private function check(pubkey k) {{ require(k == pk); }} \
                 function spend(signature sig) {{ {statement} require(checkSig(sig, pk)); }} }}"
            );
            let error = crate::compile(&source).expect_err(&statement).to_string();
            assert!(error.contains(message), "{statement}: {error}");
        }
    }

    #[test]
    fn valid_output_has_no_errors() {
        let output = make_output("Simple");
        let issues = validate_output(&output);
        assert!(issues.is_empty());
    }

    #[test]
    fn empty_asm_is_output_error() {
        let mut output = make_output("Bad");
        output.functions[0].leaves[0].asm.clear();
        let issues = validate_output(&output);
        assert!(!issues.is_empty());
        assert!(issues
            .iter()
            .any(|i| matches!(i, ValidationError::EmptyLeafAsm { .. })));
    }

    #[test]
    fn signature_placeholder_in_leaf_asm_is_output_error() {
        for leaked in ["<operatorSig>", "<ownersig>", "<sig>"] {
            let mut output = make_output("Leak");
            output.functions[0].leaves[0].asm = vec![leaked.to_string()];
            let issues = validate_output(&output);
            assert!(
                !issues.is_empty(),
                "leaked placeholder {leaked} must be an output error"
            );
            assert!(
                issues
                    .iter()
                    .any(|i| matches!(i, ValidationError::SignatureInLeafAsm { .. })),
                "expected sig-leak message for {leaked}"
            );
        }
    }
}
