use super::expressions::{
    validate_array_index, validate_binding_expression, validate_binding_requirement,
    validate_value_expression,
};
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BindingSource {
    Constructor,
    FunctionInput,
    Local,
    Loop,
}

#[derive(Clone, Debug)]
pub(super) struct BindingInfo {
    pub(super) binding_type: ArkType,
    pub(super) source: BindingSource,
}

pub(super) type BindingScopes = Vec<HashMap<String, BindingInfo>>;

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

pub(super) fn find_binding<'a>(scopes: &'a BindingScopes, name: &str) -> Option<&'a BindingInfo> {
    scopes.iter().rev().find_map(|frame| frame.get(name))
}

pub(crate) fn binding_types_compatible(expected: &ArkType, actual: &ArkType) -> bool {
    expected == actual
        || *expected == ArkType::Bytes && crate::types::is_bytes_like(actual)
        || matches!(
            (expected, actual),
            (ArkType::Array(expected, expected_len), ArkType::Array(actual, actual_len))
                if expected_len == actual_len && binding_types_compatible(expected, actual)
        )
}

pub(super) fn check_binding_semantics(contract: &Contract, issues: &mut Vec<ValidationIssue>) {
    for function in contract.functions.iter().filter(|f| !f.is_imported()) {
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
        validate_binding_statements(
            &function.statements,
            &function.name,
            &mut scopes,
            &contract.structs,
            issues,
        );
    }
}

fn validate_binding_statements(
    statements: &[LocatedStatement],
    function_name: &str,
    scopes: &mut BindingScopes,
    structs: &[crate::models::StructDefinition],
    issues: &mut Vec<ValidationIssue>,
) {
    for statement in statements {
        let first = issues.len();
        match &statement.statement {
            Statement::Call(expression) => {
                validate_binding_expression(expression, function_name, scopes, issues, false)
            }
            Statement::Return(Some(expression)) => {
                validate_value_expression(expression, function_name, scopes, issues)
            }
            Statement::Return(None) => {}
            Statement::Require(requirement) => {
                validate_binding_requirement(requirement, function_name, scopes, issues);
            }
            Statement::LetBinding {
                name,
                declared_type,
                value,
            } => {
                // Composite initializers are validated through their scalar
                // children; the declaration itself owns their result shape.
                match &value.kind {
                    ExprKind::StructLiteral(_) => {
                        if !declared_type
                            .as_deref()
                            .is_some_and(|ty| matches!(ArkType::parse(ty), ArkType::Struct(_)))
                        {
                            issues.push(ValidationIssue::error(format!(
                                "function '{function_name}': struct literal needs a declared struct type"
                            )));
                        }
                        validate_value_expression(value, function_name, scopes, issues);
                    }
                    ExprKind::ArrayLiteral(_)
                    | ExprKind::ArrayIndex { .. }
                    | ExprKind::FieldAccess { .. }
                    | ExprKind::IndexAccess { .. } => {
                        validate_value_expression(value, function_name, scopes, issues)
                    }
                    _ => validate_binding_expression(
                        value,
                        function_name,
                        scopes,
                        issues,
                        crate::models::expression_result_struct(value).is_none()
                            && !matches!(&value.kind, ExprKind::Call { .. }),
                    ),
                }
                let inferred = value.ty.clone();
                let binding_type = declared_type
                    .as_deref()
                    .map(ArkType::parse)
                    .unwrap_or_else(|| inferred.clone());
                if declared_type.is_some()
                    && !matches!(&inferred, ArkType::Array(element, _) if **element == ArkType::Unknown)
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
                if matches!(&value.kind, ExprKind::ArrayLiteral(_))
                    && declared_type
                        .as_deref()
                        .and_then(crate::models::array_type_parts)
                        .is_none()
                {
                    issues.push(ValidationIssue::error(format!(
                        "function '{function_name}': array literal needs a declared array type, as in 'int[2] {name} = …'"
                    )));
                }
                if let ArkType::Struct(struct_type) = &binding_type {
                    let result_type = crate::models::expression_result_struct(value);
                    if !matches!(&value.kind, ExprKind::StructLiteral(_))
                        && result_type != Some(struct_type.as_str())
                        && !matches!(
                            &value.kind,
                            ExprKind::Call { .. }
                                | ExprKind::ArrayIndex { .. }
                                | ExprKind::FieldAccess { .. }
                                | ExprKind::IndexAccess { .. }
                        )
                    {
                        issues.push(ValidationIssue::error(format!(
                            "function '{function_name}': struct binding '{name}' must be initialized with a matching struct value",
                        )));
                    }
                }
                let frame = scopes
                    .last_mut()
                    .expect("binding validation always has a scope");
                let mut local = Scope::new();
                crate::types::bind_local_type(
                    &mut local,
                    name,
                    declared_type.as_deref(),
                    binding_type,
                    structs,
                );
                for (binding_name, binding_type) in local {
                    frame.insert(
                        binding_name,
                        BindingInfo {
                            binding_type,
                            source: BindingSource::Local,
                        },
                    );
                }
            }
            Statement::VarAssign { target, value } => {
                validate_binding_expression(value, function_name, scopes, issues, true);
                let inferred = value.ty.clone();
                match target {
                    AssignmentTarget::Access(access) => {
                        let before = issues.len();
                        validate_binding_expression(access, function_name, scopes, issues, true);
                        // An invalid access already explains the target.
                        if issues.len() == before {
                            let expected = access.ty.clone();
                            if expected != ArkType::Unknown
                                && inferred != ArkType::Unknown
                                && !binding_types_compatible(&expected, &inferred)
                            {
                                issues.push(ValidationIssue::error(format!("function '{function_name}': assignment to an indexed field changes its type from '{}' to '{}'", expected.as_str(), inferred.as_str())));
                            }
                            match access.binding_path().as_deref().and_then(|name| find_binding(scopes, name)) {
                                None => issues.push(ValidationIssue::error(format!("function '{function_name}': assignment target is not a binding"))),
                                Some(binding) if binding.source == BindingSource::Loop => issues.push(ValidationIssue::error(format!("function '{function_name}': cannot assign to compile-time loop variable"))),
                                Some(_) => {}
                            }
                        }
                    }
                    AssignmentTarget::Binding(name) => match find_binding(scopes, name) {
                        None => issues.push(ValidationIssue::error(format!(
                            "function '{function_name}': assignment to undeclared variable '{name}'"
                        ))),
                        Some(binding) if binding.source == BindingSource::Constructor => {
                            // The shadowing walk owns the constructor-mutation diagnostic.
                        }
                        Some(binding) if binding.source == BindingSource::Loop => {
                            issues.push(ValidationIssue::error(format!(
                                "function '{function_name}': cannot assign to compile-time loop variable '{name}'"
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
                    },
                    AssignmentTarget::ArrayIndex { array, index } => {
                        if let Some((element_type, source)) =
                            validate_array_index(array, array, index, function_name, scopes, issues)
                        {
                            if source == BindingSource::Loop {
                                issues.push(ValidationIssue::error(format!(
                                    "function '{function_name}': cannot assign to compile-time loop variable '{array}'"
                                )));
                            } else if inferred != ArkType::Unknown
                                && element_type != ArkType::Unknown
                                && !binding_types_compatible(&element_type, &inferred)
                            {
                                issues.push(ValidationIssue::error(format!(
                                    "function '{}': assignment to an element of '{}' changes its type from '{}' to '{}'",
                                    function_name,
                                    array,
                                    element_type.as_str(),
                                    inferred.as_str()
                                )));
                            }
                        }
                        validate_binding_expression(index, function_name, scopes, issues, true);
                    }
                }
            }
            Statement::IfElse {
                condition,
                then_body,
                else_body,
            } => {
                validate_binding_expression(condition, function_name, scopes, issues, true);
                let condition_type = condition.ty.clone();
                if condition_type != ArkType::Bool {
                    issues.push(ValidationIssue::error(format!(
                        "function '{}': if condition has type '{}', expected bool; use an explicit comparison",
                        function_name,
                        condition_type.as_str()
                    )));
                }
                scopes.push(HashMap::new());
                validate_binding_statements(then_body, function_name, scopes, structs, issues);
                scopes.pop();
                if let Some(else_body) = else_body {
                    scopes.push(HashMap::new());
                    validate_binding_statements(else_body, function_name, scopes, structs, issues);
                    scopes.pop();
                }
            }
            Statement::ForIn {
                index_var,
                value_var,
                iterable,
                body,
            } => {
                let element_type = match &iterable.kind {
                    ExprKind::Variable(name) | ExprKind::Property(name)
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
                                    "function '{function_name}': loop iterable '{name}' is undefined"
                                )));
                                ArkType::Unknown
                            }
                        }
                    }
                    ExprKind::Property(property) if property.trim() == "tx.assetGroups" => {
                        issues.push(ValidationIssue::error(format!(
                            "function '{function_name}': cannot iterate 'tx.assetGroups'; the group count is \
                             not known at compile time. Iterate a declared array of group \
                             indices instead"
                        )));
                        ArkType::Unknown
                    }
                    ExprKind::ArrayIndex { .. }
                    | ExprKind::FieldAccess { .. }
                    | ExprKind::IndexAccess { .. } => {
                        let before = issues.len();
                        validate_value_expression(iterable, function_name, scopes, issues);
                        match iterable.ty.clone() {
                            ArkType::Array(element, _) => *element,
                            actual => {
                                if issues.len() == before {
                                    issues.push(ValidationIssue::error(format!(
                                        "function '{}': loop iterable '{}' has type '{}', expected array",
                                        function_name,
                                        iterable.source_text(),
                                        actual.as_str()
                                    )));
                                }
                                ArkType::Unknown
                            }
                        }
                    }
                    _ => {
                        issues.push(ValidationIssue::error(format!(
                            "function '{function_name}': unsupported loop iterable"
                        )));
                        ArkType::Unknown
                    }
                };
                let mut frame = HashMap::new();
                for (name, binding_type) in [(index_var, ArkType::Int), (value_var, element_type)] {
                    let mut local = Scope::new();
                    crate::types::bind_local_type(&mut local, name, None, binding_type, structs);
                    frame.extend(local.into_iter().map(|(name, binding_type)| {
                        (
                            name,
                            BindingInfo {
                                binding_type,
                                source: BindingSource::Loop,
                            },
                        )
                    }));
                }
                scopes.push(frame);
                validate_binding_statements(body, function_name, scopes, structs, issues);
                scopes.pop();
            }
            Statement::ForCount { count, body } => {
                if !matches!(&count.kind, ExprKind::Literal(value) if value.parse::<usize>().is_ok())
                {
                    issues.push(ValidationIssue::error(format!(
                        "function '{function_name}': loop count must be a non-negative integer compile-time constant"
                    )));
                }
                scopes.push(HashMap::new());
                validate_binding_statements(body, function_name, scopes, structs, issues);
                scopes.pop();
            }
        }
        locate(&mut issues[first..], statement.span);
    }
}

pub(super) fn validate_named_binding(
    name: &str,
    expected: Option<ArkType>,
    label: &str,
    function_name: &str,
    scopes: &BindingScopes,
    issues: &mut Vec<ValidationIssue>,
) {
    match find_binding(scopes, name) {
        None => issues.push(ValidationIssue::error(format!(
            "function '{function_name}': {label} '{name}' is undefined"
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
