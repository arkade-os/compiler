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
    pub(super) initialized: bool,
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
                initialized: true,
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
                validate_binding_expression(expression, scopes, issues, false)
            }
            Statement::Return(Some(expression)) => {
                validate_value_expression(expression, scopes, issues)
            }
            Statement::Return(None) => {}
            Statement::Require(condition) => {
                validate_binding_requirement(condition, scopes, issues);
            }
            Statement::Declaration {
                name,
                declared_type,
            } => {
                let mut local = Scope::new();
                crate::types::bind_local_type(
                    &mut local,
                    name,
                    Some(declared_type),
                    declared_type.ark_type(),
                    structs,
                );
                scopes
                    .last_mut()
                    .expect("binding scope")
                    .extend(local.into_iter().map(|(name, binding_type)| {
                        (
                            name,
                            BindingInfo {
                                binding_type,
                                source: BindingSource::Local,
                                initialized: false,
                            },
                        )
                    }));
            }
            Statement::LetBinding {
                name,
                declared_type,
                value,
            } => {
                // Composite initializers are validated through their scalar
                // children; the declaration itself owns their result shape.
                match &value.kind {
                    ExprKind::StructLiteral { name: literal, .. } => {
                        if literal.is_none()
                            && !declared_type
                                .as_ref()
                                .is_some_and(|ty| matches!(ty.ark_type(), ArkType::Struct(_)))
                        {
                            issues.push(ValidationIssue::error(format!(
                                "struct literal needs a struct type; name it, as in 'let {name} = Name {{ field: value }};'"
                            )));
                        }
                        validate_value_expression(value, scopes, issues);
                    }
                    _ => validate_value_expression(value, scopes, issues),
                }
                let inferred = value.ty.clone();
                let binding_type = declared_type
                    .as_ref()
                    .map_or_else(|| inferred.clone(), TypeName::ark_type);
                if issues.len() == first
                    && declared_type.is_some()
                    && !binding_types_compatible(&binding_type, &inferred)
                {
                    issues.push(ValidationIssue::error(format!(
                        "binding '{}' declares type '{}' but initializer has type '{}'",
                        name,
                        binding_type.as_str(),
                        inferred.as_str()
                    )));
                }
                if matches!(&value.kind, ExprKind::ArrayLiteral(_))
                    && declared_type
                        .as_ref()
                        .and_then(TypeName::array_parts)
                        .is_none()
                {
                    issues.push(ValidationIssue::error(format!(
                        "array literal needs a declared array type, as in 'int[2] {name} = …'"
                    )));
                }
                if let ArkType::Struct(struct_type) = &binding_type {
                    let result_type = crate::models::expression_result_struct(value);
                    if !matches!(&value.kind, ExprKind::StructLiteral { .. })
                        && result_type != Some(struct_type.as_str())
                        && !matches!(
                            &value.kind,
                            ExprKind::Call { .. }
                                | ExprKind::ArrayIndex { .. }
                                | ExprKind::FieldAccess { .. }
                                | ExprKind::IndexAccess { .. }
                                | ExprKind::Name(_)
                        )
                    {
                        issues.push(ValidationIssue::error(format!(
                            "struct binding '{name}' must be initialized with a matching struct value",
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
                    declared_type.as_ref(),
                    binding_type,
                    structs,
                );
                for (binding_name, binding_type) in local {
                    frame.insert(
                        binding_name,
                        BindingInfo {
                            binding_type,
                            source: BindingSource::Local,
                            initialized: true,
                        },
                    );
                }
            }
            Statement::VarAssign { target, value } => {
                if let AssignmentTarget::Binding(name) = target {
                    let root = name.root.as_str();
                    if !name.segments.is_empty()
                        && find_binding(scopes, root).is_some_and(|binding| !binding.initialized)
                    {
                        validate_named_binding(root, None, "binding", scopes, issues);
                    }
                }
                let target_type = match target {
                    AssignmentTarget::Binding(name) => find_binding(scopes, &name.key())
                        .map(|binding| binding.binding_type.clone()),
                    AssignmentTarget::ArrayIndex { array, .. } => {
                        find_binding(scopes, &array.key()).and_then(|binding| {
                            match &binding.binding_type {
                                ArkType::Array(element, _) => Some((**element).clone()),
                                _ => None,
                            }
                        })
                    }
                    AssignmentTarget::Access(access) => Some(access.ty.clone()),
                };
                let composite_target =
                    matches!(target_type, Some(ArkType::Struct(_) | ArkType::Array(..)));
                let before = issues.len();
                let value_position = !composite_target || value.ty == ArkType::Void;
                validate_binding_expression(value, scopes, issues, value_position);
                let valid = issues.len() == before;
                if let (
                    Some(expected),
                    ExprKind::StructLiteral { name: None, .. } | ExprKind::ArrayLiteral(_),
                ) = (&target_type, &value.kind)
                {
                    super::functions::validate_value(
                        &TypeName::from(expected),
                        value,
                        structs,
                        &format!("assignment in '{function_name}'"),
                        issues,
                    );
                }
                // Array literal elements are checked against the target's complete shape. A
                // target left untyped by its failed initializer was reported there.
                let changes = |target: &ArkType| {
                    valid
                        && *target != ArkType::Unknown
                        && !matches!(&value.kind, ExprKind::ArrayLiteral(_))
                        && !binding_types_compatible(target, &value.ty)
                };
                match target {
                    AssignmentTarget::Access(access) => {
                        let before = issues.len();
                        validate_binding_expression(access, scopes, issues, !composite_target);
                        // An invalid access already explains the target.
                        if issues.len() == before {
                            if changes(&access.ty) {
                                issues.push(ValidationIssue::error(format!("assignment to an indexed field changes its type from '{}' to '{}'", access.ty.as_str(), value.ty.as_str())));
                            }
                            match access
                                .binding_path()
                                .and_then(|path| find_binding(scopes, &path.key()))
                            {
                                None => issues.push(ValidationIssue::error(
                                    "assignment target is not a binding",
                                )),
                                Some(binding) if binding.source == BindingSource::Loop => issues
                                    .push(ValidationIssue::error(
                                        "cannot assign to compile-time loop variable",
                                    )),
                                Some(_) => {}
                            }
                        }
                    }
                    AssignmentTarget::Binding(name) => match find_binding(scopes, &name.key()) {
                        None => issues.push(ValidationIssue::error(format!(
                            "assignment to undeclared variable '{name}'"
                        ))),
                        Some(binding) if binding.source == BindingSource::Constructor => {
                            // The shadowing walk owns the constructor-mutation diagnostic.
                        }
                        Some(binding) if binding.source == BindingSource::Loop => {
                            issues.push(ValidationIssue::error(format!(
                                "cannot assign to compile-time loop variable '{name}'"
                            )));
                        }
                        Some(binding) if changes(&binding.binding_type) => {
                            issues.push(ValidationIssue::error(format!(
                                "assignment to '{}' changes its type from '{}' to '{}'",
                                name,
                                binding.binding_type.as_str(),
                                value.ty.as_str()
                            )));
                        }
                        Some(_) => {}
                    },
                    AssignmentTarget::ArrayIndex { array, index } => {
                        let before = issues.len();
                        validate_binding_expression(index, scopes, issues, true);
                        if let Some((element_type, source)) = (issues.len() == before)
                            .then(|| {
                                validate_array_index(
                                    &array.key(),
                                    &array.key(),
                                    index,
                                    scopes,
                                    issues,
                                )
                            })
                            .flatten()
                        {
                            if source == BindingSource::Loop {
                                issues.push(ValidationIssue::error(format!(
                                    "cannot assign to compile-time loop variable '{array}'"
                                )));
                            } else if changes(&element_type) {
                                issues.push(ValidationIssue::error(format!(
                                    "assignment to an element of '{}' changes its type from '{}' to '{}'",
                                    array,
                                    element_type.as_str(),
                                    value.ty.as_str()
                                )));
                            }
                        }
                    }
                }
                // A value whose error is reported elsewhere still initializes the target.
                if issues[first..].iter().all(|issue| issue.code == "reported") {
                    if let AssignmentTarget::Binding(name) = target {
                        let name = name.key();
                        if let Some(frame) = scopes
                            .iter_mut()
                            .rev()
                            .find(|frame| frame.contains_key(&name))
                        {
                            let field_prefix = format!("{name}.");
                            let index_prefix = format!("{name}[");
                            for (path, binding) in frame {
                                if *path == name
                                    || path.starts_with(&field_prefix)
                                    || path.starts_with(&index_prefix)
                                {
                                    binding.initialized = true;
                                }
                            }
                        }
                    }
                }
            }
            Statement::IfElse {
                condition,
                then_body,
                else_body,
            } => {
                validate_binding_expression(condition, scopes, issues, true);
                let condition_type = condition.ty.clone();
                if issues.len() == first && condition_type != ArkType::Bool {
                    issues.push(ValidationIssue::error(format!(
                        "if condition has type '{}', expected bool; use an explicit comparison",
                        condition_type.as_str()
                    )));
                }
                let incoming = scopes.clone();
                scopes.push(HashMap::new());
                validate_binding_statements(then_body, function_name, scopes, structs, issues);
                scopes.pop();
                let left = scopes.clone();
                *scopes = incoming;
                let else_body = else_body.as_deref().unwrap_or_default();
                scopes.push(HashMap::new());
                validate_binding_statements(else_body, function_name, scopes, structs, issues);
                scopes.pop();
                let left_continues = super::falls_through(then_body);
                let right_continues = super::falls_through(else_body);
                for (frame, left) in scopes.iter_mut().zip(left) {
                    for (name, binding) in frame {
                        binding.initialized = (!left_continues
                            || left.get(name).is_some_and(|binding| binding.initialized))
                            && (!right_continues || binding.initialized);
                    }
                }
            }
            Statement::ForIn {
                index_var,
                value_var,
                iterable,
                body,
            } => {
                let element_type = match &iterable.kind {
                    ExprKind::Name(path) if path.key() != "tx.assetGroups" => {
                        let name = &path.key();
                        if find_binding(scopes, name).is_some_and(|binding| !binding.initialized) {
                            validate_named_binding(name, None, "array", scopes, issues);
                        }
                        match find_binding(scopes, name) {
                            Some(BindingInfo {
                                binding_type: ArkType::Array(element, _),
                                ..
                            }) => (**element).clone(),
                            Some(binding) => {
                                issues.push(ValidationIssue::error(format!(
                                    "loop iterable '{}' has type '{}', expected array",
                                    name,
                                    binding.binding_type.as_str()
                                )));
                                ArkType::Unknown
                            }
                            None => {
                                issues.push(ValidationIssue::error(format!(
                                    "loop iterable '{name}' is undefined"
                                )));
                                ArkType::Unknown
                            }
                        }
                    }
                    ExprKind::Name(_) => {
                        issues.push(ValidationIssue::error(
                            "cannot iterate 'tx.assetGroups'; the group count is \
                             not known at compile time. Iterate a declared array of group \
                             indices instead",
                        ));
                        ArkType::Unknown
                    }
                    _ => {
                        let before = issues.len();
                        validate_value_expression(iterable, scopes, issues);
                        match iterable.ty.clone() {
                            // ponytail: a literal takes its first element's type, which the
                            // rest must match, so `[{ x: 1 }, p]` is rejected; join all
                            // element types if such literals need to iterate.
                            ArkType::Array(element, _)
                                if matches!(&iterable.kind, ExprKind::ArrayLiteral(_)) =>
                            {
                                if matches!(*element, ArkType::Array(..)) {
                                    issues.push(ValidationIssue::error("arrays contain scalars or structs, so a loop cannot iterate an array literal of arrays"));
                                } else if *element != ArkType::Unknown {
                                    super::functions::validate_value(
                                        &TypeName::from(&iterable.ty),
                                        iterable,
                                        structs,
                                        &format!("loop iterable in '{function_name}'"),
                                        issues,
                                    );
                                } else if issues.len() == before {
                                    issues.push(ValidationIssue::error("cannot infer the element type of the loop's array literal; iterate a typed array, as in 'T[n] items = …'"));
                                }
                                *element
                            }
                            ArkType::Array(element, _) => *element,
                            actual => {
                                // A computed iterable has no name to print, so the issue points at it.
                                if issues.len() == before {
                                    issues.push(
                                        ValidationIssue::error(format!(
                                            "loop iterable has type '{}', expected array",
                                            actual.as_str()
                                        ))
                                        .at(iterable.span),
                                    );
                                }
                                ArkType::Unknown
                            }
                        }
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
                                initialized: true,
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
                    issues.push(ValidationIssue::error(
                        "loop count must be a non-negative integer compile-time constant",
                    ));
                }
                let incoming = scopes.clone();
                scopes.push(HashMap::new());
                validate_binding_statements(body, function_name, scopes, structs, issues);
                scopes.pop();
                if !matches!(&count.kind, ExprKind::Literal(count) if count.parse::<usize>().is_ok_and(|count| count > 0))
                {
                    *scopes = incoming;
                }
            }
            Statement::ForRange {
                index_var,
                start,
                end,
                body,
            } => {
                let range = crate::models::loop_range(start, end);
                if let Err(message) = &range {
                    issues.push(ValidationIssue::error(message.clone()));
                }
                let incoming = scopes.clone();
                let index = BindingInfo {
                    binding_type: ArkType::Int,
                    source: BindingSource::Loop,
                    initialized: true,
                };
                scopes.push(HashMap::from([(index_var.clone(), index)]));
                validate_binding_statements(body, function_name, scopes, structs, issues);
                scopes.pop();
                if !range.is_ok_and(|range| !range.is_empty()) {
                    *scopes = incoming;
                }
            }
        }
        locate(&mut issues[first..], statement.span);
    }
}

pub(super) fn validate_named_binding(
    name: &str,
    expected: Option<ArkType>,
    label: &str,
    scopes: &BindingScopes,
    issues: &mut Vec<ValidationIssue>,
) {
    match find_binding(scopes, name) {
        None => {
            let issue = ValidationIssue::error(format!("{label} '{name}' is undefined"))
                .coded(crate::errors::ErrorCode::UnknownName);
            let names = scopes.iter().flat_map(|frame| frame.keys().map(String::as_str));
            let simple = names.filter(|n| !n.contains(['.', '[']));
            issues.push(match crate::errors::closest(name, simple).filter(|_| label == "binding") {
                Some(candidate) => issue.suggest(candidate, None),
                None => issue,
            });
        }
        Some(binding) if !binding.initialized => issues.push(ValidationIssue::error(format!(
            "{label} '{name}' may be uninitialized; assign it a value before use (initialize arrays and structs as a whole)"
        ))),
        Some(binding)
            if expected.as_ref().is_some_and(|expected| {
                binding.binding_type != *expected
            }) =>
        {
            issues.push(ValidationIssue::error(format!(
                "{} '{}' has type '{}', expected '{}'",
                label,
                name,
                binding.binding_type.as_str(),
                expected.expect("checked above").as_str()
            )));
        }
        Some(_) => {}
    }
}
