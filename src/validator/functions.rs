use super::*;
use crate::models::{Function, StructDefinition};

pub(super) fn validate_functions(contract: &Contract, issues: &mut Vec<ValidationIssue>) {
    let definitions = contract
        .structs
        .iter()
        .map(|s| (s.name.as_str(), s))
        .collect();
    for function in contract.functions.iter().filter(|f| !f.is_imported()) {
        if let Some(result) = &function.return_type {
            if !function.is_private {
                issues.push(ValidationIssue::error(format!(
                    "public function '{}' cannot declare a return type",
                    function.name
                )));
            }
            validate_declared_type(result, "return type", &definitions, issues);
        }
        if function.is_static {
            let referenced = super::references::referenced_parameters(&function.statements, &[]);
            for parameter in &contract.parameters {
                if referenced.contains(parameter.name.as_str()) {
                    issues.push(ValidationIssue::error(format!(
                        "static function '{}' cannot reference constructor parameter '{}'",
                        function.name, parameter.name
                    )));
                }
            }
        }
        let mut scope = build_scope_with_structs(&contract.parameters, &contract.structs);
        scope.extend(build_scope_with_structs(
            &function.parameters,
            &contract.structs,
        ));
        validate_body(&function.statements, function, &mut scope, contract, issues);
    }

    let mut guarantees = HashMap::new();
    for function in contract.functions.iter().filter(|f| !f.is_imported()) {
        if let Err(error) = analyze_function(function, contract, &mut Vec::new(), &mut guarantees) {
            issues.push(ValidationIssue::error(error));
            return;
        }
    }
    for function in contract.functions.iter().filter(|f| !f.is_imported()) {
        let flow = flow_block(&function.statements, 1, &guarantees);
        if function.is_private && function.return_type.is_some() && flow.fallthrough != 0 {
            issues.push(ValidationIssue::error(format!(
                "private function '{}' must return a value on every path",
                function.name
            )));
        }
        if !function.is_private && (flow.fallthrough | flow.returned) & 1 != 0 {
            issues.push(ValidationIssue::error(format!("function '{}' has a spend path with no require(); every branch must enforce at least one condition", function.name)));
        }
    }
}

fn validate_body(
    statements: &[Statement],
    function: &Function,
    scope: &mut Scope,
    contract: &Contract,
    issues: &mut Vec<ValidationIssue>,
) {
    for statement in statements {
        for expression in statement_expressions(statement) {
            validate_calls(
                expression,
                !matches!(statement, Statement::Call(_)),
                function,
                scope,
                contract,
                issues,
            );
        }
        match statement {
            Statement::Return(value) => {
                if !function.is_private {
                    issues.push(ValidationIssue::error(format!(
                        "return is only allowed in private functions: '{}'",
                        function.name
                    )));
                }
                match (&function.return_type, value) {
                    (Some(expected), Some(value)) => validate_value(
                        expected,
                        value,
                        scope,
                        contract,
                        &format!("return from '{}'", function.name),
                        issues,
                    ),
                    (Some(_), None) => issues.push(ValidationIssue::error(format!(
                        "function '{}' must return a value",
                        function.name
                    ))),
                    (None, Some(_)) => issues.push(ValidationIssue::error(format!(
                        "void function '{}' cannot return a value",
                        function.name
                    ))),
                    (None, None) => {}
                }
            }
            Statement::LetBinding {
                name,
                declared_type,
                value,
            } => {
                crate::typechecker::bind_local_type(
                    scope,
                    name,
                    declared_type.as_deref(),
                    infer_type(value, scope),
                    &contract.structs,
                );
            }
            Statement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                validate_body(then_body, function, &mut scope.clone(), contract, issues);
                if let Some(body) = else_body {
                    validate_body(body, function, &mut scope.clone(), contract, issues);
                }
            }
            Statement::ForIn {
                index_var,
                value_var,
                iterable,
                body,
            } => {
                let mut scope = scope.clone();
                let element = match infer_type(iterable, &scope) {
                    ArkType::Array(element, _) => *element,
                    _ => ArkType::Unknown,
                };
                scope.insert(index_var.clone(), ArkType::Int);
                scope.insert(value_var.clone(), element);
                validate_body(body, function, &mut scope, contract, issues);
            }
            Statement::Call(_) | Statement::Require(_) | Statement::VarAssign { .. } => {}
        }
    }
}

fn validate_calls(
    expression: &Expression,
    value_position: bool,
    caller: &Function,
    scope: &Scope,
    contract: &Contract,
    issues: &mut Vec<ValidationIssue>,
) {
    if let Expression::Call { name, args, .. } = expression {
        match contract.functions.iter().find(|f| f.name == *name) {
            None => issues.push(ValidationIssue::error(format!(
                "unknown private function '{name}'"
            ))),
            Some(function) => {
                if !function.is_private {
                    issues.push(ValidationIssue::error(format!(
                        "public function '{name}' is an entrypoint and cannot be called"
                    )));
                }
                if caller.is_static && !function.is_static {
                    issues.push(ValidationIssue::error(format!(
                        "static function '{}' cannot call non-static function '{name}'",
                        caller.name
                    )));
                }
                if value_position && function.return_type.is_none() {
                    issues.push(ValidationIssue::error(format!(
                        "function '{name}' does not return a value"
                    )));
                } else if !value_position && function.return_type.is_some() {
                    issues.push(ValidationIssue::error(format!(
                        "return value of '{name}' must be used"
                    )));
                }
                if function.parameters.len() != args.len() {
                    issues.push(ValidationIssue::error(format!(
                        "function '{name}' expects {} arguments, got {}",
                        function.parameters.len(),
                        args.len()
                    )));
                }
                for (parameter, argument) in function.parameters.iter().zip(args) {
                    validate_value(
                        &parameter.param_type,
                        argument,
                        scope,
                        contract,
                        &format!("argument '{}' to '{name}'", parameter.name),
                        issues,
                    );
                }
            }
        }
    }
    for child in child_exprs(expression) {
        validate_calls(child, true, caller, scope, contract, issues);
    }
}

fn validate_value(
    expected: &str,
    value: &Expression,
    scope: &Scope,
    contract: &Contract,
    context: &str,
    issues: &mut Vec<ValidationIssue>,
) {
    let expected_type = ArkType::parse(expected);
    match (value, &expected_type) {
        (Expression::ArrayLiteral(elements), ArkType::Array(element, length)) => {
            if elements.len() != *length {
                issues.push(ValidationIssue::error(format!(
                    "{context}: expected {length} array elements, got {}",
                    elements.len()
                )));
            }
            for value in elements {
                validate_value(&element.as_str(), value, scope, contract, context, issues);
            }
        }
        (Expression::StructLiteral(fields), ArkType::Struct(name)) => {
            let native =
                crate::models::builtin_struct_fields(name).map(|fields| StructDefinition {
                    name: name.clone(),
                    fields: fields
                        .iter()
                        .map(|(name, ty)| crate::models::Parameter {
                            name: name.to_string(),
                            param_type: ty.to_string(),
                        })
                        .collect(),
                });
            if let Some(definition) = native
                .as_ref()
                .or_else(|| contract.structs.iter().find(|s| s.name == *name))
            {
                let mut seen = HashSet::new();
                for (name, value) in fields {
                    if !seen.insert(name) {
                        issues.push(ValidationIssue::error(format!(
                            "{context}: duplicate field '{name}'"
                        )));
                    }
                    if let Some(field) = definition.fields.iter().find(|f| f.name == *name) {
                        validate_value(&field.param_type, value, scope, contract, context, issues);
                    } else {
                        issues.push(ValidationIssue::error(format!(
                            "{context}: unknown field '{name}'"
                        )));
                    }
                }
                for field in &definition.fields {
                    if !seen.contains(&field.name) {
                        issues.push(ValidationIssue::error(format!(
                            "{context}: missing field '{}'",
                            field.name
                        )));
                    }
                }
            }
        }
        _ => {
            let actual = infer_type(value, scope);
            if !binding_types_compatible(&expected_type, &actual) {
                issues.push(ValidationIssue::error(format!(
                    "{context}: expected '{expected}', got '{}'",
                    actual.as_str()
                )));
            }
        }
    }
}

fn statement_expressions(statement: &Statement) -> Vec<&Expression> {
    match statement {
        Statement::Call(expression) | Statement::Return(Some(expression)) => vec![expression],
        Statement::Require(Requirement::Expression(expression)) => vec![expression],
        Statement::Require(Requirement::Comparison { left, right, .. }) => vec![left, right],
        Statement::LetBinding { value, .. } => vec![value],
        Statement::VarAssign {
            target: AssignmentTarget::ArrayIndex { index, .. },
            value,
        } => vec![value, index],
        Statement::VarAssign { value, .. } => vec![value],
        Statement::IfElse { condition, .. } => vec![condition],
        Statement::ForIn { iterable, .. } => vec![iterable],
        Statement::Return(None) | Statement::Require(_) => vec![],
    }
}

fn analyze_function(
    function: &Function,
    contract: &Contract,
    visiting: &mut Vec<String>,
    guarantees: &mut HashMap<String, bool>,
) -> Result<(), String> {
    if guarantees.contains_key(&function.name) {
        return Ok(());
    }
    if visiting.contains(&function.name) {
        visiting.push(function.name.clone());
        return Err(format!(
            "recursive function call: {}",
            visiting.join(" -> ")
        ));
    }
    visiting.push(function.name.clone());
    analyze_calls(&function.statements, contract, visiting, guarantees)?;
    let flow = flow_block(&function.statements, 1, guarantees);
    guarantees.insert(
        function.name.clone(),
        (flow.fallthrough | flow.returned) & 1 == 0,
    );
    visiting.pop();
    Ok(())
}

fn analyze_calls(
    statements: &[Statement],
    contract: &Contract,
    visiting: &mut Vec<String>,
    guarantees: &mut HashMap<String, bool>,
) -> Result<(), String> {
    for statement in statements {
        for expression in statement_expressions(statement) {
            analyze_expression(expression, contract, visiting, guarantees)?;
        }
        match statement {
            Statement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                analyze_calls(then_body, contract, visiting, guarantees)?;
                if let Some(body) = else_body {
                    analyze_calls(body, contract, visiting, guarantees)?;
                }
            }
            Statement::ForIn { body, .. } => analyze_calls(body, contract, visiting, guarantees)?,
            _ => {}
        }
    }
    Ok(())
}

fn analyze_expression(
    expression: &Expression,
    contract: &Contract,
    visiting: &mut Vec<String>,
    guarantees: &mut HashMap<String, bool>,
) -> Result<(), String> {
    if let Expression::Call { name, .. } = expression {
        if let Some(function) = contract.functions.iter().find(|f| f.name == *name) {
            analyze_function(function, contract, visiting, guarantees)?;
        }
    }
    for child in child_exprs(expression) {
        analyze_expression(child, contract, visiting, guarantees)?;
    }
    Ok(())
}

// Each mask records paths without (1) and with (2) an enforced requirement.
#[derive(Default)]
struct Flow {
    fallthrough: u8,
    returned: u8,
}

fn expression_enforces(expression: &Expression, guarantees: &HashMap<String, bool>) -> bool {
    matches!(expression, Expression::Call { name, .. } if guarantees.get(name) == Some(&true))
        || child_exprs(expression)
            .into_iter()
            .any(|child| expression_enforces(child, guarantees))
}

fn flow_block(statements: &[Statement], incoming: u8, guarantees: &HashMap<String, bool>) -> Flow {
    let mut flow = Flow {
        fallthrough: incoming,
        returned: 0,
    };
    for statement in statements {
        if flow.fallthrough == 0 {
            break;
        }
        if statement_expressions(statement)
            .into_iter()
            .any(|e| expression_enforces(e, guarantees))
        {
            flow.fallthrough = 2;
        }
        match statement {
            Statement::Require(_) => flow.fallthrough = 2,
            Statement::Return(_) => {
                flow.returned |= flow.fallthrough;
                flow.fallthrough = 0;
            }
            Statement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                let left = flow_block(then_body, flow.fallthrough, guarantees);
                let right = flow_block(
                    else_body.as_deref().unwrap_or_default(),
                    flow.fallthrough,
                    guarantees,
                );
                flow.fallthrough = left.fallthrough | right.fallthrough;
                flow.returned |= left.returned | right.returned;
            }
            Statement::ForIn { body, .. } => {
                // Source arrays have a positive static length, so every loop executes at least once.
                let body = flow_block(body, flow.fallthrough, guarantees);
                flow.fallthrough = body.fallthrough;
                flow.returned |= body.returned;
            }
            Statement::Call(_) | Statement::LetBinding { .. } | Statement::VarAssign { .. } => {}
        }
    }
    flow
}
