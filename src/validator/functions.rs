use std::collections::{HashMap, HashSet};

use super::ValidationIssue;
use crate::builtins::BUILTINS;
use crate::compiler::MAX_LOOP_ITERATIONS;
use crate::diagnostics::Span;
use crate::errors::{self, ErrorCode};
use crate::models::{
    self, Contract, ExprKind, Expression, Function, LocatedStatement, Parameter, Statement,
    StructDefinition, TypeName,
};
use crate::operators::OperatorClass;
use crate::types::{self, ArkType};

pub(super) fn validate_functions(contract: &Contract, issues: &mut Vec<ValidationIssue>) {
    let definitions = contract
        .structs
        .iter()
        .map(|s| (s.name.as_str(), s))
        .collect();
    for function in contract.functions.iter().filter(|f| !f.is_imported()) {
        let first = issues.len();
        if let Some(result) = &function.return_type {
            if !function.is_private {
                issues.push(ValidationIssue::error(format!(
                    "Arkade Script function '{}' cannot declare a return type",
                    function.name
                )));
            }
            super::validate_declared_type(result, "return type", &definitions, issues);
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
        validate_body(&function.statements, function, contract, issues);
        super::locate(&mut issues[first..], function.span);
    }

    let mut guarantees = HashMap::new();
    for function in contract.functions.iter().filter(|f| !f.is_imported()) {
        if let Err(error) = analyze_function(function, contract, &mut Vec::new(), &mut guarantees) {
            issues.push(ValidationIssue::error(error).at(function.span));
            return;
        }
    }
    let mut unrolled = HashMap::new();
    for function in contract.functions.iter().filter(|f| !f.is_imported()) {
        unrolled_function(function, contract, &mut unrolled, issues);
    }
    for function in contract.functions.iter().filter(|f| !f.is_imported()) {
        let flow = flow_block(&function.statements, 1, &guarantees);
        if function.is_private && function.return_type.is_some() && flow.fallthrough != 0 {
            issues.push(
                ValidationIssue::error(format!(
                    "private function '{}' must return a value on every path",
                    function.name
                ))
                .at(function.span),
            );
        }
        if !function.is_private && (flow.fallthrough | flow.returned) & 1 != 0 {
            issues.push(ValidationIssue::error(format!("function '{}' has a spend path with no require(); every branch must enforce at least one condition", function.name)).at(function.span));
        }
    }
}

fn validate_body(
    statements: &[LocatedStatement],
    function: &Function,
    contract: &Contract,
    issues: &mut Vec<ValidationIssue>,
) {
    for located in statements {
        let first = issues.len();
        let statement = &located.statement;
        for expression in statement.expressions() {
            validate_calls(
                expression,
                !matches!(statement, Statement::Call(_)),
                function,
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
                        &contract.structs,
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
                // Other initializers, named literals included, are type-checked with the declaration.
                if let (
                    Some(expected),
                    ExprKind::ArrayLiteral(_) | ExprKind::StructLiteral { name: None, .. },
                ) = (declared_type, &value.kind)
                {
                    validate_value(
                        expected,
                        value,
                        &contract.structs,
                        &format!("binding '{name}' in '{}'", function.name),
                        issues,
                    );
                }
            }
            Statement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                validate_body(then_body, function, contract, issues);
                if let Some(body) = else_body {
                    validate_body(body, function, contract, issues);
                }
            }
            Statement::ForIn { body, .. }
            | Statement::ForCount { body, .. }
            | Statement::ForRange { body, .. } => {
                validate_body(body, function, contract, issues);
            }
            Statement::Declaration { .. }
            | Statement::Call(_)
            | Statement::Require(_)
            | Statement::VarAssign { .. } => {}
        }
        super::locate(&mut issues[first..], located.span);
    }
}

fn validate_comparison_literals(
    left: &Expression,
    right: &Expression,
    function: &Function,
    contract: &Contract,
    issues: &mut Vec<ValidationIssue>,
) {
    for (value, other) in [(left, right), (right, left)] {
        if matches!(
            &value.kind,
            ExprKind::ArrayLiteral(_) | ExprKind::StructLiteral { .. }
        ) && matches!(other.ty, ArkType::Array(..) | ArkType::Struct(_))
            && types::resolved(&other.ty)
        {
            validate_value(
                &TypeName::from(&other.ty),
                value,
                &contract.structs,
                &format!("comparison in '{}'", function.name),
                issues,
            );
        }
    }
}

fn validate_calls(
    expression: &Expression,
    value_position: bool,
    caller: &Function,
    contract: &Contract,
    issues: &mut Vec<ValidationIssue>,
) {
    let first = issues.len();
    if let ExprKind::BinaryOp { left, op, right } = &expression.kind {
        if op.compares() {
            validate_comparison_literals(left, right, caller, contract, issues);
        }
    }
    if let ExprKind::Call { name, args, .. } = &expression.kind {
        match contract.functions.iter().find(|f| f.name == *name) {
            // `require(ok, 5);` parses as a call only because its message is not a string.
            None if name == "require" && !value_position && args.len() == 2 => issues.push(
                ValidationIssue::error("the message of require must be a string"),
            ),
            None => {
                let issue = ValidationIssue::error(format!("unknown function '{name}'"))
                    .coded(ErrorCode::UnknownFunction);
                let own = contract.functions.iter().map(|f| f.name.as_str());
                let builtins = BUILTINS.iter().map(|b| b.name);
                let span = Span {
                    start: expression.span.start,
                    end: expression.span.start + name.len(),
                };
                issues.push(match errors::closest(name, own.chain(builtins)) {
                    Some(candidate) => issue.suggest(candidate, Some(span)),
                    None => issue,
                });
            }
            Some(function) => {
                if !function.is_private {
                    issues.push(ValidationIssue::error(format!(
                        "Arkade Script function '{name}' is an entrypoint and cannot be called"
                    )));
                }
                if caller.is_static && !function.is_static {
                    issues.push(ValidationIssue::error(format!(
                        "static function '{}' cannot call non-static function '{name}'",
                        caller.name
                    )));
                }
                if !value_position && function.return_type.is_some() {
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
                        &contract.structs,
                        &format!("argument '{}' to '{name}'", parameter.name),
                        issues,
                    );
                }
            }
        }
    }
    // A named literal is checked against its own type; its position checks only the name.
    if let ExprKind::StructLiteral {
        name: Some(name),
        fields,
    } = &expression.kind
    {
        let context = format!("{name} literal");
        validate_fields(name, fields, &contract.structs, &context, issues);
    }
    super::locate(&mut issues[first..], expression.span);
    for child in models::child_exprs(expression) {
        validate_calls(child, true, caller, contract, issues);
    }
}

pub(super) fn validate_value(
    expected: &TypeName,
    value: &Expression,
    structs: &[StructDefinition],
    context: &str,
    issues: &mut Vec<ValidationIssue>,
) {
    let first = issues.len();
    let expected_type = expected.ark_type();
    match (&value.kind, expected.array_parts(), &expected_type) {
        (ExprKind::ArrayLiteral(elements), Some((element, length)), _) => {
            if elements.len() != length {
                issues.push(ValidationIssue::error(format!(
                    "{context}: expected {length} array elements, got {}",
                    elements.len()
                )));
            }
            for (index, value) in elements.iter().enumerate() {
                validate_value(
                    element,
                    value,
                    structs,
                    &format!("{context}, element {index}"),
                    issues,
                );
            }
        }
        (ExprKind::StructLiteral { name: None, fields }, _, ArkType::Struct(name)) => {
            validate_fields(name, fields, structs, context, issues)
        }
        _ => {
            let actual = &value.ty;
            if !expected_type.accepts(actual) {
                issues.push(ValidationIssue::error(format!(
                    "{context}: expected '{expected}', got '{}'",
                    actual.as_str()
                )));
            }
        }
    }
    super::locate(&mut issues[first..], value.span);
}

/// Check a struct literal's fields against the definition of struct `name`.
fn validate_fields(
    name: &str,
    fields: &[(String, Expression)],
    structs: &[StructDefinition],
    context: &str,
    issues: &mut Vec<ValidationIssue>,
) {
    let native = models::builtin_struct_fields(name).map(|fields| StructDefinition {
        span: Default::default(),
        name: name.to_string(),
        fields: fields
            .iter()
            .map(|(name, ty)| Parameter {
                span: Default::default(),
                name: name.to_string(),
                param_type: TypeName::parse(ty),
            })
            .collect(),
    });
    if let Some(definition) = native
        .as_ref()
        .or_else(|| structs.iter().find(|s| s.name == *name))
    {
        let mut seen = HashSet::new();
        for (name, value) in fields {
            if !seen.insert(name) {
                issues.push(ValidationIssue::error(format!(
                    "{context}: duplicate field '{name}'"
                )));
            }
            if let Some(field) = definition.fields.iter().find(|f| f.name == *name) {
                validate_value(
                    &field.param_type,
                    value,
                    structs,
                    &format!("{context}, field '{name}'"),
                    issues,
                );
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
        if name == "AssetId" {
            super::assets::validate_gidx(fields, issues);
        }
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
    statements: &[LocatedStatement],
    contract: &Contract,
    visiting: &mut Vec<String>,
    guarantees: &mut HashMap<String, bool>,
) -> Result<(), String> {
    for statement in statements {
        let statement = &statement.statement;
        for expression in statement.expressions() {
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
            Statement::ForIn { body, .. }
            | Statement::ForCount { body, .. }
            | Statement::ForRange { body, .. } => {
                analyze_calls(body, contract, visiting, guarantees)?
            }
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
    if let ExprKind::Call { name, .. } = &expression.kind {
        if let Some(function) = contract.functions.iter().find(|f| f.name == *name) {
            analyze_function(function, contract, visiting, guarantees)?;
        }
    }
    for child in models::child_exprs(expression) {
        analyze_expression(child, contract, visiting, guarantees)?;
    }
    Ok(())
}

/// The iterations `function` unrolls along its deepest nest of loops, counting the loops of the
/// helpers it inlines. Recursion is rejected first, so the walk ends.
fn unrolled_function(
    function: &Function,
    contract: &Contract,
    unrolled: &mut HashMap<String, usize>,
    issues: &mut Vec<ValidationIssue>,
) -> usize {
    if let Some(&iterations) = unrolled.get(&function.name) {
        return iterations;
    }
    let iterations = unrolled_body(
        &function.statements,
        contract,
        &HashMap::new(),
        unrolled,
        issues,
    );
    unrolled.insert(function.name.clone(), iterations);
    iterations
}

/// The iterations `statements` unroll along their deepest nest of loops, after reporting each
/// loop that runs zero times or unrolls above the limit. Both are checked before unrolling.
/// `rereads` holds the iterations each use of a loop item unrolls when its iterable is read again
/// at every use.
fn unrolled_body(
    statements: &[LocatedStatement],
    contract: &Contract,
    rereads: &HashMap<String, usize>,
    unrolled: &mut HashMap<String, usize>,
    issues: &mut Vec<ValidationIssue>,
) -> usize {
    let limit = MAX_LOOP_ITERATIONS;
    let mut most = 1;
    for located in statements {
        let statement = &located.statement;
        for expression in statement.expressions() {
            most = most.max(unrolled_calls(
                expression, contract, rereads, unrolled, issues,
            ));
        }
        most = most.max(match statement {
            Statement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                let then = unrolled_body(then_body, contract, rereads, unrolled, issues);
                let other = else_body.as_deref().unwrap_or_default();
                then.max(unrolled_body(other, contract, rereads, unrolled, issues))
            }
            Statement::ForIn { body, .. }
            | Statement::ForCount { body, .. }
            | Statement::ForRange { body, .. } => {
                let mut rereads = rereads.clone();
                // Lowering may read a path iterable, calls in its indexes included, at each use of
                // the item instead of binding it once.
                // ponytail: counted also where lowering binds it, because the body writes nothing
                // the iterable reads; share lowering's choice if that rejects a real contract.
                if let Statement::ForIn {
                    value_var,
                    iterable,
                    ..
                } = statement
                {
                    if iterable.binding_path().is_some() {
                        let calls = unrolled_calls(iterable, contract, &rereads, unrolled, issues);
                        rereads.insert(value_var.clone(), calls);
                    }
                }
                let body = unrolled_body(body, contract, &rereads, unrolled, issues);
                // An invalid count or range is reported with the loop's bindings.
                let count = models::loop_indexes(statement).map_or(1, |range| range.len());
                let total = count.saturating_mul(body);
                if count == 0 {
                    issues.push(
                        ValidationIssue::error(
                            "loop runs zero times, so its body never executes; remove the loop \
                             or make it run at least once",
                        )
                        .at(located.span),
                    );
                } else if total > limit && body <= limit {
                    // A nest already above the limit is reported at its own loop.
                    issues.push(
                        ValidationIssue::error(format!(
                            "loop unrolls {total} iterations, nested loops and called helpers \
                             included, above the limit of {limit}"
                        ))
                        .at(located.span),
                    );
                }
                total
            }
            _ => 1,
        });
    }
    most
}

fn unrolled_calls(
    expression: &Expression,
    contract: &Contract,
    rereads: &HashMap<String, usize>,
    unrolled: &mut HashMap<String, usize>,
    issues: &mut Vec<ValidationIssue>,
) -> usize {
    let mut most = 1;
    match &expression.kind {
        ExprKind::Call { name, .. } => {
            if let Some(function) = contract.functions.iter().find(|f| f.name == *name) {
                most = unrolled_function(function, contract, unrolled, issues);
            }
        }
        ExprKind::Name(path) | ExprKind::ArrayIndex { array: path, .. } => {
            most = rereads.get(&path.root).copied().unwrap_or(1);
        }
        _ => {}
    }
    for child in models::child_exprs(expression) {
        most = most.max(unrolled_calls(child, contract, rereads, unrolled, issues));
    }
    most
}

// Each mask records paths without (1) and with (2) an enforced requirement.
#[derive(Default)]
struct Flow {
    fallthrough: u8,
    returned: u8,
}

fn expression_enforces(expression: &Expression, guarantees: &HashMap<String, bool>) -> bool {
    // Conservatively count only the always-evaluated left operand, even for literal conditions.
    if let ExprKind::BinaryOp { left, op, .. } = &expression.kind {
        if op.class() == OperatorClass::Logical {
            return expression_enforces(left, guarantees);
        }
    }
    matches!(&expression.kind, ExprKind::Call { name, .. } if guarantees.get(name) == Some(&true))
        || models::child_exprs(expression)
            .into_iter()
            .any(|child| expression_enforces(child, guarantees))
}

fn flow_block(
    statements: &[LocatedStatement],
    incoming: u8,
    guarantees: &HashMap<String, bool>,
) -> Flow {
    let mut flow = Flow {
        fallthrough: incoming,
        returned: 0,
    };
    for statement in statements {
        if flow.fallthrough == 0 {
            break;
        }
        let statement = &statement.statement;
        if statement
            .expressions()
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
            Statement::ForIn { body, .. }
            | Statement::ForCount { body, .. }
            | Statement::ForRange { body, .. } => {
                // A loop that runs zero times is an error, so every loop executes at least once.
                let body = flow_block(body, flow.fallthrough, guarantees);
                flow.fallthrough = body.fallthrough;
                flow.returned |= body.returned;
            }
            Statement::Declaration { .. }
            | Statement::Call(_)
            | Statement::LetBinding { .. }
            | Statement::VarAssign { .. } => {}
        }
    }
    flow
}

/// Whether any path reaches the next statement, independent of spend conditions.
pub(crate) fn falls_through(statements: &[LocatedStatement]) -> bool {
    flow_block(statements, 1, &HashMap::new()).fallthrough != 0
}
