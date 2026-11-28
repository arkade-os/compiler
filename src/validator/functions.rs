//! Function-level checks: returns, calls (arity, argument types, entrypoint and static rules),
//! literal shapes against their expected types, recursion, loop unrolling limits, and that every
//! entrypoint path enforces a requirement.

use std::collections::{HashMap, HashSet};

use super::error::{Declared, ValueContext};
use super::{ValidationError, ValidationIssue};
use crate::builtins::BUILTINS;
use crate::compiler::MAX_LOOP_ITERATIONS;
use crate::diagnostics::Span;
use crate::errors;
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
                let function = function.name.clone();
                issues.push(ValidationError::EntrypointReturnType { function }.into());
            }
            super::validate_declared_type(result, Declared::ReturnType, &definitions, issues);
        }
        if function.is_static {
            let referenced = super::references::referenced_parameters(&function.statements, &[]);
            for parameter in &contract.parameters {
                if referenced.contains(parameter.name.as_str()) {
                    let error = ValidationError::StaticReadsConstructorParameter {
                        function: function.name.clone(),
                        parameter: parameter.name.clone(),
                    };
                    issues.push(error.into());
                }
            }
        }
        validate_body(&function.statements, function, contract, issues);
        super::locate(&mut issues[first..], function.span);
    }

    let mut guarantees = HashMap::new();
    for function in contract.functions.iter().filter(|f| !f.is_imported()) {
        if let Err(error) = analyze_function(function, contract, &mut Vec::new(), &mut guarantees) {
            issues.push(error.at(function.span));
            return;
        }
    }
    let mut unrolled = HashMap::new();
    for function in contract.functions.iter().filter(|f| !f.is_imported()) {
        unrolled_function(function, contract, &mut unrolled, issues);
    }
    for function in contract.functions.iter().filter(|f| !f.is_imported()) {
        let flow = flow_block(&function.statements, Paths::UNENFORCED, &guarantees);
        if function.is_private && function.return_type.is_some() && flow.fallthrough.any() {
            let error = ValidationError::MissingReturnPath {
                function: function.name.clone(),
            };
            issues.push(error.at(function.span));
        }
        if !function.is_private && flow.has_unenforced() {
            let error = ValidationError::UnenforcedPath {
                function: function.name.clone(),
            };
            issues.push(error.at(function.span));
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
                    let function = function.name.clone();
                    issues.push(ValidationError::ReturnInEntrypoint { function }.into());
                }
                let name = function.name.clone();
                match (&function.return_type, value) {
                    (Some(expected), Some(value)) => validate_value(
                        expected,
                        value,
                        &contract.structs,
                        ValueContext::Return { function: name },
                        issues,
                    ),
                    (Some(_), None) => {
                        let error = ValidationError::MissingReturnValue { function: name };
                        issues.push(error.into());
                    }
                    (None, Some(_)) => {
                        let error = ValidationError::VoidReturnsValue { function: name };
                        issues.push(error.into());
                    }
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
                        ValueContext::Binding {
                            name: name.clone(),
                            function: function.name.clone(),
                        },
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
                ValueContext::Comparison {
                    function: function.name.clone(),
                },
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
            None if name == "require" && !value_position && args.len() == 2 => {
                issues.push(ValidationError::RequireMessageNotString.into())
            }
            None => {
                let issue =
                    ValidationIssue::from(ValidationError::UnknownFunction { name: name.clone() });
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
                    let name = name.clone();
                    issues.push(ValidationError::EntrypointCalled { name }.into());
                }
                if caller.is_static && !function.is_static {
                    let error = ValidationError::StaticCallsNonStatic {
                        caller: caller.name.clone(),
                        callee: name.clone(),
                    };
                    issues.push(error.into());
                }
                if !value_position && function.return_type.is_some() {
                    let name = name.clone();
                    issues.push(ValidationError::UnusedReturnValue { name }.into());
                }
                if function.parameters.len() != args.len() {
                    let error = ValidationError::ArgumentCount {
                        name: name.clone(),
                        expected: function.parameters.len(),
                        got: args.len(),
                    };
                    issues.push(error.into());
                }
                for (parameter, argument) in function.parameters.iter().zip(args) {
                    let context = ValueContext::Argument {
                        parameter: parameter.name.clone(),
                        function: name.clone(),
                    };
                    validate_value(
                        &parameter.param_type,
                        argument,
                        &contract.structs,
                        context,
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
        let context = ValueContext::Literal { name: name.clone() };
        validate_fields(name, fields, &contract.structs, context, issues);
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
    context: ValueContext,
    issues: &mut Vec<ValidationIssue>,
) {
    let first = issues.len();
    let expected_type = expected.ark_type();
    match (&value.kind, expected.array_parts(), &expected_type) {
        (ExprKind::ArrayLiteral(elements), Some((element, length)), _) => {
            if elements.len() != length {
                let error = ValidationError::ArrayLiteralLength {
                    context: context.clone(),
                    expected: length,
                    got: elements.len(),
                };
                issues.push(error.into());
            }
            for (index, value) in elements.iter().enumerate() {
                let of = Box::new(context.clone());
                let context = ValueContext::Element { of, index };
                validate_value(element, value, structs, context, issues);
            }
        }
        (ExprKind::StructLiteral { name: None, fields }, _, ArkType::Struct(name)) => {
            validate_fields(name, fields, structs, context, issues)
        }
        _ => {
            let actual = &value.ty;
            if !expected_type.accepts(actual) {
                let error = ValidationError::ValueType {
                    context,
                    expected: expected.clone(),
                    actual: actual.into(),
                };
                issues.push(error.into());
            }
        }
    }
    super::locate(&mut issues[first..], value.span);
}

fn validate_fields(
    name: &str,
    fields: &[(String, Expression)],
    structs: &[StructDefinition],
    context: ValueContext,
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
                let (context, field) = (context.clone(), name.clone());
                issues.push(ValidationError::DuplicateLiteralField { context, field }.into());
            }
            if let Some(field) = definition.fields.iter().find(|f| f.name == *name) {
                let of = Box::new(context.clone());
                let context = ValueContext::Field {
                    of,
                    name: name.clone(),
                };
                validate_value(&field.param_type, value, structs, context, issues);
            } else {
                let (context, field) = (context.clone(), name.clone());
                issues.push(ValidationError::UnknownLiteralField { context, field }.into());
            }
        }
        for field in &definition.fields {
            if !seen.contains(&field.name) {
                let (context, field) = (context.clone(), field.name.clone());
                issues.push(ValidationError::MissingLiteralField { context, field }.into());
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
) -> Result<(), ValidationError> {
    if guarantees.contains_key(&function.name) {
        return Ok(());
    }
    if visiting.contains(&function.name) {
        visiting.push(function.name.clone());
        let cycle = visiting.clone();
        return Err(ValidationError::RecursiveCall { cycle });
    }
    visiting.push(function.name.clone());
    analyze_calls(&function.statements, contract, visiting, guarantees)?;
    let flow = flow_block(&function.statements, Paths::UNENFORCED, guarantees);
    guarantees.insert(function.name.clone(), !flow.has_unenforced());
    visiting.pop();
    Ok(())
}

fn analyze_calls(
    statements: &[LocatedStatement],
    contract: &Contract,
    visiting: &mut Vec<String>,
    guarantees: &mut HashMap<String, bool>,
) -> Result<(), ValidationError> {
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
) -> Result<(), ValidationError> {
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
                // LIMITATION: counted also where lowering binds it, because the body writes
                // nothing the iterable reads; share lowering's choice if that rejects a real
                // contract.
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
                    issues.push(ValidationError::LoopRunsZeroTimes.at(located.span));
                } else if total > limit && body <= limit {
                    // A nest already above the limit is reported at its own loop.
                    issues.push(ValidationError::LoopUnrollLimit { total }.at(located.span));
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

/// Which paths reach a point: some without an enforced requirement, some with one.
#[derive(Clone, Copy)]
struct Paths {
    unenforced: bool,
    enforced: bool,
}

impl Paths {
    const NONE: Paths = Paths {
        unenforced: false,
        enforced: false,
    };
    const UNENFORCED: Paths = Paths {
        unenforced: true,
        enforced: false,
    };
    const ENFORCED: Paths = Paths {
        unenforced: false,
        enforced: true,
    };

    fn any(self) -> bool {
        self.unenforced || self.enforced
    }

    fn or(self, other: Paths) -> Paths {
        Paths {
            unenforced: self.unenforced || other.unenforced,
            enforced: self.enforced || other.enforced,
        }
    }
}

struct Flow {
    fallthrough: Paths,
    returned: Paths,
}

impl Flow {
    fn has_unenforced(&self) -> bool {
        self.fallthrough.unenforced || self.returned.unenforced
    }
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
    incoming: Paths,
    guarantees: &HashMap<String, bool>,
) -> Flow {
    let mut flow = Flow {
        fallthrough: incoming,
        returned: Paths::NONE,
    };
    for statement in statements {
        if !flow.fallthrough.any() {
            break;
        }
        let statement = &statement.statement;
        if statement
            .expressions()
            .into_iter()
            .any(|e| expression_enforces(e, guarantees))
        {
            flow.fallthrough = Paths::ENFORCED;
        }
        match statement {
            Statement::Require(_) => flow.fallthrough = Paths::ENFORCED,
            Statement::Return(_) => {
                flow.returned = flow.returned.or(flow.fallthrough);
                flow.fallthrough = Paths::NONE;
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
                flow.fallthrough = left.fallthrough.or(right.fallthrough);
                flow.returned = flow.returned.or(left.returned).or(right.returned);
            }
            Statement::ForIn { body, .. }
            | Statement::ForCount { body, .. }
            | Statement::ForRange { body, .. } => {
                // A loop that runs zero times is an error, so every loop executes at least once.
                let body = flow_block(body, flow.fallthrough, guarantees);
                flow.fallthrough = body.fallthrough;
                flow.returned = flow.returned.or(body.returned);
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
    flow_block(statements, Paths::UNENFORCED, &HashMap::new())
        .fallthrough
        .any()
}
