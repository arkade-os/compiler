//! Function bodies ready for emission: loops unrolled and, when folding, constant expressions
//! evaluated and statically dead code removed.

use super::*;
use crate::diagnostics::Span;

pub(super) enum Lowered {
    /// A statement with no nested statements.
    Simple(LocatedStatement),
    If {
        span: Span,
        condition: Expression,
        then_body: Vec<Lowered>,
        else_body: Option<Vec<Lowered>>,
    },
    /// A loop after unrolling, or a statically chosen branch: each iteration is its own
    /// scope, and a `guarded` iteration after the first runs only if no earlier one returned.
    Unrolled {
        span: Span,
        iterations: Vec<Vec<Lowered>>,
        guarded: bool,
    },
}

impl Lowered {
    pub(super) fn span(&self) -> Span {
        match self {
            Lowered::Simple(statement) => statement.span,
            Lowered::If { span, .. } | Lowered::Unrolled { span, .. } => *span,
        }
    }

    pub(super) fn is_return(&self) -> bool {
        matches!(
            self,
            Lowered::Simple(LocatedStatement {
                statement: Statement::Return(_),
                ..
            })
        )
    }
}

pub(super) fn contains_return(body: &[Lowered]) -> bool {
    body.iter().any(|item| match item {
        Lowered::Simple(_) => item.is_return(),
        Lowered::If {
            then_body,
            else_body,
            ..
        } => contains_return(then_body) || else_body.as_deref().is_some_and(contains_return),
        Lowered::Unrolled { iterations, .. } => iterations.iter().any(|body| contains_return(body)),
    })
}

/// Whether some path through `body` reaches its end.
fn falls_through(body: &[Lowered]) -> bool {
    body.iter().all(|item| match item {
        Lowered::Simple(_) => !item.is_return(),
        Lowered::If {
            then_body,
            else_body,
            ..
        } => falls_through(then_body) || else_body.as_deref().is_none_or(falls_through),
        Lowered::Unrolled { iterations, .. } => {
            iterations.last().is_none_or(|body| falls_through(body))
        }
    })
}

/// Lower `statements` in `scope`, which gains their bindings as they are declared.
pub(super) fn lower(
    statements: &[LocatedStatement],
    scope: &mut types::Scope,
    structs: &[crate::models::StructDefinition],
    fold: bool,
) -> Result<Vec<Lowered>> {
    let mut lowered = Vec::with_capacity(statements.len());
    for statement in statements {
        let span = statement.span;
        let mut statement = statement.clone();
        if fold {
            optimization::fold_statement(&mut statement.statement, scope)
                .map_err(|error| CompileError::from(error).at(span))?;
        }
        if let Some(item) =
            lower_statement(statement, scope, structs, fold).map_err(|error| error.at(span))?
        {
            lowered.push(item);
        }
    }
    Ok(lowered)
}

fn lower_statement(
    statement: LocatedStatement,
    scope: &mut types::Scope,
    structs: &[crate::models::StructDefinition],
    fold: bool,
) -> Result<Option<Lowered>> {
    let span = statement.span;
    let static_condition = |condition: &Expression| match &condition.kind {
        ExprKind::Literal(value) if fold && matches!(value.as_str(), "true" | "false") => {
            Some(value == "true")
        }
        _ => None,
    };
    Ok(Some(match statement.statement {
        Statement::Require(Requirement::Expression(Expression {
            kind: ExprKind::Literal(value),
            ..
        })) if fold && value == "true" => return Ok(None),
        Statement::IfElse {
            condition,
            then_body,
            else_body,
        } => match static_condition(&condition) {
            Some(taken) => {
                let body = if taken {
                    then_body
                } else {
                    else_body.unwrap_or_default()
                };
                Lowered::Unrolled {
                    span,
                    iterations: vec![lower(&body, &mut scope.clone(), structs, fold)?],
                    guarded: false,
                }
            }
            None => Lowered::If {
                span,
                condition,
                then_body: lower(&then_body, &mut scope.clone(), structs, fold)?,
                else_body: else_body
                    .map(|body| lower(&body, &mut scope.clone(), structs, fold))
                    .transpose()?,
            },
        },
        Statement::ForIn {
            index_var,
            value_var,
            iterable,
            body,
        } => {
            let types::ArkType::Array(_, length) = iterable.ty else {
                return Err("unsupported loop iterable".into());
            };
            let iterations = (0..length).map(|k| {
                let mut substituted =
                    substitute_loop_body(&body, &index_var, &value_var, k, &iterable);
                // Substitution builds untyped nodes; return types and group members
                // were resolved on the original body and survive the copy.
                types::annotate_statements(&mut substituted, &mut scope.clone(), structs);
                substituted
            });
            unroll(span, iterations, &body, scope, structs, fold)?
        }
        Statement::ForCount { count, body } => {
            let count = match &count.kind {
                ExprKind::Literal(count) => count.parse::<usize>().ok(),
                _ => None,
            }
            .ok_or("loop count must be a non-negative integer compile-time constant")?;
            unroll(
                span,
                std::iter::repeat_n(body.clone(), count),
                &body,
                scope,
                structs,
                fold,
            )?
        }
        Statement::Declaration {
            ref name,
            ref declared_type,
        } => {
            types::bind_local_type(
                scope,
                name,
                Some(declared_type),
                types::ArkType::Unknown,
                structs,
            );
            Lowered::Simple(statement)
        }
        Statement::LetBinding {
            ref name,
            ref declared_type,
            ref value,
        } => {
            let result_type = declared_type
                .clone()
                .or_else(|| match &value.kind {
                    ExprKind::Call { return_type, .. } => return_type.clone(),
                    _ => crate::models::expression_result_struct(value).map(TypeName::from),
                })
                .or_else(|| match &value.ty {
                    composite @ (types::ArkType::Array(..) | types::ArkType::Struct(_)) => {
                        Some(composite.into())
                    }
                    _ => None,
                });
            match &result_type {
                Some(ty) => {
                    types::bind_local_type(scope, name, Some(ty), types::ArkType::Unknown, structs)
                }
                None => {
                    scope.insert(name.clone(), value.ty.clone());
                }
            }
            Lowered::Simple(statement)
        }
        _ => Lowered::Simple(statement),
    }))
}

/// Each iteration lowered in its own scope; folding stops after one that cannot fall through.
fn unroll(
    span: Span,
    iterations: impl Iterator<Item = Vec<LocatedStatement>>,
    body: &[LocatedStatement],
    scope: &types::Scope,
    structs: &[crate::models::StructDefinition],
    fold: bool,
) -> Result<Lowered> {
    let mut lowered = Vec::new();
    for iteration in iterations {
        let iteration = lower(&iteration, &mut scope.clone(), structs, fold)?;
        let continues = falls_through(&iteration);
        lowered.push(iteration);
        if fold && !continues {
            break;
        }
    }
    Ok(Lowered::Unrolled {
        span,
        iterations: lowered,
        guarded: functions::contains_return(body),
    })
}

/// The helpers `body` calls, each with the span of the statement that calls it.
fn calls(body: &[Lowered], found: &mut Vec<(String, Span)>) {
    fn walk(expression: &Expression, span: Span, found: &mut Vec<(String, Span)>) {
        if let ExprKind::Call { name, .. } = &expression.kind {
            found.push((name.clone(), span));
        }
        for child in crate::models::child_exprs(expression) {
            walk(child, span, found);
        }
    }
    for item in body {
        match item {
            Lowered::Simple(statement) => {
                for expression in statement.statement.expressions() {
                    walk(expression, statement.span, found);
                }
            }
            Lowered::If {
                span,
                condition,
                then_body,
                else_body,
            } => {
                walk(condition, *span, found);
                calls(then_body, found);
                calls(else_body.as_deref().unwrap_or_default(), found);
            }
            Lowered::Unrolled { iterations, .. } => {
                iterations.iter().for_each(|body| calls(body, found));
            }
        }
    }
}

/// Fold `statements` and the helpers the folded code still calls, for the errors folding
/// finds, as an optimized build would.
pub(super) fn check_folded(
    statements: &[LocatedStatement],
    scope: &types::Scope,
    structs: &[crate::models::StructDefinition],
    functions: &[Function],
    checked: &mut std::collections::HashSet<String>,
) -> Result<()> {
    let body = lower(statements, &mut scope.clone(), structs, true)?;
    let mut found = Vec::new();
    calls(&body, &mut found);
    for (name, span) in found {
        let Some(helper) = functions.iter().find(|f| f.name == name) else {
            continue;
        };
        if !checked.insert(name) {
            continue;
        }
        let mut scope = scope.clone();
        for parameter in &helper.parameters {
            let ty = Some(&parameter.param_type);
            types::bind_local_type(
                &mut scope,
                &parameter.name,
                ty,
                types::ArkType::Unknown,
                structs,
            );
        }
        check_folded(&helper.statements, &scope, structs, functions, checked).map_err(
            |mut error| {
                // An imported helper's spans index its own file; the call locates the error instead.
                if helper.is_imported() {
                    error.span = None;
                }
                error.at(span)
            },
        )?;
    }
    Ok(())
}
