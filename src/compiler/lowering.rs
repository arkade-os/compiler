//! Function bodies ready for emission: loops unrolled and, when folding, constant expressions
//! evaluated and statically dead code removed.

use super::Result;
use crate::compiler::ir::Op;
use crate::compiler::loops;
use crate::compiler::optimization;
use crate::diagnostics::CompileError;
use crate::diagnostics::Span;
use crate::models::ExprKind;
use crate::models::Expression;
use crate::models::Function;
use crate::models::LocatedStatement;
use crate::models::Path;
use crate::models::Statement;
use crate::models::TypeName;
use crate::types;

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
    /// `value` evaluated once into the local `name`, which `body` reads.
    // TODO(ir): a made-up name for the same reason as `Generator::with_bound_value`.
    Bound {
        span: Span,
        name: String,
        value: Expression,
        body: Vec<Lowered>,
    },
}

impl Lowered {
    pub(super) fn span(&self) -> Span {
        match self {
            Lowered::Simple(statement) => statement.span,
            Lowered::If { span, .. }
            | Lowered::Unrolled { span, .. }
            | Lowered::Bound { span, .. } => *span,
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
        Lowered::Bound { body, .. } => contains_return(body),
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
        Lowered::Bound { body, .. } => falls_through(body),
    })
}

/// Whether a never-reassigned local or helper parameter holding `literal` is replaced by it at
/// every read instead of being bound.
// ponytail: a substituted literal that does not fold costs its full push at every read, so a
// literal that pushes 3 bytes and is read six times grows the script; count reads before
// substituting to avoid that. Literals that push 4 or more bytes stay bound for the same
// reason and never fold further; substitute them too once wide literals are hoisted into
// shared bindings.
pub(super) fn propagates(literal: &str) -> bool {
    matches!(literal, "true" | "false") || !Op::Push(literal.to_string()).pushes_more_than(2)
}

/// Lower `statements` in `scope`, which gains their bindings as they are declared. When
/// folding, a never-reassigned local folded to a literal that `propagates` is substituted into
/// the statements after it, its whole scope, instead of being bound.
pub(super) fn lower(
    statements: &[LocatedStatement],
    scope: &mut types::Scope,
    structs: &[crate::models::StructDefinition],
    fold: bool,
) -> Result<Vec<Lowered>> {
    let mut lowered = Vec::with_capacity(statements.len());
    let mut literals: Vec<(String, String)> = Vec::new();
    for (index, statement) in statements.iter().enumerate() {
        let span = statement.span;
        let mut statement = statement.clone();
        // ponytail: each substitution rebuilds the statement; substitute all names in one pass
        // if bodies with many propagated locals compile slowly.
        for (name, literal) in &literals {
            statement.statement =
                loops::substitute_statement(&statement.statement, name, literal, None);
        }
        if fold {
            optimization::fold_statement(&mut statement.statement, scope)
                .map_err(|error| CompileError::from(error).at(span))?;
            if let Statement::LetBinding {
                name,
                value:
                    Expression {
                        kind: ExprKind::Literal(literal),
                        ..
                    },
                ..
            } = &statement.statement
            {
                if propagates(literal) && !super::functions::assigns(&statements[index + 1..], name)
                {
                    literals.push((name.clone(), literal.clone()));
                    continue;
                }
            }
        }
        if let Some(item) =
            lower_statement(statement, scope, structs, fold).map_err(|error| error.at(span))?
        {
            let ends = !falls_through(std::slice::from_ref(&item));
            lowered.push(item);
            // Emission stops at an item no path falls through, so the rest is dead.
            if ends {
                break;
            }
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
    let static_condition =
        |condition: &Expression| fold.then(|| optimization::known_bool(condition)).flatten();
    Ok(Some(match statement.statement {
        Statement::Require(Expression {
            kind: ExprKind::Literal(value),
            ..
        }) if fold && value == "true" => return Ok(None),
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
                let mut iteration = lower(&body, &mut scope.clone(), structs, fold)?;
                // A condition with runtime operands still runs, for the failures they raise.
                if !matches!(condition.kind, ExprKind::Literal(_)) {
                    let evaluated = Lowered::If {
                        span,
                        condition,
                        then_body: Vec::new(),
                        else_body: None,
                    };
                    iteration.insert(0, evaluated);
                }
                Lowered::Unrolled {
                    span,
                    iterations: vec![iteration],
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
            // A runtime-indexed access is bound only when the body writes nothing it reads, so the
            // copy matches a live read and folding an index to a literal never changes results.
            // ponytail: such a body still re-evaluates the index per element, and the copy holds
            // every leaf of the selected array even when the body reads few; binding just the
            // index would cover both.
            if iterable.static_path().is_none()
                && (iterable.binding_path().is_none() || !assigns_read(&body, &iterable))
            {
                // Nested loops start at distinct offsets, so their names never collide.
                let name = format!("$iterable:{}", span.start);
                let ty = TypeName::from(&iterable.ty);
                let mut items = iterable.with_kind(ExprKind::Name(Path::new(&name)));
                items.ty = iterable.ty.clone();
                let looped = LocatedStatement {
                    statement: Statement::ForIn {
                        index_var,
                        value_var,
                        iterable: items,
                        body,
                    },
                    ..statement
                };
                let mut inner = scope.clone();
                types::bind_local_type(
                    &mut inner,
                    &name,
                    Some(&ty),
                    types::ArkType::Unknown,
                    structs,
                );
                return Ok(Some(Lowered::Bound {
                    span,
                    body: lower(&[looped], &mut inner, structs, fold)?,
                    name,
                    value: iterable,
                }));
            }
            let iterations = (0..length).map(|k| {
                let element = Some((value_var.as_str(), &iterable));
                let mut substituted =
                    loops::substitute_body(&body, &index_var, &k.to_string(), element);
                // Substitution builds untyped nodes; return types and group members
                // were resolved on the original body and survive the copy.
                types::annotate_statements(&mut substituted, &mut scope.clone(), structs);
                substituted
            });
            let unrolled = unroll(span, iterations, scope, structs, fold)?;
            if iterable.static_path().is_some() {
                unrolled
            } else {
                // Reads stay in place, but reading the iterable's length evaluates and checks
                // its runtime indexes once at entry, even if the body reads no element. A length
                // is never zero, so the requirement holds.
                // ponytail: the read also scales its offset and pushes the length to verify,
                // ops a bare index check skips; emit the checks directly if such loops grow common.
                let mut length = iterable.with_kind(ExprKind::FieldAccess {
                    value: Box::new(iterable.clone()),
                    field: "length".into(),
                });
                length.ty = types::ArkType::Int;
                let check = LocatedStatement {
                    statement: Statement::Require(length),
                    ..statement
                };
                Lowered::Unrolled {
                    span,
                    iterations: vec![vec![Lowered::Simple(check), unrolled]],
                    guarded: false,
                }
            }
        }
        Statement::ForCount { count, body } => {
            let count = match &count.kind {
                ExprKind::Literal(count) => count.parse::<usize>().ok(),
                _ => None,
            }
            .ok_or("loop count must be a non-negative integer compile-time constant")?;
            unroll(span, std::iter::repeat_n(body, count), scope, structs, fold)?
        }
        Statement::ForRange {
            index_var,
            start,
            end,
            body,
        } => {
            let iterations = crate::models::loop_range(&start, &end)?.map(|k| {
                let mut substituted =
                    loops::substitute_body(&body, &index_var, &k.to_string(), None);
                types::annotate_statements(&mut substituted, &mut scope.clone(), structs);
                substituted
            });
            unroll(span, iterations, scope, structs, fold)?
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

/// Whether `body` assigns a name `expression` reads. Helpers cannot write their caller's
/// names, so only the names in `expression` itself count.
fn assigns_read(body: &[LocatedStatement], expression: &Expression) -> bool {
    matches!(&expression.kind, ExprKind::Name(path) | ExprKind::ArrayIndex { array: path, .. }
        if super::functions::assigns(body, &path.root))
        || crate::models::child_exprs(expression)
            .into_iter()
            .any(|child| assigns_read(body, child))
}

/// Each iteration lowered in its own scope; folding stops after one that cannot fall through.
fn unroll(
    span: Span,
    iterations: impl Iterator<Item = Vec<LocatedStatement>>,
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
        guarded: lowered.iter().any(|iteration| contains_return(iteration)),
        iterations: lowered,
    })
}

/// The helper calls in `body`, each with the span of the statement that makes it.
fn calls<'a>(body: &'a [Lowered], found: &mut Vec<(&'a Expression, Span)>) {
    fn walk<'a>(expression: &'a Expression, span: Span, found: &mut Vec<(&'a Expression, Span)>) {
        if let ExprKind::Call { .. } = &expression.kind {
            found.push((expression, span));
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
            Lowered::Bound {
                span, value, body, ..
            } => {
                walk(value, *span, found);
                calls(body, found);
            }
        }
    }
}

/// Fold `statements` and the helpers the folded code still calls, for the errors folding
/// finds, as an optimized build would.
pub(super) fn check_folded(
    statements: &[LocatedStatement],
    scope: &types::Scope,
    constructor_scope: &types::Scope,
    structs: &[crate::models::StructDefinition],
    functions: &[Function],
    checked: &mut std::collections::HashSet<(String, Vec<Option<String>>)>,
) -> Result<()> {
    let body = lower(statements, &mut scope.clone(), structs, true)?;
    let mut found = Vec::new();
    calls(&body, &mut found);
    for (call, span) in found {
        let ExprKind::Call { name, args, .. } = &call.kind else {
            continue;
        };
        let Some(helper) = functions.iter().find(|f| f.name == *name) else {
            continue;
        };
        // As at a call, literal arguments fold into the body, so each set of them is checked.
        let literals = args
            .iter()
            .zip(&helper.parameters)
            .map(|(argument, parameter)| {
                super::functions::literal_argument(helper, parameter, argument).map(str::to_string)
            })
            .collect();
        if !checked.insert((name.clone(), literals)) {
            continue;
        }
        // As at a call: the constructor's bindings, or none for a static helper, and the parameters.
        let mut scope = if helper.is_static {
            types::Scope::new()
        } else {
            constructor_scope.clone()
        };
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
        check_folded(
            &super::functions::substitute_arguments(helper, args),
            &scope,
            constructor_scope,
            structs,
            functions,
            checked,
        )
        .map_err(|mut error| {
            // An imported helper's spans index its own file; the call locates the error instead.
            if helper.is_imported() {
                error.span = None;
            }
            error.at(span)
        })?;
    }
    Ok(())
}
