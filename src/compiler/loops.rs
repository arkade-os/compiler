use crate::models::*;

// ─── Loop Unrolling ─────────────────────────────────────────────────────────────

/// Substitute loop variables in the body for a specific iteration index k.
///
/// Transforms:
/// - `index_var` → `Literal(k)`
/// - `value_var` and paths rooted at it → accesses on element `k` of `items`
pub(crate) fn substitute_loop_body(
    body: &[LocatedStatement],
    index_var: &str,
    value_var: &str,
    k: usize,
    items: &Expression,
) -> Vec<LocatedStatement> {
    body.iter()
        .map(|stmt| LocatedStatement {
            span: stmt.span,
            statement: substitute_statement(&stmt.statement, index_var, value_var, k, items),
        })
        .collect()
}

pub(crate) fn substitute_statement(
    stmt: &Statement,
    index_var: &str,
    value_var: &str,
    k: usize,
    items: &Expression,
) -> Statement {
    match stmt {
        Statement::Call(expression) => Statement::Call(substitute_expression(
            expression, index_var, value_var, k, items,
        )),
        Statement::Return(value) => {
            Statement::Return(value.as_ref().map(|expression| {
                substitute_expression(expression, index_var, value_var, k, items)
            }))
        }
        Statement::Require(req) => {
            Statement::Require(substitute_requirement(req, index_var, value_var, k, items))
        }
        Statement::LetBinding {
            name,
            declared_type,
            value,
        } => Statement::LetBinding {
            name: name.clone(),
            declared_type: declared_type.clone(),
            value: substitute_expression(value, index_var, value_var, k, items),
        },
        Statement::VarAssign { target, value } => Statement::VarAssign {
            target: match substitute_expression(
                &match target {
                    AssignmentTarget::Access(value) => (**value).clone(),
                    AssignmentTarget::Binding(name) => Expression::Property(name.clone()),
                    AssignmentTarget::ArrayIndex { array, index } => Expression::ArrayIndex {
                        array: array.clone(),
                        index: index.clone(),
                    },
                },
                index_var,
                value_var,
                k,
                items,
            ) {
                Expression::Variable(name) | Expression::Property(name) => {
                    AssignmentTarget::Binding(name)
                }
                Expression::ArrayIndex { array, index } => {
                    AssignmentTarget::ArrayIndex { array, index }
                }
                value => AssignmentTarget::Access(Box::new(value)),
            },
            value: substitute_expression(value, index_var, value_var, k, items),
        },
        Statement::IfElse {
            condition,
            then_body,
            else_body,
        } => Statement::IfElse {
            condition: substitute_expression(condition, index_var, value_var, k, items),
            then_body: substitute_loop_body(then_body, index_var, value_var, k, items),
            else_body: else_body
                .as_ref()
                .map(|b| substitute_loop_body(b, index_var, value_var, k, items)),
        },
        Statement::ForIn {
            index_var: inner_idx,
            value_var: inner_val,
            iterable,
            body,
        } => Statement::ForIn {
            index_var: inner_idx.clone(),
            value_var: inner_val.clone(),
            iterable: substitute_expression(iterable, index_var, value_var, k, items),
            body: substitute_loop_body(body, index_var, value_var, k, items),
        },
        Statement::ForCount { count, body } => Statement::ForCount {
            count: substitute_expression(count, index_var, value_var, k, items),
            body: substitute_loop_body(body, index_var, value_var, k, items),
        },
    }
}

pub(crate) fn substitute_requirement(
    req: &Requirement,
    index_var: &str,
    value_var: &str,
    k: usize,
    items: &Expression,
) -> Requirement {
    match req {
        Requirement::Expression(expr) => {
            Requirement::Expression(substitute_expression(expr, index_var, value_var, k, items))
        }
        Requirement::Comparison { left, op, right } => Requirement::Comparison {
            left: substitute_expression(left, index_var, value_var, k, items),
            op: *op,
            right: substitute_expression(right, index_var, value_var, k, items),
        },
    }
}

/// Resolve a dotted binding path, rooting `value_var` paths at element `k` of `items`.
fn substitute_path(
    path: &str,
    index_var: &str,
    value_var: &str,
    k: usize,
    items: &Expression,
) -> Option<Expression> {
    if path == index_var {
        return Some(Expression::Literal(k.to_string()));
    }
    let mut fields = path.split('.');
    if fields.next() != Some(value_var) {
        return None;
    }
    let index = Box::new(Expression::Literal(k.to_string()));
    let element = match items {
        Expression::Variable(array) | Expression::Property(array) => Expression::ArrayIndex {
            array: array.clone(),
            index,
        },
        value => Expression::IndexAccess {
            value: Box::new(value.clone()),
            index,
        },
    };
    Some(
        fields.fold(element, |value, field| Expression::FieldAccess {
            value: Box::new(value),
            field: field.to_string(),
        }),
    )
}

pub(crate) fn substitute_expression(
    expr: &Expression,
    index_var: &str,
    value_var: &str,
    k: usize,
    items: &Expression,
) -> Expression {
    match expr {
        Expression::Variable(path) | Expression::Property(path) => {
            substitute_path(path, index_var, value_var, k, items).unwrap_or_else(|| expr.clone())
        }
        Expression::ArrayIndex { array, index } => {
            let index = Box::new(substitute_expression(index, index_var, value_var, k, items));
            match substitute_path(array, index_var, value_var, k, items) {
                Some(value) => Expression::IndexAccess {
                    value: Box::new(value),
                    index,
                },
                None => Expression::ArrayIndex {
                    array: array.clone(),
                    index,
                },
            }
        }
        _ => {
            let mut expression = expr.clone();
            for child in crate::models::child_exprs_mut(&mut expression) {
                *child = substitute_expression(child, index_var, value_var, k, items);
            }
            expression
        }
    }
}
