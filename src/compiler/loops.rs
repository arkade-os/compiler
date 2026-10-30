use crate::models::*;

// ─── Loop Unrolling ─────────────────────────────────────────────────────────────

/// Substitute loop variables in the body for a specific iteration index k.
///
/// Transforms:
/// - `index_var` → `Literal(k)`
/// - `value_var` and paths rooted at it → accesses on element `k` of `items`
///
/// Copies keep only the span and statement; names, branches and messages are read from the
/// parsed body.
pub(crate) fn substitute_loop_body(
    body: &[LocatedStatement],
    index_var: &str,
    value_var: &str,
    k: usize,
    items: &Expression,
) -> Vec<LocatedStatement> {
    body.iter()
        .map(|stmt| LocatedStatement {
            names: Vec::new(),
            branches: Vec::new(),
            message: None,
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
        Statement::Declaration { .. } => stmt.clone(),
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
            // A bare binding has no span of its own; the assigned value's stands in.
            target: match substitute_expression(
                &match target {
                    AssignmentTarget::Access(value) => (**value).clone(),
                    AssignmentTarget::Binding(name) => {
                        value.with_kind(ExprKind::Name(name.clone()))
                    }
                    AssignmentTarget::ArrayIndex { array, index } => {
                        index.with_kind(ExprKind::ArrayIndex {
                            array: array.clone(),
                            index: index.clone(),
                        })
                    }
                },
                index_var,
                value_var,
                k,
                items,
            ) {
                Expression {
                    kind: ExprKind::Name(path),
                    ..
                } => AssignmentTarget::Binding(path),
                Expression {
                    kind: ExprKind::ArrayIndex { array, index },
                    ..
                } => AssignmentTarget::ArrayIndex { array, index },
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
    path: &Path,
    at: &Expression,
    index_var: &str,
    value_var: &str,
    k: usize,
    items: &Expression,
) -> Option<Expression> {
    if path.root == index_var && path.segments.is_empty() {
        return Some(at.with_kind(ExprKind::Literal(k.to_string())));
    }
    if path.root != value_var {
        return None;
    }
    let index = Box::new(at.with_kind(ExprKind::Literal(k.to_string())));
    let element = at.with_kind(match &items.kind {
        ExprKind::Name(path) => ExprKind::ArrayIndex {
            array: path.clone(),
            index,
        },
        _ => ExprKind::IndexAccess {
            value: Box::new(items.clone()),
            index,
        },
    });
    Some(path.segments.iter().fold(element, |value, segment| {
        let value = Box::new(value);
        at.with_kind(match segment {
            Segment::Field(field) => ExprKind::FieldAccess {
                value,
                field: field.clone(),
            },
            Segment::Index(index) => ExprKind::IndexAccess {
                value,
                index: Box::new(at.with_kind(ExprKind::Literal(index.to_string()))),
            },
        })
    }))
}

pub(crate) fn substitute_expression(
    expr: &Expression,
    index_var: &str,
    value_var: &str,
    k: usize,
    items: &Expression,
) -> Expression {
    match &expr.kind {
        ExprKind::Name(path) => substitute_path(path, expr, index_var, value_var, k, items)
            .unwrap_or_else(|| expr.clone()),
        ExprKind::ArrayIndex { array, index } => {
            let index = Box::new(substitute_expression(index, index_var, value_var, k, items));
            expr.with_kind(
                match substitute_path(array, expr, index_var, value_var, k, items) {
                    Some(value) => ExprKind::IndexAccess {
                        value: Box::new(value),
                        index,
                    },
                    None => ExprKind::ArrayIndex {
                        array: array.clone(),
                        index,
                    },
                },
            )
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostics::Span;

    #[test]
    fn loop_substitution_preserves_spans() {
        let span = Span { start: 10, end: 20 };
        let index = Expression::new(
            ExprKind::Name(crate::models::Path::from_key("i")),
            Span { start: 12, end: 13 },
        );
        let items = ExprKind::Name(crate::models::Path::from_key("xs")).into();
        for (kind, expected) in [
            (
                ExprKind::Name(crate::models::Path::from_key("i")),
                ["0", "1"],
            ),
            (
                ExprKind::Name(crate::models::Path::from_key("x")),
                ["xs[0]", "xs[1]"],
            ),
            (
                ExprKind::Name(crate::models::Path::from_key("x.amount")),
                ["xs[0].amount", "xs[1].amount"],
            ),
            (
                ExprKind::ArrayIndex {
                    array: Path::new("x"),
                    index: Box::new(index.clone()),
                },
                ["xs[0][0]", "xs[1][1]"],
            ),
        ] {
            let expression = Expression::new(kind, span);
            for (k, expected) in expected.iter().enumerate() {
                let replaced = substitute_expression(&expression, "i", "x", k, &items);
                assert_eq!(replaced.span, span);
                assert_eq!(replaced.source_text(), *expected);
                if let ExprKind::IndexAccess {
                    index: replaced_index,
                    ..
                } = &replaced.kind
                {
                    assert_eq!(replaced_index.span, index.span);
                }
            }
        }
    }
}
