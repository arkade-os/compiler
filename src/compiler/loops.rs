use crate::models::*;

// ─── Loop Unrolling ─────────────────────────────────────────────────────────────

/// Substitute `literal` for the scalar binding `name` in `body`. For a loop iteration,
/// `element` names its value variable and the iterated items, and that variable and paths
/// rooted at it become accesses on element `literal` of the items.
///
/// The literal keeps the substituted name's type, and a rebuilt array read keeps its own;
/// element accesses are untyped. Copies keep only the span and statement; names, branches and
/// messages are read from the parsed body.
pub(crate) fn substitute_body(
    body: &[LocatedStatement],
    name: &str,
    literal: &str,
    element: Option<(&str, &Expression)>,
) -> Vec<LocatedStatement> {
    body.iter()
        .map(|stmt| LocatedStatement {
            names: Vec::new(),
            branches: Vec::new(),
            message: None,
            span: stmt.span,
            statement: substitute_statement(&stmt.statement, name, literal, element),
            attributes: stmt.attributes.clone(),
        })
        .collect()
}

pub(crate) fn substitute_statement(
    stmt: &Statement,
    name: &str,
    literal: &str,
    element: Option<(&str, &Expression)>,
) -> Statement {
    match stmt {
        Statement::Call(expression) => {
            Statement::Call(substitute_expression(expression, name, literal, element))
        }
        Statement::Return(value) => Statement::Return(
            value
                .as_ref()
                .map(|expression| substitute_expression(expression, name, literal, element)),
        ),
        Statement::Require(condition) => {
            Statement::Require(substitute_expression(condition, name, literal, element))
        }
        Statement::Declaration { .. } => stmt.clone(),
        Statement::LetBinding {
            name: binding,
            declared_type,
            value,
        } => Statement::LetBinding {
            name: binding.clone(),
            declared_type: declared_type.clone(),
            value: substitute_expression(value, name, literal, element),
        },
        Statement::VarAssign { target, value } => Statement::VarAssign {
            // A bare binding has no span of its own; the assigned value's stands in.
            target: match substitute_expression(
                &match target {
                    AssignmentTarget::Access(value) => (**value).clone(),
                    AssignmentTarget::Binding(path) => {
                        value.with_kind(ExprKind::Name(path.clone()))
                    }
                    AssignmentTarget::ArrayIndex { array, index } => {
                        index.with_kind(ExprKind::ArrayIndex {
                            array: array.clone(),
                            index: index.clone(),
                        })
                    }
                },
                name,
                literal,
                element,
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
            value: substitute_expression(value, name, literal, element),
        },
        Statement::IfElse {
            condition,
            then_body,
            else_body,
        } => Statement::IfElse {
            condition: substitute_expression(condition, name, literal, element),
            then_body: substitute_body(then_body, name, literal, element),
            else_body: else_body
                .as_ref()
                .map(|b| substitute_body(b, name, literal, element)),
        },
        Statement::ForIn {
            index_var: inner_idx,
            value_var: inner_val,
            iterable,
            body,
        } => Statement::ForIn {
            index_var: inner_idx.clone(),
            value_var: inner_val.clone(),
            iterable: substitute_expression(iterable, name, literal, element),
            body: substitute_body(body, name, literal, element),
        },
        Statement::ForCount { count, body } => Statement::ForCount {
            count: substitute_expression(count, name, literal, element),
            body: substitute_body(body, name, literal, element),
        },
    }
}

/// Resolve a dotted binding path: `name` to `literal`, and `element`'s value variable paths to
/// accesses on element `literal` of its items.
fn substitute_path(
    path: &Path,
    at: &Expression,
    name: &str,
    literal: &str,
    element: Option<(&str, &Expression)>,
) -> Option<Expression> {
    if path.root == name && path.segments.is_empty() {
        let mut value = at.clone();
        value.kind = ExprKind::Literal(literal.to_string());
        return Some(value);
    }
    let (_, items) = element.filter(|(value_var, _)| path.root == *value_var)?;
    let index = Box::new(at.with_kind(ExprKind::Literal(literal.to_string())));
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
    name: &str,
    literal: &str,
    element: Option<(&str, &Expression)>,
) -> Expression {
    match &expr.kind {
        ExprKind::Name(path) => {
            substitute_path(path, expr, name, literal, element).unwrap_or_else(|| expr.clone())
        }
        ExprKind::ArrayIndex { array, index } => {
            let index = Box::new(substitute_expression(index, name, literal, element));
            let mut access = expr.clone();
            access.kind = match substitute_path(array, expr, name, literal, element) {
                Some(value) => ExprKind::IndexAccess {
                    value: Box::new(value),
                    index,
                },
                None => ExprKind::ArrayIndex {
                    array: array.clone(),
                    index,
                },
            };
            access
        }
        _ => {
            let mut expression = expr.clone();
            for child in crate::models::child_exprs_mut(&mut expression) {
                *child = substitute_expression(child, name, literal, element);
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
                let replaced =
                    substitute_expression(&expression, "i", &k.to_string(), Some(("x", &items)));
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
