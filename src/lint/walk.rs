//! The one traversal every lint uses: each statement, then the expressions it evaluates (a
//! parent before its children), optionally into the helpers a function calls.

use crate::models::{child_exprs, Contract, ExprKind, Expression, LocatedStatement, Statement};

/// What a lint sees during a [`Walk`].
pub(super) trait Visitor<'a> {
    fn statement(&mut self, _statement: &'a LocatedStatement) {}
    fn expression(&mut self, _expression: &'a Expression) {}
    /// After the expression's children, including any helper it calls.
    fn leave_expression(&mut self, _expression: &'a Expression) {}
    /// Around the statements `body` of the `then` or else arm of the `if` numbered `id` in the
    /// walk; an absent `else` is an empty `body`.
    fn enter_arm(&mut self, _id: usize, _then: bool, _body: &'a [LocatedStatement]) {}
    fn exit_arm(&mut self) {}
    /// Around the body of an imported helper, whose spans index another file, entered from
    /// the call at `call` in the walked file.
    fn enter_import(&mut self, _call: crate::diagnostics::Span) {}
    fn exit_import(&mut self) {}
}

#[derive(Default)]
pub(super) struct Walk<'a> {
    /// The contract whose helpers a call is followed into, at every call, so each call's
    /// facts belong to the arm it sits in. Validation rejects recursive calls.
    helpers: Option<&'a Contract>,
    ifs: usize,
}

impl<'a> Walk<'a> {
    /// A walk that follows calls into `contract`'s helpers.
    pub(super) fn into_helpers(contract: &'a Contract) -> Self {
        Walk {
            helpers: Some(contract),
            ..Walk::default()
        }
    }

    pub(super) fn statements(
        &mut self,
        statements: &'a [LocatedStatement],
        visitor: &mut impl Visitor<'a>,
    ) {
        for statement in statements {
            visitor.statement(statement);
            for value in statement.statement.expressions() {
                self.expression(value, visitor);
            }
            match &statement.statement {
                Statement::IfElse {
                    then_body,
                    else_body,
                    ..
                } => {
                    let id = self.ifs;
                    self.ifs += 1;
                    visitor.enter_arm(id, true, then_body);
                    self.statements(then_body, visitor);
                    visitor.exit_arm();
                    let else_body = else_body.as_deref().unwrap_or_default();
                    visitor.enter_arm(id, false, else_body);
                    self.statements(else_body, visitor);
                    visitor.exit_arm();
                }
                Statement::ForIn { body, .. } | Statement::ForCount { body, .. } => {
                    self.statements(body, visitor)
                }
                _ => {}
            }
        }
    }

    fn expression(&mut self, expression: &'a Expression, visitor: &mut impl Visitor<'a>) {
        visitor.expression(expression);
        if let (Some(contract), ExprKind::Call { name, .. }) = (self.helpers, &expression.kind) {
            if let Some(helper) = contract.functions.iter().find(|f| f.name == *name) {
                if helper.is_imported() {
                    visitor.enter_import(expression.span);
                }
                self.statements(&helper.statements, visitor);
                if helper.is_imported() {
                    visitor.exit_import();
                }
            }
        }
        for child in child_exprs(expression) {
            self.expression(child, visitor);
        }
        visitor.leave_expression(expression);
    }
}
