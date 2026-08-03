use crate::models::*;
use crate::typechecker::ArkType;

// ─── Concat rewrite pass ────────────────────────────────────────────────────
//
// Walk every function's AST and convert `BinaryOp { op: "+" }` into
// `Concat { ... }` when at least one operand resolves to a bytes-like type
// (Bytes, Bytes20, Bytes32). Pure int+int additions stay as `BinaryOp` and
// continue to emit OP_ADD.
//
// We need types to make the decision, so the walk threads a `Scope` and
// uses `typechecker::infer_type` on rewritten subtrees. The rewrite is
// bottom-up: children are rewritten first so the parent sees the post-
// rewrite type (e.g. `bytes32 + int` rewrites to `Concat` of type Bytes,
// which then makes the outer `+ int` also a Concat).

use crate::typechecker::{is_bytes_like, Scope};

/// Numeric types that have no byte representation of their own, so mixing one
/// into a concatenation needs an explicit `num2bin(value, width)`.
fn is_numeric(t: &ArkType) -> bool {
    matches!(t, ArkType::Int | ArkType::Bool)
}

#[derive(Default)]
struct ConcatPass {
    errors: Vec<String>,
}

pub(crate) fn rewrite_concat_ops(contract: &mut crate::models::Contract) -> Result<(), String> {
    let mut pass = ConcatPass::default();
    let constructor_scope = crate::typechecker::build_scope(&contract.parameters);
    for function in &mut contract.functions {
        let mut scope = constructor_scope.clone();
        scope.extend(crate::typechecker::build_scope(&function.parameters));
        pass.rewrite_statements_concat(&mut function.statements, &mut scope);
    }
    if pass.errors.is_empty() {
        Ok(())
    } else {
        Err(pass.errors.join("; "))
    }
}

impl ConcatPass {
    fn rewrite_statements_concat(&mut self, stmts: &mut [Statement], scope: &mut Scope) {
        for stmt in stmts {
            self.rewrite_statement_concat(stmt, scope);
        }
    }

    fn rewrite_statement_concat(&mut self, stmt: &mut Statement, scope: &mut Scope) {
        match stmt {
            Statement::Require(req) => self.rewrite_requirement_concat(req, scope),
            Statement::LetBinding {
                name,
                declared_type,
                value,
            } => {
                let (new_expr, t) = self.rewrite_expression_concat(
                    std::mem::replace(value, Expression::Literal(String::new())),
                    scope,
                );
                *value = new_expr;
                scope.insert(
                    name.clone(),
                    declared_type.as_deref().map(ArkType::parse).unwrap_or(t),
                );
            }
            Statement::VarAssign { name, value } => {
                let (new_expr, t) = self.rewrite_expression_concat(
                    std::mem::replace(value, Expression::Literal(String::new())),
                    scope,
                );
                *value = new_expr;
                scope.insert(name.clone(), t);
            }
            Statement::IfElse {
                condition,
                then_body,
                else_body,
            } => {
                let (new_cond, _) = self.rewrite_expression_concat(
                    std::mem::replace(condition, Expression::Literal(String::new())),
                    scope,
                );
                *condition = new_cond;
                let mut then_scope = scope.clone();
                self.rewrite_statements_concat(then_body, &mut then_scope);
                if let Some(eb) = else_body {
                    let mut else_scope = scope.clone();
                    self.rewrite_statements_concat(eb, &mut else_scope);
                }
            }
            Statement::ForIn {
                index_var,
                value_var,
                iterable,
                body,
            } => {
                let (new_iter, iter_type) = self.rewrite_expression_concat(
                    std::mem::replace(iterable, Expression::Literal(String::new())),
                    scope,
                );
                *iterable = new_iter;
                let mut loop_scope = scope.clone();
                loop_scope.insert(index_var.clone(), ArkType::Int);
                // The element type decides whether concatenating the loop value
                // needs an explicit num2bin, so carry it rather than Unknown.
                let element_type = match iter_type {
                    ArkType::Array(inner) => *inner,
                    _ => ArkType::Unknown,
                };
                loop_scope.insert(value_var.clone(), element_type);
                self.rewrite_statements_concat(body, &mut loop_scope);
            }
        }
    }

    fn rewrite_requirement_concat(&mut self, req: &mut Requirement, scope: &Scope) {
        match req {
            Requirement::Expression(expr) => {
                let (rewritten, _) = self.rewrite_expression_concat(
                    std::mem::replace(expr, Expression::Literal(String::new())),
                    scope,
                );
                *expr = rewritten;
            }
            Requirement::Comparison { left, right, .. } => {
                let (nl, _) = self.rewrite_expression_concat(
                    std::mem::replace(left, Expression::Literal(String::new())),
                    scope,
                );
                *left = nl;
                let (nr, _) = self.rewrite_expression_concat(
                    std::mem::replace(right, Expression::Literal(String::new())),
                    scope,
                );
                *right = nr;
            }
            _ => {}
        }
    }

    fn rewrite_expression_concat(
        &mut self,
        expr: Expression,
        scope: &Scope,
    ) -> (Expression, ArkType) {
        match expr {
            Expression::ArrayIndex { array, index } => {
                let (index, _) = self.rewrite_expression_concat(*index, scope);
                let result_type = match scope.get(&array) {
                    Some(ArkType::Array(element)) => (**element).clone(),
                    _ => ArkType::Unknown,
                };
                (
                    Expression::ArrayIndex {
                        array,
                        index: Box::new(index),
                    },
                    result_type,
                )
            }
            Expression::BinaryOp { left, op, right } => {
                let (new_l, lt) = self.rewrite_expression_concat(*left, scope);
                let (new_r, rt) = self.rewrite_expression_concat(*right, scope);
                if op == "+" && (is_bytes_like(&lt) || is_bytes_like(&rt)) {
                    for (side, t) in [("left", &lt), ("right", &rt)] {
                        if is_numeric(t) {
                            self.errors.push(format!(
                                "cannot concatenate bytes with the {} `{}` operand of `+`; \
                                 convert it explicitly with num2bin(value, width) — \
                                 the compiler will not choose a width for you",
                                side,
                                t.as_str()
                            ));
                        }
                    }
                    (
                        Expression::Concat {
                            left: Box::new(new_l),
                            right: Box::new(new_r),
                        },
                        ArkType::Bytes,
                    )
                } else {
                    let result_type = match op.as_str() {
                        "+" | "-" | "*" | "/" => ArkType::Int,
                        "==" | "!=" | ">=" | "<=" | ">" | "<" => ArkType::Bool,
                        _ => ArkType::Unknown,
                    };
                    (
                        Expression::BinaryOp {
                            left: Box::new(new_l),
                            op,
                            right: Box::new(new_r),
                        },
                        result_type,
                    )
                }
            }
            Expression::Sha256 { data } => {
                let (new_data, _) = self.rewrite_expression_concat(*data, scope);
                (
                    Expression::Sha256 {
                        data: Box::new(new_data),
                    },
                    ArkType::Bytes32,
                )
            }
            Expression::Sha256Initialize { data } => {
                let (new_data, _) = self.rewrite_expression_concat(*data, scope);
                (
                    Expression::Sha256Initialize {
                        data: Box::new(new_data),
                    },
                    ArkType::Bytes32,
                )
            }
            Expression::Sha256Update { context, chunk } => {
                let (new_ctx, _) = self.rewrite_expression_concat(*context, scope);
                let (new_chunk, _) = self.rewrite_expression_concat(*chunk, scope);
                (
                    Expression::Sha256Update {
                        context: Box::new(new_ctx),
                        chunk: Box::new(new_chunk),
                    },
                    ArkType::Bytes32,
                )
            }
            Expression::Sha256Finalize {
                context,
                last_chunk,
            } => {
                let (new_ctx, _) = self.rewrite_expression_concat(*context, scope);
                let (new_chunk, _) = self.rewrite_expression_concat(*last_chunk, scope);
                (
                    Expression::Sha256Finalize {
                        context: Box::new(new_ctx),
                        last_chunk: Box::new(new_chunk),
                    },
                    ArkType::Bytes32,
                )
            }
            Expression::Concat { left, right } => {
                let (new_l, _) = self.rewrite_expression_concat(*left, scope);
                let (new_r, _) = self.rewrite_expression_concat(*right, scope);
                (
                    Expression::Concat {
                        left: Box::new(new_l),
                        right: Box::new(new_r),
                    },
                    ArkType::Bytes,
                )
            }
            // `data` is parsed as an additive expression, same as Sha256, so a
            // `+` underneath it still has to be rewritten into a Concat.
            Expression::Digest { data, hash_type } => {
                let (new_data, _) = self.rewrite_expression_concat(*data, scope);
                (
                    Expression::Digest {
                        data: Box::new(new_data),
                        hash_type,
                    },
                    ArkType::Bytes,
                )
            }
            Expression::Negate { value } => {
                let (nv, _) = self.rewrite_expression_concat(*value, scope);
                (
                    Expression::Negate {
                        value: Box::new(nv),
                    },
                    ArkType::Int,
                )
            }
            Expression::ContractInstance {
                contract_name,
                args,
            } => {
                let new_args = args
                    .into_iter()
                    .map(|a| self.rewrite_expression_concat(a, scope).0)
                    .collect();
                (
                    Expression::ContractInstance {
                        contract_name,
                        args: new_args,
                    },
                    ArkType::Bytes,
                )
            }
            // Leaves and other compound expressions: no `+` to rewrite below the surface.
            other => {
                let t = crate::typechecker::infer_type(&other, scope);
                (other, t)
            }
        }
    }
}
