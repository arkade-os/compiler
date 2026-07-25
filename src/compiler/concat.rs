use crate::models::*;
use crate::typechecker::ArkType;

// ─── Concat rewrite pass ────────────────────────────────────────────────────
//
// Walk every function's AST and convert `BinaryOp { op: "+" }` into
// `Concat { ... }` when at least one operand resolves to a bytes-like type
// (Bytes, Bytes20, Bytes32). Pure int+int additions stay as `BinaryOp` and
// continue to emit OP_ADD64.
//
// We need types to make the decision, so the walk threads a `Scope` and
// uses `typechecker::infer_type` on rewritten subtrees. The rewrite is
// bottom-up: children are rewritten first so the parent sees the post-
// rewrite type (e.g. `bytes32 + int` rewrites to `Concat` of type Bytes,
// which then makes the outer `+ int` also a Concat).

use crate::typechecker::{is_bytes_like, needs_scriptnum_to_le64, Scope};

pub(crate) fn rewrite_concat_ops(contract: &mut crate::models::Contract) {
    let constructor_scope = crate::typechecker::build_scope(&contract.parameters);
    for function in &mut contract.functions {
        let mut scope = constructor_scope.clone();
        scope.extend(crate::typechecker::build_scope(&function.parameters));
        rewrite_statements_concat(&mut function.statements, &mut scope);
    }
}

pub(crate) fn rewrite_statements_concat(stmts: &mut [Statement], scope: &mut Scope) {
    for stmt in stmts {
        rewrite_statement_concat(stmt, scope);
    }
}

pub(crate) fn rewrite_statement_concat(stmt: &mut Statement, scope: &mut Scope) {
    match stmt {
        Statement::Require(req) => rewrite_requirement_concat(req, scope),
        Statement::LetBinding { name, value } => {
            let (new_expr, t) = rewrite_expression_concat(
                std::mem::replace(value, Expression::Literal(String::new())),
                scope,
            );
            *value = new_expr;
            scope.insert(name.clone(), t);
        }
        Statement::VarAssign { name, value } => {
            let (new_expr, t) = rewrite_expression_concat(
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
            let (new_cond, _) = rewrite_expression_concat(
                std::mem::replace(condition, Expression::Literal(String::new())),
                scope,
            );
            *condition = new_cond;
            let mut then_scope = scope.clone();
            rewrite_statements_concat(then_body, &mut then_scope);
            if let Some(eb) = else_body {
                let mut else_scope = scope.clone();
                rewrite_statements_concat(eb, &mut else_scope);
            }
        }
        Statement::ForIn {
            index_var,
            value_var,
            iterable,
            body,
        } => {
            let (new_iter, _) = rewrite_expression_concat(
                std::mem::replace(iterable, Expression::Literal(String::new())),
                scope,
            );
            *iterable = new_iter;
            let mut loop_scope = scope.clone();
            loop_scope.insert(index_var.clone(), ArkType::Int);
            loop_scope.insert(value_var.clone(), ArkType::Unknown);
            rewrite_statements_concat(body, &mut loop_scope);
        }
    }
}

pub(crate) fn rewrite_requirement_concat(req: &mut Requirement, scope: &Scope) {
    if let Requirement::Comparison { left, right, .. } = req {
        let (nl, _) = rewrite_expression_concat(
            std::mem::replace(left, Expression::Literal(String::new())),
            scope,
        );
        *left = nl;
        let (nr, _) = rewrite_expression_concat(
            std::mem::replace(right, Expression::Literal(String::new())),
            scope,
        );
        *right = nr;
    }
}

pub(crate) fn rewrite_expression_concat(expr: Expression, scope: &Scope) -> (Expression, ArkType) {
    match expr {
        Expression::BinaryOp { left, op, right } => {
            let (new_l, lt) = rewrite_expression_concat(*left, scope);
            let (new_r, rt) = rewrite_expression_concat(*right, scope);
            if op == "+" && (is_bytes_like(&lt) || is_bytes_like(&rt)) {
                let coerce_left = needs_scriptnum_to_le64(&lt);
                let coerce_right = needs_scriptnum_to_le64(&rt);
                (
                    Expression::Concat {
                        left: Box::new(new_l),
                        right: Box::new(new_r),
                        coerce_left,
                        coerce_right,
                    },
                    ArkType::Bytes,
                )
            } else {
                let result_type = match op.as_str() {
                    "+" | "-" | "*" | "/" => {
                        if lt == ArkType::Uint64Le || rt == ArkType::Uint64Le {
                            ArkType::Uint64Le
                        } else {
                            ArkType::Int
                        }
                    }
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
            let (new_data, _) = rewrite_expression_concat(*data, scope);
            (
                Expression::Sha256 {
                    data: Box::new(new_data),
                },
                ArkType::Bytes32,
            )
        }
        Expression::Hash256 { data } => {
            // Recurse so a merkle step `hash256(node + sibling)` lowers its
            // inner `+` to an OP_CAT concat rather than arithmetic.
            let (new_data, _) = rewrite_expression_concat(*data, scope);
            (
                Expression::Hash256 {
                    data: Box::new(new_data),
                },
                ArkType::Bytes32,
            )
        }
        Expression::ReverseBytes { data } => {
            let (new_data, _) = rewrite_expression_concat(*data, scope);
            (
                Expression::ReverseBytes {
                    data: Box::new(new_data),
                },
                ArkType::Bytes,
            )
        }
        Expression::Sha256Initialize { data } => {
            let (new_data, _) = rewrite_expression_concat(*data, scope);
            (
                Expression::Sha256Initialize {
                    data: Box::new(new_data),
                },
                ArkType::Bytes32,
            )
        }
        Expression::Sha256Update { context, chunk } => {
            let (new_ctx, _) = rewrite_expression_concat(*context, scope);
            let (new_chunk, _) = rewrite_expression_concat(*chunk, scope);
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
            let (new_ctx, _) = rewrite_expression_concat(*context, scope);
            let (new_chunk, _) = rewrite_expression_concat(*last_chunk, scope);
            (
                Expression::Sha256Finalize {
                    context: Box::new(new_ctx),
                    last_chunk: Box::new(new_chunk),
                },
                ArkType::Bytes32,
            )
        }
        Expression::Concat {
            left,
            right,
            coerce_left,
            coerce_right,
        } => {
            let (new_l, _) = rewrite_expression_concat(*left, scope);
            let (new_r, _) = rewrite_expression_concat(*right, scope);
            (
                Expression::Concat {
                    left: Box::new(new_l),
                    right: Box::new(new_r),
                    coerce_left,
                    coerce_right,
                },
                ArkType::Bytes,
            )
        }
        Expression::Neg64 { value } => {
            let (nv, _) = rewrite_expression_concat(*value, scope);
            (
                Expression::Neg64 {
                    value: Box::new(nv),
                },
                ArkType::Uint64Le,
            )
        }
        Expression::Le64ToScriptNum { value } => {
            let (nv, _) = rewrite_expression_concat(*value, scope);
            (
                Expression::Le64ToScriptNum {
                    value: Box::new(nv),
                },
                ArkType::Int,
            )
        }
        Expression::Le32ToLe64 { value } => {
            let (nv, _) = rewrite_expression_concat(*value, scope);
            (
                Expression::Le32ToLe64 {
                    value: Box::new(nv),
                },
                ArkType::Uint64Le,
            )
        }
        Expression::ContractInstance {
            contract_name,
            args,
        } => {
            let new_args = args
                .into_iter()
                .map(|a| rewrite_expression_concat(a, scope).0)
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
