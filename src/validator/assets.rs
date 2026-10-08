use super::*;

/// Reject malformed canonical Asset ID operands at compile time instead of
/// relying on the emulator's runtime `popAssetID` check. For every
/// `lookup`/`find`/`has`/`controlIs` operand:
/// - `asset_txid` must resolve to `Bytes32` (rejects `Unknown`/swapped types),
/// - `asset_gidx` must resolve to `Int` (rejects `Unknown`); a numeric literal
///   must additionally be in `0..=65535`.
///
pub(super) fn check_asset_id_operands(contract: &Contract, issues: &mut Vec<ValidationIssue>) {
    for func in contract.functions.iter().filter(|f| !f.is_imported()) {
        walk_asset_id_stmts(&func.statements, &func.name, issues);
    }
}

fn walk_asset_id_stmts(stmts: &[LocatedStatement], fname: &str, issues: &mut Vec<ValidationIssue>) {
    for stmt in stmts {
        let first = issues.len();
        match &stmt.statement {
            Statement::Call(expression)
            | Statement::Return(Some(expression))
            | Statement::LetBinding {
                value: expression, ..
            }
            | Statement::Require(Requirement::Expression(expression)) => {
                check_asset_id_expr(expression, fname, issues)
            }
            Statement::Require(Requirement::Comparison { left, right, .. }) => {
                check_asset_id_expr(left, fname, issues);
                check_asset_id_expr(right, fname, issues);
            }
            Statement::Return(None) => {}
            Statement::VarAssign { target, value } => {
                if let AssignmentTarget::ArrayIndex { index, .. }
                | AssignmentTarget::Access(index) = target
                {
                    check_asset_id_expr(index, fname, issues);
                }
                check_asset_id_expr(value, fname, issues);
            }
            Statement::IfElse {
                condition,
                then_body,
                else_body,
            } => {
                check_asset_id_expr(condition, fname, issues);
                walk_asset_id_stmts(then_body, fname, issues);
                if let Some(eb) = else_body {
                    walk_asset_id_stmts(eb, fname, issues);
                }
            }
            Statement::ForIn { iterable, body, .. } => {
                check_asset_id_expr(iterable, fname, issues);
                walk_asset_id_stmts(body, fname, issues);
            }
            Statement::ForCount { count, body } => {
                check_asset_id_expr(count, fname, issues);
                walk_asset_id_stmts(body, fname, issues);
            }
        }
        locate(&mut issues[first..], stmt.span);
    }
}

/// Walk an expression, validating the operands of every Asset ID construct and
/// recursing through every sub-expression that can nest one.
///
/// Traversal and validation are deliberately split: this function validates the
/// Asset ID operands of the constructs that carry them, then recurses into *all*
/// direct sub-expressions via [`child_exprs`]. Because `child_exprs` is an
/// exhaustive match with no wildcard, any future `Expression` variant forces a
/// decision there and can never silently bypass this validation by falling
/// through a catch-all.
fn check_asset_id_expr(expr: &Expression, fname: &str, issues: &mut Vec<ValidationIssue>) {
    // Variant-specific Asset ID operand validation.
    match &expr.kind {
        ExprKind::AssetLookup {
            asset_txid,
            asset_gidx,
            ..
        }
        | ExprKind::AssetHas {
            asset_txid,
            asset_gidx,
            ..
        }
        | ExprKind::GroupFind {
            asset_txid,
            asset_gidx,
        }
        | ExprKind::GroupHas {
            asset_txid,
            asset_gidx,
        }
        | ExprKind::GroupControlIs {
            asset_txid,
            asset_gidx,
            ..
        } => {
            validate_asset_id(asset_txid, asset_gidx, fname, issues);
        }
        _ => {}
    }

    // Generic recursion through every sub-expression.
    for child in child_exprs(expr) {
        check_asset_id_expr(child, fname, issues);
    }
}

/// Validate one `(asset_txid, asset_gidx)` pair.
fn validate_asset_id(
    asset_txid: &Expression,
    asset_gidx: &Expression,
    fname: &str,
    issues: &mut Vec<ValidationIssue>,
) {
    let txid_type = &asset_txid.ty;
    if *txid_type != ArkType::Bytes32 {
        issues.push(ValidationIssue::error(format!(
            "function '{}': asset id txid operand '{}' must be bytes32, got {}",
            fname,
            asset_txid.source_text(),
            txid_type.as_str()
        )));
    }

    // gidx must resolve to Int; a constant one must also be in range.
    let gidx_type = &asset_gidx.ty;
    if *gidx_type != ArkType::Int {
        issues.push(ValidationIssue::error(format!(
            "function '{}': asset id gidx operand '{}' must be int (0..65535), got {}",
            fname,
            asset_gidx.source_text(),
            gidx_type.as_str()
        )));
    } else if is_constant(asset_gidx) {
        let value = crate::compiler::constants::evaluate(asset_gidx, &mut |name| Err(name.into()))
            .and_then(|value| {
                value
                    .parse::<i64>()
                    .map_err(|_| format!("'{value}' is not a valid integer"))
            });
        match value {
            Ok(v) if (0..=65535).contains(&v) => {}
            Ok(v) => issues.push(ValidationIssue::error(format!(
                "function '{}': asset id gidx {} is out of range 0..65535",
                fname, v
            ))),
            Err(error) => issues.push(ValidationIssue::error(format!(
                "function '{}': asset id gidx '{}': {}",
                fname,
                asset_gidx.source_text(),
                error
            ))),
        }
    }
}

/// Built only from literals and operators; constants are folded to literals before validation.
fn is_constant(expr: &Expression) -> bool {
    match &expr.kind {
        ExprKind::Literal(_) => true,
        ExprKind::Unary { .. } | ExprKind::BinaryOp { .. } => {
            child_exprs(expr).into_iter().all(is_constant)
        }
        _ => false,
    }
}
