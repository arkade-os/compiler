use super::*;

/// Reject malformed canonical Asset ID operands at compile time instead of
/// relying on the emulator's runtime `popAssetID` check: every
/// `lookup`/`has`/`tryLookup`/`controlIs` operand must be an `AssetId`, and the
/// gidx of an `AssetId` literal there or anywhere else must be in `0..=65535`
/// when it is a constant.
pub(super) fn check_asset_id_operands(contract: &Contract, issues: &mut Vec<ValidationIssue>) {
    for func in contract.functions.iter().filter(|f| !f.is_imported()) {
        walk_asset_id_stmts(&func.statements, &contract.structs, issues);
    }
}

fn walk_asset_id_stmts(
    stmts: &[LocatedStatement],
    structs: &[crate::models::StructDefinition],
    issues: &mut Vec<ValidationIssue>,
) {
    for stmt in stmts {
        let first = issues.len();
        match &stmt.statement {
            Statement::Call(expression)
            | Statement::Return(Some(expression))
            | Statement::LetBinding {
                value: expression, ..
            }
            | Statement::Require(Requirement::Expression(expression)) => {
                check_asset_id_expr(expression, structs, issues)
            }
            Statement::Require(Requirement::Comparison { left, right, .. }) => {
                check_asset_id_expr(left, structs, issues);
                check_asset_id_expr(right, structs, issues);
            }
            Statement::Return(None) | Statement::Declaration { .. } => {}
            Statement::VarAssign { target, value } => {
                if let AssignmentTarget::ArrayIndex { index, .. }
                | AssignmentTarget::Access(index) = target
                {
                    check_asset_id_expr(index, structs, issues);
                }
                check_asset_id_expr(value, structs, issues);
            }
            Statement::IfElse {
                condition,
                then_body,
                else_body,
            } => {
                check_asset_id_expr(condition, structs, issues);
                walk_asset_id_stmts(then_body, structs, issues);
                if let Some(eb) = else_body {
                    walk_asset_id_stmts(eb, structs, issues);
                }
            }
            Statement::ForIn { iterable, body, .. } => {
                check_asset_id_expr(iterable, structs, issues);
                walk_asset_id_stmts(body, structs, issues);
            }
            Statement::ForCount { count, body } => {
                check_asset_id_expr(count, structs, issues);
                walk_asset_id_stmts(body, structs, issues);
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
fn check_asset_id_expr(
    expr: &Expression,
    structs: &[crate::models::StructDefinition],
    issues: &mut Vec<ValidationIssue>,
) {
    match &expr.kind {
        ExprKind::AssetLookup { asset_id, .. }
        | ExprKind::AssetHas { asset_id, .. }
        | ExprKind::AssetTryLookup { asset_id, .. }
        | ExprKind::GroupLookup { asset_id }
        | ExprKind::GroupHas { asset_id }
        | ExprKind::GroupControlIs { asset_id, .. } => {
            let asset = crate::models::TypeName::Named("AssetId".to_string());
            super::functions::validate_value(&asset, asset_id, structs, "asset id", issues);
            // A named literal's gidx is checked where the literal itself is visited.
            if matches!(&asset_id.kind, ExprKind::StructLiteral { name: None, .. }) {
                validate_gidx(asset_id, issues);
            }
        }
        ExprKind::StructLiteral {
            name: Some(name), ..
        } if name == "AssetId" => validate_gidx(expr, issues),
        _ => {}
    }

    for child in child_exprs(expr) {
        check_asset_id_expr(child, structs, issues);
    }
}

/// A constant gidx field of an `AssetId` literal must be in range.
fn validate_gidx(literal: &Expression, issues: &mut Vec<ValidationIssue>) {
    let ExprKind::StructLiteral { fields, .. } = &literal.kind else {
        return;
    };
    let Some((_, gidx)) = fields.iter().find(|(name, _)| name == "gidx") else {
        return;
    };
    if gidx.ty != ArkType::Int || !is_constant(gidx) {
        return;
    }
    match crate::compiler::constants::evaluate(gidx, &mut |path| Err(path.key())) {
        Ok(v) if v.parse::<u16>().is_ok() => {}
        Ok(v) => issues.push(
            ValidationIssue::error(format!("asset id gidx {v} is out of range 0..65535"))
                .at(gidx.span),
        ),
        Err(error) => issues.push(
            ValidationIssue::error(format!("asset id gidx '{}': {}", gidx.source_text(), error))
                .at(gidx.span),
        ),
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
