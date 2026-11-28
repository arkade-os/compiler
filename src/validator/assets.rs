//! Checks that every Asset ID operand (`lookup`, `has`, `tryLookup`, `controlIs`) is an `AssetId`
//! and that a literal's constant `gidx` fits in a u16.

use super::error::ValueContext;
use super::{ValidationError, ValidationIssue};
use crate::compiler::constants;
use crate::models::{
    self, AssignmentTarget, Contract, ExprKind, Expression, LocatedStatement, Statement,
    StructDefinition, TypeName,
};
use crate::types::ArkType;

/// Catches at compile time what the emulator's runtime `popAssetID` check would reject.
pub(super) fn check_asset_id_operands(contract: &Contract, issues: &mut Vec<ValidationIssue>) {
    for func in contract.functions.iter().filter(|f| !f.is_imported()) {
        walk_asset_id_stmts(&func.statements, &contract.structs, issues);
    }
}

fn walk_asset_id_stmts(
    stmts: &[LocatedStatement],
    structs: &[StructDefinition],
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
            | Statement::Require(expression) => check_asset_id_expr(expression, structs, issues),
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
            Statement::ForRange {
                start, end, body, ..
            } => {
                check_asset_id_expr(start, structs, issues);
                check_asset_id_expr(end, structs, issues);
                walk_asset_id_stmts(body, structs, issues);
            }
        }
        super::locate(&mut issues[first..], stmt.span);
    }
}

/// Recurses through [`models::child_exprs`], whose exhaustive match keeps a new variant from
/// bypassing this check.
fn check_asset_id_expr(
    expr: &Expression,
    structs: &[StructDefinition],
    issues: &mut Vec<ValidationIssue>,
) {
    match &expr.kind {
        ExprKind::AssetLookup { asset_id, .. }
        | ExprKind::AssetHas { asset_id, .. }
        | ExprKind::AssetTryLookup { asset_id, .. }
        | ExprKind::GroupLookup { asset_id }
        | ExprKind::GroupHas { asset_id }
        | ExprKind::GroupControlIs { asset_id, .. } => {
            let asset = TypeName::Named("AssetId".to_string());
            let context = ValueContext::AssetId;
            super::functions::validate_value(&asset, asset_id, structs, context, issues);
        }
        _ => {}
    }

    for child in models::child_exprs(expr) {
        check_asset_id_expr(child, structs, issues);
    }
}

/// A constant gidx field of an `AssetId` literal must be in range.
pub(super) fn validate_gidx(fields: &[(String, Expression)], issues: &mut Vec<ValidationIssue>) {
    let Some((_, gidx)) = fields.iter().find(|(name, _)| name == "gidx") else {
        return;
    };
    if gidx.ty != ArkType::Int || !is_constant(gidx) {
        return;
    }
    match constants::evaluate(gidx, &mut constants::no_names) {
        Ok(v) if v.parse::<u16>().is_ok() => {}
        Ok(value) => issues.push(ValidationError::GidxOutOfRange { value }.at(gidx.span)),
        Err(error) => {
            let text = gidx.source_text();
            issues.push(ValidationError::GidxNotConstant { text, error }.at(gidx.span))
        }
    }
}

/// Built only from literals and operators; constants are folded to literals before validation.
fn is_constant(expr: &Expression) -> bool {
    match &expr.kind {
        ExprKind::Literal(_) => true,
        ExprKind::Unary { .. } | ExprKind::BinaryOp { .. } => {
            models::child_exprs(expr).into_iter().all(is_constant)
        }
        _ => false,
    }
}
