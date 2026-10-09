//! Signature table for builtins whose arguments are a fixed, positional list
//! of expected types. One entry per builtin, name and expected types
//! declared once; [`operands`] extracts the matching argument expressions
//! from the AST in the same order, so a caller only has to zip the two and
//! compare — the alternative to declaring "digest expects (bytes, int)"
//! again at every checking site.
//!
//! Parameter types use source syntax and parse with [`crate::types::ArkType::parse`].
//! `T[]` is an array of `T` whose length is taken from the first `[]`
//! operand, so every `[]` operand of a call must have the same length.
//!
//! Builtins whose check isn't a fixed positional-type comparison (`cast`,
//! `tunnel`, `checkSig`, ...) aren't here; they keep their own hand-written
//! check in the validator.

use crate::models::{ExprKind, Expression};

pub(crate) const BUILTIN_SIGNATURES: &[(&str, &[&str])] = &[
    ("tx.packet", &["int"]),
    ("tx.inputs[].packet", &["int", "int"]),
    ("tx.inputs[]", &["int"]),
    ("tx.outputs[]", &["int"]),
    ("tx.assetGroups[]", &["int"]),
    ("asset group property", &["AssetGroup"]),
    ("controlIs", &["AssetGroup"]),
    ("asset group inputs/outputs", &["AssetGroup", "int"]),
    ("tx.inputs[].assets", &["int"]),
    ("tx.inputs[].assets[]", &["int", "int"]),
    ("tx.inputs[].assets.lookup", &["int"]),
    ("tx.inputs[].assets.has", &["int"]),
];

pub(crate) fn find(name: &str) -> Option<Vec<&'static str>> {
    if let Some(builtin) = crate::builtins::find(name) {
        return Some(builtin.params.iter().map(|(_, ty)| *ty).collect());
    }
    BUILTIN_SIGNATURES
        .iter()
        .find(|(builtin, _)| *builtin == name)
        .map(|(_, params)| params.to_vec())
}

/// If `expr` is a registered builtin, its name and argument expressions in
/// the same order as [`find`]'s signature. Purely structural: which field
/// belongs to which builtin, no type information — the table is the only
/// place expected types live.
pub(crate) fn operands(expr: &Expression) -> Option<(&'static str, Vec<&Expression>)> {
    Some(match &expr.kind {
        ExprKind::Builtin { builtin, args } => (builtin.name, args.iter().collect()),
        ExprKind::PacketInspect { packet_type, .. } => ("tx.packet", vec![packet_type]),
        ExprKind::InputPacketInspect {
            index, packet_type, ..
        } => ("tx.inputs[].packet", vec![index, packet_type]),
        ExprKind::InputIntrospection { index, .. } => ("tx.inputs[]", vec![index]),
        ExprKind::OutputIntrospection { index, .. } => ("tx.outputs[]", vec![index]),
        ExprKind::AssetGroupAt { index } => ("tx.assetGroups[]", vec![index]),
        ExprKind::GroupProperty { group, .. } => ("asset group property", vec![group]),
        ExprKind::GroupControlIs { group, .. } => ("controlIs", vec![group]),
        ExprKind::GroupIOAccess {
            group, io_index, ..
        } => ("asset group inputs/outputs", vec![group, io_index]),
        ExprKind::AssetCount { index, .. } => ("tx.inputs[].assets", vec![index]),
        ExprKind::AssetAt {
            io_index,
            asset_index,
            ..
        } => ("tx.inputs[].assets[]", vec![io_index, asset_index]),
        ExprKind::AssetLookup { index, .. } => ("tx.inputs[].assets.lookup", vec![index]),
        ExprKind::AssetHas { index, .. } => ("tx.inputs[].assets.has", vec![index]),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ArkType;

    #[test]
    fn every_signature_is_unique_with_known_types() {
        let mut names: Vec<&str> = BUILTIN_SIGNATURES.iter().map(|(name, _)| *name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            BUILTIN_SIGNATURES.len(),
            "duplicate builtin name in the registry"
        );
        for (name, params) in BUILTIN_SIGNATURES {
            for declared in *params {
                let element = declared.strip_suffix("[]").unwrap_or(declared);
                let known = match ArkType::parse(element) {
                    ArkType::Struct(name) => crate::models::builtin_struct_fields(&name).is_some(),
                    parsed => parsed != ArkType::Unknown,
                };
                assert!(known, "{name}: unknown type '{declared}'");
            }
        }
    }
}
