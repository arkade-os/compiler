//! Signature table for builtins whose arguments are a fixed, positional list
//! of expected types. One entry per builtin, name and expected types
//! declared once; [`operands`] extracts the matching argument expressions
//! from the AST in the same order, so a caller only has to zip the two and
//! compare — the alternative to declaring "digest expects (bytes, int)"
//! again at every checking site.
//!
//! Parameter types use source syntax and parse with [`super::ArkType::parse`].
//! `T[]` is an array of `T` whose length is taken from the first `[]`
//! operand, so every `[]` operand of a call must have the same length.
//!
//! Builtins whose check isn't a fixed positional-type comparison (`cast`,
//! `checkTime`, `tunnel`, `checkSig`, ...) aren't here; they keep their own
//! hand-written check in the validator.

use crate::models::Expression;

pub(crate) const BUILTIN_SIGNATURES: &[(&str, &[&str])] = &[
    ("tx.packet", &["int"]),
    ("tx.inputs[].packet", &["int", "int"]),
    ("tx.inputs[]", &["int"]),
    ("tx.outputs[]", &["int"]),
    ("assetGroups[].sum", &["int"]),
    ("assetGroups[].numIO", &["int"]),
    ("assetGroups[].io", &["int", "int"]),
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
    Some(match expr {
        Expression::Builtin { builtin, args } => (builtin.name, args.iter().collect()),
        Expression::PacketInspect { packet_type } => ("tx.packet", vec![packet_type]),
        Expression::InputPacketInspect { index, packet_type } => {
            ("tx.inputs[].packet", vec![index, packet_type])
        }
        Expression::InputIntrospection { index, .. } => ("tx.inputs[]", vec![index]),
        Expression::OutputIntrospection { index, .. } => ("tx.outputs[]", vec![index]),
        Expression::GroupSum { index, .. } => ("assetGroups[].sum", vec![index]),
        Expression::GroupNumIO { index, .. } => ("assetGroups[].numIO", vec![index]),
        Expression::GroupIOAccess {
            group_index,
            io_index,
            ..
        } => ("assetGroups[].io", vec![group_index, io_index]),
        Expression::AssetCount { index, .. } => ("tx.inputs[].assets", vec![index]),
        Expression::AssetAt {
            io_index,
            asset_index,
            ..
        } => ("tx.inputs[].assets[]", vec![io_index, asset_index]),
        Expression::AssetLookup { index, .. } => ("tx.inputs[].assets.lookup", vec![index]),
        Expression::AssetHas { index, .. } => ("tx.inputs[].assets.has", vec![index]),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::typechecker::ArkType;

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
