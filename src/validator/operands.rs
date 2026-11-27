//! Positional parameter types of builtins and the VM's accepted values for constant operands.
//! Types use source syntax; `T[]` is an array of `T` whose length every `[]` operand of a call
//! shares. Builtins with a non-positional check (`cast`, `tunnel`) are validated by hand.

use crate::builtins;
use crate::models::{ExprKind, Expression};

pub(crate) const BUILTIN_SIGNATURES: &[(&str, &[&str])] = &[
    ("tx.packet", &["int"]),
    ("tx.proof", &["bytes"]),
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
    ("tx.inputs[].assets.tryLookup", &["int"]),
];

/// Builtin, operand index, operand name, and the inclusive ranges the VM accepts.
type Domain = (&'static str, usize, &'static str, &'static [(i128, i128)]);

/// The values the VM accepts for an operand, checked when the operand is a constant.
pub(crate) const CONSTANT_DOMAINS: &[Domain] = &[
    ("digest", 1, "hashType", &[(1, 5)]),
    ("sighash", 0, "hashType", &[(0, 3), (0x81, 0x83)]),
    ("ecAdd", 2, "curveId", &[(0, 2)]),
    ("ecMul", 2, "curveId", &[(0, 2)]),
    ("ecPairing", 2, "curveId", &[(2, 2)]),
    ("int2bytes", 1, "size", &[(0, 520)]),
    ("checkTime", 0, "timestamp", &[(0, i128::MAX)]),
    ("modExp", 1, "exponent", &[(0, i128::MAX)]),
    ("modExp", 2, "modulus", &[(1, i128::MAX)]),
    ("tx.packet", 0, "packet type", &[(0, 255)]),
    ("tx.inputs[].packet", 1, "packet type", &[(0, 255)]),
];

pub(crate) fn find(name: &str) -> Option<Vec<&'static str>> {
    if let Some(builtin) = builtins::find(name) {
        return Some(builtin.params.iter().map(|(_, ty)| *ty).collect());
    }
    BUILTIN_SIGNATURES
        .iter()
        .find(|(builtin, _)| *builtin == name)
        .map(|(_, params)| params.to_vec())
}

/// `expr`'s builtin name and argument expressions, in the order of [`find`]'s signature.
pub(crate) fn operands(expr: &Expression) -> Option<(&'static str, Vec<&Expression>)> {
    Some(match &expr.kind {
        ExprKind::Builtin { builtin, args } => (builtin.name, args.iter().collect()),
        ExprKind::PacketInspect { packet_type, .. } => ("tx.packet", vec![packet_type]),
        ExprKind::IntentInspect { path, .. } => ("tx.proof", vec![path]),
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
        ExprKind::AssetTryLookup { index, .. } => ("tx.inputs[].assets.tryLookup", vec![index]),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models;
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
                    ArkType::Struct(name) => models::builtin_struct_fields(&name).is_some(),
                    parsed => parsed != ArkType::Unknown,
                };
                assert!(known, "{name}: unknown type '{declared}'");
            }
        }
    }
}
