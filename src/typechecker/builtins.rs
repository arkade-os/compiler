//! Signature table for builtins whose arguments are a fixed, positional list
//! of expected types. One entry per builtin, name and expected types
//! declared once; [`operands`] extracts the matching argument expressions
//! from the AST in the same order, so a caller only has to zip the two and
//! compare — the alternative to declaring "digest expects (bytes, int)"
//! again at every checking site.
//!
//! Builtins whose check isn't a fixed positional-type comparison (`cast`,
//! `checkTime`, `tunnel`, `checkSig`, ...) aren't here; they keep their own
//! hand-written check.

use super::ArkType;
use crate::models::Expression;

pub(crate) struct BuiltinSignature {
    pub name: &'static str,
    pub params: &'static [(&'static str, ArkType)],
}

const fn sig(name: &'static str, params: &'static [(&'static str, ArkType)]) -> BuiltinSignature {
    BuiltinSignature { name, params }
}

pub(crate) const BUILTIN_SIGNATURES: &[BuiltinSignature] = &[
    sig(
        "substr",
        &[
            ("data", ArkType::Bytes),
            ("offset", ArkType::Int),
            ("size", ArkType::Int),
        ],
    ),
    sig(
        "cat",
        &[("left", ArkType::Bytes), ("right", ArkType::Bytes)],
    ),
    sig("bin2num", &[("data", ArkType::Bytes)]),
    sig(
        "num2bin",
        &[("value", ArkType::Int), ("size", ArkType::Int)],
    ),
    sig("reverseBytes", &[("data", ArkType::Bytes)]),
    sig("size", &[("data", ArkType::Bytes)]),
    sig(
        "digest",
        &[("data", ArkType::Bytes), ("hashType", ArkType::Int)],
    ),
    sig("sighash", &[("hashType", ArkType::Int)]),
    sig("tx.packet", &[("packetType", ArkType::Int)]),
    sig(
        "tx.inputs[].packet",
        &[("index", ArkType::Int), ("packetType", ArkType::Int)],
    ),
    sig("tx.inputs[]", &[("index", ArkType::Int)]),
    sig("tx.outputs[]", &[("index", ArkType::Int)]),
    sig(
        "modExp",
        &[
            ("base", ArkType::Int),
            ("exponent", ArkType::Int),
            ("modulus", ArkType::Int),
        ],
    ),
    sig(
        "ecAdd",
        &[
            ("x1", ArkType::Int),
            ("y1", ArkType::Int),
            ("x2", ArkType::Int),
            ("y2", ArkType::Int),
            ("curveId", ArkType::Int),
        ],
    ),
    sig(
        "ecMul",
        &[
            ("x", ArkType::Int),
            ("y", ArkType::Int),
            ("scalar", ArkType::Int),
            ("curveId", ArkType::Int),
        ],
    ),
    sig(
        "ecPairing",
        &[
            ("g1X", ArkType::Int),
            ("g1Y", ArkType::Int),
            ("g2Xc1", ArkType::Int),
            ("g2Xc0", ArkType::Int),
            ("g2Yc1", ArkType::Int),
            ("g2Yc0", ArkType::Int),
            ("curveId", ArkType::Int),
        ],
    ),
    sig(
        "ecMulScalarVerify",
        &[
            ("scalar", ArkType::Bytes32),
            ("pointP", ArkType::Pubkey),
            ("pointQ", ArkType::Pubkey),
        ],
    ),
    sig(
        "tweakVerify",
        &[
            ("pointP", ArkType::Pubkey),
            ("tweak", ArkType::Bytes32),
            ("pointQ", ArkType::Pubkey),
        ],
    ),
    sig("assetGroups[].sum", &[("index", ArkType::Int)]),
    sig("assetGroups[].numIO", &[("index", ArkType::Int)]),
    sig(
        "assetGroups[].io",
        &[("groupIndex", ArkType::Int), ("ioIndex", ArkType::Int)],
    ),
    sig("tx.inputs[].assets", &[("index", ArkType::Int)]),
    sig(
        "tx.inputs[].assets[]",
        &[("ioIndex", ArkType::Int), ("assetIndex", ArkType::Int)],
    ),
    sig("tx.inputs[].assets.lookup", &[("index", ArkType::Int)]),
    sig("tx.inputs[].assets.has", &[("index", ArkType::Int)]),
];

pub(crate) fn find(name: &str) -> Option<&'static BuiltinSignature> {
    BUILTIN_SIGNATURES.iter().find(|s| s.name == name)
}

/// If `expr` is a registered builtin, its name and argument expressions in
/// the same order as [`find`]'s signature. Purely structural: which field
/// belongs to which builtin, no type information — the table is the only
/// place expected types live.
pub(crate) fn operands(expr: &Expression) -> Option<(&'static str, Vec<&Expression>)> {
    Some(match expr {
        Expression::Substr { data, offset, size } => ("substr", vec![data, offset, size]),
        Expression::Cat { left, right } => ("cat", vec![left, right]),
        Expression::Bin2Num { data } => ("bin2num", vec![data]),
        Expression::Num2Bin { value, size } => ("num2bin", vec![value, size]),
        Expression::ReverseBytes { data } => ("reverseBytes", vec![data]),
        Expression::SizeOf { data } => ("size", vec![data]),
        Expression::Digest { data, hash_type } => ("digest", vec![data, hash_type]),
        Expression::Sighash { hash_type } => ("sighash", vec![hash_type]),
        Expression::PacketInspect { packet_type } => ("tx.packet", vec![packet_type]),
        Expression::InputPacketInspect { index, packet_type } => {
            ("tx.inputs[].packet", vec![index, packet_type])
        }
        Expression::InputIntrospection { index, .. } => ("tx.inputs[]", vec![index]),
        Expression::OutputIntrospection { index, .. } => ("tx.outputs[]", vec![index]),
        Expression::ModExp {
            base,
            exponent,
            modulus,
        } => ("modExp", vec![base, exponent, modulus]),
        Expression::EcAdd {
            x1,
            y1,
            x2,
            y2,
            curve_id,
        } => ("ecAdd", vec![x1, y1, x2, y2, curve_id]),
        Expression::EcMul {
            x,
            y,
            scalar,
            curve_id,
        } => ("ecMul", vec![x, y, scalar, curve_id]),
        Expression::EcPairing {
            g1_x,
            g1_y,
            g2_x_c1,
            g2_x_c0,
            g2_y_c1,
            g2_y_c0,
            curve_id,
        } => (
            "ecPairing",
            vec![g1_x, g1_y, g2_x_c1, g2_x_c0, g2_y_c1, g2_y_c0, curve_id],
        ),
        Expression::EcMulScalarVerify {
            scalar,
            point_p,
            point_q,
        } => ("ecMulScalarVerify", vec![scalar, point_p, point_q]),
        Expression::TweakVerify {
            point_p,
            tweak,
            point_q,
        } => ("tweakVerify", vec![point_p, tweak, point_q]),
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

    #[test]
    fn every_signature_is_unique_and_non_empty() {
        let mut names: Vec<&str> = BUILTIN_SIGNATURES.iter().map(|s| s.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            BUILTIN_SIGNATURES.len(),
            "duplicate builtin name in the registry"
        );
        for signature in BUILTIN_SIGNATURES {
            assert!(
                !signature.params.is_empty(),
                "{} has no parameters",
                signature.name
            );
        }
    }
}
