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

pub(crate) struct BuiltinSignature {
    pub name: &'static str,
    pub params: &'static [(&'static str, &'static str)],
}

const fn sig(
    name: &'static str,
    params: &'static [(&'static str, &'static str)],
) -> BuiltinSignature {
    BuiltinSignature { name, params }
}

pub(crate) const BUILTIN_SIGNATURES: &[BuiltinSignature] = &[
    sig(
        "substr",
        &[("data", "bytes"), ("offset", "int"), ("size", "int")],
    ),
    sig("cat", &[("left", "bytes"), ("right", "bytes")]),
    sig("bin2num", &[("data", "bytes")]),
    sig("num2bin", &[("value", "int"), ("size", "int")]),
    sig("reverseBytes", &[("data", "bytes")]),
    sig("size", &[("data", "bytes")]),
    sig("digest", &[("data", "bytes"), ("hashType", "int")]),
    sig("sha256", &[("data", "bytes")]),
    sig("sha256Initialize", &[("data", "bytes")]),
    sig(
        "sha256Update",
        &[("context", "bytes32"), ("chunk", "bytes")],
    ),
    sig(
        "sha256Finalize",
        &[("context", "bytes32"), ("lastChunk", "bytes")],
    ),
    sig("sighash", &[("hashType", "int")]),
    sig("tx.packet", &[("packetType", "int")]),
    sig(
        "tx.inputs[].packet",
        &[("index", "int"), ("packetType", "int")],
    ),
    sig("tx.inputs[]", &[("index", "int")]),
    sig("tx.outputs[]", &[("index", "int")]),
    sig(
        "modExp",
        &[("base", "int"), ("exponent", "int"), ("modulus", "int")],
    ),
    sig(
        "ecAdd",
        &[
            ("pointP", "ECPoint"),
            ("pointQ", "ECPoint"),
            ("curveId", "int"),
        ],
    ),
    sig(
        "ecMul",
        &[("point", "ECPoint"), ("scalar", "int"), ("curveId", "int")],
    ),
    sig(
        "ecPairing",
        &[("g1", "ECPoint[]"), ("g2", "G2Point[]"), ("curveId", "int")],
    ),
    // Scalars are 32-byte big-endian; P is x-only for tweakVerify and compressed otherwise.
    sig(
        "ecMulScalarVerify",
        &[
            ("scalar", "bytes32"),
            ("pointP", "bytes"),
            ("pointQ", "bytes"),
        ],
    ),
    sig(
        "tweakVerify",
        &[
            ("pointP", "bytes32"),
            ("tweak", "bytes32"),
            ("pointQ", "bytes"),
        ],
    ),
    sig("assetGroups[].sum", &[("index", "int")]),
    sig("assetGroups[].numIO", &[("index", "int")]),
    sig(
        "assetGroups[].io",
        &[("groupIndex", "int"), ("ioIndex", "int")],
    ),
    sig("tx.inputs[].assets", &[("index", "int")]),
    sig(
        "tx.inputs[].assets[]",
        &[("ioIndex", "int"), ("assetIndex", "int")],
    ),
    sig("tx.inputs[].assets.lookup", &[("index", "int")]),
    sig("tx.inputs[].assets.has", &[("index", "int")]),
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
        Expression::Sha256 { data } => ("sha256", vec![data]),
        Expression::Sha256Initialize { data } => ("sha256Initialize", vec![data]),
        Expression::Sha256Update { context, chunk } => ("sha256Update", vec![context, chunk]),
        Expression::Sha256Finalize {
            context,
            last_chunk,
        } => ("sha256Finalize", vec![context, last_chunk]),
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
            point_p,
            point_q,
            curve_id,
        } => ("ecAdd", vec![point_p, point_q, curve_id]),
        Expression::EcMul {
            point,
            scalar,
            curve_id,
        } => ("ecMul", vec![point, scalar, curve_id]),
        Expression::EcPairing { g1, g2, curve_id } => ("ecPairing", vec![g1, g2, curve_id]),
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
            for (param, declared) in signature.params {
                let element = declared.strip_suffix("[]").unwrap_or(declared);
                let known = match crate::typechecker::ArkType::parse(element) {
                    crate::typechecker::ArkType::Struct(name) => {
                        crate::models::builtin_struct_fields(&name).is_some()
                    }
                    parsed => parsed != crate::typechecker::ArkType::Unknown,
                };
                assert!(
                    known,
                    "{}: {param} has unknown type '{declared}'",
                    signature.name
                );
            }
        }
    }
}
