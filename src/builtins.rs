//! Builtin functions: the language functions the compiler provides. Each entry
//! is the single description of a builtin, read by the parser, the type checks
//! and code generation.

use crate::opcodes::*;

#[derive(Debug)]
pub struct Builtin {
    pub name: &'static str,
    /// Parameter names and source types, in call order.
    pub params: &'static [(&'static str, &'static str)],
    /// None when the opcode is itself the check and leaves nothing, so the
    /// call is only valid directly inside `require`.
    pub result: Option<&'static str>,
    pub lowering: Lowering,
}

#[derive(Debug)]
pub enum Lowering {
    /// Push the arguments in call order, struct arguments field by field,
    /// then emit these opcodes.
    Opcodes(&'static [&'static str]),
    /// Push each (G1, G2) array element field by field, then the pair count
    /// and the curve.
    Pairing,
    /// Count valid signatures with CHECKSIGADD and compare with the optional threshold.
    Multisig,
}

const fn builtin(
    name: &'static str,
    params: &'static [(&'static str, &'static str)],
    result: &'static str,
    opcodes: &'static [&'static str],
) -> Builtin {
    Builtin {
        name,
        params,
        result: Some(result),
        lowering: Lowering::Opcodes(opcodes),
    }
}

const fn verify(
    name: &'static str,
    params: &'static [(&'static str, &'static str)],
    opcode: &'static [&'static str],
) -> Builtin {
    Builtin {
        name,
        params,
        result: None,
        lowering: Lowering::Opcodes(opcode),
    }
}

pub(crate) const BUILTINS: &[Builtin] = &[
    builtin(
        "substr",
        &[("data", "bytes"), ("offset", "int"), ("size", "int")],
        "bytes",
        &[OP_SUBSTR],
    ),
    builtin("cat", &[("a", "bytes"), ("b", "bytes")], "bytes", &[OP_CAT]),
    builtin("bin2num", &[("data", "bytes")], "int", &[OP_BIN2NUM]),
    builtin(
        "num2bin",
        &[("value", "int"), ("size", "int")],
        "bytes",
        &[OP_NUM2BIN],
    ),
    builtin(
        "reverseBytes",
        &[("data", "bytes")],
        "bytes",
        &[OP_REVERSEBYTES],
    ),
    builtin("size", &[("data", "bytes")], "int", &[OP_SIZE, OP_NIP]),
    builtin(
        "digest",
        &[("data", "bytes"), ("hashType", "int")],
        "bytes",
        &[OP_DIGEST],
    ),
    builtin("sha256", &[("data", "bytes")], "bytes32", &[OP_SHA256]),
    builtin("hash256", &[("data", "bytes")], "bytes32", &[OP_HASH256]),
    builtin("hash160", &[("data", "bytes")], "bytes20", &[OP_HASH160]),
    builtin(
        "ripemd160",
        &[("data", "bytes")],
        "bytes20",
        &[OP_RIPEMD160],
    ),
    builtin(
        "checkSig",
        &[("signature", "signature"), ("pubkey", "bytes")],
        "bool",
        &[OP_CHECKSIG],
    ),
    builtin(
        "checkSigFromStack",
        &[
            ("signature", "signature"),
            ("pubkey", "bytes"),
            ("message", "bytes"),
        ],
        "bool",
        &[OP_SWAP, OP_CHECKSIGFROMSTACK],
    ),
    verify(
        "checkSigFromStackVerify",
        &[
            ("signature", "signature"),
            ("pubkey", "bytes"),
            ("message", "bytes"),
        ],
        &[OP_SWAP, OP_CHECKSIGFROMSTACK, OP_VERIFY],
    ),
    Builtin {
        name: "checkMultisig",
        params: &[
            ("pubkeys", "bytes[]"),
            ("sigs", "signature[]"),
            ("threshold", "int"),
        ],
        result: Some("bool"),
        lowering: Lowering::Multisig,
    },
    builtin(
        "sha256Initialize",
        &[("data", "bytes")],
        "bytes32",
        &[OP_SHA256INITIALIZE],
    ),
    builtin(
        "sha256Update",
        &[("ctx", "bytes32"), ("chunk", "bytes")],
        "bytes32",
        &[OP_SHA256UPDATE],
    ),
    builtin(
        "sha256Finalize",
        &[("ctx", "bytes32"), ("lastChunk", "bytes")],
        "bytes32",
        &[OP_SHA256FINALIZE],
    ),
    builtin("sighash", &[("hashType", "int")], "bytes32", &[OP_SIGHASH]),
    builtin(
        "checkTime",
        &[("timestamp", "int")],
        "bool",
        &[OP_CHECKTIME],
    ),
    builtin(
        "modExp",
        &[("base", "int"), ("exponent", "int"), ("modulus", "int")],
        "int",
        &[OP_MODEXP],
    ),
    builtin(
        "ecAdd",
        &[("P", "ECPoint"), ("Q", "ECPoint"), ("curveId", "int")],
        "ECPoint",
        &[OP_ECADD],
    ),
    builtin(
        "ecMul",
        &[("P", "ECPoint"), ("scalar", "int"), ("curveId", "int")],
        "ECPoint",
        &[OP_ECMUL],
    ),
    Builtin {
        name: "ecPairing",
        params: &[
            ("g1Points", "ECPoint[]"),
            ("g2Points", "G2Point[]"),
            ("curveId", "int"),
        ],
        result: Some("bool"),
        lowering: Lowering::Pairing,
    },
    // Scalars are 32-byte big-endian; P is x-only for tweakVerify and compressed otherwise.
    verify(
        "ecMulScalarVerify",
        &[("k", "bytes32"), ("P", "bytes"), ("Q", "bytes")],
        &[OP_ECMULSCALARVERIFY],
    ),
    verify(
        "tweakVerify",
        &[("P", "bytes32"), ("k", "bytes32"), ("Q", "bytes")],
        &[OP_TWEAKVERIFY],
    ),
];

impl Builtin {
    /// Source form for diagnostics, such as `substr(data, offset, size)`.
    pub(crate) fn signature(&self) -> String {
        if matches!(self.lowering, Lowering::Multisig) {
            return "checkMultisig([pubkeys], [sigs], threshold?)".to_string();
        }
        let params: Vec<&str> = self.params.iter().map(|(name, _)| *name).collect();
        format!("{}({})", self.name, params.join(", "))
    }
}

pub(crate) fn find(name: &str) -> Option<&'static Builtin> {
    BUILTINS.iter().find(|builtin| builtin.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::typechecker::ArkType;

    #[test]
    fn every_builtin_is_unique_with_known_types() {
        for (index, builtin) in BUILTINS.iter().enumerate() {
            assert!(
                BUILTINS[..index].iter().all(|b| b.name != builtin.name),
                "duplicate builtin '{}'",
                builtin.name
            );
            let types = builtin.params.iter().map(|(_, ty)| *ty);
            for ty in types.chain(builtin.result) {
                let element = ty.strip_suffix("[]").unwrap_or(ty);
                let known = match ArkType::parse(element) {
                    ArkType::Struct(name) => crate::models::builtin_struct_fields(&name).is_some(),
                    parsed => parsed != ArkType::Unknown,
                };
                assert!(known, "{}: unknown type '{ty}'", builtin.name);
            }
            if let Lowering::Opcodes(opcodes) = builtin.lowering {
                assert!(!opcodes.is_empty(), "{} emits nothing", builtin.name);
            }
        }
    }
}
