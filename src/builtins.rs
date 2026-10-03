//! Builtin functions: the language functions the compiler provides. Each entry
//! is the single description of a builtin, read by the parser, the type checks
//! and code generation.

use crate::opcodes::*;

#[derive(Debug)]
pub struct Builtin {
    pub name: &'static str,
    /// Parameter names and source types, in call order.
    pub params: &'static [(&'static str, &'static str)],
    pub result: &'static str,
    /// Emitted after the arguments, which are pushed in call order.
    pub opcodes: &'static [&'static str],
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
        result,
        opcodes,
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
        "modExp",
        &[("base", "int"), ("exponent", "int"), ("modulus", "int")],
        "int",
        &[OP_MODEXP],
    ),
];

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
            let types = builtin.params.iter().map(|(_, ty)| ty);
            for ty in types.chain([&builtin.result]) {
                assert_ne!(
                    ArkType::parse(ty),
                    ArkType::Unknown,
                    "{}: unknown type '{ty}'",
                    builtin.name
                );
            }
            assert!(
                !builtin.opcodes.is_empty(),
                "{} emits nothing",
                builtin.name
            );
        }
    }
}
