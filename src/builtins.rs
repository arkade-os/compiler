//! Builtin functions: the language functions the compiler provides. Each entry
//! is the single description of a builtin, read by the parser, the type checks
//! and code generation.

use crate::opcodes::Opcode::{self, *};

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
    Opcodes(&'static [Opcode]),
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
    opcodes: &'static [Opcode],
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
    opcode: &'static [Opcode],
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
        &[Substr],
    ),
    builtin(
        "left",
        &[("data", "bytes"), ("count", "int")],
        "bytes",
        &[Left],
    ),
    builtin(
        "right",
        &[("data", "bytes"), ("count", "int")],
        "bytes",
        &[Right],
    ),
    builtin("cat", &[("a", "bytes"), ("b", "bytes")], "bytes", &[Cat]),
    builtin("bin2num", &[("data", "bytes")], "int", &[Bin2Num]),
    builtin(
        "num2bin",
        &[("value", "int"), ("size", "int")],
        "bytes",
        &[Num2Bin],
    ),
    builtin(
        "reverseBytes",
        &[("data", "bytes")],
        "bytes",
        &[ReverseBytes],
    ),
    builtin("size", &[("data", "bytes")], "int", &[Size, Nip]),
    builtin(
        "digest",
        &[("data", "bytes"), ("hashType", "int")],
        "bytes",
        &[Digest],
    ),
    builtin("sha1", &[("data", "bytes")], "bytes20", &[Sha1]),
    builtin("sha256", &[("data", "bytes")], "bytes32", &[Sha256]),
    builtin("hash256", &[("data", "bytes")], "bytes32", &[Hash256]),
    builtin("hash160", &[("data", "bytes")], "bytes20", &[Hash160]),
    builtin("ripemd160", &[("data", "bytes")], "bytes20", &[Ripemd160]),
    builtin(
        "checkSig",
        &[("signature", "signature"), ("pubkey", "bytes")],
        "bool",
        &[CheckSig],
    ),
    builtin(
        "checkSigFromStack",
        &[
            ("signature", "signature"),
            ("pubkey", "bytes"),
            ("message", "bytes"),
        ],
        "bool",
        &[Swap, CheckSigFromStack],
    ),
    verify(
        "checkSigFromStackVerify",
        &[
            ("signature", "signature"),
            ("pubkey", "bytes"),
            ("message", "bytes"),
        ],
        &[Swap, CheckSigFromStack, Verify],
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
        &[Sha256Initialize],
    ),
    builtin(
        "sha256Update",
        &[("ctx", "bytes32"), ("chunk", "bytes")],
        "bytes32",
        &[Sha256Update],
    ),
    builtin(
        "sha256Finalize",
        &[("ctx", "bytes32"), ("lastChunk", "bytes")],
        "bytes32",
        &[Sha256Finalize],
    ),
    builtin("sighash", &[("hashType", "int")], "bytes32", &[SigHash]),
    // An empty leafTag takes a 32-byte leaf as already hashed.
    builtin(
        "merkleRoot",
        &[
            ("leafTag", "bytes"),
            ("branchTag", "bytes"),
            ("proof", "bytes"),
            ("leaf", "bytes"),
        ],
        "bytes32",
        &[MerkleBranchVerify],
    ),
    builtin("checkTime", &[("timestamp", "int")], "bool", &[CheckTime]),
    builtin(
        "modExp",
        &[("base", "int"), ("exponent", "int"), ("modulus", "int")],
        "int",
        &[ModExp],
    ),
    builtin("abs", &[("value", "int")], "int", &[Abs]),
    builtin("min", &[("a", "int"), ("b", "int")], "int", &[Min]),
    builtin("max", &[("a", "int"), ("b", "int")], "int", &[Max]),
    builtin(
        "within",
        &[("value", "int"), ("lower", "int"), ("upper", "int")],
        "bool",
        &[Within],
    ),
    builtin(
        "ecAdd",
        &[("P", "ECPoint"), ("Q", "ECPoint"), ("curveId", "int")],
        "ECPoint",
        &[EcAdd],
    ),
    builtin(
        "ecMul",
        &[("P", "ECPoint"), ("scalar", "int"), ("curveId", "int")],
        "ECPoint",
        &[EcMul],
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
        &[EcMulScalarVerify],
    ),
    verify(
        "tweakVerify",
        &[("P", "bytes32"), ("k", "bytes32"), ("Q", "bytes")],
        &[TweakVerify],
    ),
];

impl Builtin {
    /// Whether a call with `count` arguments matches; multisig's threshold is optional.
    pub(crate) fn accepts_arity(&self, count: usize) -> bool {
        count == self.params.len() || matches!(self.lowering, Lowering::Multisig) && count == 2
    }

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
    use crate::types::ArkType;

    fn known(ty: &str) -> bool {
        match ArkType::parse(ty) {
            ArkType::Struct(name) => crate::models::builtin_struct_fields(&name).is_some(),
            parsed => parsed != ArkType::Unknown,
        }
    }

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
                assert!(known(element), "{}: unknown type '{ty}'", builtin.name);
            }
            if let Lowering::Opcodes(opcodes) = builtin.lowering {
                assert!(!opcodes.is_empty(), "{} emits nothing", builtin.name);
            }
        }
    }

    #[test]
    fn the_playground_documents_every_builtin_and_property() {
        use crate::properties::*;
        let docs: serde_json::Value =
            serde_json::from_str(include_str!("../playground/builtins.json")).unwrap();
        let functions = docs["functions"].as_object().unwrap();
        for builtin in BUILTINS {
            let entry = &functions[builtin.name];
            let params: Vec<(&str, &str)> = entry["params"]
                .as_array()
                .unwrap()
                .iter()
                .map(|param| {
                    let (ty, name) = param.as_str().unwrap().split_once(' ').unwrap();
                    (name.trim_end_matches('?'), ty)
                })
                .collect();
            assert_eq!(params, builtin.params, "{}", builtin.name);
            assert_eq!(entry["result"].as_str(), builtin.result, "{}", builtin.name);
            assert!(entry["doc"]["en"].is_string(), "{}", builtin.name);
        }
        // Calls the grammar spells itself rather than through BUILTINS.
        let syntax = ["tweak", "older", "after", "blocks", "seconds"];
        for name in functions.keys() {
            assert!(
                find(name).is_some() || syntax.contains(&name.as_str()),
                "'{name}' is not a builtin"
            );
        }

        fn check<P: Copy>(
            docs: &serde_json::Value,
            path: &str,
            all: &[P],
            describe: fn(P) -> (&'static str, &'static str),
        ) {
            for &property in all {
                let (name, ty) = describe(property);
                let key = format!("{path}.{name}");
                assert_eq!(docs["members"][&key]["type"].as_str(), Some(ty), "{key}");
            }
        }
        check(&docs, "tx", TxProperty::ALL, |p| (p.name(), p.value_type()));
        check(&docs, "tx.inputs[]", InputProperty::ALL, |p| {
            (p.name(), p.value_type())
        });
        check(&docs, "tx.outputs[]", OutputProperty::ALL, |p| {
            (p.name(), p.value_type())
        });
        check(&docs, "this", ThisProperty::ALL, |p| {
            (p.name(), p.value_type())
        });
        check(&docs, "tx.assetGroups[]", GroupProperty::ALL, |p| {
            (p.name(), p.value_type())
        });
        check(
            &docs,
            "tx.assetGroups[].inputs[]",
            GroupIoProperty::ALL,
            |p| (p.name(), p.value_type()),
        );
        let outputs: Vec<_> = GroupIoProperty::ALL
            .iter()
            .copied()
            .filter(|p| *p != GroupIoProperty::Txid)
            .collect();
        check(&docs, "tx.assetGroups[].outputs[]", &outputs, |p| {
            (p.name(), p.value_type())
        });
        check(&docs, "tx.inputs[].assets[]", AssetProperty::ALL, |p| {
            (p.name(), p.value_type())
        });
    }

    /// Members the grammar spells rule by rule have no table to compare with, so each
    /// documented one is compiled as declared: called with its parameters, returning its type.
    #[test]
    fn every_documented_member_compiles_as_declared() {
        let docs: serde_json::Value =
            serde_json::from_str(include_str!("../playground/builtins.json")).unwrap();
        let mut failures = Vec::new();
        for (key, entry) in docs["members"].as_object().unwrap() {
            let Some(result) = entry["result"].as_str().or(entry["type"].as_str()) else {
                continue;
            };
            if !known(result) {
                continue;
            }
            let params: Vec<&str> = entry["params"].as_array().map_or(vec![], |params| {
                let params = params.iter().map(|param| param.as_str().unwrap());
                params.filter(|param| !param.ends_with('?')).collect()
            });
            let names: Vec<&str> = params
                .iter()
                .map(|p| p.split_once(' ').unwrap().1)
                .collect();
            let call = if entry["params"].is_array() {
                format!("({})", names.join(", "))
            } else {
                String::new()
            };
            let expression = format!("{}{call}", key.replace("[]", "[0]"));
            let source = format!(
                "contract Probe(pubkey owner) {{\n  private function probe({}) {result} {{ return {expression}; }}\n  function spend(signature sig) {{ require(checkSig(sig, owner)); }}\n}}",
                params.join(", ")
            );
            if let Err(error) = crate::compile(&source) {
                failures.push(format!("{key}: {error}\n{source}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n\n"));
    }
}
