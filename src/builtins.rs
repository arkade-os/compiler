//! Builtin functions: the language functions the compiler provides. Each entry
//! is the single description of a builtin, read by the parser, the type checks,
//! code generation and the builtin docs.

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
    pub doc: &'static str,
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
    doc: &'static str,
) -> Builtin {
    Builtin {
        name,
        params,
        result: Some(result),
        lowering: Lowering::Opcodes(opcodes),
        doc,
    }
}

const fn verify(
    name: &'static str,
    params: &'static [(&'static str, &'static str)],
    opcode: &'static [Opcode],
    doc: &'static str,
) -> Builtin {
    Builtin {
        name,
        params,
        result: None,
        lowering: Lowering::Opcodes(opcode),
        doc,
    }
}

pub(crate) const BUILTINS: &[Builtin] = &[
    builtin(
        "substr",
        &[("data", "bytes"), ("offset", "int"), ("size", "int")],
        "bytes",
        &[Substr],
        "size bytes of data starting at offset. An offset or size below 0, or offset + size above \
         data's length, fails the spend.",
    ),
    builtin(
        "left",
        &[("data", "bytes"), ("count", "int")],
        "bytes",
        &[Left],
        "The first count bytes of data. A count below 0 or above data's length fails the spend.",
    ),
    builtin(
        "right",
        &[("data", "bytes"), ("count", "int")],
        "bytes",
        &[Right],
        "The last count bytes of data. A count below 0 or above data's length fails the spend.",
    ),
    builtin(
        "cat",
        &[("a", "bytes"), ("b", "bytes")],
        "bytes",
        &[Cat],
        "a followed by b. A result over 520 bytes fails the spend.",
    ),
    builtin(
        "bin2num",
        &[("data", "bytes")],
        "int",
        &[Bin2Num],
        "Script-number bytes as an int.",
    ),
    builtin(
        "num2bin",
        &[("value", "int"), ("size", "int")],
        "bytes",
        &[Num2Bin],
        "value as little-endian Script-number bytes padded to size bytes. Fails the spend when \
         value does not fit or size is negative or above 520.",
    ),
    builtin(
        "reverseBytes",
        &[("data", "bytes")],
        "bytes",
        &[ReverseBytes],
        "data in reverse byte order.",
    ),
    builtin(
        "size",
        &[("data", "bytes")],
        "int",
        &[Size, Nip],
        "Length of data in bytes.",
    ),
    builtin(
        "digest",
        &[("data", "bytes"), ("hashType", "int")],
        "bytes",
        &[Digest],
        "Hash of data by hashType: 1 SHA-256, 2 SHA-1, 3 RIPEMD-160, 4 Keccak-256, 5 SHA3-256. \
         Any other hashType fails the spend.",
    ),
    builtin(
        "sha1",
        &[("data", "bytes")],
        "bytes20",
        &[Sha1],
        "SHA-1 of data. Its collision resistance is broken; use it only for legacy \
         interoperability.",
    ),
    builtin(
        "sha256",
        &[("data", "bytes")],
        "bytes32",
        &[Sha256],
        "SHA-256 of data.",
    ),
    builtin(
        "hash256",
        &[("data", "bytes")],
        "bytes32",
        &[Hash256],
        "Double SHA-256 of data.",
    ),
    builtin(
        "hash160",
        &[("data", "bytes")],
        "bytes20",
        &[Hash160],
        "RIPEMD-160 of the SHA-256 of data.",
    ),
    builtin(
        "ripemd160",
        &[("data", "bytes")],
        "bytes20",
        &[Ripemd160],
        "RIPEMD-160 of data.",
    ),
    builtin(
        "checkSig",
        &[("signature", "signature"), ("pubkey", "bytes")],
        "bool",
        &[CheckSig],
        "Whether signature by pubkey is valid for the spending transaction. An empty signature is \
         false; an invalid non-empty one fails the spend.",
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
        "Whether signature is valid by pubkey over message. An empty signature is false; a \
         non-empty one fails the spend unless it is valid and message is 32 bytes.",
    ),
    verify(
        "checkSigFromStackVerify",
        &[
            ("signature", "signature"),
            ("pubkey", "bytes"),
            ("message", "bytes"),
        ],
        &[Swap, CheckSigFromStack, Verify],
        "Fails the spend unless signature is valid by pubkey over message, which must be 32 bytes. \
         Produces no value; use it directly inside require.",
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
        doc: "Whether exactly threshold signatures are non-empty, each valid for the key at its \
              index; an invalid non-empty one fails the spend. Without a threshold, all must be \
              valid; a runtime threshold outside 1 to the key count fails the spend.",
    },
    // A streaming context is opaque VM state with no language-defined width.
    builtin(
        "sha256Initialize",
        &[("data", "bytes")],
        "bytes",
        &[Sha256Initialize],
        "Starts a streaming SHA-256 with data and returns its context.",
    ),
    builtin(
        "sha256Update",
        &[("ctx", "bytes"), ("chunk", "bytes")],
        "bytes",
        &[Sha256Update],
        "Adds chunk to a streaming SHA-256 context.",
    ),
    builtin(
        "sha256Finalize",
        &[("ctx", "bytes"), ("lastChunk", "bytes")],
        "bytes32",
        &[Sha256Finalize],
        "Adds lastChunk and returns the streaming SHA-256 digest.",
    ),
    builtin(
        "sighash",
        &[("hashType", "int")],
        "bytes32",
        &[SigHash],
        "The Arkade signature hash of the input being spent for hashType, the message checkSig \
         verifies; not the BIP-342 digest. An invalid hashType fails the spend.",
    ),
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
        "Root of a BIP-341 tagged-hash Merkle proof. Siblings in proof are 32 bytes each and \
         combined in sorted order. An empty leafTag takes a 32-byte leaf as already hashed; an \
         empty branchTag fails the spend.",
    ),
    builtin(
        "checkTime",
        &[("timestamp", "int")],
        "bool",
        &[CheckTime],
        "Whether the emulator's clock has reached timestamp, a Unix time in seconds. Independent \
         of the transaction locktime and sequence. A negative timestamp fails the spend.",
    ),
    builtin(
        "modExp",
        &[("base", "int"), ("exponent", "int"), ("modulus", "int")],
        "int",
        &[ModExp],
        "base raised to exponent, modulo modulus, in 0 to modulus - 1. Fails the spend when \
         modulus <= 0, exponent < 0 or an operand exceeds 64 bytes.",
    ),
    builtin("abs", &[("value", "int")], "int", &[Abs], "Absolute value."),
    builtin(
        "min",
        &[("a", "int"), ("b", "int")],
        "int",
        &[Min],
        "The smaller of a and b.",
    ),
    builtin(
        "max",
        &[("a", "int"), ("b", "int")],
        "int",
        &[Max],
        "The larger of a and b.",
    ),
    builtin(
        "within",
        &[("value", "int"), ("lower", "int"), ("upper", "int")],
        "bool",
        &[Within],
        "Whether lower <= value < upper. Empty or reversed ranges are false.",
    ),
    builtin(
        "ecAdd",
        &[("P", "ECPoint"), ("Q", "ECPoint"), ("curveId", "int")],
        "ECPoint",
        &[EcAdd],
        "P + Q on curveId: 0 secp256k1, 1 secp256r1, 2 alt_bn128; (0, 0) is the point at \
         infinity. An unknown curve or an off-curve point fails the spend.",
    ),
    builtin(
        "ecMul",
        &[("P", "ECPoint"), ("scalar", "int"), ("curveId", "int")],
        "ECPoint",
        &[EcMul],
        "scalar·P on curveId, numbered as for ecAdd. A scalar below 0 or not below the group \
         order, or an off-curve P, fails the spend.",
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
        doc: "Whether the product of the pairings of aligned G1 and G2 points is the identity, \
              for 1 to 16 pairs. Only alt_bn128 (curveId 2) pairs; another curve, or an off-curve \
              or out-of-subgroup point, fails the spend.",
    },
    verify(
        "ecMulScalarVerify",
        &[("k", "bytes32"), ("P", "bytes"), ("Q", "bytes")],
        &[EcMulScalarVerify],
        "Fails the spend unless Q = k·P. k is 32-byte big-endian; P and Q are compressed points.",
    ),
    verify(
        "tweakVerify",
        &[("P", "bytes32"), ("k", "bytes32"), ("Q", "bytes")],
        &[TweakVerify],
        "Fails the spend unless Q = P + k·G, with P a 32-byte x-only key, k 32-byte big-endian \
         and Q a 33-byte compressed point.",
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

/// A call or member the grammar spells rule by rule, so neither BUILTINS nor
/// the properties describe it.
struct Spelled {
    name: &'static str,
    /// `type name`, with a trailing `?` when optional; None for a property.
    params: Option<&'static [&'static str]>,
    /// A call's result or a property's type.
    ty: Option<&'static str>,
    /// The index name an array property suggests.
    index: Option<&'static str>,
    tapscript: bool,
    doc: &'static str,
}

const fn property(name: &'static str, ty: &'static str, doc: &'static str) -> Spelled {
    Spelled {
        name,
        params: None,
        ty: Some(ty),
        index: None,
        tapscript: false,
        doc,
    }
}

const fn method(
    name: &'static str,
    params: &'static [&'static str],
    result: &'static str,
    doc: &'static str,
) -> Spelled {
    Spelled {
        name,
        params: Some(params),
        ty: Some(result),
        index: None,
        tapscript: false,
        doc,
    }
}

const SPELLED: &[Spelled] = &[
    Spelled {
        tapscript: true,
        ..method(
            "tweak",
            &["pubkey base", "function name"],
            "pubkey",
            "base (emulator or a constructor pubkey) tweaked by the named covenant's hash. A \
             tapscript-only key expression inside checkSig or checkMultisig.",
        )
    },
    Spelled {
        name: "older",
        params: Some(&["int sequence"]),
        ty: None,
        index: None,
        tapscript: true,
        doc: "Relative timelock (CSV). Wrap a literal in blocks(n) or seconds(n) to state its \
              unit; a bare value is a raw BIP-68 sequence. Tapscript only.",
    },
    Spelled {
        name: "after",
        params: Some(&["int locktime"]),
        ty: None,
        index: None,
        tapscript: true,
        doc: "Absolute timelock (CLTV): a block height with blocks(n), or a Unix timestamp with \
              seconds(n). Tapscript only.",
    },
    Spelled {
        name: "blocks",
        params: Some(&["int count"]),
        ty: Some("int"),
        index: None,
        tapscript: true,
        doc: "A timelock in blocks, for older or after.",
    },
    Spelled {
        name: "seconds",
        params: Some(&["int count"]),
        ty: Some("int"),
        index: None,
        tapscript: true,
        doc: "A timelock in seconds, for older or after. Relative delays are multiples of 512 \
              seconds.",
    },
    Spelled {
        name: "tx.inputs",
        params: None,
        ty: Some("Input[]"),
        index: Some("i"),
        tapscript: false,
        doc: "Transaction inputs.",
    },
    Spelled {
        name: "tx.outputs",
        params: None,
        ty: Some("Output[]"),
        index: Some("o"),
        tapscript: false,
        doc: "Transaction outputs.",
    },
    Spelled {
        name: "tx.input",
        params: None,
        ty: None,
        index: None,
        tapscript: false,
        doc: "The input being spent, as tx.input.current.",
    },
    property("tx.input.current", "Input", "The input being spent."),
    property(
        "tx.assetGroups",
        "AssetGroup[]",
        "Asset groups of the transaction's asset packet. Asset group and asset members fail the \
         spend when the transaction has no asset packet.",
    ),
    Spelled {
        name: "tx.intent",
        params: None,
        ty: None,
        index: None,
        tapscript: false,
        doc: "Fields of the intent message, set only while the emulator checks an intent proof.",
    },
    method(
        "tx.packet",
        &["int packetType"],
        "bytes",
        "Bytes of this transaction's extension packet of packetType. Fails the spend when it is \
         absent or over 520 bytes.",
    ),
    method(
        "tx.packet.has",
        &["int packetType"],
        "bool",
        "Whether this transaction carries an extension packet of packetType. A packet over 520 \
         bytes fails the spend.",
    ),
    method(
        "tx.intent.field",
        &["bytes path"],
        "bytes",
        "The intent field at a dot-separated path of lowercase keys and indexes such as \
         \"cosigners.0\": a string's bytes, an integer as a Script number, true as 0x01, false as \
         empty, an object or array as JSON. Fails the spend when it is missing, null or \
         fractional, or outside an intent proof.",
    ),
    method(
        "tx.intent.has",
        &["bytes path"],
        "bool",
        "Whether tx.intent.field(path) has a value; false outside an intent proof.",
    ),
    property(
        "tx.inputs[].assets",
        "AssetEntry[]",
        "Assets held by the input.",
    ),
    method(
        "tx.inputs[].packet",
        &["int packetType"],
        "bytes",
        "Extension packet of packetType of the Arkade transaction that created this input. Fails \
         the spend when it is absent or over 520 bytes.",
    ),
    method(
        "tx.inputs[].packet.has",
        &["int packetType"],
        "bool",
        "Whether the Arkade transaction that created this input carries an extension packet of \
         packetType. A packet over 520 bytes fails the spend.",
    ),
    property(
        "tx.outputs[].assets",
        "AssetEntry[]",
        "Assets held by the output.",
    ),
    property(
        "tx.inputs[].assets.length",
        "int",
        "Number of assets. Fails the spend without an asset packet.",
    ),
    method(
        "tx.inputs[].assets.lookup",
        &["bytes32 assetTxid", "int assetGidx"],
        "int",
        "Amount of the asset. Fails the spend when it or the asset packet is absent.",
    ),
    method(
        "tx.inputs[].assets.tryLookup",
        &["bytes32 assetTxid", "int assetGidx"],
        "AssetLookup",
        "The asset's {amount, found} from one inspection; amount is 0 when it is absent. Fails \
         the spend only without an asset packet.",
    ),
    method(
        "tx.inputs[].assets.has",
        &["bytes32 assetTxid", "int assetGidx"],
        "bool",
        "Whether the asset is present. Fails the spend without an asset packet.",
    ),
    method(
        "tx.assetGroups.find",
        &["bytes32 assetTxid", "int assetGidx"],
        "AssetGroup",
        "The asset group of the asset. Fails the spend when it or the asset packet is absent.",
    ),
    method(
        "tx.assetGroups.has",
        &["bytes32 assetTxid", "int assetGidx"],
        "bool",
        "Whether the packet has a group for the asset. Fails the spend without an asset packet.",
    ),
    property(
        "tx.assetGroups.length",
        "int",
        "Number of asset groups. Fails the spend without an asset packet.",
    ),
    Spelled {
        name: "tx.assetGroups[].inputs",
        params: None,
        ty: Some("GroupInput[]"),
        index: Some("j"),
        tapscript: false,
        doc: "The group's input records.",
    },
    Spelled {
        name: "tx.assetGroups[].outputs",
        params: None,
        ty: Some("GroupOutput[]"),
        index: Some("j"),
        tapscript: false,
        doc: "The group's output records.",
    },
    method(
        "tx.assetGroups[].controlIs",
        &["bytes32 assetTxid", "int assetGidx"],
        "bool",
        "Whether the group's control asset is the given asset.",
    ),
    property(
        "this.activeBytecode",
        "ScriptPubKey",
        "Witness program and version of the input being spent, {program, version}.",
    ),
    method(
        "this.tunnel",
        &[
            "int outputIndex",
            "TunnelPolicy policy?",
            "AssetId[] except?",
        ],
        "bool",
        "True when the output keeps this input's scriptPubKey, value and exact assets, or those \
         the policy selects, apart from the excepted assets; otherwise fails the spend. Covenant \
         only.",
    ),
];

/// Every builtin function and `tx`/`this` member as pretty JSON: calls under
/// `functions`, dotted names under `members`.
pub(crate) fn docs() -> String {
    use crate::properties::*;
    use serde_json::{json, Map};

    let mut functions = Map::new();
    for builtin in BUILTINS {
        let mut params: Vec<String> = builtin
            .params
            .iter()
            .map(|(name, ty)| format!("{ty} {name}"))
            .collect();
        if matches!(builtin.lowering, Lowering::Multisig) {
            params.last_mut().unwrap().push('?');
        }
        let entry = json!({ "params": params, "result": builtin.result, "doc": builtin.doc });
        functions.insert(builtin.name.into(), entry);
    }
    let mut members = Map::new();
    let mut property = |path: &str, (name, ty, doc): (&str, &str, &str)| {
        members.insert(format!("{path}.{name}"), json!({ "type": ty, "doc": doc }));
    };
    for &p in TxProperty::ALL {
        property("tx", p.describe());
    }
    for &p in InputProperty::ALL {
        property("tx.inputs[]", p.describe());
    }
    for &p in OutputProperty::ALL {
        property("tx.outputs[]", p.describe());
    }
    for &p in ThisProperty::ALL {
        property("this", p.describe());
    }
    for &p in GroupProperty::ALL {
        property("tx.assetGroups[]", p.describe());
    }
    for &p in GroupIoProperty::ALL {
        property("tx.assetGroups[].inputs[]", p.describe());
        // Output records have no txid.
        if p != GroupIoProperty::Txid {
            property("tx.assetGroups[].outputs[]", p.describe());
        }
    }
    for &p in AssetProperty::ALL {
        property("tx.inputs[].assets[]", p.describe());
    }
    for spelled in SPELLED {
        let (result, ty) = match spelled.params {
            Some(_) => (spelled.ty, None),
            None => (None, spelled.ty),
        };
        let entry = json!({
            "params": spelled.params,
            "result": result,
            "type": ty,
            "index": spelled.index,
            "tapscript": spelled.tapscript.then_some(true),
            "doc": spelled.doc,
        });
        let table = if spelled.name.contains('.') {
            &mut members
        } else {
            &mut functions
        };
        table.insert(spelled.name.into(), entry);
    }
    for entry in functions.values_mut().chain(members.values_mut()) {
        entry
            .as_object_mut()
            .unwrap()
            .retain(|_, value| !value.is_null());
    }
    serde_json::to_string_pretty(&json!({ "functions": functions, "members": members })).unwrap()
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

    /// Members the grammar spells rule by rule are described only in SPELLED, so each
    /// documented one is compiled as declared: called with its parameters, returning its type.
    #[test]
    fn every_documented_member_compiles_as_declared() {
        let docs: serde_json::Value = serde_json::from_str(&crate::builtin_docs()).unwrap();
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
