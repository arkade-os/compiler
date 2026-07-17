use arkade_compiler::ContractJson;

/// Wire-encoding descriptor, matching the compiler's `WitnessElement.encoding` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Encoding {
    /// 33-byte SEC-compressed secp256k1 public key
    Compressed33,
    /// 64-byte BIP-340 Schnorr signature
    Schnorr64,
    /// Arbitrary-length byte array
    Raw,
    /// 20-byte fixed array (HASH160)
    Raw20,
    /// 32-byte fixed array (SHA256, txid, asset)
    Raw32,
    /// Bitcoin CScriptNum (variable-length LE integer)
    ScriptNum,
    /// 8-byte unsigned little-endian int64
    Le64,
    /// 4-byte unsigned little-endian int32
    Le32,
    /// Unrecognized encoding string
    Unknown(String),
}

impl Encoding {
    /// Parse an encoding string from the artifact.
    pub fn parse(s: &str) -> Self {
        match s {
            "compressed-33" => Encoding::Compressed33,
            "schnorr-64" => Encoding::Schnorr64,
            "raw" => Encoding::Raw,
            "raw-20" => Encoding::Raw20,
            "raw-32" => Encoding::Raw32,
            "scriptnum" => Encoding::ScriptNum,
            "le64" => Encoding::Le64,
            "le32" => Encoding::Le32,
            other => Encoding::Unknown(other.to_string()),
        }
    }

    /// Infer encoding from an Arkade Script type string. Constructor parameters
    /// and covenant inputs carry only a type, not an explicit encoding.
    pub fn from_ark_type(type_str: &str) -> Self {
        match type_str {
            "pubkey" => Encoding::Compressed33,
            "signature" => Encoding::Schnorr64,
            "bytes" => Encoding::Raw,
            "bytes20" => Encoding::Raw20,
            "bytes32" => Encoding::Raw32,
            "int" | "bool" => Encoding::ScriptNum,
            "asset" => Encoding::Raw32,
            _ => Encoding::Unknown(type_str.to_string()),
        }
    }

    /// The encoding string as it appears in the artifact JSON.
    pub fn as_str(&self) -> &str {
        match self {
            Encoding::Compressed33 => "compressed-33",
            Encoding::Schnorr64 => "schnorr-64",
            Encoding::Raw => "raw",
            Encoding::Raw20 => "raw-20",
            Encoding::Raw32 => "raw-32",
            Encoding::ScriptNum => "scriptnum",
            Encoding::Le64 => "le64",
            Encoding::Le32 => "le32",
            Encoding::Unknown(s) => s.as_str(),
        }
    }
}

/// A typed field in the IR (constructor param, covenant input, or witness element).
#[derive(Debug, Clone)]
pub struct Field {
    /// Field name as it appears in the artifact (camelCase).
    pub name: String,
    /// Arkade Script type string (e.g., "pubkey", "signature").
    pub ark_type: String,
    /// Wire encoding descriptor.
    pub encoding: Encoding,
    /// True when Arkade infrastructure supplies this field (e.g., co-signer sigs).
    pub is_injected: bool,
}

/// One L1 tapleaf spend path within a group.
#[derive(Debug, Clone)]
pub struct LeafIR {
    /// Leaf name (source tapscript name, or covenant name for a synthesized default).
    pub name: String,
    /// Witness stack the caller supplies, in order. Injected fields are marked.
    pub witness_fields: Vec<Field>,
    /// Tapleaf assembly.
    pub asm: Vec<String>,
}

impl LeafIR {
    /// Fields the caller must supply (excludes infrastructure-injected ones).
    pub fn user_fields(&self) -> Vec<&Field> {
        self.witness_fields
            .iter()
            .filter(|f| !f.is_injected)
            .collect()
    }
}

/// The emulator-run covenant attached to a function-backed group.
#[derive(Debug, Clone)]
pub struct CovenantIR {
    /// Covenant inputs (function parameters, array-expanded).
    pub inputs: Vec<Field>,
    /// Covenant assembly.
    pub asm: Vec<String>,
}

/// A spend group: an optional covenant plus its L1 leaves.
#[derive(Debug, Clone)]
pub struct GroupIR {
    /// Group name (covenant function name, or a standalone leaf's own name).
    pub name: String,
    /// Emulator covenant; absent for groups of standalone leaves.
    pub covenant: Option<CovenantIR>,
    /// L1 tapleaves grouped under this entry.
    pub leaves: Vec<LeafIR>,
}

/// The complete intermediate representation of a contract.
#[derive(Debug, Clone)]
pub struct ContractIR {
    /// Contract name (PascalCase by convention).
    pub name: String,
    /// Typed constructor parameters.
    pub constructor_fields: Vec<Field>,
    /// Spend groups in artifact order.
    pub groups: Vec<GroupIR>,
    /// Original .ark source code, if embedded.
    pub source: Option<String>,
    /// Compiler version string.
    pub compiler_version: Option<String>,
}

fn field_from_ark_type(name: &str, ark_type: &str) -> Field {
    Field {
        name: name.to_string(),
        ark_type: ark_type.to_string(),
        encoding: Encoding::from_ark_type(ark_type),
        is_injected: false,
    }
}

/// Build an IR from a compiled contract artifact.
pub fn build_ir(artifact: &ContractJson) -> Result<ContractIR, String> {
    let constructor_fields = artifact
        .parameters
        .iter()
        .map(|p| field_from_ark_type(&p.name, &p.param_type))
        .collect();

    let groups = artifact
        .functions
        .iter()
        .map(|group| GroupIR {
            name: group.name.clone(),
            covenant: group.arkade.as_ref().map(|cov| CovenantIR {
                inputs: cov
                    .inputs
                    .iter()
                    .map(|i| field_from_ark_type(&i.name, &i.param_type))
                    .collect(),
                asm: cov.asm.clone(),
            }),
            leaves: group
                .leaves
                .iter()
                .map(|leaf| LeafIR {
                    name: leaf.name.clone(),
                    witness_fields: leaf
                        .witness
                        .iter()
                        .map(|w| Field {
                            name: w.name.clone(),
                            ark_type: w.elem_type.clone(),
                            encoding: Encoding::parse(&w.encoding),
                            is_injected: w.injected,
                        })
                        .collect(),
                    asm: leaf.asm.clone(),
                })
                .collect(),
        })
        .collect();

    Ok(ContractIR {
        name: artifact.name.clone(),
        constructor_fields,
        groups,
        source: artifact.source.clone(),
        compiler_version: artifact.compiler.as_ref().map(|c| c.version.clone()),
    })
}
