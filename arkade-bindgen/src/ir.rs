use std::collections::BTreeMap;

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

    /// Infer encoding from an Arkade Script type string.
    /// Used as fallback when `witnessSchema` is absent.
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

/// A typed field in the IR (constructor param or witness element).
#[derive(Debug, Clone)]
pub struct Field {
    /// Field name as it appears in the artifact (camelCase).
    pub name: String,
    /// Arkade Script type string (e.g., "pubkey", "signature").
    pub ark_type: String,
    /// Wire encoding descriptor.
    pub encoding: Encoding,
    /// True if this field is injected by the Ark server (e.g., "serverSig").
    pub is_server_injected: bool,
}

/// One variant of a function (cooperative or exit).
#[derive(Debug, Clone)]
pub struct VariantIR {
    /// Fields the caller must supply (excludes server-injected).
    pub user_fields: Vec<Field>,
    /// All fields including server-injected.
    pub all_fields: Vec<Field>,
    /// Raw assembly instructions.
    pub asm: Vec<String>,
    /// Human-readable requirement descriptions for doc comments.
    pub requirements: Vec<String>,
    /// Whether this is an N-of-N multisig fallback exit path.
    pub is_nofn_fallback: bool,
}

/// A paired function with cooperative and exit variants.
#[derive(Debug, Clone)]
pub struct FunctionIR {
    /// Function name as it appears in the artifact.
    pub name: String,
    /// Cooperative path (serverVariant: true).
    pub cooperative: VariantIR,
    /// Exit path (serverVariant: false).
    pub exit: VariantIR,
}

/// The complete intermediate representation of a contract.
#[derive(Debug, Clone)]
pub struct ContractIR {
    /// Contract name (PascalCase by convention).
    pub name: String,
    /// Typed constructor parameters.
    pub constructor_fields: Vec<Field>,
    /// Paired functions (cooperative + exit).
    pub functions: Vec<FunctionIR>,
    /// Original .ark source code, if embedded.
    pub source: Option<String>,
    /// Compiler version string.
    pub compiler_version: Option<String>,
}

/// Build an IR from a compiled contract artifact.
pub fn build_ir(artifact: &ContractJson) -> Result<ContractIR, String> {
    let constructor_fields = artifact
        .parameters
        .iter()
        .map(|p| Field {
            name: p.name.clone(),
            ark_type: p.param_type.clone(),
            encoding: Encoding::from_ark_type(&p.param_type),
            is_server_injected: false,
        })
        .collect();

    let functions = pair_functions(artifact)?;

    Ok(ContractIR {
        name: artifact.name.clone(),
        constructor_fields,
        functions,
        source: artifact.source.clone(),
        compiler_version: artifact.compiler.as_ref().map(|c| c.version.clone()),
    })
}

/// Group artifact functions by name and pair cooperative + exit variants.
fn pair_functions(artifact: &ContractJson) -> Result<Vec<FunctionIR>, String> {
    // Use BTreeMap to preserve insertion order (sorted, but stable).
    // We'll re-sort by first-appearance order afterwards.
    let mut groups: BTreeMap<String, (Option<usize>, Vec<&arkade_compiler::models::AbiFunction>)> =
        BTreeMap::new();

    for (idx, func) in artifact.functions.iter().enumerate() {
        let entry = groups
            .entry(func.name.clone())
            .or_insert_with(|| (Some(idx), Vec::new()));
        entry.1.push(func);
    }

    // Sort by first appearance order
    let mut ordered: Vec<_> = groups.into_iter().collect();
    ordered.sort_by_key(|(_, (first_idx, _))| first_idx.unwrap_or(usize::MAX));

    let mut result = Vec::new();

    for (name, (_, variants)) in ordered {
        let mut cooperative = None;
        let mut exit = None;

        for func in &variants {
            if func.server_variant {
                if cooperative.is_some() {
                    return Err(format!(
                        "Function '{}' has multiple cooperative variants",
                        name
                    ));
                }
                cooperative = Some(*func);
            } else {
                if exit.is_some() {
                    return Err(format!("Function '{}' has multiple exit variants", name));
                }
                exit = Some(*func);
            }
        }

        let cooperative_func = cooperative
            .ok_or_else(|| format!("Function '{}' missing cooperative variant", name))?;
        let exit_func = exit.ok_or_else(|| format!("Function '{}' missing exit variant", name))?;

        result.push(FunctionIR {
            name: name.clone(),
            cooperative: build_variant(cooperative_func),
            exit: build_variant(exit_func),
        });
    }

    Ok(result)
}

/// Build a VariantIR from a single AbiFunction.
fn build_variant(func: &arkade_compiler::models::AbiFunction) -> VariantIR {
    let has_witness_schema = !func.witness_schema.is_empty();

    // Check if "serverSig" is a user-declared input (not protocol-injected)
    let user_declared_server_sig = func
        .function_inputs
        .iter()
        .any(|fi| fi.name == "serverSig");

    let all_fields: Vec<Field> = if has_witness_schema {
        // Primary path: use witnessSchema with explicit encodings
        func.witness_schema
            .iter()
            .map(|w| Field {
                name: w.name.clone(),
                ark_type: w.elem_type.clone(),
                encoding: Encoding::parse(&w.encoding),
                is_server_injected: func.server_variant
                    && w.name == "serverSig"
                    && !user_declared_server_sig,
            })
            .collect()
    } else {
        // Fallback: infer encodings from functionInputs type strings
        let mut fields: Vec<Field> = func
            .function_inputs
            .iter()
            .map(|fi| Field {
                name: fi.name.clone(),
                ark_type: fi.param_type.clone(),
                encoding: Encoding::from_ark_type(&fi.param_type),
                is_server_injected: false,
            })
            .collect();

        // If this is a cooperative variant and serverSig isn't user-declared, add it
        if func.server_variant && !user_declared_server_sig {
            fields.push(Field {
                name: "serverSig".to_string(),
                ark_type: "signature".to_string(),
                encoding: Encoding::Schnorr64,
                is_server_injected: true,
            });
        }

        fields
    };

    let user_fields = all_fields
        .iter()
        .filter(|f| !f.is_server_injected)
        .cloned()
        .collect();

    let requirements = func
        .require
        .iter()
        .map(|r| {
            if let Some(ref msg) = r.message {
                format!("{}: {}", r.req_type, msg)
            } else {
                r.req_type.clone()
            }
        })
        .collect();

    let is_nofn_fallback = func.require.iter().any(|r| r.req_type == "nOfNMultisig");

    VariantIR {
        user_fields,
        all_fields,
        asm: func.asm.clone(),
        requirements,
        is_nofn_fallback,
    }
}
