//! The compiled contract as it is serialized to JSON: the public artifact format.

use super::{Parameter, StructDefinition};
use serde::{Deserialize, Serialize};

fn is_false(value: &bool) -> bool {
    !*value
}

pub const ARTIFACT_FORMAT_VERSION: u32 = 1;

/// Function input parameter
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FunctionInput {
    /// Parameter name
    pub name: String,
    /// Parameter type
    #[serde(rename = "type")]
    pub param_type: String,
}

/// A single element in a tapleaf's `witness` array.
///
/// Each leaf's `witness` lists every value the caller must supply at spend time,
/// in source-declared order (constructor parameters, which are baked into the
/// script, are excluded).
///
/// The `encoding` field is a stable identifier that code generators
/// (TypeScript, Go, …) can switch on to pick the correct serializer:
///
/// | encoding        | description                                   |
/// |-----------------|-----------------------------------------------|
/// | `schnorr-64`    | 64-byte Schnorr signature (BIP-340)           |
/// | `raw`           | arbitrary byte array (caller decides length)  |
/// | `raw-20`        | 20-byte array (e.g., HASH160)                 |
/// | `raw-32`        | 32-byte array (e.g., SHA256, txid)            |
/// | `scriptnum`     | Bitcoin CScriptNum (variable-length LE)       |
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WitnessElement {
    /// Parameter name (matches an `<name>` placeholder in `asm`)
    pub name: String,
    /// Arkade Script type string (e.g., `"pubkey"`, `"signature"`, `"bytes32"`)
    #[serde(rename = "type")]
    pub elem_type: String,
    /// Wire-encoding descriptor for client stub generators
    pub encoding: String,
    /// True when Arkade infrastructure supplies this witness field.
    #[serde(default, skip_serializing_if = "is_false")]
    pub injected: bool,
}

/// The emulator-run covenant for a function-backed spend group.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ArkadeCovenant {
    /// Covenant inputs (function parameters, array-expanded). No server/emulator sigs.
    pub inputs: Vec<FunctionInput>,
    /// Covenant assembly.
    pub asm: Vec<String>,
}

/// One L1 tapleaf within a spend group.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AbiLeaf {
    /// Leaf name (source tapscript name, or covenant name for a synthesized default).
    pub name: String,
    /// Ordered witness stack the caller supplies at spend time.
    pub witness: Vec<WitnessElement>,
    /// Tapleaf assembly (pubkeys + ops; signatures live in `witness`).
    pub asm: Vec<String>,
}

/// A spend group: an optional covenant plus its L1 leaves.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AbiFunctionGroup {
    /// Group name (covenant function name, or a standalone leaf's own name).
    pub name: String,
    /// Emulator covenant; absent for groups containing only standalone leaves.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arkade: Option<ArkadeCovenant>,
    /// L1 tapleaves grouped under this entry.
    pub leaves: Vec<AbiLeaf>,
}

/// JSON output for a contract
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ContractJson {
    #[serde(rename = "formatVersion", skip_serializing_if = "Option::is_none")]
    pub format_version: Option<u32>,
    #[serde(rename = "contractName")]
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub structs: Vec<StructDefinition>,
    #[serde(rename = "constructorInputs")]
    pub parameters: Vec<Parameter>,
    pub functions: Vec<AbiFunctionGroup>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceBundle>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiler: Option<CompilerInfo>,
    #[serde(rename = "updatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing, default)]
    pub warnings: Vec<String>,
}

/// Original files needed to reproduce a compilation without filesystem access.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SourceBundle {
    pub entry: String,
    pub files: std::collections::BTreeMap<String, String>,
}

/// Compiler information
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CompilerInfo {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<crate::CompileOptions>,
}
