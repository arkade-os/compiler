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
    /// The entry-file statement each run of `asm` tokens was compiled from; tokens the
    /// compiler adds itself, such as the final cleanup, are not covered. Written to the
    /// debug file (`ContractJson::debug_info`), not the artifact.
    #[serde(skip_serializing, default)]
    pub source_map: Vec<SourceRange>,
    /// Resource usage for reports; not part of the artifact.
    #[serde(skip)]
    pub costs: Vec<Cost>,
}

/// A run of covenant tokens and the source statement they come from.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SourceRange {
    /// Half-open range of indexes into `asm`.
    pub asm: [usize; 2],
    /// 1-based `[line, column]` of the statement's start and end, with columns in UTF-16
    /// code units.
    pub start: [usize; 2],
    pub end: [usize; 2],
    /// The statement's `require` message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Resource usage: script bytes (a lower bound, since variable-width arguments can add
/// more), stack peak, or an upper bound on executions of a named opcode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cost {
    pub name: String,
    pub used: usize,
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

impl ContractJson {
    /// The debug file: each covenant's source map keyed by spend group name, linked to this
    /// artifact by its fingerprint. Positions point into the artifact's `source` bundle.
    pub fn debug_info(&self) -> serde_json::Value {
        let functions: serde_json::Map<_, _> = self
            .functions
            .iter()
            .filter_map(|group| {
                let arkade = group.arkade.as_ref()?;
                Some((
                    group.name.clone(),
                    serde_json::json!({ "sourceMap": arkade.source_map }),
                ))
            })
            .collect();
        serde_json::json!({
            "formatVersion": 1,
            "artifactFingerprint": self.fingerprint,
            "functions": functions,
        })
    }
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
