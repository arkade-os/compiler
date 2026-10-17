//! Read an `arkadec` artifact into a [`Program`].
//!
//! [`program_from_artifact`] walks the compiler leaves the same way the
//! TypeScript SDK does. Types and `OP_` names stay as the compiler wrote them.

use std::collections::HashSet;
use std::fmt::Display;

use serde::Serialize;

use crate::models::{
    flatten_parameter, is_builtin_struct, is_builtin_type, AbiLeaf, ContractJson, Parameter,
    StructDefinition, WitnessElement, ARTIFACT_FORMAT_VERSION,
};

/// Program shape produced by [`program_from_artifact`].
pub const PROGRAM_VERSION: u32 = 1;

/// A compiled contract, ready for a caller to bind constructor arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Program {
    pub version: u32,
    pub name: String,
    pub params: Vec<Param>,
    pub functions: Vec<Function>,
}

impl Program {
    /// The spend path named `name`.
    pub fn function(&self, name: &str) -> Option<&Function> {
        self.functions.iter().find(|function| function.name == name)
    }
}

/// One flattened constructor argument or function input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Param {
    pub name: String,
    #[serde(rename = "type")]
    pub value_type: ValueType,
}

/// Compiler types, uncollapsed. `bytes32` is not rewritten to a generic hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ValueType {
    Pubkey,
    Signature,
    Bytes,
    Bytes20,
    Bytes32,
    Asset,
    #[serde(rename = "AssetGroup")]
    AssetGroup,
    Int,
    Bool,
}

impl ValueType {
    fn encoding(self) -> &'static str {
        match self {
            Self::Pubkey | Self::Bytes => "raw",
            Self::Signature => "schnorr-64",
            Self::Bytes20 => "raw-20",
            Self::Bytes32 | Self::Asset => "raw-32",
            Self::Int | Self::Bool | Self::AssetGroup => "scriptnum",
        }
    }

    fn from_artifact(ark_type: &str) -> Result<Self, String> {
        match ark_type {
            "pubkey" => Ok(Self::Pubkey),
            "signature" => Ok(Self::Signature),
            "bytes" => Ok(Self::Bytes),
            "bytes20" => Ok(Self::Bytes20),
            "bytes32" => Ok(Self::Bytes32),
            "asset" => Ok(Self::Asset),
            "AssetGroup" => Ok(Self::AssetGroup),
            "int" => Ok(Self::Int),
            "bool" => Ok(Self::Bool),
            other => Err(err(format!("unknown type '{other}'"))),
        }
    }
}

/// A key that must sign a tapleaf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Signer {
    /// Constructor pubkey, or the appended `server` role.
    Param(String),
    /// `tweak(base, func)`: `base` signed by that function's covenant.
    Tweaked { base: String, func: String },
    /// Function name from `<EMULATOR_KEY:fn>`, in script order.
    Emulator(String),
}

/// CLTV operand. A placeholder is the flattened constructor name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum LockValue {
    Param(String),
    Number(u64),
}

/// CSV operand. Constructor placeholders stay names; the server delay is a role.
/// Canonical literals decode to blocks or seconds (512-second units, bit 22 set).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CsvValue {
    Param(String),
    /// The server-configured unilateral exit delay (`<SERVER_EXIT_DELAY>`).
    ServerExitDelay,
    Blocks(u64),
    Seconds(u64),
}

/// One token of a condition or covenant script.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AsmToken {
    Opcode(String),
    /// Decimal text, preserving integers of any width without JSON rounding.
    Number(String),
    Bytes(Vec<u8>),
    /// Flattened placeholder name, including a child-output parameter.
    Param(String),
}

/// L1 tapleaf. `condition` keeps preimage length checks and the hash comparison,
/// with only the trailing `OP_VERIFY` removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Tapscript {
    pub signers: Vec<Signer>,
    /// Optional preimage length check followed by the hash comparison.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub condition: Vec<AsmToken>,
    /// Relative lock decoded from a canonical BIP68 sequence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csv: Option<CsvValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cltv: Option<LockValue>,
    /// Non-signature witness values the caller supplies (a preimage, for example).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub witness: Vec<String>,
    /// Caller signatures supplied through transaction signing, in artifact order.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<Param>,
}

/// Emulator covenant copied onto every leaf of its spend group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArkadeScript {
    pub asm: Vec<AsmToken>,
    /// Covenant inputs in reverse declaration order.
    pub witness: Vec<String>,
}

/// One spend path, named after its source tapleaf, in artifact order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Function {
    pub name: String,
    /// Compiler spend group used to resolve named covenant commitments.
    pub group: String,
    /// Colliding tapleaf inputs use a `tapscript:` prefix.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<Param>,
    pub tapscript: Tapscript,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arkade: Option<ArkadeScript>,
}

/// Parse a compiled artifact into a [`Program`].
///
/// Always appends a `server` pubkey parameter. `<CONTRACT:...>` placeholders
/// become extra `bytes32` parameters in the order they appear. The name is
/// `contract_` plus the sanitized body.
pub fn program_from_artifact(artifact: &ContractJson) -> Result<Program, String> {
    if let Some(version) = artifact.format_version {
        if version != ARTIFACT_FORMAT_VERSION {
            return Err(err(format!(
                "unsupported artifact format version: {version}"
            )));
        }
    }
    if artifact.name.is_empty() || artifact.functions.is_empty() {
        return Err(err(
            "expected a complete arkadec artifact with contractName, constructorInputs, and non-empty functions",
        ));
    }

    let mut struct_names = HashSet::new();
    for definition in &artifact.structs {
        if is_builtin_type(&definition.name) || is_builtin_struct(&definition.name) {
            return Err(err(format!(
                "struct name '{}' shadows a built-in type",
                definition.name
            )));
        }
        claim(&mut struct_names, &definition.name, "struct")?;
        let mut fields = HashSet::new();
        for field in &definition.fields {
            if field.name.is_empty() || field.param_type.is_empty() {
                return Err(err(format!(
                    "struct '{}': field needs a name and type",
                    definition.name
                )));
            }
            claim(&mut fields, &field.name, "struct field")?;
        }
    }

    let mut instantiations = Vec::new();
    let mut functions = Vec::new();
    let mut groups = HashSet::new();
    let mut leaf_names = HashSet::new();

    for group in &artifact.functions {
        claim(&mut groups, &group.name, "spend group")?;
        if group.leaves.is_empty() {
            return Err(err(format!("spend group '{}' has no leaves", group.name)));
        }

        let (covenant_inputs, arkade) = if let Some(covenant) = &group.arkade {
            let inputs = flatten_all(
                covenant
                    .inputs
                    .iter()
                    .map(|input| (input.name.as_str(), input.param_type.as_str())),
                &artifact.structs,
            )?;
            let mut input_names = HashSet::new();
            for input in &inputs {
                claim(&mut input_names, &input.name, "covenant input")?;
            }
            let script = ArkadeScript {
                asm: covenant
                    .asm
                    .iter()
                    .map(|token| asm_token(token, &mut instantiations))
                    .collect::<Result<Vec<_>, _>>()?,
                witness: inputs
                    .iter()
                    .rev()
                    .map(|param| param.name.clone())
                    .collect(),
            };
            (inputs, Some(script))
        } else {
            (Vec::new(), None)
        };

        for leaf in &group.leaves {
            claim(&mut leaf_names, &leaf.name, "function name")?;
            if leaf.asm.is_empty() {
                return Err(err(format!("leaf '{}': assembly is empty", leaf.name)));
            }
            let (mut extras, signatures) = witness_fields(&leaf.witness)?;
            // ponytail: scan each small leaf per collision; index tokens if leaves grow large.
            for extra in &mut extras {
                if leaf.asm.contains(&format!("<{}>", extra.name)) {
                    return Err(err(format!(
                        "leaf '{}': call input '{}' is a script operand; it must be a constructor binding to derive a fixed Taproot tree",
                        leaf.name, extra.name
                    )));
                }
                if covenant_inputs.iter().any(|input| input.name == extra.name) {
                    extra.name.insert_str(0, "tapscript:");
                }
            }
            let mut tapscript =
                parse_leaf(leaf, group.arkade.is_some(), &mut instantiations, &extras)?;
            for signer in &tapscript.signers {
                if let Signer::Emulator(covenant) = signer {
                    if covenant != &group.name {
                        return Err(err(format!(
                            "leaf '{}': emulator covenant '{covenant}' must match group '{}'",
                            leaf.name, group.name
                        )));
                    }
                }
            }
            tapscript.signatures = signatures;
            let mut inputs = covenant_inputs.clone();
            inputs.extend(extras);
            let mut input_names = HashSet::new();
            for input in &inputs {
                claim(&mut input_names, &input.name, "function input")?;
            }
            functions.push(Function {
                name: leaf.name.clone(),
                group: group.name.clone(),
                inputs,
                tapscript,
                arkade: arkade.clone(),
            });
        }
    }

    let mut params = flatten_all(
        artifact
            .parameters
            .iter()
            .map(|input| (input.name.as_str(), input.param_type.as_str())),
        &artifact.structs,
    )?;
    params.push(Param {
        name: "server".to_string(),
        value_type: ValueType::Pubkey,
    });
    if functions
        .iter()
        .any(|function| function.tapscript.csv == Some(CsvValue::ServerExitDelay))
    {
        params.push(Param {
            name: "SERVER_EXIT_DELAY".to_string(),
            value_type: ValueType::Int,
        });
    }
    for (name, _) in &instantiations {
        params.push(Param {
            name: name.clone(),
            value_type: ValueType::Bytes32,
        });
    }
    let mut param_names = HashSet::new();
    for param in &params {
        claim(&mut param_names, &param.name, "program parameter")?;
    }

    Ok(Program {
        version: PROGRAM_VERSION,
        name: artifact.name.clone(),
        params,
        functions,
    })
}

/// Parse artifact JSON into a [`Program`].
pub fn program_from_json(json: &str) -> Result<Program, String> {
    let artifact: ContractJson = serde_json::from_str(json).map_err(err)?;
    program_from_artifact(&artifact)
}

fn err(detail: impl Display) -> String {
    format!("program_from_artifact: {detail}")
}

fn claim(seen: &mut HashSet<String>, name: &str, kind: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err(err(format!("empty {kind}")));
    }
    if !seen.insert(name.to_string()) {
        return Err(err(format!("duplicate {kind} '{name}'")));
    }
    Ok(())
}

fn flatten_all<'a>(
    params: impl IntoIterator<Item = (&'a str, &'a str)>,
    structs: &[StructDefinition],
) -> Result<Vec<Param>, String> {
    let mut flat = Vec::new();
    for (name, declared_type) in params {
        flat.extend(flatten_named(name, declared_type, structs)?);
    }
    Ok(flat)
}

fn flatten_named(
    name: &str,
    declared_type: &str,
    structs: &[StructDefinition],
) -> Result<Vec<Param>, String> {
    if name.is_empty() || declared_type.is_empty() {
        return Err(err("parameter needs a name and a type"));
    }
    let parameter = Parameter {
        name: name.to_string(),
        param_type: declared_type.to_string(),
    };
    flatten_parameter(&parameter, structs)
        .map_err(err)?
        .into_iter()
        .map(|leaf| {
            Ok(Param {
                name: leaf.emitted_name,
                value_type: ValueType::from_artifact(&leaf.leaf_type)?,
            })
        })
        .collect()
}

fn witness_fields(witness: &[WitnessElement]) -> Result<(Vec<Param>, Vec<Param>), String> {
    let mut extras = Vec::new();
    let mut signatures = Vec::new();
    let mut names = HashSet::new();
    for item in witness {
        if item.name.is_empty() || item.elem_type.is_empty() {
            return Err(err("witness item needs a name and a type"));
        }
        claim(&mut names, &item.name, "leaf witness")?;
        let value_type = ValueType::from_artifact(&item.elem_type)?;
        if item.injected && value_type != ValueType::Signature {
            return Err(err(format!(
                "witness '{}': only infrastructure signatures can be injected",
                item.name
            )));
        }
        if item.encoding != value_type.encoding() {
            return Err(err(format!(
                "witness '{}': encoding '{}' does not match type '{}'",
                item.name, item.encoding, item.elem_type
            )));
        }
        if !item.injected {
            let param = Param {
                name: item.name.clone(),
                value_type,
            };
            if value_type == ValueType::Signature {
                signatures.push(param);
            } else {
                extras.push(param);
            }
        }
    }
    Ok((extras, signatures))
}

/// `SingleSig(<sellerPk>,<exit>)` → `contract_SingleSig_sellerPk_exit`.
fn instantiation_param(body: &str) -> String {
    let mut collapsed = String::new();
    let mut pending_separator = false;
    for ch in body.chars() {
        if ch.is_ascii_alphanumeric() {
            if pending_separator {
                collapsed.push('_');
            }
            pending_separator = false;
            collapsed.push(ch);
        } else {
            pending_separator = true;
        }
    }
    format!("contract_{collapsed}")
        .trim_end_matches('_')
        .to_string()
}

fn remember_instantiation(
    entries: &mut Vec<(String, String)>,
    body: &str,
) -> Result<String, String> {
    let name = instantiation_param(body);
    if let Some((_, seen)) = entries.iter().find(|(existing, _)| existing == &name) {
        if seen != body {
            return Err(err(format!(
                "instantiations '{seen}' and '{body}' both map to parameter '{name}'"
            )));
        }
    } else {
        entries.push((name.clone(), body.to_string()));
    }
    Ok(name)
}

fn asm_token(token: &str, instantiations: &mut Vec<(String, String)>) -> Result<AsmToken, String> {
    if token.starts_with("OP_") {
        if !crate::opcodes::is_opcode(token) {
            return Err(err(format!("unknown opcode '{token}'")));
        }
        return Ok(AsmToken::Opcode(token.to_string()));
    }
    if let Some(inner) = placeholder(token) {
        if inner.is_empty() {
            return Err(err(format!("unrecognized assembly token '{token}'")));
        }
        if let Some(body) = inner.strip_prefix("CONTRACT:") {
            return Ok(AsmToken::Param(remember_instantiation(
                instantiations,
                body,
            )?));
        }
        if inner.starts_with("VTXO:") {
            return Err(err(format!(
                "'{token}' is not a placeholder; the compiler emits <CONTRACT:...>"
            )));
        }
        if inner == "SERVER_KEY" || inner.starts_with("EMULATOR_KEY:") {
            return Err(err(format!(
                "{token} is a signer role and cannot appear in a covenant"
            )));
        }
        return Ok(AsmToken::Param(inner.to_string()));
    }
    if let Some(hex) = token.strip_prefix("0x") {
        return decode_hex(hex)
            .map(AsmToken::Bytes)
            .map_err(|_| err(format!("invalid hex '{token}'")));
    }
    let digits = token.strip_prefix('-').unwrap_or(token);
    if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(AsmToken::Number(token.to_string()));
    }
    Err(err(format!("unrecognized assembly token '{token}'")))
}

fn placeholder(token: &str) -> Option<&str> {
    token
        .strip_prefix('<')
        .and_then(|rest| rest.strip_suffix('>'))
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, ()> {
    if !hex.is_ascii() || !hex.len().is_multiple_of(2) {
        return Err(());
    }
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).map_err(|_| ()))
        .collect()
}

const BIP68_SECONDS_FLAG: u64 = 1 << 22;
const BIP68_DISABLE_FLAG: u64 = 1 << 31;
const BIP68_VALUE_MASK: u64 = 0xffff;
const BIP68_SECONDS_GRANULARITY: u64 = 512;

/// Decode only BIP68 sequences that re-encode to the same operand.
fn decode_bip68(operand: u64) -> Option<CsvValue> {
    if operand >= BIP68_DISABLE_FLAG {
        return None;
    }
    let count = operand & BIP68_VALUE_MASK;
    let seconds = operand & BIP68_SECONDS_FLAG != 0;
    let canonical = if seconds {
        count | BIP68_SECONDS_FLAG
    } else {
        count
    };
    if canonical != operand {
        return None;
    }
    if seconds {
        Some(CsvValue::Seconds(count * BIP68_SECONDS_GRANULARITY))
    } else {
        Some(CsvValue::Blocks(count))
    }
}

fn csv_value(leaf: &str, token: &str) -> Result<CsvValue, String> {
    if token == "<SERVER_EXIT_DELAY>" {
        return Ok(CsvValue::ServerExitDelay);
    }
    if let Some(inner) = placeholder(token) {
        if inner.is_empty() {
            return Err(err(format!("unrecognized timelock '{token}'")));
        }
        return Ok(CsvValue::Param(inner.to_string()));
    }
    let operand = token
        .parse::<u64>()
        .map_err(|_| err(format!("unrecognized timelock '{token}'")))?;
    decode_bip68(operand).ok_or_else(|| {
        err(format!(
            "leaf '{leaf}': CSV literal {operand} is not a canonical BIP68 sequence"
        ))
    })
}

fn lock_value(token: &str) -> Result<LockValue, String> {
    if let Some(inner) = placeholder(token) {
        if inner.is_empty() {
            return Err(err(format!("unrecognized timelock '{token}'")));
        }
        return Ok(LockValue::Param(inner.to_string()));
    }
    token
        .parse::<u64>()
        .map(LockValue::Number)
        .map_err(|_| err(format!("unrecognized timelock '{token}'")))
}

fn parse_tweak(rest: &str) -> Option<(String, String)> {
    let (base, func) = rest.split_once(':')?;
    if base.is_empty() || func.is_empty() || func.contains(':') {
        return None;
    }
    Some((base.to_string(), func.to_string()))
}

fn parse_leaf(
    leaf: &AbiLeaf,
    has_covenant: bool,
    instantiations: &mut Vec<(String, String)>,
    extras: &[Param],
) -> Result<Tapscript, String> {
    let asm = &leaf.asm;
    let mut index = 0;
    let mut condition = Vec::new();

    if asm.len() >= 7
        && asm[0] == "OP_SIZE"
        && matches!(asm[1].as_str(), "20" | "32")
        && asm[2] == "OP_EQUALVERIFY"
        && is_hash_opcode(&asm[3])
    {
        index = 3;
    }
    if asm.len() >= index + 4 && is_hash_opcode(&asm[index]) && asm[index + 2] == "OP_EQUAL" {
        if asm[index + 3] != "OP_VERIFY" {
            return Err(err(format!(
                "leaf '{}': hash condition must end in OP_VERIFY",
                leaf.name
            )));
        }
        for token in &asm[..index + 3] {
            condition.push(asm_token(token, instantiations)?);
        }
        index += 4;
    }

    let mut csv = None;
    let mut cltv = None;
    if asm.len() >= index + 3 && asm[index + 2] == "OP_DROP" {
        match asm[index + 1].as_str() {
            "OP_CHECKSEQUENCEVERIFY" => csv = Some(csv_value(&leaf.name, &asm[index])?),
            "OP_CHECKLOCKTIMEVERIFY" => cltv = Some(lock_value(&asm[index])?),
            other => {
                return Err(err(format!(
                    "leaf '{}': unexpected timelock opcode {other}",
                    leaf.name
                )));
            }
        }
        index += 3;
    }

    let mut signers = Vec::new();
    while index < asm.len() {
        let key = &asm[index];
        let terminator = asm.get(index + 1).map(String::as_str).unwrap_or("");
        let expected = if index + 2 == asm.len() {
            "OP_CHECKSIG"
        } else {
            "OP_CHECKSIGVERIFY"
        };
        if terminator != expected {
            let found = if terminator.is_empty() {
                "end of script"
            } else {
                terminator
            };
            return Err(err(format!(
                "leaf '{}': expected CHECKSIG after '{key}', found '{found}'",
                leaf.name
            )));
        }
        let Some(inner) = placeholder(key).filter(|inner| !inner.is_empty()) else {
            return Err(err(format!(
                "leaf '{}': unsupported key operand '{key}'",
                leaf.name
            )));
        };
        if inner == "SERVER_KEY" {
            signers.push(Signer::Param("server".to_string()));
        } else if let Some(rest) = inner.strip_prefix("TWEAK:") {
            let (base, func) = parse_tweak(rest)
                .ok_or_else(|| err(format!("leaf '{}': malformed tweak '{key}'", leaf.name)))?;
            signers.push(Signer::Tweaked { base, func });
        } else if let Some(func) = inner.strip_prefix("EMULATOR_KEY:") {
            if !has_covenant {
                return Err(err(format!("leaf '{}': {key} needs a covenant", leaf.name)));
            }
            if func.is_empty() {
                return Err(err(format!(
                    "leaf '{}': malformed emulator '{key}'",
                    leaf.name
                )));
            }
            if signers
                .iter()
                .any(|signer| matches!(signer, Signer::Emulator(_)))
            {
                return Err(err(format!(
                    "leaf '{}': duplicate emulator signer",
                    leaf.name
                )));
            }
            signers.push(Signer::Emulator(func.to_string()));
        } else {
            signers.push(Signer::Param(inner.to_string()));
        }
        index += 2;
    }

    if has_covenant
        && !signers
            .iter()
            .any(|signer| matches!(signer, Signer::Tweaked { .. } | Signer::Emulator(_)))
    {
        return Err(err(format!(
            "leaf '{}': covenant leaf must sign with the emulator or a tweaked constructor key",
            leaf.name
        )));
    }
    if signers.is_empty() {
        return Err(err(format!(
            "leaf '{}': at least one named signer is required",
            leaf.name
        )));
    }

    Ok(Tapscript {
        signers,
        condition,
        csv,
        cltv,
        witness: extras.iter().map(|param| param.name.clone()).collect(),
        signatures: Vec::new(),
    })
}

fn is_hash_opcode(token: &str) -> bool {
    matches!(
        token,
        "OP_SHA256" | "OP_HASH160" | "OP_HASH256" | "OP_RIPEMD160"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn artifact() -> serde_json::Value {
        json!({
            "formatVersion": 1,
            "contractName": "Demo",
            "constructorInputs": [{"name": "digest", "type": "bytes32"}],
            "structs": [],
            "functions": [{
                "name": "spend",
                "arkade": {"inputs": [], "asm": ["OP_1"]},
                "leaves": [{
                    "name": "claim",
                    "witness": [
                        {"name": "preimage", "type": "bytes32", "encoding": "raw-32", "injected": false},
                        {"name": "userSig", "type": "signature", "encoding": "schnorr-64"},
                        {"name": "serverSig", "type": "signature", "encoding": "schnorr-64", "injected": true}
                    ],
                    "asm": ["OP_SIZE", "32", "OP_EQUALVERIFY", "OP_SHA256", "<digest>", "OP_EQUAL", "OP_VERIFY", "<SERVER_KEY>", "OP_CHECKSIGVERIFY", "<EMULATOR_KEY:spend>", "OP_CHECKSIG"]
                }]
            }]
        })
    }

    #[test]
    fn caller_signatures_are_separate_from_inputs_and_injected_signatures() {
        let program = program_from_json(&artifact().to_string()).unwrap();
        let claim = program.function("claim").unwrap();
        assert_eq!(program.version, 1);
        assert_eq!(claim.group, "spend");
        assert_eq!(
            claim.inputs,
            vec![Param {
                name: "preimage".into(),
                value_type: ValueType::Bytes32,
            }]
        );
        assert_eq!(claim.tapscript.witness, ["preimage"]);
        assert_eq!(
            claim.tapscript.signatures,
            vec![Param {
                name: "userSig".into(),
                value_type: ValueType::Signature,
            }]
        );
        assert_eq!(
            serde_json::to_value(&claim.tapscript).unwrap()["signatures"],
            json!([{"name": "userSig", "type": "signature"}])
        );
    }

    #[test]
    fn malformed_artifact_declarations_are_rejected_at_both_entry_points() {
        for (pointer, replacement, expected) in [
            ("/contractName", json!(""), "complete arkadec artifact"),
            ("/functions/0/name", json!(""), "empty spend group"),
            (
                "/functions/0/leaves/0/name",
                json!(""),
                "empty function name",
            ),
            ("/functions/0/leaves/0/asm", json!([]), "assembly is empty"),
            (
                "/functions/0/leaves/0/asm",
                json!(["<EMULATOR_KEY:other>", "OP_CHECKSIG"]),
                "must match group 'spend'",
            ),
            (
                "/functions/0/leaves/0/asm",
                json!([
                    "<EMULATOR_KEY:spend>",
                    "OP_CHECKSIGVERIFY",
                    "<EMULATOR_KEY:spend>",
                    "OP_CHECKSIG"
                ]),
                "duplicate emulator signer",
            ),
            (
                "/functions/0/arkade/asm",
                json!(["OP_NOT_A_REAL_OPCODE"]),
                "unknown opcode",
            ),
            (
                "/functions/0/arkade/inputs",
                json!([{"name": "n", "type": "int"}, {"name": "n", "type": "int"}]),
                "duplicate covenant input",
            ),
            (
                "/functions/0/leaves/0/witness/0/injected",
                json!(true),
                "only infrastructure signatures can be injected",
            ),
            (
                "/functions/0/leaves/0/witness/2/type",
                json!("unknown"),
                "unknown type",
            ),
            (
                "/functions/0/leaves/0/witness/2/encoding",
                json!("raw"),
                "does not match type",
            ),
            (
                "/functions/0/leaves/0/witness/0/encoding",
                json!("raw-20"),
                "does not match type",
            ),
            (
                "/functions/0/leaves/0/witness/1/name",
                json!("serverSig"),
                "duplicate leaf witness",
            ),
            (
                "/functions/0/leaves/0/witness/0/name",
                json!(""),
                "witness item needs a name and a type",
            ),
            (
                "/constructorInputs/0/name",
                json!(""),
                "parameter needs a name and a type",
            ),
            ("/constructorInputs/0/type", json!("hash"), "unknown type"),
            (
                "/structs",
                json!([{"name": "S", "fields": [{"name": "x", "type": "int"}, {"name": "x", "type": "int"}]}]),
                "duplicate struct field",
            ),
            (
                "/structs",
                json!([{"name": "S", "fields": [{"name": "", "type": "int"}]}]),
                "field needs a name and type",
            ),
        ] {
            let mut json = artifact();
            *json.pointer_mut(pointer).unwrap() = replacement;
            let typed: ContractJson = serde_json::from_value(json.clone()).unwrap();
            let error = program_from_artifact(&typed).unwrap_err();
            assert!(error.contains(expected), "{pointer}: {error}");
            assert_eq!(program_from_json(&json.to_string()).unwrap_err(), error);
        }
    }

    #[test]
    fn duplicate_source_leaf_names_are_rejected_across_groups() {
        let mut json = artifact();
        json["functions"].as_array_mut().unwrap().push(json!({
            "name": "other",
            "leaves": [{"name": "claim", "witness": [], "asm": ["<SERVER_KEY>", "OP_CHECKSIG"]}]
        }));
        assert!(program_from_json(&json.to_string())
            .unwrap_err()
            .contains("duplicate function name 'claim'"));
    }

    #[test]
    fn malformed_array_layouts_are_rejected() {
        for declared_type in [
            "int[0]",
            "int[+1]",
            "int[1e2]",
            "int[]",
            "int[1][2]",
            "int[18446744073709551616]",
        ] {
            let mut json = artifact();
            json["constructorInputs"][0]["type"] = json!(declared_type);
            assert!(
                program_from_json(&json.to_string())
                    .unwrap_err()
                    .contains("invalid array type"),
                "{declared_type}"
            );
        }
    }

    #[test]
    fn arrays_of_structs_and_native_layouts_flatten_in_compiler_order() {
        let mut json = artifact();
        json["structs"] =
            json!([{"name": "Policy", "fields": [{"name": "owners", "type": "Outpoint[2]"}]}]);
        json["constructorInputs"] = json!([
            {"name": "entries", "type": "AssetEntry[2]"},
            {"name": "lookup", "type": "AssetLookup"},
            {"name": "spk", "type": "ScriptPubKey"},
            {"name": "point", "type": "ECPoint"},
            {"name": "g2", "type": "G2Point"},
            {"name": "policies", "type": "Policy[2]"}
        ]);
        let program = program_from_json(&json.to_string()).unwrap();
        assert_eq!(
            program
                .params
                .iter()
                .map(|param| param.name.as_str())
                .collect::<Vec<_>>(),
            [
                "entries.0.assetId.txid",
                "entries.0.assetId.gidx",
                "entries.0.amount",
                "entries.1.assetId.txid",
                "entries.1.assetId.gidx",
                "entries.1.amount",
                "lookup.amount",
                "lookup.found",
                "spk.program",
                "spk.version",
                "point.x",
                "point.y",
                "g2.xC1",
                "g2.xC0",
                "g2.yC1",
                "g2.yC0",
                "policies.0.owners.0.txid",
                "policies.0.owners.0.vout",
                "policies.0.owners.1.txid",
                "policies.0.owners.1.vout",
                "policies.1.owners.0.txid",
                "policies.1.owners.0.vout",
                "policies.1.owners.1.txid",
                "policies.1.owners.1.vout",
                "server"
            ]
        );
        json["structs"][0]["fields"][0]["type"] = json!("Policy[1]");
        assert!(program_from_json(&json.to_string())
            .unwrap_err()
            .contains("recursive struct layout"));
    }

    #[test]
    fn malformed_hex_returns_an_error() {
        assert!(asm_token("0x0é0", &mut Vec::new()).is_err());
        assert!(asm_token("0x0", &mut Vec::new()).is_err());
        assert_eq!(
            asm_token("0x00ff", &mut Vec::new()).unwrap(),
            AsmToken::Bytes(vec![0, 255])
        );
    }

    #[test]
    fn instantiation_param_collapses_like_the_sdk() {
        assert_eq!(
            instantiation_param("SingleSig(<sellerPk>,<exit>)"),
            "contract_SingleSig_sellerPk_exit"
        );
        assert_eq!(instantiation_param("A-B"), "contract_A_B");
        assert_eq!(instantiation_param("___"), "contract");
    }

    #[test]
    fn malformed_integer_tokens_are_rejected() {
        for invalid in ["-", "+1", "1.0", "1e3", "１２"] {
            assert!(asm_token(invalid, &mut Vec::new()).is_err());
        }
    }

    #[test]
    fn disabled_csv_literals_are_rejected() {
        for operand in [1 << 31, u32::MAX as u64 + 1, u64::MAX] {
            assert!(decode_bip68(operand).is_none());
        }
    }
}
