//! Read an `arkadec` artifact into a [`Program`].
//!
//! [`program_from_artifact`] walks the same leaves as the TypeScript SDK's
//! `programFromArtifact`: one spend path per compiler leaf, constructor
//! parameters flattened through structs, and `<VTXO:...>` placeholders turned
//! into parameters the caller binds to a child program. Call this instead of
//! parsing the artifact again.
//!
//! The value keeps the compiler's own types ([`ValueType::Bytes32`] stays
//! distinct from a 20-byte hash) and canonical `OP_` names. The emulator
//! co-signer is [`Tapscript::emulator`], not another signer. Placeholder names
//! have no `$` prefix.

use std::collections::HashSet;
use std::fmt::Display;

use serde::Serialize;

use crate::models::{
    flatten_parameter, is_builtin_struct, is_builtin_type, AbiLeaf, ContractJson, Parameter,
    StructDefinition, WitnessElement,
};
use crate::opcodes::{self, opcode};

/// Program shape produced by [`program_from_artifact`].
pub const PROGRAM_VERSION: u32 = 0;

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
    Int,
    Bool,
}

impl ValueType {
    fn from_artifact(ark_type: &str) -> Result<Self, String> {
        match ark_type {
            "pubkey" => Ok(Self::Pubkey),
            "signature" => Ok(Self::Signature),
            "bytes" => Ok(Self::Bytes),
            "bytes20" => Ok(Self::Bytes20),
            "bytes32" => Ok(Self::Bytes32),
            "asset" => Ok(Self::Asset),
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
}

/// CSV or CLTV operand. A placeholder is the flattened constructor name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum LockValue {
    Param(String),
    Number(u64),
}

/// One token of a condition or covenant script.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AsmToken {
    Opcode(&'static str),
    Number(i64),
    Bytes(Vec<u8>),
    /// Flattened placeholder name, including a `<VTXO:...>` parameter.
    Param(String),
}

/// L1 tapleaf. `condition` is the hash prefix with its trailing `OP_VERIFY` removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Tapscript {
    pub signers: Vec<Signer>,
    /// Hash condition (`OP_SHA256` / `OP_HASH160` / `OP_HASH256` / `OP_RIPEMD160`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub condition: Vec<AsmToken>,
    /// Relative lock. The operand is the CSV number as emitted; this reader does
    /// not split out the BIP68 seconds bit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csv: Option<LockValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cltv: Option<LockValue>,
    /// Non-signature witness values the caller supplies (a preimage, for example).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub witness: Vec<String>,
    /// Function name from `<EMULATOR_KEY:fn>` when this leaf has a covenant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emulator: Option<String>,
}

/// Emulator covenant copied onto every leaf of its spend group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArkadeScript {
    pub asm: Vec<AsmToken>,
    /// Covenant inputs in reverse declaration order.
    pub witness: Vec<String>,
}

/// One spend path. The first leaf of a group keeps the group name; later leaves
/// are `{group}/{index}:{leaf}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Function {
    pub name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<Param>,
    pub tapscript: Tapscript,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arkade: Option<ArkadeScript>,
}

/// Parse a compiled artifact into a [`Program`].
///
/// Always appends a `server` pubkey parameter. `<VTXO:...>` placeholders become
/// extra `bytes32` parameters in the order they appear.
pub fn program_from_artifact(artifact: &ContractJson) -> Result<Program, String> {
    if artifact.functions.is_empty() {
        return Err(err(
            "expected a complete arkadec artifact with contractName, constructorInputs, and non-empty functions",
        ));
    }

    let mut struct_names = HashSet::new();
    for definition in &artifact.structs {
        if definition.name.is_empty() {
            return Err(err("struct name is empty"));
        }
        if is_builtin_type(&definition.name) || is_builtin_struct(&definition.name) {
            return Err(err(format!(
                "struct name '{}' shadows a built-in type",
                definition.name
            )));
        }
        claim(&mut struct_names, &definition.name, "struct")?;
    }

    let mut instantiations = Instantiations::default();
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

        for (index, leaf) in group.leaves.iter().enumerate() {
            let name = if index == 0 {
                group.name.clone()
            } else {
                format!("{}/{index}:{}", group.name, leaf.name)
            };
            claim(&mut leaf_names, &name, "function name")?;
            let extras = witness_extras(&leaf.witness, &artifact.structs)?;
            let tapscript = parse_leaf(leaf, group.arkade.is_some(), &mut instantiations, &extras)?;
            let mut inputs = covenant_inputs.clone();
            inputs.extend(extras);
            functions.push(Function {
                name,
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
    for (name, _) in &instantiations.entries {
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

fn witness_extras(
    witness: &[WitnessElement],
    structs: &[StructDefinition],
) -> Result<Vec<Param>, String> {
    let mut extras = Vec::new();
    for item in witness {
        if item.name.is_empty() || item.elem_type.is_empty() {
            return Err(err("witness item needs a name and a type"));
        }
        if item.injected || item.elem_type == "signature" {
            continue;
        }
        let mut params = flatten_named(&item.name, &item.elem_type, structs)?;
        params.retain(|param| param.value_type != ValueType::Signature);
        extras.extend(params);
    }
    Ok(extras)
}

/// `<VTXO:SingleSig(<sellerPk>,<exit>)>` → `vtxo_SingleSig_sellerPk_exit`.
fn instantiation_param(token: &str) -> String {
    let body = token
        .strip_prefix("<VTXO:")
        .and_then(|rest| rest.strip_suffix('>'))
        .unwrap_or("");
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
    let mut name = format!("vtxo_{collapsed}");
    while name.ends_with('_') {
        name.pop();
    }
    name
}

#[derive(Default)]
struct Instantiations {
    entries: Vec<(String, String)>,
}

impl Instantiations {
    fn remember(&mut self, token: &str) -> Result<String, String> {
        let name = instantiation_param(token);
        if let Some((_, seen)) = self.entries.iter().find(|(existing, _)| existing == &name) {
            if seen != token {
                return Err(err(format!(
                    "instantiations '{seen}' and '{token}' both map to parameter '{name}'"
                )));
            }
        } else {
            self.entries.push((name.clone(), token.to_string()));
        }
        Ok(name)
    }
}

fn asm_token(token: &str, instantiations: &mut Instantiations) -> Result<AsmToken, String> {
    if let Some(op) = opcode(token) {
        return Ok(AsmToken::Opcode(op));
    }
    if let Some(inner) = placeholder(token) {
        if inner.is_empty() {
            return Err(err(format!("unrecognized assembly token '{token}'")));
        }
        if inner.starts_with("VTXO:") {
            return Ok(AsmToken::Param(instantiations.remember(token)?));
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
    if let Ok(number) = token.parse::<i64>() {
        return Ok(AsmToken::Number(number));
    }
    Err(err(format!("unrecognized assembly token '{token}'")))
}

fn placeholder(token: &str) -> Option<&str> {
    token
        .strip_prefix('<')
        .and_then(|rest| rest.strip_suffix('>'))
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, ()> {
    if !hex.len().is_multiple_of(2) {
        return Err(());
    }
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).map_err(|_| ()))
        .collect()
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
    instantiations: &mut Instantiations,
    extras: &[Param],
) -> Result<Tapscript, String> {
    let asm = &leaf.asm;
    let mut index = 0;
    let mut condition = Vec::new();

    if asm.len() >= 4 && is_hash_opcode(&asm[0]) && asm[2] == opcodes::OP_EQUAL {
        if asm[3] != opcodes::OP_VERIFY {
            return Err(err(format!(
                "leaf '{}': hash condition must end in OP_VERIFY",
                leaf.name
            )));
        }
        for token in &asm[..3] {
            condition.push(asm_token(token, instantiations)?);
        }
        index = 4;
    }

    let mut csv = None;
    let mut cltv = None;
    if asm.len() >= index + 3 && asm[index + 2] == opcodes::OP_DROP {
        let value = lock_value(&asm[index])?;
        match asm[index + 1].as_str() {
            opcodes::OP_CHECKSEQUENCEVERIFY => csv = Some(value),
            opcodes::OP_CHECKLOCKTIMEVERIFY => cltv = Some(value),
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
    let mut emulator = None;
    while index < asm.len() {
        let key = &asm[index];
        let terminator = asm.get(index + 1).map(String::as_str).unwrap_or("");
        let last = terminator == opcodes::OP_CHECKSIG;
        if !last && terminator != opcodes::OP_CHECKSIGVERIFY {
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
            if !last {
                return Err(err(format!(
                    "leaf '{}': {key} must be the last signer",
                    leaf.name
                )));
            }
            if func.is_empty() {
                return Err(err(format!(
                    "leaf '{}': malformed emulator '{key}'",
                    leaf.name
                )));
            }
            emulator = Some(func.to_string());
        } else {
            signers.push(Signer::Param(inner.to_string()));
        }
        index += 2;
    }

    if has_covenant && emulator.is_none() {
        return Err(err(format!(
            "leaf '{}': covenant leaf must end with the tweaked co-signer",
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
        emulator,
    })
}

fn is_hash_opcode(token: &str) -> bool {
    matches!(
        token,
        opcodes::OP_SHA256 | opcodes::OP_HASH160 | opcodes::OP_HASH256 | opcodes::OP_RIPEMD160
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcodes::{OP_EQUAL, OP_HASH160};

    fn example(rel: &str) -> Program {
        let path = format!("{}/examples/{rel}", env!("CARGO_MANIFEST_DIR"));
        let source = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let artifact = crate::compile(&source).unwrap_or_else(|e| panic!("{rel}: {e}"));
        let json = serde_json::to_string(&artifact).unwrap();
        let from_json = program_from_json(&json).unwrap_or_else(|e| panic!("{rel}: {e}"));
        let from_artifact =
            program_from_artifact(&artifact).unwrap_or_else(|e| panic!("{rel}: {e}"));
        assert_eq!(from_json, from_artifact);
        from_artifact
    }

    fn param(name: &str, value_type: ValueType) -> Param {
        Param {
            name: name.to_string(),
            value_type,
        }
    }

    #[test]
    fn single_sig_splits_the_covenant_from_the_csv_exit() {
        let program = example("single_sig/single_sig.ark");
        assert_eq!(program.version, PROGRAM_VERSION);
        assert_eq!(program.name, "SingleSig");
        assert_eq!(
            program.params,
            vec![
                param("user", ValueType::Pubkey),
                param("exit", ValueType::Int),
                param("server", ValueType::Pubkey),
            ]
        );

        let spend = program.function("spend").unwrap();
        assert_eq!(spend.inputs, vec![param("userSig", ValueType::Signature)]);
        assert_eq!(
            spend.tapscript.signers,
            vec![Signer::Param("server".into())]
        );
        assert_eq!(spend.tapscript.emulator.as_deref(), Some("spend"));
        assert!(spend.tapscript.csv.is_none());
        assert_eq!(
            spend.arkade.as_ref().unwrap().witness,
            vec!["userSig".to_string()]
        );

        let exit = program.function("unilateral").unwrap();
        assert!(exit.inputs.is_empty());
        assert!(exit.arkade.is_none());
        assert_eq!(exit.tapscript.signers, vec![Signer::Param("user".into())]);
        assert_eq!(exit.tapscript.emulator, None);
        assert_eq!(exit.tapscript.csv, Some(LockValue::Param("exit".into())));
    }

    #[test]
    fn htlc_keeps_hash_timelock_and_preimage_witness() {
        let program = example("htlc/htlc.ark");
        assert_eq!(
            program.params,
            vec![
                param("sender", ValueType::Pubkey),
                param("receiver", ValueType::Pubkey),
                param("preimageHash", ValueType::Bytes20),
                param("refundTime", ValueType::Int),
                param("exit", ValueType::Int),
                param("server", ValueType::Pubkey),
            ]
        );

        let claim = program.function("claim").unwrap();
        assert_eq!(claim.inputs, vec![param("preimage", ValueType::Bytes)]);
        assert_eq!(claim.tapscript.witness, vec!["preimage".to_string()]);
        assert_eq!(
            claim.tapscript.condition,
            vec![
                AsmToken::Opcode(OP_HASH160),
                AsmToken::Param("preimageHash".into()),
                AsmToken::Opcode(OP_EQUAL),
            ]
        );
        assert_eq!(
            claim.tapscript.signers,
            vec![Signer::Param("server".into())]
        );
        assert_eq!(claim.tapscript.emulator.as_deref(), Some("claim"));
        assert!(claim.arkade.is_some());

        let refund = program.function("refund").unwrap();
        assert!(refund.inputs.is_empty());
        assert_eq!(
            refund.tapscript.cltv,
            Some(LockValue::Param("refundTime".into()))
        );
        assert_eq!(refund.tapscript.emulator.as_deref(), Some("refund"));

        let exit = program.function("unilateral").unwrap();
        assert_eq!(exit.tapscript.csv, Some(LockValue::Param("exit".into())));
        assert_eq!(exit.tapscript.signers, vec![Signer::Param("sender".into())]);
        assert!(exit.tapscript.emulator.is_none());

        let json = serde_json::to_string(&program).unwrap();
        assert!(json.contains("OP_HASH160"));
        assert!(json.contains("\"bytes20\""));
        assert!(!json.contains("$preimageHash"));
        assert!(!json.contains("\"hash\""));
    }

    #[test]
    fn struct_vault_flattens_policy_fields() {
        let program = example("struct_vault/struct_vault.ark");
        assert_eq!(
            program.params,
            vec![
                param("policy.primary.key", ValueType::Pubkey),
                param("policy.primary.weight", ValueType::Int),
                param("policy.limits.0", ValueType::Int),
                param("policy.limits.1", ValueType::Int),
                param("policy.exitDelay", ValueType::Int),
                param("server", ValueType::Pubkey),
            ]
        );

        let update = program.function("update").unwrap();
        assert_eq!(
            update
                .inputs
                .iter()
                .map(|input| input.name.as_str())
                .collect::<Vec<_>>(),
            vec![
                "next.primary.key",
                "next.primary.weight",
                "next.limits.0",
                "next.limits.1",
                "next.exitDelay",
                "sig",
                "message",
            ]
        );
        assert_eq!(
            update
                .inputs
                .iter()
                .find(|input| input.name == "message")
                .unwrap()
                .value_type,
            ValueType::Bytes32
        );
        assert_eq!(
            update.arkade.as_ref().unwrap().witness,
            update
                .inputs
                .iter()
                .rev()
                .map(|input| input.name.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(update.tapscript.emulator.as_deref(), Some("update"));

        let exit = program.function("unilateral").unwrap();
        assert_eq!(
            exit.tapscript.csv,
            Some(LockValue::Param("policy.exitDelay".into()))
        );
        assert_eq!(
            exit.tapscript.signers,
            vec![Signer::Param("policy.primary.key".into())]
        );
    }

    #[test]
    fn vtxo_placeholder_becomes_a_bytes32_parameter() {
        let files = [
            (
                "single_sig.ark",
                "contract SingleSig(pubkey owner, int exit) {}",
            ),
            (
                "main.ark",
                r#"
                import "single_sig.ark";
                contract Recursive(pubkey ownerPk, int exit) {
                    function send() {
                        require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk, exit));
                    }
                }
                "#,
            ),
        ]
        .into_iter()
        .map(|(path, source)| (path.to_string(), source.to_string()))
        .collect();
        let artifact = crate::compile_sources("main.ark", &files).unwrap();
        let program = program_from_artifact(&artifact).unwrap();
        let send = program.function("send").unwrap();
        let vtxo = "vtxo_SingleSig_ownerPk_exit";
        assert!(send
            .arkade
            .as_ref()
            .unwrap()
            .asm
            .iter()
            .any(|token| { matches!(token, AsmToken::Param(name) if name == vtxo) }));
        assert_eq!(
            program.params.last().unwrap(),
            &param(vtxo, ValueType::Bytes32)
        );
    }

    fn leaf(asm: &[&str]) -> String {
        let asm = asm
            .iter()
            .map(|token| format!("\"{token}\""))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            r#"{{
                "contractName": "Demo",
                "constructorInputs": [{{"name": "user", "type": "pubkey"}}],
                "functions": [{{
                    "name": "spend",
                    "leaves": [{{
                        "name": "spend",
                        "witness": [],
                        "asm": [{asm}]
                    }}]
                }}]
            }}"#
        )
    }

    #[test]
    fn constructor_tweak_is_its_own_signer() {
        let program = program_from_json(&leaf(&["<TWEAK:insurer:late>", "OP_CHECKSIG"])).unwrap();
        assert_eq!(
            program.function("spend").unwrap().tapscript.signers,
            vec![Signer::Tweaked {
                base: "insurer".into(),
                func: "late".into(),
            }]
        );
        assert!(program
            .function("spend")
            .unwrap()
            .tapscript
            .emulator
            .is_none());
    }

    #[test]
    fn rejects_a_malformed_tweak_duplicate_server_and_unknown_opcode() {
        let tweak = program_from_json(&leaf(&["<TWEAK:insurer:late:extra>", "OP_CHECKSIG"]));
        assert_eq!(
            tweak.unwrap_err(),
            "program_from_artifact: leaf 'spend': malformed tweak '<TWEAK:insurer:late:extra>'"
        );

        let server = r#"{
            "contractName": "Demo",
            "constructorInputs": [{"name": "server", "type": "pubkey"}],
            "functions": [{
                "name": "spend",
                "leaves": [{
                    "name": "spend",
                    "witness": [],
                    "asm": ["<server>", "OP_CHECKSIG"]
                }]
            }]
        }"#;
        assert_eq!(
            program_from_json(server).unwrap_err(),
            "program_from_artifact: duplicate program parameter 'server'"
        );

        let opcode = r#"{
            "contractName": "Demo",
            "constructorInputs": [],
            "functions": [{
                "name": "spend",
                "arkade": {"inputs": [], "asm": ["OP_NOT_REAL"]},
                "leaves": [{
                    "name": "spend",
                    "witness": [],
                    "asm": ["<SERVER_KEY>", "OP_CHECKSIGVERIFY", "<EMULATOR_KEY:spend>", "OP_CHECKSIG"]
                }]
            }]
        }"#;
        assert_eq!(
            program_from_json(opcode).unwrap_err(),
            "program_from_artifact: unrecognized assembly token 'OP_NOT_REAL'"
        );

        let shadow = r#"{
            "contractName": "Demo",
            "constructorInputs": [],
            "structs": [{"name": "pubkey", "fields": []}],
            "functions": [{
                "name": "spend",
                "leaves": [{
                    "name": "spend",
                    "witness": [],
                    "asm": ["<SERVER_KEY>", "OP_CHECKSIG"]
                }]
            }]
        }"#;
        assert_eq!(
            program_from_json(shadow).unwrap_err(),
            "program_from_artifact: struct name 'pubkey' shadows a built-in type"
        );

        let missing_emulator = r#"{
            "contractName": "Demo",
            "constructorInputs": [{"name": "user", "type": "pubkey"}],
            "functions": [{
                "name": "spend",
                "arkade": {"inputs": [], "asm": ["OP_1"]},
                "leaves": [{
                    "name": "spend",
                    "witness": [],
                    "asm": ["<user>", "OP_CHECKSIG"]
                }]
            }]
        }"#;
        assert_eq!(
            program_from_json(missing_emulator).unwrap_err(),
            "program_from_artifact: leaf 'spend': covenant leaf must end with the tweaked co-signer"
        );

        let collision = r#"{
            "contractName": "Demo",
            "constructorInputs": [],
            "functions": [{
                "name": "spend",
                "arkade": {"inputs": [], "asm": ["<VTXO:A-B>", "<VTXO:A_B>"]},
                "leaves": [{
                    "name": "spend",
                    "witness": [],
                    "asm": ["<SERVER_KEY>", "OP_CHECKSIGVERIFY", "<EMULATOR_KEY:spend>", "OP_CHECKSIG"]
                }]
            }]
        }"#;
        assert_eq!(
            program_from_json(collision).unwrap_err(),
            "program_from_artifact: instantiations '<VTXO:A-B>' and '<VTXO:A_B>' both map to parameter 'vtxo_A_B'"
        );
    }

    #[test]
    fn hash_condition_drops_verify_and_keeps_the_preimage() {
        let json = r#"{
            "contractName": "Lock",
            "constructorInputs": [{"name": "hash", "type": "bytes32"}, {"name": "user", "type": "pubkey"}],
            "functions": [{
                "name": "claim",
                "leaves": [{
                    "name": "claim",
                    "witness": [
                        {"name": "preimage", "type": "bytes32", "encoding": "raw-32"},
                        {"name": "userSig", "type": "signature", "encoding": "schnorr-64"}
                    ],
                    "asm": ["OP_SHA256", "<hash>", "OP_EQUAL", "OP_VERIFY", "<user>", "OP_CHECKSIG"]
                }]
            }]
        }"#;
        let program = program_from_json(json).unwrap();
        let claim = program.function("claim").unwrap();
        assert_eq!(claim.tapscript.witness, vec!["preimage".to_string()]);
        assert_eq!(claim.inputs, vec![param("preimage", ValueType::Bytes32)]);
        assert!(claim
            .tapscript
            .condition
            .iter()
            .all(|token| !matches!(token, AsmToken::Opcode(op) if *op == "OP_VERIFY")));
        assert_eq!(
            program
                .params
                .iter()
                .find(|p| p.name == "hash")
                .unwrap()
                .value_type,
            ValueType::Bytes32
        );
    }

    #[test]
    fn later_leaves_are_named_by_group_and_index() {
        let json = r#"{
            "contractName": "Demo",
            "constructorInputs": [{"name": "user", "type": "pubkey"}],
            "functions": [{
                "name": "spend",
                "leaves": [
                    {"name": "first", "witness": [], "asm": ["<user>", "OP_CHECKSIG"]},
                    {"name": "second", "witness": [], "asm": ["<user>", "OP_CHECKSIG"]}
                ]
            }]
        }"#;
        let program = program_from_json(json).unwrap();
        assert_eq!(
            program
                .functions
                .iter()
                .map(|f| f.name.as_str())
                .collect::<Vec<_>>(),
            vec!["spend", "spend/1:second"]
        );
    }

    #[test]
    fn instantiation_param_collapses_like_the_sdk() {
        assert_eq!(
            instantiation_param("<VTXO:SingleSig(<sellerPk>,<exit>)>"),
            "vtxo_SingleSig_sellerPk_exit"
        );
        assert_eq!(instantiation_param("<VTXO:A-B>"), "vtxo_A_B");
        assert_eq!(instantiation_param("<VTXO:___>"), "vtxo");
    }
}
