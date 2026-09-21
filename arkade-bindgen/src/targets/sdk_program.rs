//! `sdk-program` target: `ContractJson` → the TypeScript SDK's Program JSON.
//!
//! The SDK (`packages/ts-sdk/src/arkade/program.ts`) consumes a different
//! artifact from the one `arkadec` writes: functions keyed by name rather than
//! an array of spend groups, `$param` placeholders rather than `<param>`, and
//! tapleaves described structurally (`signers` + optional condition/timelock)
//! rather than as assembly. Feeding it a raw `ContractJson` does not fail — it
//! silently yields a program with numeric function names — so the bridge has
//! to be explicit.
//!
//! Two conventions are load-bearing here, both owned by the SDK:
//!
//! - Opcode names follow `@scure/btc-signer` merged with the SDK's Arkade
//!   table: the `OP_` prefix is dropped except on the numeric pushes `OP_0`
//!   and `OP_1`..`OP_16`. An opcode the SDK's table does not carry fails when
//!   the program is encoded, which is what the SDK-side acceptance test is for.
//! - The tweaked co-signer key is appended to a covenant leaf's signer set by
//!   the SDK itself, so `<EMULATOR_KEY:fn>` is dropped from `signers` rather
//!   than translated.

use serde::ser::{SerializeMap, Serializer};
use serde::Serialize;
use serde_json::{json, Value};

use crate::ir::{ContractIR, CovenantIR, Encoding, Field, GroupIR, LeafIR};
use crate::naming::to_snake_case;
use crate::targets::{CodegenOptions, CodegenTarget, GeneratedFile};

/// A JSON object that keeps insertion order.
///
/// `serde_json::Map` sorts its keys, and for `functions` that is not cosmetic:
/// the SDK builds the taproot tree from `Object.keys(functions)`, and btcd's
/// tree assembly pairs adjacent leaves, so reordering the functions changes
/// the derived address. Spend groups have to reach the SDK in artifact order.
#[derive(Default)]
struct Object(Vec<(String, Node)>);

/// Either a plain JSON value or a nested ordered object.
enum Node {
    Value(Value),
    Object(Object),
}

impl Object {
    fn set(&mut self, key: &str, value: impl Into<Value>) {
        self.0.push((key.to_string(), Node::Value(value.into())));
    }

    fn set_object(&mut self, key: &str, value: Object) {
        self.0.push((key.to_string(), Node::Object(value)));
    }
}

impl Serialize for Object {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in &self.0 {
            match value {
                Node::Value(value) => map.serialize_entry(key, value)?,
                Node::Object(object) => map.serialize_entry(key, object)?,
            }
        }
        map.end()
    }
}

/// The SDK's `SUPPORTED_PROGRAM_VERSION`.
const PROGRAM_VERSION: u64 = 0;

/// The SDK auto-binds a param with this name to the Arkade Service key.
const SERVER_PARAM: &str = "server";

pub struct SdkProgramTarget;

impl CodegenTarget for SdkProgramTarget {
    fn name(&self) -> &str {
        "sdk-program"
    }

    fn file_extension(&self) -> &str {
        "program.json"
    }

    fn generate(
        &self,
        ir: &ContractIR,
        _options: &CodegenOptions,
    ) -> Result<GeneratedFile, String> {
        Ok(GeneratedFile {
            filename: format!("{}.program.json", to_snake_case(&ir.name)),
            content: render(ir)?,
        })
    }
}

/// Render a contract's SDK Program JSON, newline-terminated.
pub fn render(ir: &ContractIR) -> Result<String, String> {
    let program = build_program(ir)?;
    serde_json::to_string_pretty(&program)
        .map(|json| format!("{json}\n"))
        .map_err(|e| e.to_string())
}

/// Map an Arkade type onto the SDK's narrower `ArkadeArgType`.
///
/// The SDK length-checks only `pubkey` (32) and `sig` (64); every other
/// byte-like type lands on `hash`, which it accepts as opaque bytes.
fn sdk_type(encoding: &Encoding) -> &'static str {
    match encoding {
        Encoding::Compressed33 => "pubkey",
        Encoding::Schnorr64 => "sig",
        Encoding::Raw20 | Encoding::Raw32 => "hash",
        Encoding::ScriptNum => "int",
        Encoding::Raw | Encoding::Unknown(_) => "bytes",
    }
}

fn param_entry(name: &str, ty: &str) -> Value {
    json!({ "name": name, "type": ty })
}

/// Translate one covenant/leaf assembly token.
///
/// Opcodes lose the `OP_` prefix per the SDK's naming convention, `<name>`
/// becomes `"$name"`, `0x..` literals stay hex strings for the SDK to decode,
/// and decimal literals become JSON numbers so the SDK pushes them as data
/// rather than looking them up as opcodes.
fn asm_token(token: &str, vtxo: &mut VtxoParams) -> Result<Value, String> {
    if let Some(base) = token.strip_prefix("OP_") {
        // @scure keeps the small-integer pushes prefixed; everything else is bare.
        if base == "0" || matches!(base.parse::<u8>(), Ok(1..=16)) {
            return Ok(Value::String(token.to_string()));
        }
        return Ok(Value::String(base.to_string()));
    }
    if let Some(inner) = token.strip_prefix('<').and_then(|t| t.strip_suffix('>')) {
        if inner.starts_with("VTXO:") {
            return Ok(Value::String(format!("${}", vtxo.param_for(token)?)));
        }
        if inner == "SERVER_KEY" || inner.starts_with("EMULATOR_KEY:") {
            return Err(format!(
                "{token} is a signer role and cannot appear in an arkade script"
            ));
        }
        return Ok(Value::String(format!("${inner}")));
    }
    if token.starts_with("0x") {
        return Ok(Value::String(token.to_string()));
    }
    if let Ok(number) = token.parse::<i64>() {
        return Ok(script_number(number));
    }
    Err(format!("unrecognized assembly token '{token}'"))
}

/// JSON encode a script integer. The SDK reads numbers as literal pushes, but
/// JSON numbers above 2^53-1 lose precision, so wide values fall back to the
/// minimal script-num hex the SDK decodes byte-for-byte identically.
fn script_number(value: i64) -> Value {
    const MAX_SAFE: i64 = 9_007_199_254_740_991;
    if (-MAX_SAFE..=MAX_SAFE).contains(&value) {
        return json!(value);
    }
    Value::String(format!("0x{}", hex_lower(&minimal_script_num(value))))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Bitcoin's minimal CScriptNum encoding: little-endian magnitude with the
/// sign in the high bit of the final byte.
fn minimal_script_num(value: i64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let negative = value < 0;
    let mut magnitude = value.unsigned_abs();
    let mut out = Vec::new();
    while magnitude > 0 {
        out.push((magnitude & 0xff) as u8);
        magnitude >>= 8;
    }
    if out.last().is_some_and(|b| b & 0x80 != 0) {
        out.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        let last = out.len() - 1;
        out[last] |= 0x80;
    }
    out
}

/// Synthesized constructor params for `new Contract(...)` instantiations.
///
/// The compiler leaves those as opaque `<VTXO:...>` tokens for the runtime to
/// resolve into the child's 32-byte witness program. The SDK has no notion of
/// child instantiation, so each distinct token becomes a param the caller
/// binds to that witness program.
#[derive(Default)]
struct VtxoParams {
    /// Declaration order, as `(param name, originating token)`.
    entries: Vec<(String, String)>,
}

impl VtxoParams {
    fn param_for(&mut self, token: &str) -> Result<String, String> {
        if let Some((name, _)) = self.entries.iter().find(|(_, t)| t == token) {
            return Ok(name.clone());
        }
        let name = mangle_vtxo(token);
        if let Some((_, existing)) = self
            .entries
            .iter()
            .find(|(candidate, _)| *candidate == name)
        {
            return Err(format!(
                "instantiations '{existing}' and '{token}' both map to parameter '{name}'"
            ));
        }
        self.entries.push((name.clone(), token.to_string()));
        Ok(name)
    }
}

/// `<VTXO:SingleSig(<sellerPk>,<exit>)>` → `vtxo_SingleSig_sellerPk_exit`.
fn mangle_vtxo(token: &str) -> String {
    let mut out = String::from("vtxo_");
    let mut previous_underscore = false;
    for ch in token
        .trim_matches(['<', '>'])
        .trim_start_matches("VTXO:")
        .chars()
    {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            previous_underscore = false;
        } else if !previous_underscore {
            out.push('_');
            previous_underscore = true;
        }
    }
    out.trim_end_matches('_').to_string()
}

/// The structural form of one tapleaf, as the SDK's `TapscriptSegment`.
struct Tapscript {
    signers: Vec<Value>,
    condition: Option<Vec<Value>>,
    csv: Option<Value>,
    cltv: Option<Value>,
}

/// Parse a leaf back into the closure the compiler emitted it from:
/// `condition? · timelock? · N-of-N multisig` (see `src/compiler/tapscript.rs`).
/// Anything else is refused rather than guessed at.
fn parse_leaf(
    leaf: &LeafIR,
    has_covenant: bool,
    vtxo: &mut VtxoParams,
) -> Result<Tapscript, String> {
    let asm = &leaf.asm;
    let mut index = 0;

    let condition = if asm.len() >= 4 && is_hash_opcode(&asm[0]) && asm[2] == "OP_EQUAL" {
        if asm[3] != "OP_VERIFY" {
            return Err(format!(
                "leaf '{}': hash condition must end in OP_VERIFY",
                leaf.name
            ));
        }
        index = 4;
        // The SDK appends the VERIFY itself when it builds the condition closure.
        Some(
            asm[0..3]
                .iter()
                .map(|t| asm_token(t, vtxo))
                .collect::<Result<Vec<_>, _>>()?,
        )
    } else {
        None
    };

    let mut csv = None;
    let mut cltv = None;
    if asm.len() >= index + 3 && asm[index + 2] == "OP_DROP" {
        let operand = timelock_operand(&asm[index])?;
        match asm[index + 1].as_str() {
            "OP_CHECKSEQUENCEVERIFY" => {
                // The compiler emits block-denominated CSV only, and BIP68
                // encodes a block count as itself, so the scripts agree.
                csv = Some(json!({ "type": "blocks", "value": operand }));
            }
            "OP_CHECKLOCKTIMEVERIFY" => cltv = Some(operand),
            other => {
                return Err(format!(
                    "leaf '{}': unexpected timelock opcode {other}",
                    leaf.name
                ))
            }
        }
        index += 3;
    }

    let mut signers = Vec::new();
    let mut emulator_seen = false;
    while index < asm.len() {
        let key = &asm[index];
        let terminator = asm
            .get(index + 1)
            .ok_or_else(|| format!("leaf '{}': key '{key}' has no signature check", leaf.name))?;
        let last = terminator == "OP_CHECKSIG";
        if !last && terminator != "OP_CHECKSIGVERIFY" {
            return Err(format!(
                "leaf '{}': expected a signature check after '{key}', found '{terminator}'",
                leaf.name
            ));
        }
        match key.strip_prefix('<').and_then(|k| k.strip_suffix('>')) {
            Some("SERVER_KEY") => signers.push(Value::String(format!("${SERVER_PARAM}"))),
            Some(role) if role.starts_with("EMULATOR_KEY:") => {
                if !has_covenant {
                    return Err(format!(
                        "leaf '{}': references {key} but its group has no covenant, so the SDK cannot derive the tweak",
                        leaf.name
                    ));
                }
                if !last {
                    return Err(format!(
                        "leaf '{}': the SDK appends the tweaked co-signer last, but {key} is not the final key",
                        leaf.name
                    ));
                }
                emulator_seen = true;
            }
            Some(name) => signers.push(Value::String(format!("${name}"))),
            None => {
                return Err(format!(
                    "leaf '{}': unsupported key operand '{key}'",
                    leaf.name
                ))
            }
        }
        index += 2;
    }

    if has_covenant && !emulator_seen {
        return Err(format!(
            "leaf '{}': a covenant group's leaf must commit to the tweaked co-signer key",
            leaf.name
        ));
    }
    if signers.is_empty() {
        return Err(format!(
            "leaf '{}': the SDK requires at least one named signer",
            leaf.name
        ));
    }

    Ok(Tapscript {
        signers,
        condition,
        csv,
        cltv,
    })
}

fn is_hash_opcode(token: &str) -> bool {
    matches!(
        token,
        "OP_SHA256" | "OP_HASH160" | "OP_HASH256" | "OP_RIPEMD160"
    )
}

fn timelock_operand(token: &str) -> Result<Value, String> {
    if let Some(name) = token.strip_prefix('<').and_then(|t| t.strip_suffix('>')) {
        return Ok(Value::String(format!("${name}")));
    }
    token
        .parse::<i64>()
        .map(|n| json!(n))
        .map_err(|_| format!("unsupported timelock operand '{token}'"))
}

/// Covenant witness order: the artifact documents that clients push covenant
/// inputs in reverse declaration order, composite entries expanded deepest
/// first. The IR has already flattened composites, so reversing the flattened
/// list reproduces that stack.
fn covenant_witness(covenant: &CovenantIR) -> Vec<Value> {
    covenant
        .inputs
        .iter()
        .rev()
        .map(|field| Value::String(field.name.clone()))
        .collect()
}

/// Leaf witness items that satisfy a hash condition. Signature entries are not
/// listed: they are produced from `signers`, one per key.
fn condition_witness(leaf: &LeafIR) -> Vec<&Field> {
    leaf.witness_fields
        .iter()
        .filter(|field| !field.is_injected && field.ark_type != "signature")
        .collect()
}

fn build_function(group: &GroupIR, vtxo: &mut VtxoParams) -> Result<Object, String> {
    let leaf = match group.leaves.as_slice() {
        [single] => single,
        leaves => {
            return Err(format!(
                "group '{}' has {} leaves; the SDK program model allows one tapscript per function",
                group.name,
                leaves.len()
            ))
        }
    };

    let tapscript = parse_leaf(leaf, group.covenant.is_some(), vtxo)?;
    let condition_inputs = condition_witness(leaf);

    // Call arguments: the covenant's flattened inputs, then anything the leaf
    // condition needs. Arrays and structs arrive already flattened, so an
    // `int[3]` parameter becomes three arguments.
    let inputs: Vec<Value> = group
        .covenant
        .iter()
        .flat_map(|covenant| covenant.inputs.iter())
        .chain(condition_inputs.iter().copied())
        .map(|field| param_entry(&field.name, sdk_type(&field.encoding)))
        .collect();

    let mut tap = Object::default();
    tap.set("signers", Value::Array(tapscript.signers));
    if let Some(condition) = tapscript.condition {
        tap.set("asm", Value::Array(condition));
    }
    if let Some(csv) = tapscript.csv {
        tap.set("csv", csv);
    }
    if let Some(cltv) = tapscript.cltv {
        tap.set("cltv", cltv);
    }
    if !condition_inputs.is_empty() {
        tap.set(
            "witness",
            Value::Array(
                condition_inputs
                    .iter()
                    .map(|field| Value::String(field.name.clone()))
                    .collect(),
            ),
        );
    }

    let mut function = Object::default();
    if !inputs.is_empty() {
        function.set("inputs", Value::Array(inputs));
    }
    function.set_object("tapscript", tap);
    if let Some(covenant) = &group.covenant {
        let asm = covenant
            .asm
            .iter()
            .map(|token| asm_token(token, vtxo))
            .collect::<Result<Vec<_>, _>>()?;
        let mut arkade = Object::default();
        arkade.set("asm", Value::Array(asm));
        let witness = covenant_witness(covenant);
        if !witness.is_empty() {
            arkade.set("witness", Value::Array(witness));
        }
        function.set_object("arkadeScript", arkade);
    }

    Ok(function)
}

/// Build the SDK Program JSON for a contract.
fn build_program(ir: &ContractIR) -> Result<Object, String> {
    let mut vtxo = VtxoParams::default();

    let mut functions = Object::default();
    for group in &ir.groups {
        if functions.0.iter().any(|(name, _)| *name == group.name) {
            return Err(format!("duplicate spend group '{}'", group.name));
        }
        functions.set_object(&group.name, build_function(group, &mut vtxo)?);
    }

    let mut params: Vec<Value> = ir
        .constructor_fields
        .iter()
        .map(|field| param_entry(&field.name, sdk_type(&field.encoding)))
        .collect();
    // The SDK binds a param literally named `server` to the Arkade Service key.
    params.push(param_entry(SERVER_PARAM, "pubkey"));
    for (name, _) in &vtxo.entries {
        params.push(param_entry(name, "hash"));
    }

    let mut program = Object::default();
    program.set("version", PROGRAM_VERSION);
    program.set("name", ir.name.clone());
    program.set("params", Value::Array(params));
    program.set_object("functions", functions);
    Ok(program)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_names_follow_the_sdk_convention() {
        let mut vtxo = VtxoParams::default();
        let mut token = |t: &str| asm_token(t, &mut vtxo).unwrap();
        assert_eq!(token("OP_CHECKSIG"), json!("CHECKSIG"));
        assert_eq!(token("OP_CHECKSIGFROMSTACK"), json!("CHECKSIGFROMSTACK"));
        // Small-integer pushes keep the prefix in @scure's table.
        assert_eq!(token("OP_0"), json!("OP_0"));
        assert_eq!(token("OP_16"), json!("OP_16"));
        assert_eq!(token("OP_1NEGATE"), json!("1NEGATE"));
    }

    #[test]
    fn literals_and_placeholders_translate() {
        let mut vtxo = VtxoParams::default();
        let mut token = |t: &str| asm_token(t, &mut vtxo).unwrap();
        assert_eq!(token("<sellerPk>"), json!("$sellerPk"));
        assert_eq!(token("<oracles.0>"), json!("$oracles.0"));
        assert_eq!(token("0xdeadbeef"), json!("0xdeadbeef"));
        assert_eq!(token("10000"), json!(10000));
        assert_eq!(token("0"), json!(0));
    }

    #[test]
    fn wide_integers_fall_back_to_script_num_hex() {
        // Beyond JSON's exact integer range, the value ships as the minimal
        // script-num bytes. Cross-checked against the SDK's BigNum.encode.
        assert_eq!(
            script_number(9_007_199_254_740_992),
            json!("0x00000000000020")
        );
        assert_eq!(
            script_number(-9_007_199_254_740_992),
            json!("0x000000000000a0")
        );
        assert_eq!(script_number(-1), json!(-1));
        assert_eq!(script_number(0), json!(0));
    }

    #[test]
    fn signer_roles_are_refused_inside_a_covenant() {
        let mut vtxo = VtxoParams::default();
        assert!(asm_token("<SERVER_KEY>", &mut vtxo).is_err());
        assert!(asm_token("<EMULATOR_KEY:claim>", &mut vtxo).is_err());
    }

    #[test]
    fn instantiations_become_bindable_parameters() {
        let mut vtxo = VtxoParams::default();
        let a = asm_token("<VTXO:SingleSig(<sellerPk>,<exit>)>", &mut vtxo).unwrap();
        let b = asm_token("<VTXO:SingleSig(<buyerPk>,<exit>)>", &mut vtxo).unwrap();
        assert_eq!(a, json!("$vtxo_SingleSig_sellerPk_exit"));
        assert_eq!(b, json!("$vtxo_SingleSig_buyerPk_exit"));
        // The same instantiation resolves to the same parameter.
        assert_eq!(
            asm_token("<VTXO:SingleSig(<sellerPk>,<exit>)>", &mut vtxo).unwrap(),
            a
        );
        assert_eq!(vtxo.entries.len(), 2);
    }
}
