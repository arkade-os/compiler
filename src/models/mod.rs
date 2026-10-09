use serde::{Deserialize, Serialize};

mod artifact;
mod ast;

pub use artifact::*;
pub use ast::*;

/// Split a declared type string into element type and length when it is an
/// array type (`"pubkey[3]"` → `("pubkey", 3)`), otherwise `None`.
///
/// Array lengths are static and always present: the grammar has no unsized
/// array type.
pub fn array_type_parts(declared_type: &str) -> Option<(&str, usize)> {
    let (element, length) = declared_type.strip_suffix(']')?.split_once('[')?;
    Some((element, length.parse().ok()?))
}

pub fn is_builtin_type(declared_type: &str) -> bool {
    matches!(
        declared_type,
        "pubkey"
            | "signature"
            | "bytes"
            | "bytes20"
            | "bytes32"
            | "int"
            | "bool"
            | "asset"
            | "AssetGroup"
    )
}

/// Native struct fields in source order; producing opcodes push the first field deepest.
pub fn builtin_struct_fields(
    declared_type: &str,
) -> Option<&'static [(&'static str, &'static str)]> {
    match declared_type {
        "AssetId" => Some(&[("txid", "bytes32"), ("gidx", "int")]),
        "Outpoint" => Some(&[("txid", "bytes32"), ("vout", "int")]),
        "ECPoint" => Some(&[("x", "int"), ("y", "int")]),
        // alt_bn128 G2 point; each coordinate is an Fp2 element `c1 * i + c0`.
        "G2Point" => Some(&[
            ("xC1", "int"),
            ("xC0", "int"),
            ("yC1", "int"),
            ("yC0", "int"),
        ]),
        _ => None,
    }
}

pub fn is_builtin_struct(declared_type: &str) -> bool {
    builtin_struct_fields(declared_type).is_some()
}

/// Parameter in a contract or function
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Parameter {
    /// Parameter name
    pub name: String,
    /// Parameter type (pubkey, signature, bytes32, int, bool, asset, value)
    #[serde(rename = "type")]
    pub param_type: String,
}

/// A named, statically laid-out source type.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StructDefinition {
    pub name: String,
    pub fields: Vec<Parameter>,
}

/// One scalar leaf in a recursively flattened parameter layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeLeaf {
    /// Source path used by expressions, such as `policy.owner.key`.
    pub access_name: String,
    /// Artifact and placeholder name, such as `policy.owner.key`.
    pub emitted_name: String,
    pub leaf_type: String,
}

pub fn flatten_parameter(
    parameter: &Parameter,
    structs: &[StructDefinition],
) -> Result<Vec<TypeLeaf>, String> {
    let mut leaves = Vec::new();
    flatten_type(
        &parameter.name,
        &parameter.name,
        &parameter.param_type,
        structs,
        &mut Vec::new(),
        &mut leaves,
    )?;
    Ok(leaves)
}

fn flatten_type(
    access_name: &str,
    emitted_name: &str,
    declared_type: &str,
    structs: &[StructDefinition],
    stack: &mut Vec<String>,
    leaves: &mut Vec<TypeLeaf>,
) -> Result<(), String> {
    if let Some((element_type, length)) = array_type_parts(declared_type) {
        for index in 0..length {
            flatten_type(
                &format!("{access_name}[{index}]"),
                &format!("{emitted_name}.{index}"),
                element_type,
                structs,
                stack,
                leaves,
            )?;
        }
        return Ok(());
    }
    if is_builtin_type(declared_type) {
        leaves.push(TypeLeaf {
            access_name: access_name.to_string(),
            emitted_name: emitted_name.to_string(),
            leaf_type: declared_type.to_string(),
        });
        return Ok(());
    }
    if let Some(fields) = builtin_struct_fields(declared_type) {
        for (field_name, field_type) in fields {
            flatten_type(
                &format!("{access_name}.{field_name}"),
                &format!("{emitted_name}.{field_name}"),
                field_type,
                structs,
                stack,
                leaves,
            )?;
        }
        return Ok(());
    }

    let definition = structs
        .iter()
        .find(|definition| definition.name == declared_type)
        .ok_or_else(|| format!("unknown type '{declared_type}'"))?;
    if stack.iter().any(|name| name == declared_type) {
        return Err(format!("recursive struct layout: {declared_type}"));
    }
    stack.push(declared_type.to_string());
    for field in &definition.fields {
        flatten_type(
            &format!("{access_name}.{}", field.name),
            &format!("{emitted_name}.{}", field.name),
            &field.param_type,
            structs,
            stack,
            leaves,
        )?;
    }
    stack.pop();
    Ok(())
}
