use serde::{Deserialize, Serialize};

mod artifact;
mod ast;

pub use artifact::*;
pub use ast::*;

/// A declared type as written: a builtin or struct name such as `pubkey`, or a
/// fixed-size array of one such as `int[3]` or `int[N]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeName {
    Named(String),
    Array(Box<TypeName>, ArraySize),
}

/// An array length; constant folding resolves every `Const` to `Fixed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArraySize {
    Fixed(usize),
    Const(String),
}

impl ArraySize {
    /// A length literal, or the constant that names one.
    pub fn parse(text: &str) -> Self {
        match text.parse() {
            Ok(length) => ArraySize::Fixed(length),
            Err(_) => ArraySize::Const(text.to_string()),
        }
    }
}

impl TypeName {
    /// The type a declaration spells, such as `bytes32` or `Point[N]`.
    pub fn parse(text: &str) -> Self {
        let Some((element, size)) = text.strip_suffix(']').and_then(|ty| ty.split_once('[')) else {
            return TypeName::Named(text.to_string());
        };
        TypeName::Array(Box::new(TypeName::parse(element)), ArraySize::parse(size))
    }

    pub fn array(element: TypeName, length: usize) -> Self {
        TypeName::Array(Box::new(element), ArraySize::Fixed(length))
    }

    /// The element type and length of a resolved array type.
    pub fn array_parts(&self) -> Option<(&TypeName, usize)> {
        match self {
            TypeName::Array(element, ArraySize::Fixed(length)) => Some((element, *length)),
            _ => None,
        }
    }

    /// The builtin or struct name, when this is not an array.
    pub fn name(&self) -> Option<&str> {
        match self {
            TypeName::Named(name) => Some(name),
            TypeName::Array(..) => None,
        }
    }

    /// The name, or an array's element name.
    pub fn base_name(&self) -> &str {
        match self {
            TypeName::Named(name) => name,
            TypeName::Array(element, _) => element.base_name(),
        }
    }

    pub fn is_builtin(&self) -> bool {
        self.name().is_some_and(is_builtin_type)
    }

    pub fn is_builtin_struct(&self) -> bool {
        self.name().is_some_and(is_builtin_struct)
    }

    pub fn ark_type(&self) -> crate::types::ArkType {
        match self {
            TypeName::Named(name) => crate::types::ArkType::named(name),
            TypeName::Array(element, ArraySize::Fixed(length)) => {
                crate::types::ArkType::Array(Box::new(element.ark_type()), *length)
            }
            TypeName::Array(_, ArraySize::Const(_)) => crate::types::ArkType::Unknown,
        }
    }
}

impl std::fmt::Display for TypeName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TypeName::Named(name) => f.write_str(name),
            TypeName::Array(element, ArraySize::Fixed(length)) => write!(f, "{element}[{length}]"),
            TypeName::Array(element, ArraySize::Const(name)) => write!(f, "{element}[{name}]"),
        }
    }
}

impl From<&str> for TypeName {
    fn from(text: &str) -> Self {
        TypeName::parse(text)
    }
}

impl Serialize for TypeName {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for TypeName {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(TypeName::parse(&String::deserialize(deserializer)?))
    }
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
        // An inspected scriptPubKey: witness program, then witness version (-1 for non-witness).
        "ScriptPubKey" => Some(&[("program", "bytes"), ("version", "int")]),
        "AssetEntry" => Some(&[("assetId", "AssetId"), ("amount", "int")]),
        "AssetLookup" => Some(&[("amount", "int"), ("found", "bool")]),
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
    pub param_type: TypeName,
    /// Byte range of the name; empty for parameters the compiler builds.
    #[serde(skip)]
    pub span: crate::diagnostics::Span,
}

/// A named, statically laid-out source type.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StructDefinition {
    pub name: String,
    pub fields: Vec<Parameter>,
    #[serde(skip)]
    pub span: crate::diagnostics::Span,
}

/// One scalar leaf in a recursively flattened parameter layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeLeaf {
    /// Source path used by expressions, such as `policy.owner.key`.
    pub access: Path,
    /// Artifact and placeholder name, such as `policy.owner.key`.
    pub emitted_name: String,
    pub leaf_type: TypeName,
}

pub fn flatten_parameter(
    parameter: &Parameter,
    structs: &[StructDefinition],
) -> Result<Vec<TypeLeaf>, String> {
    let mut leaves = Vec::new();
    flatten_type(
        Path::new(&parameter.name),
        &parameter.name,
        &parameter.param_type,
        structs,
        &mut Vec::new(),
        &mut leaves,
    )?;
    Ok(leaves)
}

/// The leaves of a `declared_type` value stored at `access`.
pub(crate) fn flatten_value(
    access: &Path,
    declared_type: &TypeName,
    structs: &[StructDefinition],
) -> Result<Vec<TypeLeaf>, String> {
    let mut leaves = Vec::new();
    let emitted_name = access.key();
    flatten_type(
        access.clone(),
        &emitted_name,
        declared_type,
        structs,
        &mut Vec::new(),
        &mut leaves,
    )?;
    Ok(leaves)
}

fn flatten_type(
    access: Path,
    emitted_name: &str,
    declared_type: &TypeName,
    structs: &[StructDefinition],
    stack: &mut Vec<String>,
    leaves: &mut Vec<TypeLeaf>,
) -> Result<(), String> {
    if let Some((element_type, length)) = declared_type.array_parts() {
        for index in 0..length {
            flatten_type(
                access.clone().index(index),
                &format!("{emitted_name}.{index}"),
                element_type,
                structs,
                stack,
                leaves,
            )?;
        }
        return Ok(());
    }
    if declared_type.is_builtin() {
        leaves.push(TypeLeaf {
            access,
            emitted_name: emitted_name.to_string(),
            leaf_type: declared_type.clone(),
        });
        return Ok(());
    }
    let name = declared_type.name().unwrap_or_default();
    if let Some(fields) = builtin_struct_fields(name) {
        for (field_name, field_type) in fields {
            flatten_type(
                access.clone().field(*field_name),
                &format!("{emitted_name}.{field_name}"),
                &TypeName::parse(field_type),
                structs,
                stack,
                leaves,
            )?;
        }
        return Ok(());
    }

    let definition = structs
        .iter()
        .find(|definition| definition.name == name)
        .ok_or_else(|| format!("unknown type '{declared_type}'"))?;
    if stack.iter().any(|ty| ty == name) {
        return Err(format!("recursive struct layout: {declared_type}"));
    }
    stack.push(name.to_string());
    for field in &definition.fields {
        flatten_type(
            access.clone().field(&field.name),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_names_keep_their_spelling() {
        for text in ["pubkey", "Point", "int[3]", "pubkey[C.N]"] {
            assert_eq!(TypeName::parse(text).to_string(), text);
        }
        let pubkeys = TypeName::parse("pubkey[2]");
        assert_eq!(
            pubkeys.array_parts(),
            Some((&TypeName::Named("pubkey".into()), 2))
        );
        assert_eq!(pubkeys.ark_type().as_str(), "bytes[2]");
        assert_eq!(serde_json::to_string(&pubkeys).unwrap(), "\"pubkey[2]\"");
    }
}
