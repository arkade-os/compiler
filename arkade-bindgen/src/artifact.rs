use std::path::Path;

pub use arkade_compiler::ContractJson;

/// Load a compiled Arkade contract artifact from a file path.
pub fn load_artifact(path: &Path) -> Result<ContractJson, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read artifact file '{}': {}", path.display(), e))?;
    load_artifact_str(&content)
}

/// Load a compiled Arkade contract artifact from a JSON string.
pub fn load_artifact_str(json: &str) -> Result<ContractJson, String> {
    let artifact: ContractJson =
        serde_json::from_str(json).map_err(|e| format!("Failed to parse artifact JSON: {}", e))?;

    if artifact.name.is_empty() {
        return Err("Artifact missing 'contractName' field".to_string());
    }
    if artifact.functions.is_empty() {
        return Err("Artifact has no functions".to_string());
    }

    Ok(artifact)
}
