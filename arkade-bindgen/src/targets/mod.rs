pub mod go;
pub mod typescript;

use crate::ir::ContractIR;

/// Options controlling code generation behavior.
#[derive(Debug, Clone)]
pub struct CodegenOptions {
    /// Whether to embed the artifact JSON inline in generated code.
    pub embed_artifact: bool,
    /// Package/module/namespace name for generated code.
    pub package_name: Option<String>,
    /// The raw artifact JSON string (needed when embed_artifact is true).
    pub artifact_json: Option<String>,
}

impl Default for CodegenOptions {
    fn default() -> Self {
        Self {
            embed_artifact: false,
            package_name: None,
            artifact_json: None,
        }
    }
}

/// A generated source file.
#[derive(Debug, Clone)]
pub struct GeneratedFile {
    /// Output filename (e.g., "htlc.ts", "htlc.go").
    pub filename: String,
    /// Generated source code content.
    pub content: String,
}

/// Trait implemented by each language backend.
pub trait CodegenTarget {
    /// Target name (e.g., "typescript", "go").
    fn name(&self) -> &str;

    /// File extension for generated files (e.g., "ts", "go").
    fn file_extension(&self) -> &str;

    /// Generate a source file from the contract IR.
    fn generate(
        &self,
        ir: &ContractIR,
        options: &CodegenOptions,
    ) -> Result<GeneratedFile, String>;
}

/// All available codegen targets.
pub const AVAILABLE_TARGETS: &[&str] = &["typescript", "go"];

/// Get a codegen target by name.
pub fn get_target(name: &str) -> Option<Box<dyn CodegenTarget>> {
    match name {
        "typescript" | "ts" => Some(Box::new(typescript::TypeScriptTarget)),
        "go" => Some(Box::new(go::GoTarget)),
        _ => None,
    }
}
