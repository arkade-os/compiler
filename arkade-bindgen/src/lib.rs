pub mod artifact;
pub mod ir;
pub mod naming;
pub mod targets;

use std::path::Path;

pub use targets::GeneratedFile;
use targets::{CodegenOptions, CodegenTarget};

/// Language target selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    TypeScript,
    Go,
}

impl Target {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "typescript" | "ts" => Some(Target::TypeScript),
            "go" => Some(Target::Go),
            _ => None,
        }
    }

    fn backend(&self) -> Box<dyn CodegenTarget> {
        match self {
            Target::TypeScript => Box::new(targets::typescript::TypeScriptTarget),
            Target::Go => Box::new(targets::go::GoTarget),
        }
    }
}

/// Options for the `generate` library API.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Embed artifact JSON inline in generated code.
    pub embed: bool,
    /// Package/namespace name for generated code.
    pub package: Option<String>,
}

/// Generate bindings for the given artifact files.
///
/// Suitable for use in `build.rs`:
/// ```ignore
/// arkade_bindgen::generate(
///     &["artifacts/htlc.json"],
///     "src/contracts/",
///     arkade_bindgen::Target::TypeScript,
///     &arkade_bindgen::Options::default(),
/// ).unwrap();
/// ```
pub fn generate(
    artifact_paths: &[&str],
    output_dir: &str,
    target: Target,
    options: &Options,
) -> Result<Vec<GeneratedFile>, String> {
    let backend = target.backend();
    let out_path = Path::new(output_dir);
    let mut results = Vec::new();

    for path_str in artifact_paths {
        let path = Path::new(path_str);
        let artifact = artifact::load_artifact(path)?;
        let artifact_json = if options.embed {
            Some(std::fs::read_to_string(path).map_err(|e| e.to_string())?)
        } else {
            None
        };

        let ir = ir::build_ir(&artifact)?;
        let codegen_opts = CodegenOptions {
            embed_artifact: options.embed,
            package_name: options.package.clone(),
            artifact_json,
        };

        let generated = backend.generate(&ir, &codegen_opts)?;

        // Write to output directory
        let dest = out_path.join(&generated.filename);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&dest, &generated.content)
            .map_err(|e| format!("Failed to write '{}': {}", dest.display(), e))?;

        // In non-embed mode, copy the artifact JSON alongside the generated source
        if !options.embed {
            let json_filename = path
                .file_stem()
                .map(|s| format!("{}.json", s.to_string_lossy()))
                .unwrap_or_else(|| "artifact.json".to_string());
            let artifact_dest = out_path.join(&json_filename);
            let artifact_bytes = std::fs::read(path)
                .map_err(|e| format!("Failed to read '{}': {}", path.display(), e))?;
            std::fs::write(&artifact_dest, artifact_bytes)
                .map_err(|e| format!("Failed to write '{}': {}", artifact_dest.display(), e))?;
        }

        results.push(generated);
    }

    Ok(results)
}

/// Generate bindings from an in-memory artifact JSON string.
/// Returns the generated source code without writing to disk.
pub fn generate_from_str(
    artifact_json: &str,
    target: Target,
    options: &Options,
) -> Result<GeneratedFile, String> {
    let artifact = artifact::load_artifact_str(artifact_json)?;
    let ir = ir::build_ir(&artifact)?;

    let codegen_opts = CodegenOptions {
        embed_artifact: options.embed,
        package_name: options.package.clone(),
        artifact_json: if options.embed {
            Some(artifact_json.to_string())
        } else {
            None
        },
    };

    let backend = target.backend();
    backend.generate(&ir, &codegen_opts)
}
