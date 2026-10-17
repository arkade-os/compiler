//! Compiled Arkade artifact models and artifact-to-program conversion.

pub mod models;
pub mod program;

pub use models::*;
pub use program::{program_from_artifact, program_from_json, Program};

/// Per-call compiler settings. Optimizations are enabled by default.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct CompileOptions {
    /// Fold constant expressions, remove static branches, and optimize Arkade assembly.
    pub optimize: bool,
}

impl Default for CompileOptions {
    fn default() -> Self {
        Self { optimize: true }
    }
}
