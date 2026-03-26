use clap::Parser;
use std::path::{Path, PathBuf};

use arkade_bindgen::artifact;
use arkade_bindgen::ir;
use arkade_bindgen::targets::{self, CodegenOptions, AVAILABLE_TARGETS};

#[derive(Parser)]
#[command(name = "arkade-bindgen")]
#[command(about = "Generate typed SDK bindings from Arkade contract artifacts")]
#[command(version)]
struct Cli {
    /// Path to a .json artifact file or directory of artifacts.
    #[arg(required_unless_present = "list_targets")]
    input: Option<PathBuf>,

    /// Comma-separated language targets (e.g., "typescript,go").
    #[arg(long = "lang", value_delimiter = ',')]
    lang: Vec<String>,

    /// Output directory.
    #[arg(short, long, default_value = "./generated/")]
    output: PathBuf,

    /// Embed artifact JSON inline in generated code.
    #[arg(long)]
    embed: bool,

    /// Package/module/namespace name for generated code.
    #[arg(long)]
    package: Option<String>,

    /// List available language targets and exit.
    #[arg(long = "list-targets")]
    list_targets: bool,
}

fn main() {
    let cli = Cli::parse();

    if cli.list_targets {
        println!("Available targets:");
        for target in AVAILABLE_TARGETS {
            println!("  {}", target);
        }
        return;
    }

    let input = cli.input.expect("input path is required");

    if cli.lang.is_empty() {
        eprintln!("Error: --lang is required (e.g., --lang typescript,go)");
        std::process::exit(1);
    }

    // Resolve targets
    let target_backends: Vec<Box<dyn targets::CodegenTarget>> = cli
        .lang
        .iter()
        .map(|name| {
            targets::get_target(name).unwrap_or_else(|| {
                eprintln!(
                    "Error: unknown target '{}'. Use --list-targets to see available.",
                    name
                );
                std::process::exit(1);
            })
        })
        .collect();

    // Collect input artifact paths
    let artifact_paths = collect_artifacts(&input);
    if artifact_paths.is_empty() {
        eprintln!("Error: no .json artifacts found at '{}'", input.display());
        std::process::exit(1);
    }

    let multi_target = target_backends.len() > 1;
    let mut generated_count = 0;

    for backend in &target_backends {
        let target_dir = if multi_target {
            cli.output.join(backend.name())
        } else {
            cli.output.clone()
        };

        for artifact_path in &artifact_paths {
            match process_artifact(artifact_path, backend.as_ref(), &target_dir, &cli) {
                Ok(filename) => {
                    println!(
                        "  {} -> {}",
                        artifact_path.display(),
                        target_dir.join(&filename).display()
                    );
                    generated_count += 1;
                }
                Err(e) => {
                    eprintln!("Error processing '{}': {}", artifact_path.display(), e);
                    std::process::exit(1);
                }
            }
        }
    }

    println!("Generated {} file(s)", generated_count);
}

fn process_artifact(
    path: &Path,
    backend: &dyn targets::CodegenTarget,
    output_dir: &Path,
    cli: &Cli,
) -> Result<String, String> {
    let artifact = artifact::load_artifact(path)?;
    let artifact_json = if cli.embed {
        Some(std::fs::read_to_string(path).map_err(|e| e.to_string())?)
    } else {
        None
    };

    let contract_ir = ir::build_ir(&artifact)?;

    let options = CodegenOptions {
        embed_artifact: cli.embed,
        package_name: cli.package.clone(),
        artifact_json,
    };

    let generated = backend.generate(&contract_ir, &options)?;

    // Ensure output directory exists
    std::fs::create_dir_all(output_dir).map_err(|e| e.to_string())?;

    let dest = output_dir.join(&generated.filename);
    std::fs::write(&dest, &generated.content)
        .map_err(|e| format!("Failed to write '{}': {}", dest.display(), e))?;

    Ok(generated.filename)
}

fn collect_artifacts(input: &Path) -> Vec<PathBuf> {
    if input.is_file() {
        vec![input.to_path_buf()]
    } else if input.is_dir() {
        let mut paths: Vec<PathBuf> = std::fs::read_dir(input)
            .unwrap_or_else(|e| {
                eprintln!("Error reading directory '{}': {}", input.display(), e);
                std::process::exit(1);
            })
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let path = entry.path();
                if path.extension().map_or(false, |ext| ext == "json") {
                    Some(path)
                } else {
                    None
                }
            })
            .collect();
        paths.sort();
        paths
    } else {
        Vec::new()
    }
}
