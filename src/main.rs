use clap::Parser as ClapParser;
use std::fs;
use std::path::Path;

use arkade_compiler::{analyze_file, compile_file_with_options, CompileOptions, Severity};

/// Arkade Compiler CLI
///
/// This is the command-line interface for the Arkade Compiler.
/// It compiles Arkade Script source code (.ark files) into JSON output
/// that represents Bitcoin Taproot scripts.
///
/// The JSON output includes:
/// - Contract name
/// - Constructor parameters
/// - Spend groups with optional arkade covenants
/// - L1 tapleaves and witness schemas

// CLI arguments
#[derive(ClapParser, Debug)]
#[command(name = "arkadec")]
#[command(version)]
#[command(about = "Arkade Compiler for Bitcoin Taproot scripts", long_about = None)]
struct Args {
    /// Source file path (.ark)
    #[arg(required = true)]
    file: String,

    /// Output file path (defaults to source filename with .json extension)
    #[arg(short, long)]
    output: Option<String>,

    /// Disable constant folding, static branch removal, and assembly optimizations
    #[arg(long)]
    no_optimize: bool,

    /// Report every error and warning, with its location, instead of writing an artifact;
    /// exits with status 1 when there is an error
    #[arg(long)]
    check: bool,

    /// With --check, print the diagnostics as a JSON array
    #[arg(long, requires = "check")]
    json: bool,

    /// Also write the covenant source maps to a debug file next to the artifact
    /// (`<name>.debug.json`)
    #[arg(long, conflicts_with = "check")]
    debug: bool,
}

/// Main function for the Arkade Compiler CLI
///
/// This function:
/// 1. Parses command-line arguments
/// 2. Reads the source file
/// 3. Parses the source code into an AST
/// 4. Compiles the AST to a JSON structure
/// 5. Writes the JSON to the output file
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse CLI arguments
    let args = Args::parse();

    // Ensure file has .ark extension
    let file_path = Path::new(&args.file);
    if file_path.extension().unwrap_or_default() != "ark" {
        return Err("Input file must have .ark extension".into());
    }

    let options = CompileOptions {
        optimize: !args.no_optimize,
    };
    if args.check {
        check(file_path, args.json, options)?;
        return Ok(());
    }

    // Compile source code to JSON
    let output = match compile_file_with_options(file_path, options) {
        Ok(json) => json,
        Err(err) => {
            eprintln!("Compilation error: {err}");
            return Err(err);
        }
    };

    // Print any type-check warnings to stderr
    for w in &output.warnings {
        eprintln!("{w}");
    }

    // Determine output path
    let output_path = match args.output {
        Some(path) => path,
        None => {
            let stem = file_path.file_stem().unwrap_or_default().to_string_lossy();
            format!("{stem}.json")
        }
    };

    // Write output JSON
    let json = serde_json::to_string_pretty(&output)?;
    fs::write(&output_path, json)?;

    println!("Compilation successful. Output written to {output_path}");

    if args.debug {
        let debug_path = Path::new(&output_path).with_extension("debug.json");
        fs::write(
            &debug_path,
            serde_json::to_string_pretty(&output.debug_info())?,
        )?;
        println!("Debug information written to {}", debug_path.display());
    }

    Ok(())
}

/// Print every diagnostic of the file at `path`, and exit with status 1 if one is an error.
fn check(
    path: &Path,
    json: bool,
    options: CompileOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    let analysis = analyze_file(path);
    let diagnostics = analysis.check(options);
    // Files show relative to the working directory, as text and as JSON.
    let cwd = std::env::current_dir().unwrap_or_default();
    let shown = |file: &str| {
        let file = Path::new(file);
        file.strip_prefix(&cwd)
            .unwrap_or(file)
            .display()
            .to_string()
    };
    if json {
        let diagnostics: Vec<_> = diagnostics
            .iter()
            .map(|d| {
                let mut json = arkade_compiler::diagnostics::to_json(d, analysis.source(&d.file));
                json["file"] = shown(&d.file).into();
                json
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&diagnostics)?);
    } else {
        for d in &diagnostics {
            let mut location = shown(&d.file);
            let start = d.span.zip(analysis.source(&d.file));
            if let Some((line, column)) = start.and_then(|(span, source)| {
                arkade_compiler::diagnostics::position(source, span.start)
            }) {
                location.push_str(&format!(":{line}:{column}"));
            }
            let severity = match d.severity {
                Severity::Error => "error",
                Severity::Warning => "warning",
            };
            let code = d
                .code
                .as_deref()
                .map(|code| format!("[{code}]"))
                .unwrap_or_default();
            println!("{location}: {severity}{code}: {}", d.message);
        }
    }
    if diagnostics.iter().any(|d| d.severity == Severity::Error) {
        std::process::exit(1);
    }
    Ok(())
}
