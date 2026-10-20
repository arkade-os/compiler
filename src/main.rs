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

    if args.check {
        check(file_path, args.json)?;
        return Ok(());
    }

    // Compile source code to JSON
    let output = match compile_file_with_options(
        file_path,
        CompileOptions {
            optimize: !args.no_optimize,
        },
    ) {
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

    Ok(())
}

/// Print every diagnostic of the file at `path`, and exit with status 1 if one is an error.
fn check(path: &Path, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let diagnostics = analyze_file(path).check();
    let source = |file: &str| fs::read_to_string(file).ok();
    if json {
        let diagnostics: Vec<_> = diagnostics
            .iter()
            .map(|d| arkade_compiler::diagnostics::to_json(d, source(&d.file).as_deref()))
            .collect();
        println!("{}", serde_json::to_string_pretty(&diagnostics)?);
    } else {
        let cwd = std::env::current_dir().unwrap_or_default();
        for d in &diagnostics {
            let file = Path::new(&d.file);
            let mut location = file
                .strip_prefix(&cwd)
                .unwrap_or(file)
                .display()
                .to_string();
            let start = d.span.zip(source(&d.file));
            if let Some((line, column)) = start.and_then(|(span, source)| {
                arkade_compiler::diagnostics::position(&source, span.start)
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
