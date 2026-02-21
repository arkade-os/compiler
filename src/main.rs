use clap::Parser as ClapParser;
use std::fs;
use std::path::Path;

mod compiler;
mod models;
mod opcodes;
mod parser;

/// Arkade Compiler CLI
///
/// This is the command-line interface for the Arkade Compiler.
/// It compiles Arkade Script source code (.ark files) into JSON output
/// that represents Bitcoin Taproot scripts.
///
/// The JSON output includes:
/// - Contract name
/// - Parameters
/// - Server key placeholder
/// - Script paths for each function
///
/// Each script path includes a serverVariant flag. When using the script:
/// - If serverVariant is true, use the script as-is
/// - If serverVariant is false, libraries should add an exit delay timelock
///   (default 48 hours) for additional security

// CLI arguments
#[derive(ClapParser, Debug)]
#[command(name = "arkadec")]
#[command(about = "Arkade Compiler for Bitcoin Taproot scripts", long_about = None)]
struct Args {
    /// Source file path (.ark)
    #[arg(required = true)]
    file: String,

    /// Output file path (defaults to source filename with .json extension)
    #[arg(short, long)]
    output: Option<String>,
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

    // Read source code
    let source_code = fs::read_to_string(&args.file)?;

    // Compile source code to JSON
    let output = match compiler::compile(&source_code) {
        Ok(json) => json,
        Err(err) => {
            eprintln!("Compilation error: {}", err);
            return Err(err.into());
        }
    };

    // Determine output path
    let output_path = match args.output {
        Some(path) => path,
        None => {
            let stem = file_path.file_stem().unwrap_or_default().to_string_lossy();
            format!("{}.json", stem)
        }
    };

    // Write output JSON
    let json = serde_json::to_string_pretty(&output)?;
    fs::write(&output_path, json)?;

    println!("Compilation successful. Output written to {}", output_path);

    Ok(())
}
