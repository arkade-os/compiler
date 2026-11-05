use clap::{CommandFactory, FromArgMatches, Parser as ClapParser};
use std::fs;
use std::path::Path;

use arkade_compiler::lint::{Level, Levels, Lint};
use arkade_compiler::{analyze_file, CompileOptions, Severity};

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
    #[arg(required_unless_present = "explain")]
    file: Option<String>,

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

    /// Print each covenant's script bytes, stack peak and opcode execution counts
    #[arg(long, conflicts_with = "check")]
    report: bool,

    /// Leave out a lint (by id, category, or `all`)
    #[arg(long, value_name = "LINT")]
    allow: Vec<String>,

    /// Report a lint as a warning (by id, category, or `all`)
    #[arg(long, value_name = "LINT")]
    warn: Vec<String>,

    /// Explain a lint: what it reports, why it matters and how to fix it
    #[arg(long, value_name = "LINT", exclusive = true)]
    explain: Option<String>,

    /// Report a lint as an error (by id, category, `all`, or `warnings` for every warning-level lint)
    #[arg(long, value_name = "LINT")]
    deny: Vec<String>,
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
    let matches = Args::command().get_matches();
    let args = Args::from_arg_matches(&matches)?;
    if let Some(id) = &args.explain {
        let lint: Lint = id.parse()?;
        let level = format!("{:?}", lint.level()).to_lowercase();
        let category = format!("{:?}", lint.category()).to_lowercase();
        println!(
            "{id}: {category}, {level} by default\n\n{}",
            lint.explanation()
        );
        return Ok(());
    }

    // Ensure file has .ark extension
    let file = args
        .file
        .as_deref()
        .expect("clap requires a file without --explain");
    let file_path = Path::new(file);
    if file_path.extension().unwrap_or_default() != "ark" {
        return Err("Input file must have .ark extension".into());
    }

    // Level flags apply in the order given, so a later one wins, except that a lint
    // named by its id overrides a category, `all` or `warnings` wherever it appears.
    let mut flags = Vec::new();
    for (name, ids, level) in [
        ("allow", &args.allow, Level::Allow),
        ("warn", &args.warn, Level::Warn),
        ("deny", &args.deny, Level::Deny),
    ] {
        let indices = matches.indices_of(name).into_iter().flatten();
        flags.extend(indices.zip(ids).map(|(index, id)| (index, id, level)));
    }
    flags.sort_by_key(|&(index, ..)| index);
    let mut levels = Levels::default();
    for one_lint in [false, true] {
        for (_, id, level) in flags
            .iter()
            .filter(|(_, id, _)| id.parse::<Lint>().is_ok() == one_lint)
        {
            levels.set_named(id, *level)?;
        }
    }

    let options = CompileOptions {
        optimize: !args.no_optimize,
    };
    if args.check {
        check(file_path, args.json, options, &levels)?;
        return Ok(());
    }

    let analysis = analyze_file(file_path);
    let diagnostics = analysis.diagnostics_with(&levels);
    print_diagnostics(&analysis, &diagnostics, &mut std::io::stderr())?;
    if diagnostics.iter().any(|d| d.severity == Severity::Error) {
        std::process::exit(1);
    }
    let output = match analysis.compile_with(options, &levels) {
        Ok(output) => output,
        Err(errors) => {
            print_diagnostics(&analysis, &errors, &mut std::io::stderr())?;
            std::process::exit(1);
        }
    };

    if args.report {
        print_report(&output);
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
    levels: &Levels,
) -> Result<(), Box<dyn std::error::Error>> {
    let analysis = analyze_file(path);
    let diagnostics = analysis.check_with(options, levels);
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
        print_diagnostics(&analysis, &diagnostics, &mut std::io::stdout())?;
    }
    if diagnostics.iter().any(|d| d.severity == Severity::Error) {
        std::process::exit(1);
    }
    Ok(())
}

/// One block per covenant with its resource usage.
fn print_report(output: &arkade_compiler::models::ContractJson) {
    for group in &output.functions {
        let Some(covenant) = &group.arkade else {
            continue;
        };
        println!("{}", group.name);
        for cost in &covenant.costs {
            println!("  {:<24} {:>6}", cost.name, cost.used);
        }
    }
}

/// `file` relative to the working directory, as diagnostics show it in text and JSON.
fn shown(file: &str) -> String {
    let cwd = std::env::current_dir().unwrap_or_default();
    let file = Path::new(file);
    file.strip_prefix(&cwd)
        .unwrap_or(file)
        .display()
        .to_string()
}

/// Write each diagnostic as `file:line:column: severity[code]: message`.
fn print_diagnostics(
    analysis: &arkade_compiler::Analysis,
    diagnostics: &[arkade_compiler::Diagnostic],
    out: &mut impl std::io::Write,
) -> std::io::Result<()> {
    for d in diagnostics {
        let mut location = shown(&d.file);
        let start = d.span.zip(analysis.source(&d.file));
        if let Some((line, column)) = start
            .and_then(|(span, source)| arkade_compiler::diagnostics::position(source, span.start))
        {
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
        writeln!(out, "{location}: {severity}{code}: {}", d.message)?;
    }
    Ok(())
}
