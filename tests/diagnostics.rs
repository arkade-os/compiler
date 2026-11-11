//! Every program in `tests/diagnostics/` against the diagnostics it gets, rendered as an author
//! reads them. `BLESS=1 cargo test --test diagnostics` rewrites the expected `.txt` files.

use std::collections::BTreeMap;
use std::path::Path;

use arkade_compiler::diagnostics::{position, Severity};
use arkade_compiler::Diagnostic;

#[test]
fn diagnostics_match_their_baselines() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/diagnostics");
    let bless = std::env::var_os("BLESS").is_some();
    let mut programs: Vec<_> = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == "ark"))
        .collect();
    programs.sort();
    assert!(!programs.is_empty());
    let mut changed = Vec::new();
    for program in programs {
        let source = std::fs::read_to_string(&program).unwrap();
        let name = program.file_name().unwrap().to_string_lossy().to_string();
        let files = BTreeMap::from([(name.clone(), source.clone())]);
        let diagnostics = arkade_compiler::analyze(&name, &files).check(Default::default());
        let rendered: String = diagnostics.iter().map(|d| render(d, &source)).collect();
        let baseline = program.with_extension("txt");
        if bless {
            std::fs::write(&baseline, &rendered).unwrap();
        } else if std::fs::read_to_string(&baseline).ok().as_deref() != Some(rendered.as_str()) {
            changed.push(format!("{name}:\n{rendered}"));
        }
    }
    assert!(
        changed.is_empty(),
        "diagnostics changed; review and run with BLESS=1:\n\n{}",
        changed.join("\n")
    );
}

/// `diagnostic` as `severity[code]: message`, then its line with the span underlined.
fn render(diagnostic: &Diagnostic, source: &str) -> String {
    let severity = match diagnostic.severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
    };
    let code = diagnostic
        .code
        .as_deref()
        .map(|c| format!("[{c}]"))
        .unwrap_or_default();
    let mut text = format!("{severity}{code}: {}\n", diagnostic.message);
    let Some(span) = diagnostic.span else {
        return text + "\n";
    };
    let (line, column) = position(source, span.start).unwrap();
    let source_line = source.lines().nth(line - 1).unwrap_or_default();
    let width = source[span.start..span.end]
        .lines()
        .next()
        .map_or(1, |t| t.chars().count());
    let pad = " ".repeat(line.to_string().len());
    text += &format!("{pad} --> {line}:{column}\n{line} | {source_line}\n");
    text += &format!(
        "{pad} | {}{}\n\n",
        " ".repeat(column - 1),
        "^".repeat(width.max(1))
    );
    text
}
