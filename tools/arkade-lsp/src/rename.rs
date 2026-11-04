//! Renaming a definition in every file that can see it.

use std::collections::{HashMap, HashSet};

use arkade_compiler::symbols::{Definition, Symbols};
use arkade_compiler::{Severity, Span};
use lsp_types::{Position, Range, TextEdit, Url, WorkspaceEdit};

use crate::project::{offset, range, Project};
use crate::{uses, Server};

impl Server {
    /// The name under the cursor, when it names a definition.
    pub(crate) fn prepare_rename(&self, (uri, cursor): (Url, Position)) -> Option<Range> {
        let project = self.project(&uri)?;
        let analysis = self.analyze(&project);
        let at = offset(project.source(), cursor)?;
        let mut names = uses(&analysis, &project, cursor, true).into_iter();
        let (_, span) = names
            .find(|(file, span)| *file == project.entry && span.start <= at && at <= span.end)?;
        Some(range(project.source(), span))
    }

    /// The edits renaming the definition at the cursor to `name` everywhere it is used, or why
    /// it cannot be. A file-level definition is renamed in every file importing its file,
    /// directly or not: one cached analysis per such file.
    pub(crate) fn rename(
        &self,
        (uri, cursor): (Url, Position),
        name: &str,
    ) -> Result<WorkspaceEdit, String> {
        if !is_identifier(name) {
            return Err(format!("'{name}' is not an identifier"));
        }
        let project = self.project(&uri).ok_or("the document is not open")?;
        let analysis = self.analyze(&project);
        let at = offset(project.source(), cursor);
        let symbols = analysis.symbols();
        let definition = at.and_then(|at| symbols.definition_at(&project.entry, at));
        let definition = definition.ok_or("no name to rename here")?.clone();
        let mut projects = Vec::new();
        if definition.visible.is_none() {
            let file = project.id(&self.index, &definition.file);
            let dependents = file.map(|file| self.index.dependents(file));
            let dependents = dependents.into_iter().flatten();
            projects.extend(dependents.filter_map(|id| Project::new(&self.index, id)));
        }
        projects.push(project);

        let mut spans: HashMap<Url, Vec<Span>> = HashMap::new();
        let mut edits: HashMap<Url, Vec<TextEdit>> = HashMap::new();
        let mut seen = HashSet::new();
        for project in &projects {
            let analysis = self.analyze(project);
            let symbols = analysis.symbols();
            let same = |d: &Definition| d.file == definition.file && d.span == definition.span;
            let Some(index) = symbols.definitions().iter().position(same) else {
                continue;
            };
            let target = &symbols.definitions()[index];
            let references = symbols.references().iter();
            let references = references.filter(|r| r.definition == index);
            let all = std::iter::once((target.file.as_str(), target.span))
                .chain(references.map(|r| (r.file.as_str(), r.span)));
            for (file, span) in all {
                if let Some(other) = collision(symbols, target, file, span.start, name) {
                    return Err(format!("'{other}' is already defined there"));
                }
                let (Some(uri), Some(source)) = (project.uri(file), analysis.source(file)) else {
                    continue;
                };
                if seen.insert((uri.clone(), span.start)) {
                    spans.entry(uri.clone()).or_default().push(span);
                    let edit = TextEdit::new(range(source, span), name.to_string());
                    edits.entry(uri).or_default().push(edit);
                }
            }
        }
        let project = projects.last().expect("the entry");
        if let Some(error) = self.new_error(project, &spans, name) {
            return Err(format!("renaming to '{name}' fails: {error}"));
        }
        Ok(WorkspaceEdit {
            changes: Some(edits),
            ..Default::default()
        })
    }

    /// An error the compiler finds in `project` with `spans` renamed to `name` but not before,
    /// such as a reserved name.
    fn new_error(
        &self,
        project: &Project,
        spans: &HashMap<Url, Vec<Span>>,
        name: &str,
    ) -> Option<String> {
        let errors = |diagnostics: Vec<arkade_compiler::Diagnostic>| -> Vec<String> {
            let errors = diagnostics.into_iter();
            let errors = errors.filter(|d| d.severity == Severity::Error);
            errors.map(|d| d.message).collect()
        };
        let before = errors(self.analyze(project).diagnostics().to_vec());
        let mut files = project.sources();
        for (file, text) in &mut files {
            let mut renamed = project.uri(file).and_then(|uri| spans.get(&uri)).cloned();
            let renamed = renamed.get_or_insert_with(Vec::new);
            renamed.sort_by_key(|span| std::cmp::Reverse(span.start));
            for span in renamed {
                text.replace_range(span.start..span.end, name);
            }
        }
        let after = arkade_compiler::analyze(&project.entry, &files).check(Default::default());
        let after = errors(after);
        after.into_iter().find(|error| !before.contains(error))
    }
}

/// How `name` would be written at `offset` in `file` in place of `target`, when that already
/// means another definition there.
fn collision(
    symbols: &Symbols,
    target: &Definition,
    file: &str,
    offset: usize,
    name: &str,
) -> Option<String> {
    let visible = symbols.visible_at(file, offset);
    // Each way the target is written there, such as `Rules.check` and `check`, renamed.
    let mut renamed: Vec<String> = visible
        .iter()
        .filter(|(_, d)| std::ptr::eq(*d, target))
        .map(|(written, _)| match written.rsplit_once('.') {
            Some((owner, _)) => format!("{owner}.{name}"),
            None => name.to_string(),
        })
        .collect();
    if renamed.is_empty() {
        renamed.push(name.to_string());
    }
    let taken = visible
        .iter()
        .find(|(written, d)| renamed.iter().any(|r| r == written) && !std::ptr::eq(*d, target));
    taken.map(|(written, _)| written.to_string())
}

/// Whether `name` is an identifier: a letter, then letters, digits and underscores.
fn is_identifier(name: &str) -> bool {
    let mut characters = name.chars();
    characters.next().is_some_and(|c| c.is_ascii_alphabetic())
        && characters.all(|c| c.is_ascii_alphanumeric() || c == '_')
}
