//! The files the compiler sees for one open document, their imports, and conversions between
//! compiler byte spans and LSP positions.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Component, Path};
use std::rc::Rc;

use arkade_compiler::diagnostics::{offset as byte_offset, position as compiler_position};
use arkade_compiler::{Analysis, Span};
use lsp_types::{Position, Range, Url};

use crate::index::{import_statements, FileId, Index};

/// One document as an entry, with the indexed files under its workspace root, keyed by paths
/// relative to the root.
pub struct Project {
    pub entry: String,
    pub files: BTreeMap<String, String>,
    uris: BTreeMap<String, Url>,
}

impl Project {
    pub fn new(index: &Index, id: FileId) -> Option<Self> {
        let path = &index.file(id).path;
        let root = index.root(path);
        let entry = relative(&root, path)?;
        let mut files = BTreeMap::new();
        let mut uris = BTreeMap::new();
        for (_, file) in index.files() {
            let Some(name) = relative(&root, &file.path) else {
                continue;
            };
            let uri = match &file.open {
                Some((uri, _)) => Some(uri.clone()),
                None => Url::from_file_path(&file.path).ok(),
            };
            uris.extend(uri.map(|uri| (name.clone(), uri)));
            files.insert(name, file.text.as_deref().unwrap_or_default().to_string());
        }
        Some(Self { entry, files, uris })
    }

    pub fn source(&self) -> &str {
        &self.files[&self.entry]
    }

    pub fn uri(&self, file: &str) -> Option<Url> {
        self.uris.get(file).cloned()
    }

    /// The directory imports of the entry are relative to.
    pub fn directory(&self) -> &Path {
        Path::new(&self.entry).parent().unwrap_or(Path::new(""))
    }

    /// Each import statement of the entry: the file it names and the statement's range, from the
    /// compiler's parse, or from the import lines while the header does not parse.
    pub fn imports(&self) -> Vec<(String, Range)> {
        let source = self.source();
        import_statements(source)
            .into_iter()
            .filter_map(|(path, span)| Some((join(self.directory(), &path)?, range(source, span))))
            .collect()
    }
}

/// The entry and files last analyzed, and their analysis.
type Analyzed = (String, BTreeMap<String, String>, Rc<Analysis>);

/// The last analysis, reused while the entry and files are unchanged.
#[derive(Default)]
pub struct Cache(RefCell<Option<Analyzed>>);

impl Cache {
    pub fn analyze(&self, entry: &str, files: &BTreeMap<String, String>) -> Rc<Analysis> {
        let mut cached = self.0.borrow_mut();
        if let Some((e, f, analysis)) = cached.as_ref() {
            if e == entry && f == files {
                return analysis.clone();
            }
        }
        let analysis = Rc::new(arkade_compiler::analyze(entry, files));
        *cached = Some((entry.to_string(), files.clone(), analysis.clone()));
        analysis
    }
}

pub fn range(source: &str, span: Span) -> Range {
    let at = |offset| {
        compiler_position(source, offset).map_or(Position::default(), |(line, column)| {
            Position::new(line as u32 - 1, column as u32 - 1)
        })
    };
    Range::new(at(span.start), at(span.end))
}

pub fn offset(source: &str, position: Position) -> Option<usize> {
    byte_offset(
        source,
        position.line as usize + 1,
        position.character as usize + 1,
    )
}

pub fn first_line(source: &str) -> Range {
    let first = source.split('\n').next().unwrap_or_default();
    Range::new(Position::new(0, 0), Position::new(0, utf16_len(first)))
}

pub fn utf16_len(text: &str) -> u32 {
    text.encode_utf16().count() as u32
}

/// `path` imported from `directory`, as a workspace-relative file; `None` above the root.
pub fn join(directory: &Path, path: &str) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    for component in directory.join(path).components() {
        match component {
            Component::Normal(part) => parts.push(part.to_str()?.to_string()),
            Component::ParentDir => {
                parts.pop()?;
            }
            Component::CurDir => {}
            _ => return None,
        }
    }
    Some(parts.join("/"))
}

/// Relative import path from the importing file's directory, e.g. `../lib/rules.ark`.
pub fn import_path(from: &Path, file: &str) -> String {
    let file = Path::new(file);
    let common = from
        .components()
        .zip(file.components())
        .take_while(|(a, b)| a == b)
        .count();
    let up = from.components().count() - common;
    let down = file
        .components()
        .skip(common)
        .map(|c| c.as_os_str().to_string_lossy());
    std::iter::repeat_n("..".into(), up)
        .chain(down)
        .collect::<Vec<_>>()
        .join("/")
}

/// The line after the last import or pragma, or the top of the file.
pub fn import_line(source: &str) -> usize {
    source
        .split('\n')
        .enumerate()
        .filter(|(_, text)| {
            let text = text.trim_start();
            text.starts_with("import") || text.starts_with("pragma")
        })
        .map(|(i, _)| i + 1)
        .last()
        .unwrap_or(0)
}

fn relative(root: &Path, path: &Path) -> Option<String> {
    let parts: Option<Vec<_>> = path
        .strip_prefix(root)
        .ok()?
        .components()
        .map(|c| c.as_os_str().to_str())
        .collect();
    Some(parts?.join("/"))
}
