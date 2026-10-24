//! The files the compiler sees for one open document, their imports, and conversions between
//! compiler byte spans and LSP positions.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;

use arkade_compiler::diagnostics::{offset as byte_offset, position as compiler_position};
use arkade_compiler::{Analysis, Span};
use lsp_types::{Position, Range, Url};

// Whole-tree scan per request; keep an index of the workspace if large projects make this slow.
const MAX_FILES: usize = 2000;

/// One open document as an entry, with every `.ark` file under its workspace root, keyed by
/// paths relative to the root; open documents replace their text on disk.
pub struct Project {
    pub uri: Url,
    pub root: PathBuf,
    pub entry: String,
    pub files: BTreeMap<String, String>,
}

impl Project {
    pub fn new(uri: &Url, roots: &[PathBuf], documents: &BTreeMap<Url, String>) -> Option<Self> {
        let text = documents.get(uri)?;
        let Ok(path) = uri.to_file_path() else {
            let entry = "untitled.ark".to_string();
            return Some(Self {
                uri: uri.clone(),
                root: PathBuf::new(),
                files: BTreeMap::from([(entry.clone(), text.clone())]),
                entry,
            });
        };
        let root = roots
            .iter()
            .filter(|root| path.starts_with(root))
            .max_by_key(|root| root.components().count())
            .cloned()
            .or_else(|| path.parent().map(Path::to_path_buf))?;
        let mut files = BTreeMap::new();
        collect(&root, &root, &mut files);
        for (uri, text) in documents {
            if let Some(relative) = uri.to_file_path().ok().and_then(|p| relative(&root, &p)) {
                files.insert(relative, text.clone());
            }
        }
        let entry = relative(&root, &path)?;
        files.insert(entry.clone(), text.clone());
        Some(Self {
            uri: uri.clone(),
            root,
            entry,
            files,
        })
    }

    pub fn source(&self) -> &str {
        &self.files[&self.entry]
    }

    pub fn uri(&self, file: &str) -> Option<Url> {
        match file == self.entry {
            true => Some(self.uri.clone()),
            false => Url::from_file_path(self.root.join(file)).ok(),
        }
    }

    /// The directory imports of the entry are relative to.
    pub fn directory(&self) -> &Path {
        Path::new(&self.entry).parent().unwrap_or(Path::new(""))
    }

    /// Each import statement of the entry: the file it names and the statement's range.
    pub fn imports(&self) -> Vec<(String, Range)> {
        let mut imports = Vec::new();
        for (index, line) in self.source().split('\n').enumerate() {
            let statement = line.trim();
            let (Some(start), Some(end)) = (statement.find('"'), statement.rfind('"')) else {
                continue;
            };
            if !statement.starts_with("import") || start == end {
                continue;
            }
            let Some(file) = join(self.directory(), &statement[start + 1..end]) else {
                continue;
            };
            let indent = utf16_len(&line[..line.len() - line.trim_start().len()]);
            let at = |character| Position::new(index as u32, character);
            let range = Range::new(at(indent), at(indent + utf16_len(statement)));
            imports.push((file, range));
        }
        imports
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

fn collect(root: &Path, dir: &Path, files: &mut BTreeMap<String, String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if files.len() >= MAX_FILES {
            return;
        }
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') || name == "node_modules" || name == "target" {
            continue;
        }
        if path.is_dir() {
            collect(root, &path, files);
        } else if name.ends_with(".ark") {
            if let (Some(relative), Ok(text)) =
                (relative(root, &path), std::fs::read_to_string(&path))
            {
                files.insert(relative, text);
            }
        }
    }
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
