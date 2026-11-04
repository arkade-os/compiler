//! The files the compiler sees for one open document, their imports, and conversions between
//! compiler byte spans and LSP positions.

use std::cell::{OnceCell, RefCell};
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

use arkade_compiler::diagnostics::{offset as byte_offset, position as compiler_position};
use arkade_compiler::{Analysis, Diagnostic, Span};
use lsp_types::{Position, Range, Url};

use crate::index::{import_statements, File, FileId, Index};

/// One document as an entry with its import closure, keyed by paths relative to its workspace
/// root.
pub struct Project {
    pub entry: String,
    pub files: BTreeMap<String, Arc<str>>,
    /// The entry and a hash of each closure file's id and version.
    pub key: (FileId, u64),
    root: PathBuf,
    uris: BTreeMap<String, Url>,
}

impl Project {
    /// O(closure): its files' texts are shared, not copied.
    pub fn new(index: &Index, id: FileId) -> Option<Self> {
        let path = &index.file(id).path;
        let root = index.root(path);
        let entry = relative(&root, path)?;
        let mut files = BTreeMap::new();
        let mut uris = BTreeMap::new();
        let mut hasher = DefaultHasher::new();
        for (member, _) in index.closure(id) {
            let file = index.file(member);
            (member, file.version).hash(&mut hasher);
            let (Some(name), Some(text)) = (relative(&root, &file.path), &file.text) else {
                continue;
            };
            uris.extend(uri(file).map(|uri| (name.clone(), uri)));
            files.insert(name, text.clone());
        }
        Some(Self {
            entry,
            files,
            key: (id, hasher.finish()),
            root,
            uris,
        })
    }

    /// The closure's texts as the compiler takes them.
    pub fn sources(&self) -> BTreeMap<String, String> {
        let files = self.files.iter();
        files
            .map(|(name, text)| (name.clone(), text.to_string()))
            .collect()
    }

    /// Every indexed file under the root, by relative path. O(workspace).
    pub fn workspace<'a>(&self, index: &'a Index) -> impl Iterator<Item = (String, &'a File)> {
        let root = self.root.clone();
        index
            .files()
            .filter_map(move |(_, file)| Some((relative(&root, &file.path)?, file)))
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

const CACHED: usize = 32;

/// One analysis of a project, and the diagnostics derived from it on first use.
pub struct Analyzed {
    analysis: Analysis,
    diagnostics: OnceCell<Vec<Diagnostic>>,
}

impl Analyzed {
    /// Every diagnostic, code generation's included.
    pub fn diagnostics(&self) -> &[Diagnostic] {
        (self.diagnostics).get_or_init(|| self.analysis.check(Default::default()))
    }
}

impl std::ops::Deref for Analyzed {
    type Target = Analysis;

    fn deref(&self) -> &Analysis {
        &self.analysis
    }
}

/// An analysis and its project's key.
type Cached = ((FileId, u64), Rc<Analyzed>);

/// Analyses by entry and closure fingerprint, most recently used first.
#[derive(Default)]
pub struct Cache(RefCell<VecDeque<Cached>>);

impl Cache {
    /// The analysis of `project`, reused while no file of its closure changed. O(`CACHED`) on a
    /// hit.
    pub fn analyze(&self, project: &Project) -> Rc<Analyzed> {
        let mut cached = self.0.borrow_mut();
        if let Some(at) = cached.iter().position(|(key, _)| *key == project.key) {
            let hit = cached.remove(at).expect("position");
            cached.push_front(hit.clone());
            return hit.1;
        }
        drop(cached);
        let analysis = Rc::new(Analyzed {
            analysis: arkade_compiler::analyze(&project.entry, &project.sources()),
            diagnostics: OnceCell::new(),
        });
        let mut cached = self.0.borrow_mut();
        cached.push_front((project.key, analysis.clone()));
        cached.truncate(CACHED);
        analysis
    }
}

/// The client's URI of `file` while open, its file URI otherwise.
pub fn uri(file: &File) -> Option<Url> {
    match &file.open {
        Some((uri, _)) => Some(uri.clone()),
        None => Url::from_file_path(&file.path).ok(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cache_follows_each_entry_closure() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let library = "library L { function f() { require(true); } }";
        std::fs::write(root.join("l.ark"), library).unwrap();
        let entry = "import \"l.ark\";\ncontract A() { function f() { L.f(); } }";
        std::fs::write(root.join("a.ark"), entry).unwrap();
        std::fs::write(
            root.join("b.ark"),
            "contract B() { function f() { require(true); } }",
        )
        .unwrap();
        let mut index = Index::new(vec![root.clone()]);
        let [a, b, l] = ["a.ark", "b.ark", "l.ark"].map(|f| index.get(&root.join(f)).unwrap());
        let cache = Cache::default();
        let analyze = |index: &Index, id| cache.analyze(&Project::new(index, id).unwrap());

        let first = analyze(&index, a);
        analyze(&index, b);
        assert!(Rc::ptr_eq(&first, &analyze(&index, a)));
        index.set(b, Some("contract B() {}".into()));
        assert!(Rc::ptr_eq(&first, &analyze(&index, a)));
        let broken = library.replace("require(true)", "require(missing)");
        index.set(l, Some(broken.into()));
        let analyzed = analyze(&index, a);
        assert!(!Rc::ptr_eq(&first, &analyzed));
        let sources = Project::new(&index, a).unwrap().sources();
        let checked = arkade_compiler::check("a.ark", &sources);
        assert_eq!(checked.len(), 1);
        assert_eq!(analyzed.diagnostics(), checked);
    }
}
