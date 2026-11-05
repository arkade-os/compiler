//! Every `.ark` file the server knows, read from disk once and then kept current from the editor
//! and the file watcher: its text, version, imports and declared names, and its importers.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use arkade_compiler::symbols::SymbolKind;
use arkade_compiler::Span;
use lsp_types::Url;

const MAX_FILES: usize = 2000;
const MAX_ENTRIES: usize = 20_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileId(pub u32);

pub struct Declaration {
    pub name: String,
    pub kind: SymbolKind,
    pub span: Span,
}

pub struct File {
    pub path: PathBuf,
    /// `None` while the file is neither on disk nor open.
    pub text: Option<Arc<str>>,
    /// Changes with `text`, and is never reused by another text of any file.
    pub version: u64,
    /// The client's URI and version while the editor has the file open.
    pub open: Option<(Url, i32)>,
    pub imports: Vec<FileId>,
    pub declarations: Vec<Declaration>,
}

#[derive(Default)]
pub struct Index {
    roots: Vec<PathBuf>,
    files: Vec<File>,
    by_path: HashMap<PathBuf, FileId>,
    importers: Vec<Vec<FileId>>,
    /// Each declared name, lowercased for prefix search, with its spelling and file.
    exports: BTreeSet<(String, String, FileId)>,
    clock: u64,
}

impl Index {
    /// The `.ark` files under `roots`, at most `MAX_FILES` files and `MAX_ENTRIES` directory
    /// entries per root, with the files they import. O(workspace), once at startup.
    pub fn new(roots: Vec<PathBuf>) -> Self {
        let mut index = Index {
            roots,
            ..Default::default()
        };
        for root in index.roots.clone() {
            let mut paths = Vec::new();
            collect(&root, &mut paths, &mut 0);
            for path in paths {
                index.load(&path);
            }
        }
        index
    }

    pub fn file(&self, id: FileId) -> &File {
        &self.files[id.0 as usize]
    }

    pub fn get(&self, path: &Path) -> Option<FileId> {
        self.by_path.get(path).copied()
    }

    /// Every file with text. O(workspace); only for answers that list the workspace.
    pub fn files(&self) -> impl Iterator<Item = (FileId, &File)> {
        let files = self.files.iter().enumerate();
        files
            .filter(|(_, file)| file.text.is_some())
            .map(|(i, file)| (FileId(i as u32), file))
    }

    /// Up to `limit` declared names starting with `prefix`, ignoring case, each with its file.
    /// O(log names + limit).
    pub fn exported(&self, prefix: &str, limit: usize) -> Vec<(&str, FileId)> {
        let prefix = prefix.to_lowercase();
        let from = (prefix.clone(), String::new(), FileId(0));
        let names = self.exports.range(from..);
        let names = names.take_while(|(lower, _, _)| lower.starts_with(&prefix));
        names
            .take(limit)
            .map(|(_, name, id)| (name.as_str(), *id))
            .collect()
    }

    /// The files declaring `name`. O(log names + their count).
    pub fn exporters(&self, name: &str) -> Vec<FileId> {
        let named = self.exported(name, usize::MAX).into_iter();
        named
            .filter(|(n, _)| *n == name)
            .map(|(_, id)| id)
            .collect()
    }

    /// The deepest workspace folder holding `path`, or its directory outside every folder.
    pub fn root(&self, path: &Path) -> PathBuf {
        let folder = self.roots.iter().filter(|root| path.starts_with(root));
        let folder = folder.max_by_key(|root| root.components().count()).cloned();
        folder.unwrap_or_else(|| path.parent().map(Path::to_path_buf).unwrap_or_default())
    }

    /// The file at `path`, read from disk with its imports the first time it is named.
    pub fn load(&mut self, path: &Path) -> FileId {
        if let Some(id) = self.get(path) {
            return id;
        }
        let id = self.insert(path);
        self.set(id, read(path));
        id
    }

    /// Track `path` as open in the editor with `text`. O(text + its imports).
    pub fn open(&mut self, path: &Path, uri: Url, version: i32, text: String) -> FileId {
        let id = self.get(path).unwrap_or_else(|| self.insert(path));
        self.files[id.0 as usize].open = Some((uri, version));
        self.set(id, Some(text.into()));
        id
    }

    /// Stop tracking the editor's text of `path`, falling back to the disk's.
    pub fn close(&mut self, path: &Path) -> Option<FileId> {
        let id = self.get(path)?;
        self.files[id.0 as usize].open = None;
        self.set(id, read(path));
        Some(id)
    }

    /// Re-read `path` from disk unless it is open; the file when its text changed.
    pub fn refresh(&mut self, path: &Path) -> Option<FileId> {
        let id = self.get(path);
        if id.is_some_and(|id| self.file(id).open.is_some()) {
            return None;
        }
        let text = read(path);
        let id = match id {
            Some(id) if self.file(id).text == text => return None,
            Some(id) => id,
            None if text.is_none() => return None,
            None => self.insert(path),
        };
        self.set(id, text);
        Some(id)
    }

    /// Refresh `dir`'s `.ark` files, found or deleted; the files that changed. O(dir + files
    /// indexed), for clients that cannot watch files.
    pub fn rescan(&mut self, dir: &Path) -> Vec<FileId> {
        let entries = std::fs::read_dir(dir).into_iter().flatten().flatten();
        let mut paths: HashSet<PathBuf> = entries
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|e| e == "ark"))
            .collect();
        paths.extend(
            self.by_path
                .keys()
                .filter(|p| p.parent() == Some(dir))
                .cloned(),
        );
        paths.iter().filter_map(|path| self.refresh(path)).collect()
    }

    /// Replace the text of `id`, then read from disk each file its imports name the first time.
    /// O(text + imports) when the import and declaration sets are unchanged.
    pub fn set(&mut self, id: FileId, text: Option<Arc<str>>) {
        let mut pending = vec![(id, text)];
        while let Some((id, text)) = pending.pop() {
            for new in self.replace(id, text) {
                let path = self.file(new).path.clone();
                pending.push((new, read(&path)));
            }
        }
    }

    /// The open files among `dirty` and the files importing them, directly or not. O(those
    /// files and their import edges).
    pub fn affected(&self, dirty: impl IntoIterator<Item = FileId>) -> Vec<FileId> {
        let affected = self.importing(dirty).into_iter();
        affected
            .filter(|id| self.file(*id).open.is_some())
            .collect()
    }

    /// `id` and every file importing it, directly or not. O(those files and their import edges).
    pub fn dependents(&self, id: FileId) -> Vec<FileId> {
        self.importing([id])
    }

    /// `files` and the files importing them, directly or not, in breadth-first order.
    fn importing(&self, files: impl IntoIterator<Item = FileId>) -> Vec<FileId> {
        let mut seen = HashSet::new();
        let mut queue: VecDeque<FileId> = files.into_iter().collect();
        let mut found = Vec::new();
        while let Some(id) = queue.pop_front() {
            if seen.insert(id) {
                found.push(id);
                queue.extend(&self.importers[id.0 as usize]);
            }
        }
        found
    }

    /// `entry`'s import closure in breadth-first order, each file with the importer that reached
    /// it first. O(closure and its import edges).
    pub fn closure(&self, entry: FileId) -> Vec<(FileId, Option<FileId>)> {
        let mut seen = HashSet::from([entry]);
        let mut closure = vec![(entry, None)];
        let mut next = 0;
        while let Some(&(id, _)) = closure.get(next) {
            next += 1;
            for &import in &self.file(id).imports {
                if seen.insert(import) {
                    closure.push((import, Some(id)));
                }
            }
        }
        closure
    }

    fn insert(&mut self, path: &Path) -> FileId {
        let id = FileId(self.files.len() as u32);
        self.files.push(File {
            path: path.to_path_buf(),
            text: None,
            version: 0,
            open: None,
            imports: Vec::new(),
            declarations: Vec::new(),
        });
        self.importers.push(Vec::new());
        self.by_path.insert(path.to_path_buf(), id);
        id
    }

    /// Replace the text, imports and declarations of `id`; the files its imports name that were
    /// not tracked yet.
    fn replace(&mut self, id: FileId, text: Option<Arc<str>>) -> Vec<FileId> {
        self.clock += 1;
        let path = self.file(id).path.clone();
        let source = text.as_deref().unwrap_or_default();
        let mut new = Vec::new();
        let mut imports = Vec::new();
        for (import, _) in import_statements(source) {
            let Some(target) = resolve(&path, &import) else {
                continue;
            };
            let file = self.get(&target).unwrap_or_else(|| {
                let file = self.insert(&target);
                new.push(file);
                file
            });
            imports.push(file);
        }
        let declarations = arkade_compiler::declarations(source);
        let declarations: Vec<_> = declarations
            .into_iter()
            .map(|(name, kind, span)| Declaration { name, kind, span })
            .collect();

        let file = &mut self.files[id.0 as usize];
        let names = |declarations: &[Declaration]| -> BTreeSet<String> {
            declarations.iter().map(|d| d.name.clone()).collect()
        };
        let (old_names, new_names) = (names(&file.declarations), names(&declarations));
        let targets = |imports: &[FileId]| -> Vec<FileId> {
            let mut targets = imports.to_vec();
            targets.sort();
            targets.dedup();
            targets
        };
        let (old, now) = (targets(&file.imports), targets(&imports));
        file.text = text;
        file.version = self.clock;
        file.imports = imports;
        file.declarations = declarations;
        if old != now {
            for target in &old {
                self.importers[target.0 as usize].retain(|importer| *importer != id);
            }
            for target in &now {
                self.importers[target.0 as usize].push(id);
            }
        }
        if old_names != new_names {
            for name in old_names {
                self.exports.remove(&(name.to_lowercase(), name, id));
            }
            for name in new_names {
                self.exports.insert((name.to_lowercase(), name, id));
            }
        }
        new
    }
}

/// Each import's path and statement, from the compiler's parse or, for a broken header, its lines.
pub fn import_statements(source: &str) -> Vec<(String, Span)> {
    arkade_compiler::imports(source).unwrap_or_else(|| import_lines(source))
}

/// Lines starting with `import`: the path up to the first closing quote and the statement up to
/// its `;`, or its closing quote without one.
fn import_lines(source: &str) -> Vec<(String, Span)> {
    let mut imports = Vec::new();
    let mut start = 0;
    for line in source.split('\n') {
        let at = start + line.len() - line.trim_start().len();
        start += line.len() + 1;
        let Some(rest) = line.trim_start().strip_prefix("import") else {
            continue;
        };
        let Some((before, quoted)) = rest.split_once('"') else {
            continue;
        };
        let Some((path, after)) = quoted.split_once('"') else {
            continue;
        };
        if !before.trim().is_empty() {
            continue;
        }
        let tail = after.trim_start();
        let semicolon = tail.starts_with(';').then(|| after.len() - tail.len() + 1);
        let end = at + "import".len() + rest.len() - after.len() + semicolon.unwrap_or(0);
        imports.push((path.to_string(), Span { start: at, end }));
    }
    imports
}

/// The `.ark` file `import` names from the file at `importer`, as the compiler resolves it.
fn resolve(importer: &Path, import: &str) -> Option<PathBuf> {
    if import.starts_with('/') || import.contains(['\\', ':']) || !import.ends_with(".ark") {
        return None;
    }
    let mut path = PathBuf::new();
    for component in importer.parent()?.join(import).components() {
        match component {
            Component::ParentDir => {
                path.pop();
            }
            Component::CurDir => {}
            component => path.push(component),
        }
    }
    Some(path)
}

fn read(path: &Path) -> Option<Arc<str>> {
    std::fs::read_to_string(path).ok().map(Into::into)
}

/// Every `.ark` file under `dir`, sorted, skipping symlinked directories; at most `MAX_FILES`
/// files and `MAX_ENTRIES` directory entries, counted in `visited`.
fn collect(dir: &Path, paths: &mut Vec<PathBuf>, visited: &mut usize) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.flatten().collect();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        *visited += 1;
        if paths.len() >= MAX_FILES || *visited > MAX_ENTRIES {
            return;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') || name == "node_modules" || name == "target" {
            continue;
        }
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            collect(&entry.path(), paths, visited);
        } else if name.ends_with(".ark") {
            paths.push(entry.path());
        }
    }
}
