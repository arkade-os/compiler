//! Program loading: reads an entry file and its relative imports, resolves names across files,
//! and prepares each module once, producing an [`Analysis`] that reports diagnostics and emits
//! the entry's artifact. Imports are acyclic, and each contract and struct name is declared in
//! one file.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{self, Component, Path, PathBuf};
use std::{error, fmt, fs};

use crate::compiler::error::InternalError;
use crate::diagnostics::{self, CompileError, Diagnostic, Severity, Span};
use crate::lint::{Levels, Lints};
use crate::models::{
    self, Contract, ContractJson, ExprKind, Expression, LocatedStatement, SourceBundle, Statement,
};
use crate::parser::ParseError;
use crate::symbols::Symbols;
use crate::{compiler, parser, types, validator};

const MAX_IMPORT_DEPTH: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LoadError {
    SourceNotFound {
        path: String,
    },
    Unreadable {
        path: String,
        message: String,
    },
    AbsolutePath {
        message: String,
    },
    DuplicateSourcePath {
        path: String,
    },
    SourcePathNotRelative {
        path: String,
    },
    PathEscapesRoot {
        path: String,
    },
    NotArkFile {
        path: String,
    },
    PathNotUtf8,
    ImportNotRelative {
        import: String,
    },
    CircularImport {
        chain: Vec<String>,
        path: String,
    },
    ImportTooDeep,
    LibraryEntry,
    DependencyFails {
        name: String,
        path: String,
        message: String,
    },
    ReservedContractName {
        name: String,
    },
    DuplicateDeclaration {
        name: String,
        previous: String,
        path: String,
    },
    ShadowsContract {
        name: String,
    },
    UnknownType {
        name: String,
    },
    UnknownContract {
        name: String,
    },
    UnknownFunction {
        name: String,
    },
    NotStaticFunction {
        name: String,
    },
    PrivateLibraryFunction {
        name: String,
    },
    UnknownConstant {
        name: String,
    },
    NotStructType {
        name: String,
    },
    LibraryInstantiated {
        name: String,
    },
    SelfInstantiation {
        name: String,
    },
    ConstructorArgumentCount {
        contract: String,
        expected: usize,
        got: usize,
    },
    ConstructorArgumentType {
        contract: String,
        parameter: String,
        expected: models::TypeName,
        got: String,
    },
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::SourceNotFound { path } => write!(
                f,
                "source file '{path}' not found; imports require source files supplied with the entry"
            ),
            LoadError::Unreadable { path, message } => write!(f, "cannot read '{path}': {message}"),
            LoadError::AbsolutePath { message } => f.write_str(message),
            LoadError::DuplicateSourcePath { path } => write!(f, "duplicate source path '{path}'"),
            LoadError::SourcePathNotRelative { path } => write!(
                f,
                "source path '{path}' must be a relative .ark path using '/'"
            ),
            LoadError::PathEscapesRoot { path } => write!(f, "path '{path}' escapes the source root"),
            LoadError::NotArkFile { path } => {
                write!(f, "source path '{path}' must have .ark extension")
            }
            LoadError::PathNotUtf8 => f.write_str("source paths must be UTF-8"),
            LoadError::ImportNotRelative { import } => write!(
                f,
                "import '{import}' must be a relative .ark path using '/'"
            ),
            LoadError::CircularImport { chain, path } => {
                write!(f, "circular import: {} -> {path}", chain.join(" -> "))
            }
            LoadError::ImportTooDeep => {
                write!(f, "import depth exceeds {MAX_IMPORT_DEPTH} files")
            }
            LoadError::LibraryEntry => {
                f.write_str("entry file must declare a contract, not a library")
            }
            LoadError::DependencyFails {
                name,
                path,
                message,
            } => write!(
                f,
                "contract '{name}' does not compile on its own: {path}: {message}"
            ),
            LoadError::ReservedContractName { name } => {
                write!(f, "contract name '{name}' is reserved")
            }
            LoadError::DuplicateDeclaration {
                name,
                previous,
                path,
            } => write!(
                f,
                "duplicate declaration '{name}' in '{previous}' and '{path}'"
            ),
            LoadError::ShadowsContract { name } => {
                write!(f, "binding '{name}' shadows a contract namespace")
            }
            LoadError::UnknownType { name } => {
                write!(f, "unknown type '{name}'; import its defining file")
            }
            LoadError::UnknownContract { name } => {
                write!(f, "unknown contract '{name}'; import its defining file")
            }
            LoadError::UnknownFunction { name } => write!(f, "unknown function '{name}'"),
            LoadError::NotStaticFunction { name } => write!(f, "'{name}' is not a static function"),
            LoadError::PrivateLibraryFunction { name } => {
                write!(f, "library function '{name}' is private")
            }
            LoadError::UnknownConstant { name } => write!(f, "unknown constant '{name}'"),
            LoadError::NotStructType { name } => write!(f, "'{name}' is not a struct type"),
            LoadError::LibraryInstantiated { name } => {
                write!(f, "library '{name}' cannot be instantiated")
            }
            LoadError::SelfInstantiation { name } => write!(
                f,
                "contract '{name}' cannot instantiate itself, since its address would depend on itself; to keep funds in this contract, compare against the input's own script, e.g. `tx.outputs[0].script == tx.input.current.script`"
            ),
            LoadError::ConstructorArgumentCount {
                contract,
                expected,
                got,
            } => write!(
                f,
                "constructor '{contract}' expects {expected} arguments, got {got}"
            ),
            LoadError::ConstructorArgumentType {
                contract,
                parameter,
                expected,
                got,
            } => write!(
                f,
                "constructor '{contract}' argument '{parameter}' expects {expected}, got {got}"
            ),
        }
    }
}

impl error::Error for LoadError {}

// Dependency definitions are copied per module; use a shared symbol table if quadratic copying becomes costly.
struct Module {
    contract: Contract,
    structs: HashSet<String>,
    lints: Lints,
    leaves: Vec<compiler::tapscript::CheckedLeaf>,
}

/// `load()`'s failure: one error, or the diagnostics `compiler::prepare` collected for one
/// file, with that file's source.
pub(crate) enum LoadFailure {
    /// An error `load` has yet to tie to the file it was loading.
    Message(CompileError),
    /// A diagnostic, and the string the `compile_*` functions return.
    Located(Box<Diagnostic>, String),
    Diagnostics(Vec<Diagnostic>, String),
}

impl From<LoadError> for LoadFailure {
    fn from(error: LoadError) -> Self {
        LoadFailure::Message(error.into())
    }
}

impl From<CompileError> for LoadFailure {
    fn from(error: CompileError) -> Self {
        LoadFailure::Message(error)
    }
}

/// A program after parsing, import resolution, typing and validation, before code generation.
pub struct Analysis {
    entry: String,
    loaded: Result<Loaded, LoadFailure>,
    /// The text of every file read, by the path diagnostics and symbols name it with.
    sources: BTreeMap<String, String>,
    symbols: Symbols,
    /// Whether `entry` is a filesystem path, whose bundle is rebased onto the files' common root.
    filesystem: bool,
}

impl Analysis {
    fn load(
        entry: String,
        mut read: impl FnMut(&str) -> Result<String, LoadError>,
        filesystem: bool,
        symbols: bool,
    ) -> Self {
        let mut sources = BTreeMap::new();
        let mut table = Symbols::default();
        let mut record = |path: &str| -> Result<String, LoadError> {
            let source = read(path)?;
            sources.insert(path.to_string(), source.clone());
            Ok(source)
        };
        let loaded = Loaded::load(&entry, &mut record, symbols.then_some(&mut table));
        Analysis {
            entry,
            loaded,
            sources,
            symbols: table,
            filesystem,
        }
    }

    fn failed(entry: &str, error: LoadError, filesystem: bool) -> Self {
        Analysis {
            entry: entry.to_string(),
            loaded: Err(error.into()),
            sources: BTreeMap::new(),
            symbols: Default::default(),
            filesystem,
        }
    }

    /// Every parse, validation and type diagnostic, warnings included, with each lint at its
    /// own level. Independent problems in the entry file each get their own; diagnostics from
    /// imports name the imported file.
    pub fn diagnostics(&self) -> Vec<Diagnostic> {
        self.diagnostics_with(&Default::default())
    }

    /// [`Analysis::diagnostics`] with each lint at its level in `levels`: allowed lints are
    /// left out and denied ones are errors.
    pub fn diagnostics_with(&self, levels: &Levels) -> Vec<Diagnostic> {
        match &self.loaded {
            Ok(loaded) => loaded
                .warnings(&self.entry, levels)
                .flat_map(|(_, warnings)| warnings)
                .collect(),
            Err(error) => error.diagnostics(&self.entry),
        }
    }

    /// The entry file's typed AST, when it analyzed without errors.
    pub fn contract(&self) -> Option<&Contract> {
        let loaded = self.loaded.as_ref().ok()?;
        Some(&loaded.modules[&self.entry].contract)
    }

    /// The text of `file`, named as diagnostics and symbols name it, when analysis read it.
    pub fn source(&self, file: &str) -> Option<&str> {
        self.sources.get(file).map(String::as_str)
    }

    /// The definitions and references of every file that parsed and typed, including files that
    /// failed validation.
    pub fn symbols(&self) -> &Symbols {
        &self.symbols
    }

    /// The diagnostics, and for a contract code generation's first error with `options`, which
    /// finds some problems alone, such as the VM's stack and script limits.
    pub fn check(&self, options: crate::CompileOptions) -> Vec<Diagnostic> {
        self.check_with(options, &Default::default())
    }

    /// [`Analysis::check`] with each lint at its level in `levels`.
    pub fn check_with(&self, options: crate::CompileOptions, levels: &Levels) -> Vec<Diagnostic> {
        let mut diagnostics = self.diagnostics_with(levels);
        let failed = diagnostics.iter().any(|d| d.severity == Severity::Error);
        if !failed && self.contract().is_some_and(|contract| !contract.is_library) {
            if let Err(errors) = self.compile_with(options, levels) {
                diagnostics.extend(errors);
            }
        }
        diagnostics
    }

    /// Generate the artifact with each lint at its default level.
    pub fn compile(&self, options: crate::CompileOptions) -> Result<ContractJson, Vec<Diagnostic>> {
        self.compile_with(options, &Default::default())
    }

    /// Generate the artifact. Fails with the analysis errors, the entry file's lints `levels`
    /// denies, or code generation's first error.
    pub fn compile_with(
        &self,
        options: crate::CompileOptions,
        levels: &Levels,
    ) -> Result<ContractJson, Vec<Diagnostic>> {
        let loaded = self
            .loaded
            .as_ref()
            .map_err(|error| error.diagnostics(&self.entry))?;
        loaded
            .emit(
                &self.entry,
                &self.sources,
                self.filesystem,
                options,
                levels,
                &mut BTreeMap::new(),
            )
            .map_err(|error| match error {
                EmitError::Library => {
                    vec![Diagnostic::error(
                        &self.entry,
                        LoadError::LibraryEntry.to_string(),
                    )]
                }
                EmitError::Lints(errors) => errors,
                EmitError::Code(error, _) => vec![error.diagnostic(&self.entry)],
            })
    }

    /// `compile`, failing with the message the `compile_*` functions return.
    fn compile_message(&self, options: crate::CompileOptions) -> Result<ContractJson, String> {
        let loaded = self
            .loaded
            .as_ref()
            .map_err(|error| error.message(&self.entry))?;
        loaded
            .emit(
                &self.entry,
                &self.sources,
                self.filesystem,
                options,
                &Default::default(),
                &mut BTreeMap::new(),
            )
            .map_err(|error| match error {
                EmitError::Library => format!("{}: {}", self.entry, LoadError::LibraryEntry),
                EmitError::Lints(errors) => format!(
                    "{}: {}",
                    self.entry,
                    diagnostics::render_errors(&errors, &self.sources[&self.entry])
                ),
                EmitError::Code(error, source) => {
                    diagnostics::located(&error.to_string(), error.span, &source)
                }
            })
    }
}

impl LoadFailure {
    fn diagnostics(&self, entry: &str) -> Vec<Diagnostic> {
        match self {
            LoadFailure::Diagnostics(diagnostics, _) => diagnostics.clone(),
            LoadFailure::Located(diagnostic, _) => vec![(**diagnostic).clone()],
            // An error `load` has not located is about the entry itself, such as reading it.
            LoadFailure::Message(error) => vec![Diagnostic::error(entry, error.to_string())],
        }
    }

    fn message(&self, entry: &str) -> String {
        match self {
            LoadFailure::Message(error) => error.to_string(),
            LoadFailure::Located(_, message) => message.clone(),
            LoadFailure::Diagnostics(diagnostics, source) => format!(
                "{}: {}",
                diagnostics.first().map_or(entry, |d| d.file.as_str()),
                diagnostics::render_errors(diagnostics, source)
            ),
        }
    }
}

/// Analyze `entry` and its imports from an in-memory map of relative paths to source text,
/// collecting their symbols when `symbols`. `entry` may be a library file.
pub(crate) fn analyze(entry: &str, files: &BTreeMap<String, String>, symbols: bool) -> Analysis {
    let entry = match relative_path(entry) {
        Ok(entry) => entry,
        Err(e) => return Analysis::failed(entry, e, false),
    };
    let files = match normalize_files(files) {
        Ok(files) => files,
        Err(e) => return Analysis::failed(&entry, e, false),
    };
    let read = |path: &str| {
        files
            .get(path)
            .cloned()
            .ok_or_else(|| LoadError::SourceNotFound {
                path: path.to_string(),
            })
    };
    Analysis::load(entry, read, false, symbols)
}

pub(crate) fn analyze_file(path: &Path, symbols: bool) -> Analysis {
    let entry = path::absolute(path)
        .map_err(|e| LoadError::AbsolutePath {
            message: e.to_string(),
        })
        .and_then(|absolute| normalize(&absolute));
    let read = |path: &str| {
        fs::read_to_string(path).map_err(|e| LoadError::Unreadable {
            path: path.to_string(),
            message: e.to_string(),
        })
    };
    match entry {
        Ok(entry) => Analysis::load(entry, read, true, symbols),
        Err(error) => Analysis::failed(&path.to_string_lossy(), error, true),
    }
}

pub(crate) fn check_sources(entry: &str, files: &BTreeMap<String, String>) -> Vec<Diagnostic> {
    analyze(entry, files, false).check(Default::default())
}

pub(crate) fn compile_sources(
    entry: &str,
    files: &BTreeMap<String, String>,
    options: crate::CompileOptions,
) -> Result<ContractJson, String> {
    analyze(entry, files, false).compile_message(options)
}

fn normalize_files(
    files: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, LoadError> {
    let mut normalized = BTreeMap::new();
    for (path, source) in files {
        let path = relative_path(path)?;
        if normalized.insert(path.clone(), source.clone()).is_some() {
            return Err(LoadError::DuplicateSourcePath { path });
        }
    }
    Ok(normalized)
}

pub(crate) fn compile_file(
    path: &Path,
    options: crate::CompileOptions,
) -> Result<ContractJson, String> {
    analyze_file(path, false).compile_message(options)
}

pub(crate) fn relative_path(path: &str) -> Result<String, LoadError> {
    if path.starts_with('/') || path.contains('\\') || path.contains(':') {
        return Err(LoadError::SourcePathNotRelative {
            path: path.to_string(),
        });
    }
    normalize(Path::new(path))
}

fn normalize(path: &Path) -> Result<String, LoadError> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(LoadError::PathEscapesRoot {
                        path: path.display().to_string(),
                    });
                }
            }
            _ => normalized.push(component),
        }
    }
    if normalized
        .extension()
        .is_none_or(|extension| extension != "ark")
    {
        return Err(LoadError::NotArkFile {
            path: path.display().to_string(),
        });
    }
    normalized
        .into_os_string()
        .into_string()
        .map_err(|_| LoadError::PathNotUtf8)
}

fn import_path(importer: &str, import: &str) -> Result<String, LoadError> {
    if import.starts_with('/') || import.contains('\\') || import.contains(':') {
        return Err(LoadError::ImportNotRelative {
            import: import.to_string(),
        });
    }
    normalize(
        &Path::new(importer)
            .parent()
            .unwrap_or(Path::new(""))
            .join(import),
    )
}

struct Loaded {
    modules: BTreeMap<String, Module>,
}

enum EmitError {
    Library,
    Lints(Vec<Diagnostic>),
    Code(CompileError, String),
}

impl Loaded {
    fn load(
        entry: &str,
        read: &mut impl FnMut(&str) -> Result<String, LoadError>,
        symbols: Option<&mut Symbols>,
    ) -> Result<Self, LoadFailure> {
        let mut loaded = Loaded {
            modules: BTreeMap::new(),
        };
        load(
            entry,
            entry,
            read,
            &mut loaded,
            &mut Vec::new(),
            &mut HashMap::new(),
            symbols,
        )?;
        Ok(loaded)
    }

    fn warnings<'a>(
        &'a self,
        entry: &'a str,
        levels: &'a Levels,
    ) -> impl Iterator<Item = (&'a String, Vec<Diagnostic>)> {
        self.modules.iter().map(move |(path, module)| {
            (path, module.lints.diagnostics(path, levels, path != entry))
        })
    }

    /// `files` are the sources of every module, and `hashes` the `codeHash` of each contract
    /// compiled so far for this artifact.
    fn emit(
        &self,
        entry: &str,
        files: &BTreeMap<String, String>,
        filesystem: bool,
        options: crate::CompileOptions,
        levels: &Levels,
        hashes: &mut BTreeMap<String, String>,
    ) -> Result<ContractJson, EmitError> {
        let root = &self.modules[entry];
        if root.contract.is_library {
            return Err(EmitError::Library);
        }
        let lints: Vec<_> = self.warnings(entry, levels).collect();
        let denied: Vec<_> = lints
            .iter()
            .flat_map(|(_, warnings)| warnings)
            .filter(|d| d.severity == Severity::Error)
            .cloned()
            .collect();
        if !denied.is_empty() {
            return Err(EmitError::Lints(denied));
        }
        let mut bundle = SourceBundle {
            entry: entry.to_string(),
            files: files.clone(),
        };
        let mut base = PathBuf::new();
        if filesystem {
            base = Path::new(entry)
                .parent()
                .expect("absolute entry")
                .to_path_buf();
            for path in bundle.files.keys() {
                while !Path::new(path).starts_with(&base) {
                    base.pop();
                }
            }
            bundle.entry = Path::new(entry)
                .strip_prefix(&base)
                .expect("common root")
                .to_string_lossy()
                .replace('\\', "/");
            bundle.files = bundle
                .files
                .into_iter()
                .map(|(path, source)| {
                    (
                        Path::new(&path)
                            .strip_prefix(&base)
                            .expect("common root")
                            .to_string_lossy()
                            .replace('\\', "/"),
                        source,
                    )
                })
                .collect();
        }
        let warnings = lints
            .into_iter()
            .flat_map(|(path, warnings)| {
                let path = Path::new(path)
                    .strip_prefix(&base)
                    .expect("common root")
                    .to_string_lossy()
                    .replace('\\', "/");
                let source = bundle.files.get(&path).map(String::as_str).unwrap_or("");
                warnings.into_iter().map(move |warning| {
                    let tag = warning.code.as_deref().unwrap_or("general");
                    let message = diagnostics::located(&warning.message, warning.span, source);
                    format!("warning[{tag}]: {message} ({path})")
                })
            })
            .collect();
        let source = bundle.files.get(&bundle.entry).cloned().unwrap_or_default();
        compiler::emit(
            &root.contract,
            &root.leaves,
            bundle,
            warnings,
            options,
            &mut |name| {
                let hash = self.code_hash(name, files, filesystem, options, levels, hashes);
                hash.map_err(|error| match instantiation(&root.contract, name) {
                    Some(span) => error.at(span),
                    None => error,
                })
            },
        )
        .map_err(|error| EmitError::Code(error, source))
    }

    /// The `codeHash` of contract `name` compiled as the entry, failing where that compilation
    /// fails, and cached in `hashes`. Imports are acyclic and a contract cannot instantiate
    /// itself, so the recursion ends.
    fn code_hash(
        &self,
        name: &str,
        files: &BTreeMap<String, String>,
        filesystem: bool,
        options: crate::CompileOptions,
        levels: &Levels,
        hashes: &mut BTreeMap<String, String>,
    ) -> Result<String, CompileError> {
        if let Some(hash) = hashes.get(name) {
            return Ok(hash.clone());
        }
        let (path, module) = self
            .modules
            .iter()
            .find(|(_, module)| module.contract.name == name)
            .ok_or_else(|| {
                let name = name.to_string();
                CompileError::from(InternalError::ContractNotLoaded { name })
            })?;
        let source = files.get(path).map_or("", String::as_str);
        // Loading prepared this module as an import, without the checks only an entry gets.
        let compiled = match validator::validate_ast(&module.contract, true).first() {
            Some(issue) => Err(diagnostics::located(&issue.message, issue.span, source)),
            None => self
                .emit(path, files, filesystem, options, levels, hashes)
                .map_err(|error| match error {
                    EmitError::Library => LoadError::LibraryEntry.to_string(),
                    EmitError::Lints(errors) => diagnostics::render_errors(&errors, source),
                    EmitError::Code(error, _) => {
                        diagnostics::located(&error.to_string(), error.span, source)
                    }
                }),
        };
        let hash = compiled
            .map_err(|message| {
                CompileError::from(LoadError::DependencyFails {
                    name: name.to_string(),
                    path: path.clone(),
                    message,
                })
            })?
            .code_hash
            .expect("emit sets codeHash");
        hashes.insert(name.to_string(), hash.clone());
        Ok(hash)
    }
}

/// The span of the first `new name(...)` in `contract`'s own functions.
fn instantiation(contract: &Contract, name: &str) -> Option<Span> {
    let mut span = None;
    for function in contract.functions.iter().filter(|f| !f.is_imported()) {
        let mut statements = function.statements.clone();
        let _ = visit_statements(&mut statements, &mut |expression| {
            if matches!(&expression.kind, ExprKind::ContractInstance { contract_name, .. } if contract_name == name)
            {
                span.get_or_insert(expression.span);
            }
            Ok(())
        });
    }
    span
}

fn load(
    path: &str,
    entry: &str,
    read: &mut impl FnMut(&str) -> Result<String, LoadError>,
    loaded: &mut Loaded,
    active: &mut Vec<String>,
    declarations: &mut HashMap<String, String>,
    mut symbols: Option<&mut Symbols>,
) -> Result<(), LoadFailure> {
    if loaded.modules.contains_key(path) {
        return Ok(());
    }
    if active.iter().any(|p| p == path) {
        let chain = active.clone();
        return Err(LoadError::CircularImport {
            chain,
            path: path.to_string(),
        }
        .into());
    }
    // Recursive loading is bounded; use an iterative traversal for deeper projects.
    if active.len() >= MAX_IMPORT_DEPTH {
        return Err(LoadError::ImportTooDeep.into());
    }
    // An unreadable file is an error of the file importing it.
    let source = read(path)?;
    active.push(path.to_string());
    let result = (|| -> Result<(), LoadFailure> {
        let source = &source;
        parser::check_pragma(source, env!("CARGO_PKG_VERSION"))
            .map_err(|error| locate(path, source, error, None))?;
        let pairs = parser::try_parse(source).map_err(|error| {
            let diagnostic = parser::parse_error_diagnostic(&error, path, source);
            let error = ParseError::Syntax(Box::new(error));
            LoadFailure::Located(Box::new(diagnostic), format!("{path}: {error}"))
        })?;
        let imports =
            parser::imports(&pairs).map_err(|error| locate(path, source, error.into(), None))?;
        let mut dependencies = Vec::new();
        // LIMITATION: when collecting symbols, a failed import stops loading the rest, though the
        // file's own names are still recorded. Remember failed files, so a diamond of imports
        // does not load one twice, if editors need the later imports' symbols.
        let mut failed = None;
        for (import, span) in imports {
            let at_import = |error: LoadFailure| match error {
                LoadFailure::Message(error) => locate(path, source, error.at(span), None),
                other => other,
            };
            let imported = match import_path(path, &import) {
                Ok(dependency) => {
                    let imported = load(
                        &dependency,
                        entry,
                        read,
                        loaded,
                        active,
                        declarations,
                        symbols.as_deref_mut(),
                    );
                    if !dependencies.contains(&dependency) {
                        dependencies.push(dependency);
                    }
                    imported
                }
                Err(error) => Err(error.into()),
            };
            match imported.map_err(at_import) {
                Err(error) if symbols.is_some() => {
                    failed = Some(error);
                    break;
                }
                imported => imported?,
            }
        }
        let mut constants = Vec::new();
        for module in dependencies.iter().filter_map(|d| loaded.modules.get(d)) {
            let contract = &module.contract;
            for constant in contract.constants.iter().filter(|c| !c.name.contains('.')) {
                let mut constant = constant.clone();
                constant.name = format!("{}.{}", contract.name, constant.name);
                constants.push(constant);
            }
        }
        let mut contract = match parser::build_ast(pairs, &constants) {
            Ok(contract) => contract,
            Err(error) => return Err(failed.unwrap_or_else(|| error.into())),
        };
        let own_structs: HashSet<_> = contract.structs.iter().map(|s| s.name.clone()).collect();
        let declared = match failed {
            Some(error) => Err(error),
            None => declare(path, &contract, declarations).map_err(LoadFailure::from),
        };
        if let Err(error) = declared {
            // The contract is not typed yet, so an inferred `let` gets no type in its symbol.
            if let Some(symbols) = &mut symbols {
                symbols.collect(path, source, &contract, &own_structs, &dependencies, &[]);
            }
            return Err(error);
        }
        let mut visible_structs = own_structs.clone();
        let mut visible_contracts = HashMap::new();
        for dependency in &dependencies {
            let module = &loaded.modules[dependency];
            visible_structs.extend(module.structs.clone());
            if !module.contract.name.is_empty() {
                visible_contracts.insert(module.contract.name.clone(), &module.contract);
            }
        }
        for function in &mut contract.functions {
            visit_statements(&mut function.statements, &mut |expression| {
                if let ExprKind::GroupControlIs { group, asset_id } = &expression.kind {
                    // Only a bare name can be a library; other groups stay asset groups.
                    let ExprKind::Name(models::Path {
                        root: group,
                        segments,
                    }) = &group.as_ref().kind
                    else {
                        return Ok(());
                    };
                    if !segments.is_empty() {
                        return Ok(());
                    }
                    if group == &contract.name || visible_contracts.contains_key(group) {
                        expression.kind = ExprKind::Call {
                            name: format!("{group}.controlIs"),
                            args: vec![*asset_id.clone()],
                            return_type: None,
                        };
                    }
                }
                Ok(())
            })?;
        }
        let checked = compiler::fold_constants(&mut contract).and_then(|uses| {
            visible_contracts.insert(contract.name.clone(), &contract);
            validate_scope(&contract, &visible_structs, &visible_contracts).map(|()| uses)
        });
        let constant_uses = match checked {
            Ok(uses) => uses,
            Err(error) => {
                // The contract is not typed yet, so an inferred `let` gets no type in its symbol.
                if let Some(symbols) = &mut symbols {
                    symbols.collect(path, source, &contract, &own_structs, &dependencies, &[]);
                }
                return Err(error.into());
            }
        };
        let mut structs: BTreeMap<_, _> = contract
            .structs
            .iter()
            .map(|s| (s.name.clone(), s.clone()))
            .collect();
        let mut helpers = BTreeMap::new();
        for dependency in &dependencies {
            let imported = &loaded.modules[dependency].contract;
            structs.extend(imported.structs.iter().map(|s| (s.name.clone(), s.clone())));
            for function in imported.functions.iter().filter(|f| f.is_static) {
                let mut function = function.clone();
                if !function.is_imported() {
                    function.name = format!("{}.{}", imported.name, function.name);
                    visit_statements(&mut function.statements, &mut |expression| {
                        if let ExprKind::Call { name, .. } = &mut expression.kind {
                            if !name.contains('.') {
                                *name = format!("{}.{}", imported.name, name);
                            }
                        }
                        Ok(())
                    })?;
                }
                helpers.insert(function.name.clone(), function);
            }
        }
        // Keep standalone declaration order; append dependency types deterministically.
        let own_names: HashSet<_> = contract.structs.iter().map(|s| s.name.clone()).collect();
        contract.structs.extend(
            structs
                .into_values()
                .filter(|s| !own_names.contains(&s.name)),
        );
        let owner = contract.name.clone();
        for function in &mut contract.functions {
            visit_statements(&mut function.statements, &mut |expression| {
                if let ExprKind::Call { name, .. } = &mut expression.kind {
                    if let Some(local) = name.strip_prefix(&format!("{owner}.")) {
                        *name = local.to_string();
                    }
                }
                Ok(())
            })?;
        }
        contract.functions.extend(helpers.into_values());
        let require_entrypoint = path == entry && !contract.is_library;
        let prepared = compiler::prepare(&mut contract, require_entrypoint, path);
        if let Some(symbols) = &mut symbols {
            symbols.collect(
                path,
                source,
                &contract,
                &own_structs,
                &dependencies,
                &constant_uses,
            );
        }
        let prepared = prepared
            .map_err(|diagnostics| LoadFailure::Diagnostics(diagnostics, source.clone()))?;
        loaded.modules.insert(
            path.to_string(),
            Module {
                contract,
                structs: own_structs,
                lints: prepared.lints,
                leaves: prepared.leaves,
            },
        );
        Ok(())
    })();
    active.pop();
    result.map_err(|error| match error {
        LoadFailure::Message(error) => {
            let code = if error.is_internal() {
                "internal"
            } else {
                "validation"
            };
            locate(path, &source, error, Some(code))
        }
        other => other,
    })
}

/// `error` in the file at `path`, with `code`; import errors have none.
fn locate(path: &str, source: &str, error: CompileError, code: Option<&str>) -> LoadFailure {
    let message = diagnostics::located(&error.to_string(), error.span, source);
    let mut diagnostic = Diagnostic::error(path, error.to_string()).with_span(error.span);
    diagnostic.code = code.map(str::to_string);
    LoadFailure::Located(Box::new(diagnostic), format!("{path}: {message}"))
}

/// Reject a reserved contract name, then record `contract`'s declarations as made in `path`,
/// rejecting a name another file declared.
fn declare(
    path: &str,
    contract: &Contract,
    declarations: &mut HashMap<String, String>,
) -> Result<(), CompileError> {
    if models::is_builtin_type(&contract.name)
        || models::is_builtin_struct(&contract.name)
        || matches!(contract.name.as_str(), "tx" | "this")
    {
        let name = contract.name.clone();
        let error = LoadError::ReservedContractName { name };
        return Err(CompileError::from(error).at(contract.span));
    }
    for (name, span) in contract
        .structs
        .iter()
        .map(|s| (&s.name, s.span))
        .chain((!contract.name.is_empty()).then_some((&contract.name, contract.span)))
    {
        if let Some(previous) = declarations.insert(name.clone(), path.to_string()) {
            let error = LoadError::DuplicateDeclaration {
                name: name.clone(),
                previous,
                path: path.to_string(),
            };
            return Err(CompileError::from(error).at(span));
        }
    }
    Ok(())
}

fn validate_scope(
    contract: &Contract,
    structs: &HashSet<String>,
    contracts: &HashMap<String, &Contract>,
) -> Result<(), CompileError> {
    let at = |result: Result<(), LoadError>, span| {
        result.map_err(|error| CompileError::from(error).at(span))
    };
    let check_binding = |name: &str| {
        if contracts.contains_key(name) {
            Err(LoadError::ShadowsContract {
                name: name.to_string(),
            })
        } else {
            Ok(())
        }
    };
    for constant in &contract.constants {
        at(check_binding(&constant.name), constant.span)?;
    }
    let check_type = |ty: &models::TypeName| {
        let base = ty.base_name();
        if models::is_builtin_type(base)
            || models::is_builtin_struct(base)
            || structs.contains(base)
        {
            Ok(())
        } else {
            Err(LoadError::UnknownType {
                name: base.to_string(),
            })
        }
    };
    for parameter in contract
        .parameters
        .iter()
        .chain(contract.structs.iter().flat_map(|s| &s.fields))
        .chain(contract.functions.iter().flat_map(|f| &f.parameters))
        .chain(contract.tapscripts.iter().flat_map(|t| &t.inputs))
    {
        at(check_type(&parameter.param_type), parameter.span)?;
    }
    for parameter in contract
        .parameters
        .iter()
        .chain(contract.functions.iter().flat_map(|f| &f.parameters))
        .chain(contract.tapscripts.iter().flat_map(|t| &t.inputs))
    {
        at(check_binding(&parameter.name), parameter.span)?;
    }
    for function in &contract.functions {
        if let Some(ty) = &function.return_type {
            at(check_type(ty), function.span)?;
        }
        let mut scope = types::build_scope_with_structs(&contract.parameters, &contract.structs);
        scope.extend(types::build_scope_with_structs(
            &function.parameters,
            &contract.structs,
        ));
        let mut body = function.statements.clone();
        validate_local_types(&body, &check_type, &check_binding)?;
        visit_statements(&mut body, &mut |expression| {
            match &expression.kind {
                ExprKind::Call { name, .. } if name.contains('.') => {
                    let (owner, member) = name.split_once('.').expect("qualified name");
                    let target =
                        contracts
                            .get(owner)
                            .ok_or_else(|| LoadError::UnknownContract {
                                name: owner.to_string(),
                            })?;
                    let function = target
                        .functions
                        .iter()
                        .find(|f| f.name == member)
                        .ok_or_else(|| LoadError::UnknownFunction { name: name.clone() })?;
                    if !function.is_static {
                        return Err(LoadError::NotStaticFunction { name: name.clone() });
                    }
                    // Static but unexported is reachable only for a library's private helpers.
                    if !function.is_exported && owner != contract.name {
                        return Err(LoadError::PrivateLibraryFunction { name: name.clone() });
                    }
                }
                ExprKind::Name(path)
                    if !path.segments.is_empty() && contracts.contains_key(&path.root) =>
                {
                    return Err(LoadError::UnknownConstant { name: path.key() });
                }
                ExprKind::StructLiteral {
                    name: Some(name), ..
                } => {
                    check_type(&models::TypeName::Named(name.clone()))?;
                    if models::is_builtin_type(name) {
                        return Err(LoadError::NotStructType { name: name.clone() });
                    }
                }
                ExprKind::ContractInstance {
                    contract_name,
                    args,
                } => {
                    let name = contract_name.clone();
                    let Some(target) = contracts.get(contract_name) else {
                        return Err(LoadError::UnknownContract { name });
                    };
                    if target.is_library {
                        return Err(LoadError::LibraryInstantiated { name });
                    }
                    if contract_name == &contract.name {
                        return Err(LoadError::SelfInstantiation { name });
                    }
                    if args.len() != target.parameters.len() {
                        return Err(LoadError::ConstructorArgumentCount {
                            contract: name,
                            expected: target.parameters.len(),
                            got: args.len(),
                        });
                    }
                    for (arg, param) in args.iter().zip(&target.parameters) {
                        let mut arg = arg.clone();
                        types::annotate_expression(&mut arg, &scope, &contract.structs);
                        let actual = arg.ty;
                        if actual != types::ArkType::Unknown
                            && !param.param_type.ark_type().accepts(&actual)
                        {
                            return Err(LoadError::ConstructorArgumentType {
                                contract: name,
                                parameter: param.name.clone(),
                                expected: param.param_type.clone(),
                                got: actual.as_str(),
                            });
                        }
                    }
                }
                _ => {}
            }
            Ok(())
        })?;
    }
    Ok(())
}

fn validate_local_types(
    statements: &[LocatedStatement],
    check: &impl Fn(&models::TypeName) -> Result<(), LoadError>,
    binding: &impl Fn(&str) -> Result<(), LoadError>,
) -> Result<(), CompileError> {
    for statement in statements {
        let at = |result: Result<(), LoadError>| {
            result.map_err(|error| CompileError::from(error).at(statement.span))
        };
        match &statement.statement {
            Statement::Declaration {
                name,
                declared_type,
            } => {
                at(binding(name))?;
                at(check(declared_type))?;
            }
            Statement::LetBinding {
                name,
                declared_type,
                ..
            } => {
                at(binding(name))?;
                if let Some(ty) = declared_type {
                    at(check(ty))?;
                }
            }
            Statement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                validate_local_types(then_body, check, binding)?;
                if let Some(body) = else_body {
                    validate_local_types(body, check, binding)?;
                }
            }
            Statement::ForIn {
                index_var,
                value_var,
                body,
                ..
            } => {
                at(binding(index_var))?;
                at(binding(value_var))?;
                validate_local_types(body, check, binding)?;
            }
            Statement::ForRange {
                index_var, body, ..
            } => {
                at(binding(index_var))?;
                validate_local_types(body, check, binding)?;
            }
            Statement::ForCount { body, .. } => {
                validate_local_types(body, check, binding)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn visit_statements(
    statements: &mut [LocatedStatement],
    visit: &mut impl FnMut(&mut Expression) -> Result<(), LoadError>,
) -> Result<(), CompileError> {
    for statement in statements {
        match &mut statement.statement {
            Statement::Call(expr)
            | Statement::Return(Some(expr))
            | Statement::Require(expr)
            | Statement::LetBinding { value: expr, .. } => visit_expression(expr, visit)?,
            Statement::VarAssign { target, value } => {
                if let models::AssignmentTarget::ArrayIndex { index, .. }
                | models::AssignmentTarget::Access(index) = target
                {
                    visit_expression(index, visit)?;
                }
                visit_expression(value, visit)?;
            }
            Statement::IfElse {
                condition,
                then_body,
                else_body,
            } => {
                visit_expression(condition, visit)?;
                visit_statements(then_body, visit)?;
                if let Some(body) = else_body {
                    visit_statements(body, visit)?;
                }
            }
            Statement::ForIn { iterable, body, .. } => {
                visit_expression(iterable, visit)?;
                visit_statements(body, visit)?;
            }
            Statement::ForCount { count, body } => {
                visit_expression(count, visit)?;
                visit_statements(body, visit)?;
            }
            Statement::ForRange {
                start, end, body, ..
            } => {
                visit_expression(start, visit)?;
                visit_expression(end, visit)?;
                visit_statements(body, visit)?;
            }
            Statement::Return(None) | Statement::Declaration { .. } => {}
        }
    }
    Ok(())
}

fn visit_expression(
    expr: &mut Expression,
    visit: &mut impl FnMut(&mut Expression) -> Result<(), LoadError>,
) -> Result<(), CompileError> {
    for child in models::child_exprs_mut(expr) {
        visit_expression(child, visit)?;
    }
    let span = expr.span;
    visit(expr).map_err(|error| CompileError::from(error).at(span))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::diagnostics::{Diagnostic, Severity};

    fn check_one(source: &str) -> Vec<Diagnostic> {
        let files: BTreeMap<_, _> = [("main.ark".to_string(), source.to_string())].into();
        super::check_sources("main.ark", &files)
    }

    #[test]
    fn valid_contract_has_no_diagnostics() {
        let source = "contract Vault(pubkey owner) {\n  function spend(signature sig) {\n    require(checkSig(sig, owner));\n  }\n}\n";
        assert_eq!(check_one(source), vec![]);
    }

    #[test]
    fn three_independent_errors_yield_three_diagnostics() {
        let source = "contract Bad(pubkey owner, pubkey owner) {\n  function spend(signature sig, signature sig) { require(checkSig(sig, owner)); }\n  function spend(signature s) { require(checkSig(s, owner)); }\n}\n";
        let diagnostics = check_one(source);
        assert_eq!(diagnostics.len(), 3, "{diagnostics:?}");
        assert!(diagnostics.iter().all(|d| d.severity == Severity::Error));
        assert!(diagnostics.iter().any(|d| d
            .message
            .contains("duplicate constructor parameter 'owner'")));
        assert!(diagnostics
            .iter()
            .any(|d| d.message.contains("duplicate function name 'spend'")));
        assert!(diagnostics
            .iter()
            .any(|d| d.message.contains("duplicate parameter 'sig'")));
    }

    #[test]
    fn semantic_diagnostics_carry_a_precise_byte_span() {
        let source = "contract V(pubkey owner) {\n  function spend(signature sig) { require(checkSig(sig, owner)); }\n  function spend(signature s) { require(checkSig(s, owner)); }\n}\n";
        let diagnostics = check_one(source);
        let duplicate = diagnostics
            .iter()
            .find(|d| d.message.contains("duplicate function name"))
            .expect("duplicate function name diagnostic");
        let span = duplicate.span.expect("semantic diagnostics carry a span");
        assert!(
            span.start < span.end,
            "span must be a real range, not a point"
        );
        assert_eq!(&source[span.start..span.end], "spend");
    }

    #[test]
    fn syntax_error_has_a_span_and_a_plain_message() {
        let source = "contract Vault(pubkey owner) {\n  function spend(signature sig) {\n    require(checkSig(sig, owner))\n  }\n}\n";
        let [diagnostic]: [_; 1] = check_one(source).try_into().unwrap();
        assert_eq!(diagnostic.severity, Severity::Error);
        assert_eq!(diagnostic.message, "expected ';'");
        let span = diagnostic.span.expect("syntax errors carry a span");
        assert!(span.start < span.end, "span must cover at least one byte");
        assert!(span.end <= source.len());
    }

    #[test]
    fn syntax_error_spans_cover_a_whole_character_even_at_end_of_input() {
        for (source, expected) in [
            ("contract V(pubkey o) {\n  function f(signature s) {\n    require(checkSig(s, o)) é\n  }\n}\n", "é"),
            ("contract A(pubkey o) {\n", "{"),
        ] {
            let [diagnostic]: [_; 1] = check_one(source).try_into().unwrap();
            let span = diagnostic.span.expect("syntax errors carry a span");
            assert_eq!(source.get(span.start..span.end), Some(expected), "{source:?}");
        }
    }

    #[test]
    fn a_library_is_checked_directly_without_a_wrapper() {
        let library = "library Rules {\n  function preservesValue() {\n    require(tx.outputs[0].value >= tx.inputs[0].value);\n  }\n}\n";
        let files: BTreeMap<_, _> = [("lib/rules.ark".to_string(), library.to_string())].into();
        assert_eq!(super::check_sources("lib/rules.ark", &files), vec![]);

        let broken = library.replace("tx.inputs[0].value", "missing");
        let files: BTreeMap<_, _> = [("lib/rules.ark".to_string(), broken)].into();
        let [diagnostic]: [_; 1] = super::check_sources("lib/rules.ark", &files)
            .try_into()
            .unwrap();
        assert_eq!(diagnostic.file, "lib/rules.ark");
        assert!(
            !diagnostic.message.contains("__arkade_lsp_check__"),
            "{}",
            diagnostic.message
        );
    }

    #[test]
    fn check_reports_an_entry_not_present_in_files_instead_of_going_silent() {
        let files: BTreeMap<_, _> = [("main.ark".to_string(), "irrelevant".to_string())].into();
        let [diagnostic]: [_; 1] = super::check_sources("missing.ark", &files)
            .try_into()
            .unwrap();
        assert_eq!(diagnostic.severity, Severity::Error);
        assert!(
            diagnostic.message.contains("missing.ark"),
            "{}",
            diagnostic.message
        );
    }

    #[test]
    fn dependency_warnings_are_reported_in_the_dependency() {
        let main = "import \"other.ark\";\ncontract V(pubkey owner) {\n  function spend(signature sig) {\n    require(checkSig(sig, owner));\n  }\n}\n";
        let other = "contract Other(pubkey owner, int unused) {\n  function spend(signature sig) {\n    require(checkSig(sig, owner));\n  }\n}\n";
        let files: BTreeMap<_, _> = [
            ("main.ark".to_string(), main.to_string()),
            ("other.ark".to_string(), other.to_string()),
        ]
        .into();
        let [diagnostic]: [_; 1] = super::check_sources("main.ark", &files).try_into().unwrap();
        assert_eq!(diagnostic.severity, Severity::Warning);
        assert_eq!(diagnostic.file, "other.ark");
        assert!(
            diagnostic.message.contains("'unused'"),
            "{}",
            diagnostic.message
        );
    }

    #[test]
    fn a_dependency_failure_is_located_in_the_dependency() {
        let main = "import \"lib.ark\";\ncontract V(pubkey owner) {\n  function spend(signature sig) {\n    require(checkSig(sig, owner));\n  }\n}\n";
        let broken_lib = "library L {\n  function helper() {\n    require(missing);\n  }\n}\n";
        let files: BTreeMap<_, _> = [
            ("main.ark".to_string(), main.to_string()),
            ("lib.ark".to_string(), broken_lib.to_string()),
        ]
        .into();
        let [diagnostic]: [_; 1] = super::check_sources("main.ark", &files).try_into().unwrap();
        assert_eq!(diagnostic.severity, Severity::Error);
        assert_eq!(diagnostic.file, "lib.ark");
        let span = diagnostic
            .span
            .expect("dependency diagnostics carry a span");
        assert_eq!(&broken_lib[span.start..span.end], "missing");

        let error = super::compile_sources("main.ark", &files, Default::default()).unwrap_err();
        assert!(
            error.starts_with("lib.ark: validation error: line 3, column 13: "),
            "{error}"
        );
    }

    #[test]
    fn a_dependency_syntax_failure_keeps_its_file_and_span() {
        let files = BTreeMap::from([
            (
                "main.ark".into(),
                "import \"lib.ark\"; contract C() { function spend() { require(true); } }".into(),
            ),
            ("lib.ark".into(), "// é 🐴\nlibrary Broken(".into()),
        ]);
        let [diagnostic]: [_; 1] = super::check_sources("main.ark", &files).try_into().unwrap();
        assert_eq!(diagnostic.file, "lib.ark");
        assert_eq!(diagnostic.severity, Severity::Error);
        let span = diagnostic.span.unwrap();
        assert_eq!(&files["lib.ark"][span.start..span.end], "(");
        let error = super::compile_sources("main.ark", &files, Default::default()).unwrap_err();
        assert!(error.starts_with("lib.ark: Parse error:"), "{error}");
    }

    #[test]
    fn a_dependency_loader_failure_keeps_its_file() {
        let files = BTreeMap::from([
            (
                "main.ark".into(),
                "import \"lib.ark\"; contract C() { function spend() { require(true); } }".into(),
            ),
            (
                "lib.ark".into(),
                "library AssetId { function value() int { return 1; } }".into(),
            ),
        ]);
        let [diagnostic]: [_; 1] = super::check_sources("main.ark", &files).try_into().unwrap();
        assert_eq!(diagnostic.file, "lib.ark");
        assert_eq!(diagnostic.message, "contract name 'AssetId' is reserved");
        let span = diagnostic.span.unwrap();
        assert_eq!(&files["lib.ark"][span.start..span.end], "AssetId");
    }
}
