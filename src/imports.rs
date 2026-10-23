use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Component, Path, PathBuf};

use crate::diagnostics::{CompileError, Diagnostic, Severity};
use crate::models::{
    self, Contract, ContractJson, ExprKind, Expression, LocatedStatement, SourceBundle, Statement,
};
use crate::{compiler, parser, types};

// Dependency definitions are copied per module; use a shared symbol table if quadratic copying becomes costly.
struct Module {
    contract: Contract,
    structs: HashSet<String>,
    lints: crate::lint::Lints,
    leaves: Vec<compiler::tapscript::CheckedLeaf>,
}

/// `load()`'s failure: one error, or the diagnostics `compiler::prepare` collected for one
/// file, with that file's source.
pub(crate) enum LoadError {
    /// An error `load` has yet to tie to the file it was loading.
    Message(crate::diagnostics::CompileError),
    /// A diagnostic, and the string the `compile_*` functions return.
    Located(Box<Diagnostic>, String),
    Diagnostics(Vec<Diagnostic>, String),
}

impl From<String> for LoadError {
    fn from(message: String) -> Self {
        LoadError::Message(message.into())
    }
}

impl From<crate::diagnostics::CompileError> for LoadError {
    fn from(error: crate::diagnostics::CompileError) -> Self {
        LoadError::Message(error)
    }
}

/// A program after parsing, import resolution, typing and validation, before code generation.
pub struct Analysis {
    entry: String,
    loaded: Result<Loaded, LoadError>,
    /// The text of every file read, by the path diagnostics and symbols name it with.
    sources: BTreeMap<String, String>,
    symbols: crate::symbols::Symbols,
    /// Whether `entry` is a filesystem path, whose bundle is rebased onto the files' common root.
    filesystem: bool,
}

impl Analysis {
    /// Load `entry` and its imports through `read`, collecting their symbols when `symbols`.
    fn load(
        entry: String,
        mut read: impl FnMut(&str) -> Result<String, String>,
        filesystem: bool,
        symbols: bool,
    ) -> Self {
        let mut sources = BTreeMap::new();
        let mut table = crate::symbols::Symbols::default();
        let mut record = |path: &str| -> Result<String, String> {
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

    /// An analysis that failed before reading `entry`.
    fn failed(entry: &str, message: String, filesystem: bool) -> Self {
        Analysis {
            entry: entry.to_string(),
            loaded: Err(LoadError::Message(message.into())),
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
    pub fn diagnostics_with(&self, levels: &crate::lint::Levels) -> Vec<Diagnostic> {
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
    pub fn symbols(&self) -> &crate::symbols::Symbols {
        &self.symbols
    }

    /// The diagnostics, and for a contract code generation's first error with `options`, which
    /// finds some problems alone, such as the VM's stack and script limits.
    pub fn check(&self, options: crate::CompileOptions) -> Vec<Diagnostic> {
        self.check_with(options, &Default::default())
    }

    /// [`Analysis::check`] with each lint at its level in `levels`.
    pub fn check_with(
        &self,
        options: crate::CompileOptions,
        levels: &crate::lint::Levels,
    ) -> Vec<Diagnostic> {
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
        levels: &crate::lint::Levels,
    ) -> Result<ContractJson, Vec<Diagnostic>> {
        let loaded = self
            .loaded
            .as_ref()
            .map_err(|error| error.diagnostics(&self.entry))?;
        loaded
            .emit(&self.entry, &self.sources, self.filesystem, options, levels)
            .map_err(|error| match error {
                EmitError::Library => vec![Diagnostic::error(&self.entry, LIBRARY_ENTRY)],
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
            )
            .map_err(|error| match error {
                EmitError::Library => format!("{}: {LIBRARY_ENTRY}", self.entry),
                EmitError::Lints(errors) => format!(
                    "{}: {}",
                    self.entry,
                    crate::diagnostics::render_errors(&errors, &self.sources[&self.entry])
                ),
                EmitError::Code(error, source) => {
                    crate::diagnostics::located(&error.to_string(), error.span, &source)
                }
            })
    }
}

impl LoadError {
    fn diagnostics(&self, entry: &str) -> Vec<Diagnostic> {
        match self {
            LoadError::Diagnostics(diagnostics, _) => diagnostics.clone(),
            LoadError::Located(diagnostic, _) => vec![(**diagnostic).clone()],
            // An error `load` has not located is about the entry itself, such as reading it.
            LoadError::Message(error) => vec![Diagnostic::error(entry, error.to_string())],
        }
    }

    fn message(&self, entry: &str) -> String {
        match self {
            LoadError::Message(error) => error.to_string(),
            LoadError::Located(_, message) => message.clone(),
            LoadError::Diagnostics(diagnostics, source) => format!(
                "{}: {}",
                diagnostics.first().map_or(entry, |d| d.file.as_str()),
                crate::diagnostics::render_errors(diagnostics, source)
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
        files.get(path).cloned().ok_or_else(|| {
            format!("source file '{path}' not found; imports require source files supplied with the entry")
        })
    };
    Analysis::load(entry, read, false, symbols)
}

/// Analyze the entry file at `path` and its imports, read from the filesystem, collecting their
/// symbols when `symbols`.
pub(crate) fn analyze_file(path: &Path, symbols: bool) -> Analysis {
    let entry = std::path::absolute(path)
        .map_err(|e| e.to_string())
        .and_then(|absolute| normalize(&absolute));
    let read = |path: &str| {
        std::fs::read_to_string(path).map_err(|e| format!("cannot read '{path}': {e}"))
    };
    match entry {
        Ok(entry) => Analysis::load(entry, read, true, symbols),
        Err(message) => Analysis::failed(&path.to_string_lossy(), message, true),
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

#[cfg(any(feature = "wasm", test))]
/// Completion symbols for `entry`: its own declarations, plus the structs,
/// contracts, libraries, constants and exported functions of its direct imports.
pub(crate) fn source_symbols(
    entry: &str,
    files: &BTreeMap<String, String>,
) -> Result<serde_json::Value, String> {
    let entry = relative_path(entry)?;
    let files = normalize_files(files)?;
    let source = files
        .get(&entry)
        .ok_or_else(|| format!("source file '{entry}' not found"))?;
    let (mut symbols, mut structs) = parser::symbols(source)?;
    let mut members: BTreeMap<String, Vec<parser::Symbol>> = BTreeMap::new();
    for (import, _) in parser::imports(&parser::parse_main(source)?)? {
        // Imports that are rejected, missing or do not parse contribute nothing.
        let Ok(path) = import_path(&entry, &import) else {
            continue;
        };
        let Some(Ok((imported, imported_structs))) = files.get(&path).map(|s| parser::symbols(s))
        else {
            continue;
        };
        structs.extend(imported_structs);
        let owner = imported
            .iter()
            .find(|s| matches!(s.kind, "contract" | "library"))
            .map(|s| s.name.clone());
        for mut symbol in imported {
            symbol.file = Some(path.clone());
            match (symbol.kind, &owner) {
                ("struct" | "contract" | "library", _) => symbols.push(symbol),
                ("constant", Some(owner)) => members.entry(owner.clone()).or_default().push(symbol),
                ("function", Some(owner)) if symbol.exported => {
                    members.entry(owner.clone()).or_default().push(symbol)
                }
                _ => {}
            }
        }
    }
    Ok(serde_json::json!({ "symbols": symbols, "structs": structs, "members": members }))
}

fn normalize_files(files: &BTreeMap<String, String>) -> Result<BTreeMap<String, String>, String> {
    let mut normalized = BTreeMap::new();
    for (path, source) in files {
        let path = relative_path(path)?;
        if normalized.insert(path.clone(), source.clone()).is_some() {
            return Err(format!("duplicate source path '{path}'"));
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

pub(crate) fn relative_path(path: &str) -> Result<String, String> {
    if Path::new(path).is_absolute() || path.contains('\\') || path.contains(':') {
        return Err(format!(
            "source path '{path}' must be a relative .ark path using '/'"
        ));
    }
    normalize(Path::new(path))
}

fn normalize(path: &Path) -> Result<String, String> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(format!("path '{}' escapes the source root", path.display()));
                }
            }
            _ => normalized.push(component),
        }
    }
    if normalized
        .extension()
        .is_none_or(|extension| extension != "ark")
    {
        return Err(format!(
            "source path '{}' must have .ark extension",
            path.display()
        ));
    }
    normalized
        .into_os_string()
        .into_string()
        .map_err(|_| "source paths must be UTF-8".to_string())
}

fn import_path(importer: &str, import: &str) -> Result<String, String> {
    if Path::new(import).is_absolute() || import.contains('\\') || import.contains(':') {
        return Err(format!(
            "import '{import}' must be a relative .ark path using '/'"
        ));
    }
    normalize(
        &Path::new(importer)
            .parent()
            .unwrap_or(Path::new(""))
            .join(import),
    )
}

const LIBRARY_ENTRY: &str = "entry file must declare a contract, not a library";

/// Every module of a program, prepared.
struct Loaded {
    modules: BTreeMap<String, Module>,
}

enum EmitError {
    Library,
    Lints(Vec<Diagnostic>),
    Code(crate::diagnostics::CompileError, String),
}

impl Loaded {
    fn load(
        entry: &str,
        read: &mut impl FnMut(&str) -> Result<String, String>,
        symbols: Option<&mut crate::symbols::Symbols>,
    ) -> Result<Self, LoadError> {
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

    /// Each module's lint diagnostics at `levels`.
    fn warnings<'a>(
        &'a self,
        entry: &'a str,
        levels: &'a crate::lint::Levels,
    ) -> impl Iterator<Item = (&'a String, Vec<Diagnostic>)> {
        self.modules.iter().map(move |(path, module)| {
            (path, module.lints.diagnostics(path, levels, path != entry))
        })
    }

    /// `files` are the sources of every module.
    fn emit(
        &self,
        entry: &str,
        files: &BTreeMap<String, String>,
        filesystem: bool,
        options: crate::CompileOptions,
        levels: &crate::lint::Levels,
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
                    let message =
                        crate::diagnostics::located(&warning.message, warning.span, source);
                    format!("warning[{tag}]: {message} ({path})")
                })
            })
            .collect();
        let source = bundle.files.get(&bundle.entry).cloned().unwrap_or_default();
        compiler::emit(&root.contract, &root.leaves, bundle, warnings, options)
            .map_err(|error| EmitError::Code(error, source))
    }
}

fn load(
    path: &str,
    entry: &str,
    read: &mut impl FnMut(&str) -> Result<String, String>,
    loaded: &mut Loaded,
    active: &mut Vec<String>,
    declarations: &mut HashMap<String, String>,
    mut symbols: Option<&mut crate::symbols::Symbols>,
) -> Result<(), LoadError> {
    if loaded.modules.contains_key(path) {
        return Ok(());
    }
    if active.iter().any(|p| p == path) {
        return Err(format!("circular import: {} -> {path}", active.join(" -> ")).into());
    }
    // Recursive loading is bounded; use an iterative traversal for deeper projects.
    if active.len() >= 128 {
        return Err("import depth exceeds 128 files".to_string().into());
    }
    // An unreadable file is an error of the file importing it.
    let source = read(path)?;
    active.push(path.to_string());
    let result = (|| -> Result<(), LoadError> {
        let source = &source;
        let pairs = parser::try_parse(source).map_err(|error| {
            let diagnostic = parser::parse_error_diagnostic(&error, path, source);
            LoadError::Located(
                Box::new(diagnostic),
                format!("{path}: Parse error: {error}"),
            )
        })?;
        let imports =
            parser::imports(&pairs).map_err(|error| locate(path, source, error.into(), None))?;
        let mut dependencies = Vec::new();
        for (import, span) in imports {
            let at_import = |error: LoadError| match error {
                LoadError::Message(error) => locate(path, source, error.at(span), None),
                other => other,
            };
            let dependency = import_path(path, &import).map_err(|e| at_import(e.into()))?;
            load(
                &dependency,
                entry,
                read,
                loaded,
                active,
                declarations,
                symbols.as_deref_mut(),
            )
            .map_err(at_import)?;
            if !dependencies.contains(&dependency) {
                dependencies.push(dependency);
            }
        }
        let mut constants = Vec::new();
        for dependency in &dependencies {
            let contract = &loaded.modules[dependency].contract;
            for constant in contract.constants.iter().filter(|c| !c.name.contains('.')) {
                let mut constant = constant.clone();
                constant.name = format!("{}.{}", contract.name, constant.name);
                constants.push(constant);
            }
        }
        let mut contract = parser::build_ast(pairs, &constants)?;
        let own_structs: HashSet<_> = contract.structs.iter().map(|s| s.name.clone()).collect();
        if models::is_builtin_type(&contract.name)
            || models::is_builtin_struct(&contract.name)
            || matches!(contract.name.as_str(), "tx" | "this")
        {
            let message = format!("contract name '{}' is reserved", contract.name);
            return Err(CompileError::from(message).at(contract.span).into());
        }
        for (name, span) in contract
            .structs
            .iter()
            .map(|s| (&s.name, s.span))
            .chain((!contract.name.is_empty()).then_some((&contract.name, contract.span)))
        {
            if let Some(previous) = declarations.insert(name.clone(), path.to_string()) {
                let message =
                    format!("duplicate declaration '{name}' in '{previous}' and '{path}'");
                return Err(CompileError::from(message).at(span).into());
            }
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
                if let ExprKind::GroupControlIs {
                    group,
                    asset_txid,
                    asset_gidx,
                } = &expression.kind
                {
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
                            args: vec![*asset_txid.clone(), *asset_gidx.clone()],
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
                // Untyped, so a `let` without a declared type has no type.
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
        let prepared =
            prepared.map_err(|diagnostics| LoadError::Diagnostics(diagnostics, source.clone()))?;
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
        LoadError::Message(error) => {
            let code = if error.internal {
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
fn locate(path: &str, source: &str, error: CompileError, code: Option<&str>) -> LoadError {
    let message = crate::diagnostics::located(&error.to_string(), error.span, source);
    let mut diagnostic = Diagnostic::error(path, error.to_string()).with_span(error.span);
    diagnostic.code = code.map(str::to_string);
    LoadError::Located(Box::new(diagnostic), format!("{path}: {message}"))
}

fn validate_scope(
    contract: &Contract,
    structs: &HashSet<String>,
    contracts: &HashMap<String, &Contract>,
) -> Result<(), CompileError> {
    let at = |result: Result<(), String>, span| {
        result.map_err(|error| CompileError::from(error).at(span))
    };
    let check_binding = |name: &str| {
        if contracts.contains_key(name) {
            Err(format!("binding '{name}' shadows a contract namespace"))
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
            Err(format!("unknown type '{base}'; import its defining file"))
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
                    let target = contracts.get(owner).ok_or_else(|| {
                        format!("unknown contract '{owner}'; import its defining file")
                    })?;
                    let function = target
                        .functions
                        .iter()
                        .find(|f| f.name == member)
                        .ok_or_else(|| format!("unknown function '{name}'"))?;
                    if !function.is_static {
                        return Err(format!("'{name}' is not a static function"));
                    }
                    // Static but unexported is reachable only for a library's private helpers.
                    if !function.is_exported && owner != contract.name {
                        return Err(format!("library function '{name}' is private"));
                    }
                }
                ExprKind::Name(path)
                    if !path.segments.is_empty() && contracts.contains_key(&path.root) =>
                {
                    return Err(format!("unknown constant '{}'", path.key()));
                }
                ExprKind::ContractInstance {
                    contract_name,
                    args,
                } => {
                    let target = contracts.get(contract_name).ok_or_else(|| {
                        format!("unknown contract '{contract_name}'; import its defining file")
                    })?;
                    if target.is_library {
                        return Err(format!("library '{contract_name}' cannot be instantiated"));
                    }
                    if args.len() != target.parameters.len() {
                        return Err(format!(
                            "constructor '{contract_name}' expects {} arguments, got {}",
                            target.parameters.len(),
                            args.len()
                        ));
                    }
                    for (arg, param) in args.iter().zip(&target.parameters) {
                        let mut arg = arg.clone();
                        types::annotate_expression(&mut arg, &scope);
                        let actual = arg.ty;
                        if actual != types::ArkType::Unknown
                            && !crate::validator::binding_types_compatible(
                                &param.param_type.ark_type(),
                                &actual,
                            )
                        {
                            return Err(format!(
                                "constructor '{contract_name}' argument '{}' expects {}, got {}",
                                param.name,
                                param.param_type,
                                actual.as_str()
                            ));
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
    check: &impl Fn(&models::TypeName) -> Result<(), String>,
    binding: &impl Fn(&str) -> Result<(), String>,
) -> Result<(), CompileError> {
    for statement in statements {
        let at = |result: Result<(), String>| {
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
    visit: &mut impl FnMut(&mut Expression) -> Result<(), String>,
) -> Result<(), CompileError> {
    for statement in statements {
        match &mut statement.statement {
            Statement::Call(expr)
            | Statement::Return(Some(expr))
            | Statement::LetBinding { value: expr, .. } => visit_expression(expr, visit)?,
            Statement::Require(requirement) => match requirement {
                models::Requirement::Expression(expr) => visit_expression(expr, visit)?,
                models::Requirement::Comparison { left, right, .. } => {
                    visit_expression(left, visit)?;
                    visit_expression(right, visit)?;
                }
            },
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
            Statement::Return(None) | Statement::Declaration { .. } => {}
        }
    }
    Ok(())
}

fn visit_expression(
    expr: &mut Expression,
    visit: &mut impl FnMut(&mut Expression) -> Result<(), String>,
) -> Result<(), CompileError> {
    for child in models::child_exprs_mut(expr) {
        visit_expression(child, visit)?;
    }
    let span = expr.span;
    visit(expr).map_err(|error| CompileError::from(error).at(span))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn source_symbols_scope_locals_and_expose_direct_imports() {
        let main = r#"import "fees.ark"; import "/absolute.ark";
struct Point { int x; }
contract Vault(Point[2] points, pubkey owner) {
    function spend(signature sig, bytes32 txid) {
        let group = tx.assetGroups.find(txid, 0);
        for (i, point) in points {
            int total = point.x;
        }
        require(checkSig(sig, owner));
    }
    function exit() {
        require(tx.locktime >= Fees.DELAY);
    }
}"#;
        let fees = r#"import "deep.ark";
struct Policy { int maximum; }
library Fees {
    const int DELAY = 144;
    function calculate(int amount) int { return amount * 2; }
    private function hidden(int amount) int { return amount; }
}"#;
        let files = [
            ("./main.ark", main),
            ("fees.ark", fees),
            ("deep.ark", "struct Hidden { int x; }"),
        ]
        .into_iter()
        .map(|(path, source)| (path.to_string(), source.to_string()))
        .collect();
        let output = super::source_symbols("main.ark", &files).unwrap();
        assert_eq!(
            output["symbols"],
            json!([
                { "name": "Point", "kind": "struct", "position": [2, 8] },
                { "name": "Vault", "kind": "contract", "position": [3, 10] },
                { "name": "points", "kind": "parameter", "type": "Point[2]", "position": [3, 25] },
                { "name": "owner", "kind": "parameter", "type": "pubkey", "position": [3, 40] },
                { "name": "spend", "kind": "function", "position": [4, 14] },
                { "name": "sig", "kind": "parameter", "type": "signature", "position": [4, 30], "scope": [4, 10] },
                { "name": "txid", "kind": "parameter", "type": "bytes32", "position": [4, 43], "scope": [4, 10] },
                { "name": "group", "kind": "variable", "type": "AssetGroup", "position": [5, 13], "scope": [4, 10] },
                { "name": "i", "kind": "variable", "type": "int", "position": [6, 14], "scope": [4, 10] },
                { "name": "point", "kind": "variable", "type": "Point", "position": [6, 17], "scope": [4, 10] },
                { "name": "total", "kind": "variable", "type": "int", "position": [7, 17], "scope": [4, 10] },
                { "name": "exit", "kind": "function", "position": [11, 14] },
                { "name": "Policy", "kind": "struct", "position": [2, 8], "file": "fees.ark" },
                { "name": "Fees", "kind": "library", "position": [3, 9], "file": "fees.ark" },
            ])
        );
        assert_eq!(
            output["members"],
            json!({ "Fees": [
                { "name": "DELAY", "kind": "constant", "type": "int", "position": [4, 15], "file": "fees.ark" },
                { "name": "calculate", "kind": "function", "type": "int", "position": [5, 14], "file": "fees.ark" },
            ] })
        );
        assert_eq!(
            output["structs"],
            json!([
                { "name": "Point", "fields": [{ "name": "x", "type": "int" }] },
                { "name": "Policy", "fields": [{ "name": "maximum", "type": "int" }] },
            ])
        );
        let broken = [("main.ark".to_string(), "contract A( {".to_string())].into();
        assert!(super::source_symbols("main.ark", &broken).is_err());
    }

    use crate::diagnostics::Severity;
    use std::collections::BTreeMap;

    fn check_one(source: &str) -> Vec<crate::diagnostics::Diagnostic> {
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
}
