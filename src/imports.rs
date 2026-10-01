use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Component, Path, PathBuf};

use crate::diagnostics::Diagnostic;
use crate::models::{
    self, Contract, ContractJson, Expression, LocatedStatement, SourceBundle, Statement,
};
use crate::{compiler, parser, typechecker};

// Dependency definitions are copied per module; use a shared symbol table if quadratic copying becomes costly.
struct Module {
    contract: Contract,
    structs: HashSet<String>,
    warnings: Vec<Diagnostic>,
}

/// `load()`'s failure: either a single fail-fast message (I/O, cycle, unknown
/// import, internal invariant) or the diagnostics `compiler::prepare`
/// collected for the file currently being loaded.
pub(crate) enum LoadError {
    Message(String),
    Diagnostics(Vec<Diagnostic>),
}

impl From<String> for LoadError {
    fn from(message: String) -> Self {
        LoadError::Message(message)
    }
}

/// Every parse, validation and type diagnostic for `entry`, without writing
/// an artifact. `entry` may be a library file, checked directly rather than
/// through a synthetic importer. Unlike `compile_sources`, independent
/// problems in `entry` each get their own diagnostic instead of being joined
/// into one message.
pub(crate) fn check_sources(entry: &str, files: &BTreeMap<String, String>) -> Vec<Diagnostic> {
    let entry = match relative_path(entry) {
        Ok(entry) => entry,
        Err(e) => return vec![Diagnostic::error(entry, e)],
    };
    let normalized = match normalize_files(files) {
        Ok(normalized) => normalized,
        Err(e) => return vec![Diagnostic::error(entry, e)],
    };
    let Some(source) = normalized.get(&entry) else {
        let message = format!(
            "source file '{entry}' not found; imports require source files supplied through compile_sources or compile_file"
        );
        return vec![Diagnostic::error(entry, message)];
    };
    if let Err(error) = parser::try_parse(source) {
        return vec![parser::parse_error_diagnostic(&error, &entry, source)];
    }

    let mut modules = BTreeMap::new();
    let mut loaded_files = BTreeMap::new();
    let result = load(
        &entry,
        &entry,
        &mut |path| {
            normalized.get(path).cloned().ok_or_else(|| {
            format!("source file '{path}' not found; imports require source files supplied through compile_sources or compile_file")
        })
        },
        &mut modules,
        &mut loaded_files,
        &mut Vec::new(),
        &mut HashMap::new(),
        true,
    );

    match result {
        Ok(()) => modules[&entry].warnings.clone(),
        Err(LoadError::Diagnostics(diagnostics)) => diagnostics,
        Err(LoadError::Message(message)) => {
            let message = message
                .strip_prefix(&format!("{entry}: "))
                .unwrap_or(&message);
            vec![Diagnostic::error(entry, message)]
        }
    }
}

pub(crate) fn compile_sources(
    entry: &str,
    files: &BTreeMap<String, String>,
    options: crate::CompileOptions,
) -> Result<ContractJson, String> {
    let entry = relative_path(entry)?;
    let normalized = normalize_files(files)?;
    compile_with_loader(
        &entry,
        |path| {
            normalized.get(path).cloned().ok_or_else(|| format!(
                "source file '{path}' not found; imports require source files supplied through compile_sources or compile_file"
            ))
        },
        false,
        options,
    )
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
    for import in parser::imports(source)? {
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
    let absolute = std::path::absolute(path).map_err(|e| e.to_string())?;
    let entry = normalize(&absolute)?;
    compile_with_loader(
        &entry,
        |path| std::fs::read_to_string(path).map_err(|e| format!("cannot read '{path}': {e}")),
        true,
        options,
    )
}

fn relative_path(path: &str) -> Result<String, String> {
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

fn compile_with_loader(
    entry: &str,
    mut read: impl FnMut(&str) -> Result<String, String>,
    filesystem: bool,
    options: crate::CompileOptions,
) -> Result<ContractJson, String> {
    let mut modules = BTreeMap::new();
    let mut files = BTreeMap::new();
    load(
        entry,
        entry,
        &mut read,
        &mut modules,
        &mut files,
        &mut Vec::new(),
        &mut HashMap::new(),
        false,
    )
    .map_err(|e| match e {
        LoadError::Message(message) => message,
        LoadError::Diagnostics(diagnostics) => {
            let source = read(entry).unwrap_or_default();
            format!(
                "{entry}: {}",
                crate::diagnostics::render_errors(&diagnostics, &source)
            )
        }
    })?;
    let root = &modules[entry];
    let mut bundle = SourceBundle {
        entry: entry.to_string(),
        files,
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
    let warnings = modules
        .iter()
        .flat_map(|(path, module)| {
            let path = Path::new(path)
                .strip_prefix(&base)
                .expect("common root")
                .to_string_lossy()
                .replace('\\', "/");
            let source = bundle.files.get(&path).map(String::as_str).unwrap_or("");
            module.warnings.iter().map(move |warning| {
                let tag = warning.code.as_deref().unwrap_or("general");
                let message = crate::diagnostics::located(&warning.message, warning.span, source);
                format!("warning[{tag}]: {message} ({path})")
            })
        })
        .collect();
    compiler::emit(&root.contract, bundle, warnings, options)
}

fn load(
    path: &str,
    entry: &str,
    read: &mut impl FnMut(&str) -> Result<String, String>,
    modules: &mut BTreeMap<String, Module>,
    files: &mut BTreeMap<String, String>,
    active: &mut Vec<String>,
    declarations: &mut HashMap<String, String>,
    entry_may_be_library: bool,
) -> Result<(), LoadError> {
    if modules.contains_key(path) {
        return Ok(());
    }
    if active.iter().any(|p| p == path) {
        return Err(LoadError::Message(format!(
            "circular import: {} -> {path}",
            active.join(" -> ")
        )));
    }
    // Recursive loading is bounded; use an iterative traversal for deeper projects.
    if active.len() >= 128 {
        return Err(LoadError::Message(
            "import depth exceeds 128 files".to_string(),
        ));
    }
    active.push(path.to_string());
    let result = (|| {
        let source = read(path)?;
        let imports = parser::imports(&source)?;
        let mut dependencies = Vec::new();
        for import in imports {
            let dependency = import_path(path, &import)?;
            load(
                &dependency,
                entry,
                read,
                modules,
                files,
                active,
                declarations,
                entry_may_be_library,
            )?;
            if !dependencies.contains(&dependency) {
                dependencies.push(dependency);
            }
        }
        let mut constants = Vec::new();
        for dependency in &dependencies {
            let contract = &modules[dependency].contract;
            for constant in contract.constants.iter().filter(|c| !c.name.contains('.')) {
                let mut constant = constant.clone();
                constant.name = format!("{}.{}", contract.name, constant.name);
                constants.push(constant);
            }
        }
        let mut contract = parser::parse_with_constants(&source, &constants)?;
        if path == entry && contract.is_library && !entry_may_be_library {
            return Err(LoadError::Message(
                "entry file must declare a contract, not a library".to_string(),
            ));
        }
        let own_structs: HashSet<_> = contract.structs.iter().map(|s| s.name.clone()).collect();
        if models::is_builtin_type(&contract.name)
            || models::is_builtin_struct(&contract.name)
            || matches!(contract.name.as_str(), "tx" | "this")
        {
            return Err(LoadError::Message(format!(
                "contract name '{}' is reserved",
                contract.name
            )));
        }
        for name in contract
            .structs
            .iter()
            .map(|s| &s.name)
            .chain((!contract.name.is_empty()).then_some(&contract.name))
        {
            if let Some(previous) = declarations.insert(name.clone(), path.to_string()) {
                return Err(LoadError::Message(format!(
                    "duplicate declaration '{name}' in '{previous}' and '{path}'"
                )));
            }
        }
        let mut visible_structs = own_structs.clone();
        let mut visible_contracts = HashMap::new();
        for dependency in &dependencies {
            let module = &modules[dependency];
            visible_structs.extend(module.structs.clone());
            if !module.contract.name.is_empty() {
                visible_contracts.insert(module.contract.name.clone(), &module.contract);
            }
        }
        for function in &mut contract.functions {
            visit_statements(&mut function.statements, &mut |expression| {
                if let Expression::GroupControlIs {
                    group,
                    asset_txid,
                    asset_gidx,
                } = expression
                {
                    if group == &contract.name || visible_contracts.contains_key(group) {
                        *expression = Expression::Call {
                            name: format!("{group}.controlIs"),
                            args: vec![*asset_txid.clone(), *asset_gidx.clone()],
                            return_type: None,
                        };
                    }
                }
                Ok(())
            })?;
        }
        compiler::fold_constants(&mut contract)?;
        visible_contracts.insert(contract.name.clone(), &contract);
        validate_scope(&contract, &visible_structs, &visible_contracts)?;
        let mut structs: BTreeMap<_, _> = contract
            .structs
            .iter()
            .map(|s| (s.name.clone(), s.clone()))
            .collect();
        let mut helpers = BTreeMap::new();
        for dependency in &dependencies {
            let imported = &modules[dependency].contract;
            structs.extend(imported.structs.iter().map(|s| (s.name.clone(), s.clone())));
            for function in imported.functions.iter().filter(|f| f.is_static) {
                let mut function = function.clone();
                if !function.is_imported() {
                    function.name = format!("{}.{}", imported.name, function.name);
                    visit_statements(&mut function.statements, &mut |expression| {
                        if let Expression::Call { name, .. } = expression {
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
                if let Expression::Call { name, .. } = expression {
                    if let Some(local) = name.strip_prefix(&format!("{owner}.")) {
                        *name = local.to_string();
                    }
                }
                Ok(())
            })?;
        }
        contract.functions.extend(helpers.into_values());
        let require_entrypoint = path == entry && !contract.is_library;
        let warnings = match compiler::prepare(&mut contract, require_entrypoint, path) {
            Ok(warnings) => warnings,
            Err(diagnostics) if path == entry => {
                return Err(LoadError::Diagnostics(diagnostics));
            }
            Err(diagnostics) => {
                return Err(LoadError::Message(crate::diagnostics::render_errors(
                    &diagnostics,
                    &source,
                )));
            }
        };
        files.insert(path.to_string(), source);
        modules.insert(
            path.to_string(),
            Module {
                contract,
                structs: own_structs,
                warnings,
            },
        );
        Ok(())
    })();
    active.pop();
    result.map_err(|error| match error {
        LoadError::Message(message) => LoadError::Message(format!("{path}: {message}")),
        diagnostics @ LoadError::Diagnostics(_) => diagnostics,
    })
}

fn validate_scope(
    contract: &Contract,
    structs: &HashSet<String>,
    contracts: &HashMap<String, &Contract>,
) -> Result<(), String> {
    let check_binding = |name: &str| {
        if contracts.contains_key(name) {
            Err(format!("binding '{name}' shadows a contract namespace"))
        } else {
            Ok(())
        }
    };
    for constant in &contract.constants {
        check_binding(&constant.name)?;
    }
    let check_type = |ty: &str| {
        let base = models::array_type_parts(ty)
            .map(|(base, _)| base)
            .unwrap_or(ty);
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
        check_type(&parameter.param_type)?;
    }
    for parameter in contract
        .parameters
        .iter()
        .chain(contract.functions.iter().flat_map(|f| &f.parameters))
        .chain(contract.tapscripts.iter().flat_map(|t| &t.inputs))
    {
        check_binding(&parameter.name)?;
    }
    for function in &contract.functions {
        if let Some(ty) = &function.return_type {
            check_type(ty)?;
        }
        let mut scope =
            typechecker::build_scope_with_structs(&contract.parameters, &contract.structs);
        scope.extend(typechecker::build_scope_with_structs(
            &function.parameters,
            &contract.structs,
        ));
        let mut body = function.statements.clone();
        validate_local_types(&body, &check_type, &check_binding)?;
        visit_statements(&mut body, &mut |expression| {
            match expression {
                Expression::Call { name, .. } if name.contains('.') => {
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
                Expression::Property(name) => {
                    if let Some((owner, _)) = name.split_once('.') {
                        if contracts.contains_key(owner) {
                            return Err(format!("unknown constant '{name}'"));
                        }
                    }
                }
                Expression::ContractInstance {
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
                        let actual = typechecker::infer_type(arg, &scope);
                        if actual != typechecker::ArkType::Unknown
                            && !crate::validator::binding_types_compatible(
                                &typechecker::ArkType::parse(&param.param_type),
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
    check: &impl Fn(&str) -> Result<(), String>,
    binding: &impl Fn(&str) -> Result<(), String>,
) -> Result<(), String> {
    for statement in statements {
        match &statement.statement {
            Statement::LetBinding {
                name,
                declared_type,
                ..
            } => {
                binding(name)?;
                if let Some(ty) = declared_type {
                    check(ty)?;
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
                binding(index_var)?;
                binding(value_var)?;
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
) -> Result<(), String> {
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
                _ => {}
            },
            Statement::VarAssign { target, value } => {
                if let models::AssignmentTarget::ArrayIndex { index, .. } = target {
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
            Statement::Return(None) => {}
        }
    }
    Ok(())
}

fn visit_expression(
    expr: &mut Expression,
    visit: &mut impl FnMut(&mut Expression) -> Result<(), String>,
) -> Result<(), String> {
    for child in models::child_exprs_mut(expr) {
        visit_expression(child, visit)?;
    }
    visit(expr)
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
        require(tx.time >= Fees.DELAY);
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
                { "name": "group", "kind": "variable", "type": "assetGroup", "position": [5, 13], "scope": [4, 10] },
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
    fn a_dependency_failure_reaches_the_entry_as_a_diagnostic() {
        let main = "import \"lib.ark\";\ncontract V(pubkey owner) {\n  function spend(signature sig) {\n    require(checkSig(sig, owner));\n  }\n}\n";
        let broken_lib = "library L {\n  function helper() {\n    require(missing);\n  }\n}\n";
        let files: BTreeMap<_, _> = [
            ("main.ark".to_string(), main.to_string()),
            ("lib.ark".to_string(), broken_lib.to_string()),
        ]
        .into();
        let diagnostics = super::check_sources("main.ark", &files);
        assert!(
            !diagnostics.is_empty(),
            "a broken import must surface a diagnostic"
        );
        assert!(diagnostics[0].severity == Severity::Error);
    }
}
