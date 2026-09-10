use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Component, Path, PathBuf};

use crate::models::{self, Contract, ContractJson, Expression, SourceBundle, Statement};
use crate::{compiler, parser, typechecker};

// Dependency definitions are copied per module; use a shared symbol table if quadratic copying becomes costly.
struct Module {
    contract: Contract,
    structs: HashSet<String>,
    warnings: Vec<String>,
}

pub(crate) fn compile_sources(
    entry: &str,
    files: &BTreeMap<String, String>,
) -> Result<ContractJson, String> {
    let entry = relative_path(entry)?;
    let mut normalized = BTreeMap::new();
    for (path, source) in files {
        let path = relative_path(path)?;
        if normalized.insert(path.clone(), source.clone()).is_some() {
            return Err(format!("duplicate source path '{path}'"));
        }
    }
    compile_with_loader(
        &entry,
        |path| {
            normalized.get(path).cloned().ok_or_else(|| format!(
                "source file '{path}' not found; imports require source files supplied through compile_sources or compile_file"
            ))
        },
        false,
    )
}

pub(crate) fn compile_file(path: &Path) -> Result<ContractJson, String> {
    let absolute = std::path::absolute(path).map_err(|e| e.to_string())?;
    let entry = normalize(&absolute)?;
    compile_with_loader(
        &entry,
        |path| std::fs::read_to_string(path).map_err(|e| format!("cannot read '{path}': {e}")),
        true,
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
    )?;
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
            module
                .warnings
                .iter()
                .map(move |warning| format!("{warning} ({path})"))
        })
        .collect();
    compiler::emit(&root.contract, bundle, warnings)
}

fn load(
    path: &str,
    entry: &str,
    read: &mut impl FnMut(&str) -> Result<String, String>,
    modules: &mut BTreeMap<String, Module>,
    files: &mut BTreeMap<String, String>,
    active: &mut Vec<String>,
    declarations: &mut HashMap<String, String>,
) -> Result<(), String> {
    if modules.contains_key(path) {
        return Ok(());
    }
    if active.iter().any(|p| p == path) {
        return Err(format!(
            "circular import: {} -> {path}",
            active.join(" -> ")
        ));
    }
    // Recursive loading is bounded; use an iterative traversal for deeper projects.
    if active.len() >= 128 {
        return Err("import depth exceeds 128 files".to_string());
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
        let own_structs: HashSet<_> = contract.structs.iter().map(|s| s.name.clone()).collect();
        if models::is_builtin_type(&contract.name)
            || models::is_builtin_struct(&contract.name)
            || matches!(contract.name.as_str(), "tx" | "this")
        {
            return Err(format!("contract name '{}' is reserved", contract.name));
        }
        for name in contract
            .structs
            .iter()
            .map(|s| &s.name)
            .chain((!contract.name.is_empty()).then_some(&contract.name))
        {
            if let Some(previous) = declarations.insert(name.clone(), path.to_string()) {
                return Err(format!(
                    "duplicate declaration '{name}' in '{previous}' and '{path}'"
                ));
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
        let warnings = compiler::prepare(&mut contract, path == entry)?;
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
    result.map_err(|error: String| format!("{path}: {error}"))
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
                    if !target
                        .functions
                        .iter()
                        .any(|f| f.name == member && f.is_static)
                    {
                        return Err(format!("'{name}' is not a static function"));
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
    statements: &[Statement],
    check: &impl Fn(&str) -> Result<(), String>,
    binding: &impl Fn(&str) -> Result<(), String>,
) -> Result<(), String> {
    for statement in statements {
        match statement {
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
            _ => {}
        }
    }
    Ok(())
}

fn visit_statements(
    statements: &mut [Statement],
    visit: &mut impl FnMut(&mut Expression) -> Result<(), String>,
) -> Result<(), String> {
    for statement in statements {
        match statement {
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
