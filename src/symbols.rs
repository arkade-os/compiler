//! Definitions and references with their source positions, for editors.

use std::collections::{HashMap, HashSet};

use crate::diagnostics::Span;
use crate::models::{
    AssignmentTarget, Contract, ExprKind, Expression, LocatedStatement, Path, Statement, TypeName,
};
use crate::types::ArkType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    Contract,
    Library,
    Struct,
    Constant,
    Function,
    Tapscript,
    Parameter,
    Variable,
    /// A struct field, whose `owner` is the struct.
    Field,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Definition {
    pub name: String,
    pub kind: SymbolKind,
    /// The declared type, or the inferred one of a `let`; `None` when there is neither.
    pub ty: Option<TypeName>,
    pub file: String,
    /// Byte range of the name.
    pub span: Span,
    /// Where a function parameter or local can be used; `None` for file-level names.
    pub visible: Option<Span>,
    /// The struct a field belongs to.
    pub owner: Option<String>,
}

/// A use of a name, which `definition` indexes in [`Symbols::definitions`].
#[derive(Debug, Clone, PartialEq)]
pub struct Reference {
    pub file: String,
    pub span: Span,
    pub definition: usize,
}

/// The definitions of every analyzed file and the references to them.
// ponytail: references cover bindings, calls, `new` and constants; struct fields, type names and
// tapscript operands carry no spans yet, so they are not recorded.
#[derive(Debug, Clone, Default)]
pub struct Symbols {
    definitions: Vec<Definition>,
    references: Vec<Reference>,
    /// Each file's names visible to a file importing it, such as `Fees` and `Fees.DELAY`.
    exports: HashMap<String, HashMap<String, usize>>,
    /// Each file's file-level names, its own and those it imports.
    globals: HashMap<String, HashMap<String, usize>>,
}

impl Symbols {
    pub fn definitions(&self) -> &[Definition] {
        &self.definitions
    }

    pub fn references(&self) -> &[Reference] {
        &self.references
    }

    /// The definition of the name at `offset` in `file`, from a reference or the name itself.
    /// A name's end counts, so a cursor just after it finds it.
    pub fn definition_at(&self, file: &str, offset: usize) -> Option<&Definition> {
        let at = |span: Span| span.start <= offset && offset <= span.end;
        self.references
            .iter()
            .find(|reference| reference.file == file && at(reference.span))
            .map(|reference| &self.definitions[reference.definition])
            .or_else(|| {
                self.definitions
                    .iter()
                    .find(|definition| definition.file == file && at(definition.span))
            })
    }

    /// Every name usable at `offset` in `file`, as it is written there (such as `Fees.DELAY`),
    /// with its definition: the file-level names, then the parameters and locals in scope.
    pub fn visible_at(&self, file: &str, offset: usize) -> Vec<(&str, &Definition)> {
        let mut visible: Vec<_> = self
            .globals
            .get(file)
            .into_iter()
            .flatten()
            .map(|(name, &id)| (name.as_str(), &self.definitions[id]))
            .collect();
        visible
            .sort_by(|(a, x), (b, y)| (&x.file, x.span.start, a).cmp(&(&y.file, y.span.start, b)));
        visible.extend(
            self.definitions
                .iter()
                .filter(|d| d.file == file)
                .filter(|d| {
                    d.visible
                        .is_some_and(|v| v.start <= offset && offset <= v.end)
                })
                .map(|d| (d.name.as_str(), d)),
        );
        // Broken source can repeat a name; the latest definition, the innermost, shadows.
        let mut seen = HashSet::new();
        visible.reverse();
        visible.retain(|(name, _)| seen.insert(*name));
        visible.reverse();
        visible
    }

    /// Record `contract`, typed, as `file`; `constants` are the constant references folded away.
    pub(crate) fn collect(
        &mut self,
        file: &str,
        source: &str,
        contract: &Contract,
        own_structs: &HashSet<String>,
        dependencies: &[String],
        constants: &[(Path, Span)],
    ) {
        let mut names = Names::default();
        for dependency in dependencies {
            names.globals.extend(self.exports[dependency].clone());
        }
        let mut collector = Collector {
            symbols: self,
            file,
            source,
            scopes: Vec::new(),
        };
        let owner = (!contract.name.is_empty()).then_some(contract.name.as_str());
        if let Some(owner) = owner {
            let kind = match contract.is_library {
                true => SymbolKind::Library,
                false => SymbolKind::Contract,
            };
            let id = collector.define(owner, kind, None, contract.span, None);
            names.export(owner.to_string(), id);
        }
        for definition in contract
            .structs
            .iter()
            .filter(|s| own_structs.contains(&s.name))
        {
            let span = definition.span;
            let id = collector.define(&definition.name, SymbolKind::Struct, None, span, None);
            names.export(definition.name.clone(), id);
            for field in &definition.fields {
                let ty = Some(field.param_type.clone());
                let id = collector.define(&field.name, SymbolKind::Field, ty, field.span, None);
                collector.symbols.definitions[id].owner = Some(definition.name.clone());
            }
        }
        for constant in contract.constants.iter().filter(|c| !c.name.contains('.')) {
            let ty = Some(constant.const_type.clone());
            let id = collector.define(
                &constant.name,
                SymbolKind::Constant,
                ty,
                constant.span,
                None,
            );
            names.member(owner, &constant.name, id, true);
        }
        let functions: Vec<_> = contract
            .functions
            .iter()
            .filter(|f| !f.is_imported())
            .collect();
        for function in &functions {
            let ty = function.return_type.clone();
            let id = collector.define(
                &function.name,
                SymbolKind::Function,
                ty,
                function.span,
                None,
            );
            names.member(owner, &function.name, id, function.is_exported);
        }
        for tapscript in &contract.tapscripts {
            let span = tapscript.span;
            let id = collector.define(&tapscript.name, SymbolKind::Tapscript, None, span, None);
            names.globals.insert(tapscript.name.clone(), id);
        }
        for parameter in &contract.parameters {
            let ty = Some(parameter.param_type.clone());
            let span = parameter.span;
            let id = collector.define(&parameter.name, SymbolKind::Parameter, ty, span, None);
            names.globals.insert(parameter.name.clone(), id);
        }
        collector
            .symbols
            .globals
            .insert(file.to_string(), names.globals.clone());
        collector.scopes.push(names.globals);
        for (path, span) in constants {
            let start = collector.token(span.start);
            collector.qualified(start, &path.key());
        }
        for constant in contract.constants.iter().filter(|c| !c.name.contains('.')) {
            collector.initializer(&constant.initializer);
        }
        for function in functions {
            collector.scopes.push(HashMap::new());
            for parameter in &function.parameters {
                let ty = Some(parameter.param_type.clone());
                let visible = Some(function.declaration);
                collector.bind(
                    &parameter.name,
                    SymbolKind::Parameter,
                    ty,
                    parameter.span,
                    visible,
                );
            }
            collector.statements(&function.statements, function.declaration.end);
            collector.scopes.pop();
        }
        for tapscript in &contract.tapscripts {
            collector.scopes.push(HashMap::new());
            for input in &tapscript.inputs {
                let ty = Some(input.param_type.clone());
                let visible = Some(tapscript.declaration);
                collector.bind(&input.name, SymbolKind::Parameter, ty, input.span, visible);
            }
            for (name, span) in &tapscript.operands {
                collector.refer(name, span.start);
            }
            collector.scopes.pop();
        }
        self.exports.insert(file.to_string(), names.exports);
    }
}

/// The file-level names of one file, and those an importing file sees.
#[derive(Default)]
struct Names {
    globals: HashMap<String, usize>,
    exports: HashMap<String, usize>,
}

impl Names {
    fn export(&mut self, name: String, id: usize) {
        self.globals.insert(name.clone(), id);
        self.exports.insert(name, id);
    }

    /// A member resolves bare and as `Owner.name`; an exported one also in importing files.
    fn member(&mut self, owner: Option<&str>, name: &str, id: usize, exported: bool) {
        self.globals.insert(name.to_string(), id);
        if let Some(owner) = owner {
            let qualified = format!("{owner}.{name}");
            if exported {
                self.export(qualified, id);
            } else {
                self.globals.insert(qualified, id);
            }
        }
    }
}

struct Collector<'a> {
    symbols: &'a mut Symbols,
    file: &'a str,
    source: &'a str,
    /// File-level names, then one frame per enclosing block.
    scopes: Vec<HashMap<String, usize>>,
}

impl Collector<'_> {
    fn define(
        &mut self,
        name: &str,
        kind: SymbolKind,
        ty: Option<TypeName>,
        span: Span,
        visible: Option<Span>,
    ) -> usize {
        self.symbols.definitions.push(Definition {
            name: name.to_string(),
            kind,
            ty,
            file: self.file.to_string(),
            span,
            visible,
            owner: None,
        });
        self.symbols.definitions.len() - 1
    }

    fn bind(
        &mut self,
        name: &str,
        kind: SymbolKind,
        ty: Option<TypeName>,
        span: Span,
        visible: Option<Span>,
    ) {
        let id = self.define(name, kind, ty, span, visible);
        let frame = self.scopes.last_mut().expect("a block frame");
        frame.insert(name.to_string(), id);
    }

    fn local(&mut self, name: &str, ty: Option<TypeName>, span: Span, end: usize) {
        let visible = Some(Span {
            start: span.start,
            end,
        });
        self.bind(name, SymbolKind::Variable, ty, span, visible);
    }

    fn refer(&mut self, name: &str, start: usize) {
        let found = self.scopes.iter().rev().find_map(|frame| frame.get(name));
        if let Some(&definition) = found {
            self.symbols.references.push(Reference {
                file: self.file.to_string(),
                span: Span {
                    start,
                    end: start + name.len(),
                },
                definition,
            });
        }
    }

    /// `name` or `Owner.name` spelled at `start`: the owner and the member are each a reference.
    fn qualified(&mut self, start: usize, spelled: &str) {
        match spelled.split_once('.') {
            Some((owner, _)) => {
                self.refer(owner, start);
                let found = self.scopes[0].get(spelled).copied();
                if let Some(definition) = found {
                    let member_start = start + owner.len() + 1;
                    self.symbols.references.push(Reference {
                        file: self.file.to_string(),
                        span: Span {
                            start: member_start,
                            end: start + spelled.len(),
                        },
                        definition,
                    });
                }
            }
            None => self.refer(spelled, start),
        }
    }

    /// The first token at or after `start`, past the `(`, whitespace and comments that can open
    /// an expression's span.
    // ponytail: recovers name positions from source text; syntax that puts anything else before
    // a name needs the parser to record the name's span.
    fn token(&self, start: usize) -> usize {
        let mut rest = self.source.get(start..).unwrap_or_default();
        loop {
            rest = rest.trim_start_matches(['(', ' ', '\t', '\r', '\n']);
            match rest.strip_prefix("//") {
                Some(comment) => rest = comment.find('\n').map_or("", |end| &comment[end..]),
                None => return self.source.len() - rest.len(),
            }
        }
    }

    /// The dotted identifier spelled at `start`, as a call's callee.
    fn spelled(&self, start: usize) -> &str {
        let rest = self.source.get(start..).unwrap_or_default();
        let end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
            .unwrap_or(rest.len());
        &rest[..end]
    }

    fn statements(&mut self, statements: &[LocatedStatement], end: usize) {
        for located in statements {
            let start = located.span.start;
            match &located.statement {
                Statement::Declaration {
                    name,
                    declared_type,
                } => self.local(name, Some(declared_type.clone()), located.names[0], end),
                Statement::LetBinding {
                    name,
                    declared_type,
                    value,
                } => {
                    self.expression(value);
                    let ty = declared_type.clone().or_else(|| known(value.ty()));
                    self.local(name, ty, located.names[0], end);
                }
                Statement::VarAssign { target, value } => {
                    match target {
                        AssignmentTarget::Binding(path) => self.refer(&path.root, start),
                        AssignmentTarget::ArrayIndex { array, index } => {
                            self.refer(&array.root, start);
                            self.expression(index);
                        }
                        AssignmentTarget::Access(access) => self.expression(access),
                    }
                    self.expression(value);
                }
                Statement::IfElse {
                    condition,
                    then_body,
                    else_body,
                } => {
                    self.expression(condition);
                    self.block(then_body, located.branches[0].end);
                    if let Some(else_body) = else_body {
                        self.block(else_body, located.branches[1].end);
                    }
                }
                Statement::ForIn {
                    index_var,
                    value_var,
                    iterable,
                    body,
                } => {
                    self.expression(iterable);
                    self.scopes.push(HashMap::new());
                    let element = match iterable.ty() {
                        ArkType::Array(element, _) => known(element),
                        _ => None,
                    };
                    let index_type = Some(TypeName::Named("int".to_string()));
                    self.local(index_var, index_type, located.names[0], located.span.end);
                    self.local(value_var, element, located.names[1], located.span.end);
                    self.statements(body, located.span.end);
                    self.scopes.pop();
                }
                Statement::ForCount { count, body } => {
                    self.expression(count);
                    self.block(body, located.span.end);
                }
                Statement::Call(_) | Statement::Return(_) | Statement::Require(_) => {
                    for expression in located.statement.expressions() {
                        self.expression(expression);
                    }
                }
            }
        }
    }

    fn block(&mut self, statements: &[LocatedStatement], end: usize) {
        self.scopes.push(HashMap::new());
        self.statements(statements, end);
        self.scopes.pop();
    }

    /// A constant's initializer as written, whose names are all constants.
    fn initializer(&mut self, expression: &Expression) {
        if let ExprKind::Name(path) = &expression.kind {
            let start = self.token(expression.span.start);
            self.qualified(start, &path.key());
        }
        for child in crate::models::child_exprs(expression) {
            self.initializer(child);
        }
    }

    fn expression(&mut self, expression: &Expression) {
        let start = self.token(expression.span.start);
        match &expression.kind {
            ExprKind::Name(path) | ExprKind::ArrayIndex { array: path, .. } => {
                self.refer(&path.root, start)
            }
            ExprKind::Call { .. } => {
                let spelled = self.spelled(start).to_string();
                self.qualified(start, &spelled);
            }
            ExprKind::ContractInstance { contract_name, .. } => {
                let name_start = self.token(start + "new".len());
                self.refer(contract_name, name_start);
            }
            _ => {}
        }
        for child in crate::models::child_exprs(expression) {
            self.expression(child);
        }
    }
}

fn known(ty: &ArkType) -> Option<TypeName> {
    (*ty != ArkType::Unknown).then(|| TypeName::from(ty))
}
