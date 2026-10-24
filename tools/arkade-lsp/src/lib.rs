//! Language server for Arkade Script. Every answer comes from the compiler's own analysis:
//! `check` for diagnostics and `analyze` with its symbol table for everything else.

use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::path::PathBuf;

mod project;

use arkade_compiler::models::ExprKind;
use arkade_compiler::symbols::{Definition, SymbolKind as Kind};
use arkade_compiler::{Analysis, Severity, Span};
use lsp_server::{Connection, ErrorCode, Message, Notification, Request, Response};
use lsp_types::notification::{
    DidChangeTextDocument, DidCloseTextDocument, DidOpenTextDocument, Notification as _,
    PublishDiagnostics,
};
use lsp_types::request::{
    Completion, DocumentHighlightRequest, DocumentSymbolRequest, GotoDefinition, HoverRequest,
    References, Request as _,
};
use lsp_types::{
    CompletionItem, CompletionItemKind, CompletionOptions, CompletionParams, CompletionTextEdit,
    Diagnostic, DiagnosticSeverity, DidChangeTextDocumentParams, DidCloseTextDocumentParams,
    DidOpenTextDocumentParams, DocumentHighlight, DocumentHighlightParams, DocumentSymbol,
    DocumentSymbolParams, GotoDefinitionParams, Hover, HoverContents, HoverParams,
    HoverProviderCapability, InitializeParams, InsertTextFormat, Location, MarkupContent,
    MarkupKind, NumberOrString, OneOf, Position, PublishDiagnosticsParams, Range, ReferenceParams,
    ServerCapabilities, SymbolKind, TextDocumentPositionParams, TextDocumentSyncKind, TextEdit,
    Url,
};
use project::{first_line, import_line, import_path, offset, range, utf16_len, Cache, Project};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

/// Serve one client until it sends `shutdown` and `exit`.
pub fn run(connection: Connection) -> Result<()> {
    let capabilities = ServerCapabilities {
        text_document_sync: Some(TextDocumentSyncKind::FULL.into()),
        document_symbol_provider: Some(OneOf::Left(true)),
        definition_provider: Some(OneOf::Left(true)),
        references_provider: Some(OneOf::Left(true)),
        document_highlight_provider: Some(OneOf::Left(true)),
        hover_provider: Some(HoverProviderCapability::Simple(true)),
        completion_provider: Some(CompletionOptions {
            trigger_characters: Some(vec![".".into(), "\"".into(), "/".into()]),
            ..Default::default()
        }),
        ..Default::default()
    };
    let params = connection.initialize(serde_json::to_value(capabilities)?)?;
    let mut server = Server::new(serde_json::from_value(params)?);
    for message in &connection.receiver {
        match message {
            Message::Request(request) => {
                if connection.handle_shutdown(&request)? {
                    return Ok(());
                }
                connection.sender.send(server.request(request).into())?;
            }
            Message::Notification(notification) => {
                for message in server.notify(notification) {
                    connection.sender.send(message.into())?;
                }
            }
            Message::Response(_) => {}
        }
    }
    Ok(())
}

struct Server {
    roots: Vec<PathBuf>,
    documents: BTreeMap<Url, String>,
    cache: Cache,
}

impl Server {
    #[allow(deprecated)]
    fn new(params: InitializeParams) -> Self {
        let folders = params.workspace_folders.unwrap_or_default();
        let uris = folders.into_iter().map(|f| f.uri).chain(params.root_uri);
        Self {
            roots: uris.filter_map(|uri| uri.to_file_path().ok()).collect(),
            documents: BTreeMap::new(),
            cache: Cache::default(),
        }
    }

    fn notify(&mut self, notification: Notification) -> Vec<Notification> {
        match notification.method.as_str() {
            DidOpenTextDocument::METHOD => {
                let Ok(params) =
                    serde_json::from_value::<DidOpenTextDocumentParams>(notification.params)
                else {
                    return Vec::new();
                };
                let document = params.text_document;
                self.documents.insert(document.uri, document.text);
            }
            DidChangeTextDocument::METHOD => {
                let Ok(mut params) =
                    serde_json::from_value::<DidChangeTextDocumentParams>(notification.params)
                else {
                    return Vec::new();
                };
                let Some(change) = params.content_changes.pop() else {
                    return Vec::new();
                };
                self.documents.insert(params.text_document.uri, change.text);
            }
            DidCloseTextDocument::METHOD => {
                let Ok(params) =
                    serde_json::from_value::<DidCloseTextDocumentParams>(notification.params)
                else {
                    return Vec::new();
                };
                let uri = params.text_document.uri;
                self.documents.remove(&uri);
                return vec![publish(uri, Vec::new())];
            }
            _ => return Vec::new(),
        }
        // Importers depend on the edited file, so every open document is checked again.
        self.documents
            .keys()
            .map(|uri| publish(uri.clone(), self.diagnostics(uri)))
            .collect()
    }

    fn request(&self, request: Request) -> Response {
        fn at(params: TextDocumentPositionParams) -> (Url, Position) {
            (params.text_document.uri, params.position)
        }
        let params = request.params;
        let result = match request.method.as_str() {
            DocumentSymbolRequest::METHOD => serde_json::from_value::<DocumentSymbolParams>(params)
                .map(|p| serde_json::json!(self.document_symbols(&p.text_document.uri))),
            GotoDefinition::METHOD => serde_json::from_value::<GotoDefinitionParams>(params)
                .map(|p| serde_json::json!(self.definition(at(p.text_document_position_params)))),
            References::METHOD => serde_json::from_value::<ReferenceParams>(params).map(|p| {
                let declaration = p.context.include_declaration;
                serde_json::json!(self.references(at(p.text_document_position), declaration))
            }),
            DocumentHighlightRequest::METHOD => {
                serde_json::from_value::<DocumentHighlightParams>(params).map(|p| {
                    serde_json::json!(self.highlights(at(p.text_document_position_params)))
                })
            }
            HoverRequest::METHOD => serde_json::from_value::<HoverParams>(params)
                .map(|p| serde_json::json!(self.hover(at(p.text_document_position_params)))),
            Completion::METHOD => serde_json::from_value::<CompletionParams>(params)
                .map(|p| serde_json::json!(self.completion(at(p.text_document_position)))),
            method => {
                return Response::new_err(
                    request.id,
                    ErrorCode::MethodNotFound as i32,
                    format!("unsupported request {method}"),
                )
            }
        };
        match result {
            Ok(value) => Response::new_ok(request.id, value),
            Err(error) => Response::new_err(
                request.id,
                ErrorCode::InvalidParams as i32,
                error.to_string(),
            ),
        }
    }

    fn project(&self, uri: &Url) -> Option<Project> {
        Project::new(uri, &self.roots, &self.documents)
    }

    fn analyze(&self, project: &Project) -> std::rc::Rc<Analysis> {
        self.cache.analyze(&project.entry, &project.files)
    }

    fn diagnostics(&self, uri: &Url) -> Vec<Diagnostic> {
        let Some(project) = self.project(uri) else {
            return Vec::new();
        };
        let source = project.source();
        let imports = project.imports();
        arkade_compiler::check(&project.entry, &project.files)
            .into_iter()
            .map(|diagnostic| {
                let (range, message) = if diagnostic.file == project.entry {
                    let range = diagnostic.span.map(|span| range(source, span));
                    (
                        range.unwrap_or_else(|| first_line(source)),
                        diagnostic.message,
                    )
                } else {
                    // A dependency's problem shows on the import that reaches it; the first import
                    // stands in for one reached through another file.
                    let import = imports
                        .iter()
                        .find(|(file, _)| *file == diagnostic.file)
                        .or(imports.first());
                    let at = diagnostic.span.and_then(|span| {
                        let source = project.files.get(&diagnostic.file)?;
                        let start = range(source, span).start;
                        Some(format!(":{}:{}", start.line + 1, start.character + 1))
                    });
                    let message = format!(
                        "{}{}: {}",
                        diagnostic.file,
                        at.unwrap_or_default(),
                        diagnostic.message
                    );
                    (
                        import.map_or_else(|| first_line(source), |(_, range)| *range),
                        message,
                    )
                };
                Diagnostic {
                    range,
                    severity: Some(match diagnostic.severity {
                        Severity::Error => DiagnosticSeverity::ERROR,
                        Severity::Warning => DiagnosticSeverity::WARNING,
                    }),
                    code: diagnostic.code.map(NumberOrString::String),
                    source: Some("arkade".to_string()),
                    message,
                    ..Default::default()
                }
            })
            .collect()
    }

    #[allow(deprecated)]
    fn document_symbols(&self, uri: &Url) -> Vec<DocumentSymbol> {
        let Some(project) = self.project(uri) else {
            return Vec::new();
        };
        let analysis = self.analyze(&project);
        let source = project.source();
        let mut own: Vec<&Definition> = analysis
            .symbols()
            .definitions()
            .iter()
            .filter(|d| d.file == project.entry && d.visible.is_none())
            .collect();
        own.sort_by_key(|d| d.span.start);
        let functions: HashSet<&str> = own
            .iter()
            .filter(|d| d.kind == Kind::Function)
            .map(|d| d.name.as_str())
            .collect();
        let outline = |definition: &Definition, children| DocumentSymbol {
            name: definition.name.clone(),
            detail: definition.ty.as_ref().map(ToString::to_string),
            kind: symbol_kind(definition.kind),
            tags: None,
            deprecated: None,
            range: range(source, definition.span),
            selection_range: range(source, definition.span),
            children,
        };
        let fields = |owner: &Definition| {
            own.iter()
                .filter(|d| d.kind == Kind::Field && d.owner.as_deref() == Some(&owner.name))
                .map(|d| outline(d, None))
                .collect()
        };
        // A tapscript function also defines the tapscript of the same name.
        let members = own
            .iter()
            .filter(|d| {
                !matches!(
                    d.kind,
                    Kind::Contract | Kind::Library | Kind::Struct | Kind::Field
                )
            })
            .filter(|d| d.kind != Kind::Tapscript || !functions.contains(d.name.as_str()))
            .map(|d| outline(d, None))
            .collect();
        let mut members = Some(members);
        own.iter()
            .filter(|d| matches!(d.kind, Kind::Contract | Kind::Library | Kind::Struct))
            .map(|d| match d.kind {
                Kind::Struct => outline(d, Some(fields(d))),
                _ => outline(d, members.take()),
            })
            .collect()
    }

    fn definition(&self, (uri, cursor): (Url, Position)) -> Option<Location> {
        let project = self.project(&uri)?;
        let at = offset(project.source(), cursor)?;
        let import = project.imports().into_iter().find(|(_, statement)| {
            statement.start.line == cursor.line
                && statement.start.character <= cursor.character
                && cursor.character <= statement.end.character
        });
        if let Some((file, _)) = import {
            return Some(Location::new(project.uri(&file)?, Range::default()));
        }
        let analysis = self.analyze(&project);
        let definition = analysis.symbols().definition_at(&project.entry, at)?;
        let source = analysis.source(&definition.file)?;
        Some(Location::new(
            project.uri(&definition.file)?,
            range(source, definition.span),
        ))
    }

    /// The uses of the name at the cursor, across every analyzed file.
    fn references(&self, (uri, cursor): (Url, Position), declaration: bool) -> Vec<Location> {
        let Some(project) = self.project(&uri) else {
            return Vec::new();
        };
        let analysis = self.analyze(&project);
        uses(&analysis, &project, cursor, declaration)
            .into_iter()
            .filter_map(|(file, span)| {
                let source = analysis.source(file)?;
                Some(Location::new(project.uri(file)?, range(source, span)))
            })
            .collect()
    }

    fn highlights(&self, (uri, cursor): (Url, Position)) -> Vec<DocumentHighlight> {
        let Some(project) = self.project(&uri) else {
            return Vec::new();
        };
        let analysis = self.analyze(&project);
        uses(&analysis, &project, cursor, true)
            .into_iter()
            .filter(|(file, _)| *file == project.entry)
            .map(|(_, span)| DocumentHighlight {
                range: range(project.source(), span),
                kind: None,
            })
            .collect()
    }

    /// The declaration under the cursor; constants also show their folded value.
    fn hover(&self, (uri, cursor): (Url, Position)) -> Option<Hover> {
        let project = self.project(&uri)?;
        let analysis = self.analyze(&project);
        let at = offset(project.source(), cursor)?;
        let definition = analysis.symbols().definition_at(&project.entry, at)?;
        let ty = definition
            .ty
            .as_ref()
            .map(|ty| format!("{ty} "))
            .unwrap_or_default();
        let name = &definition.name;
        let declaration = match definition.kind {
            Kind::Constant => match constant_value(&analysis, &project, definition) {
                Some(value) => format!("const {ty}{name} = {value}"),
                None => format!("const {ty}{name}"),
            },
            kind => format!("{} {ty}{name}", format!("{kind:?}").to_lowercase()),
        };
        let mut text = format!("```arkade\n{declaration}\n```");
        if definition.file != project.entry {
            text.push_str(&format!("\n\nFrom `{}`", definition.file));
        }
        Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: text,
            }),
            range: None,
        })
    }

    /// Import paths inside an import's quotes; elsewhere the names visible at the cursor, members
    /// after `Name.`, and names from files not imported yet, with the import that brings them.
    fn completion(&self, (uri, cursor): (Url, Position)) -> Vec<CompletionItem> {
        let Some(project) = self.project(&uri) else {
            return Vec::new();
        };
        let source = project.source();
        let Some(at) = offset(source, cursor) else {
            return Vec::new();
        };
        let before = &source[source[..at].rfind('\n').map_or(0, |i| i + 1)..at];
        if before.trim_start().starts_with("import") && before.matches('"').count() == 1 {
            let typed = before.rfind('"').map_or(0, |i| i + 1);
            let start = Position::new(cursor.line, utf16_len(&before[..typed]));
            return project
                .files
                .keys()
                .filter(|file| **file != project.entry)
                .map(|file| {
                    let path = import_path(project.directory(), file);
                    CompletionItem {
                        label: path.clone(),
                        kind: Some(CompletionItemKind::FILE),
                        text_edit: Some(CompletionTextEdit::Edit(TextEdit::new(
                            Range::new(start, cursor),
                            path,
                        ))),
                        ..Default::default()
                    }
                })
                .collect();
        }
        let prefix = &before[..word_start(before)];
        let owner = prefix
            .trim_end()
            .strip_suffix('.')
            .map(|before| &before[word_start(before)..]);
        let imported: HashSet<String> = project.imports().into_iter().map(|(f, _)| f).collect();
        let others: Vec<String> = project
            .files
            .keys()
            .filter(|file| **file != project.entry && !imported.contains(*file))
            .map(|file| format!("import \"{}\";", import_path(project.directory(), file)))
            .collect();
        let Some((analysis, at)) = visible_while_typing(&project, cursor, &others)
            .or_else(|| visible_while_typing(&project, cursor, &[]))
        else {
            return Vec::new();
        };
        let symbols = analysis.symbols();
        let visible = symbols.visible_at(&project.entry, at);
        let item = |label: &str, definition: &Definition| {
            let mut item = completion_item(label, definition);
            if definition.file != project.entry && !imported.contains(&definition.file) {
                let path = import_path(project.directory(), &definition.file);
                let line = Position::new(import_line(source) as u32, 0);
                let edit = TextEdit::new(Range::new(line, line), format!("import \"{path}\";\n"));
                item.additional_text_edits = Some(vec![edit]);
                item.detail = Some(format!("import from {}", definition.file));
            }
            item
        };
        let offered = |d: &&Definition| !matches!(d.kind, Kind::Tapscript | Kind::Field);
        let Some(owner) = owner else {
            return visible
                .iter()
                .filter(|(name, d)| !name.contains('.') && offered(d))
                .map(|(name, d)| item(name, d))
                .collect();
        };
        let members: Vec<_> = visible
            .iter()
            .filter_map(|(name, d)| Some((name.strip_prefix(owner)?.strip_prefix('.')?, d)))
            .filter(|(_, d)| offered(d))
            .map(|(name, d)| item(name, d))
            .collect();
        if !members.is_empty() {
            return members;
        }
        // A binding of struct type offers the struct's fields.
        let Some(ty) = visible
            .iter()
            .find(|(name, _)| *name == owner)
            .and_then(|(_, d)| d.ty.as_ref())
            .map(ToString::to_string)
        else {
            return Vec::new();
        };
        let Some(structure) = visible
            .iter()
            .find(|(name, d)| *name == ty && d.kind == Kind::Struct)
        else {
            return Vec::new();
        };
        symbols
            .definitions()
            .iter()
            .filter(|d| d.kind == Kind::Field && d.file == structure.1.file)
            .filter(|d| d.owner.as_deref() == Some(structure.0))
            .map(|d| completion_item(&d.name, d))
            .collect()
    }
}

/// The definition at the cursor and its references, with the declaration first if wanted.
fn uses<'a>(
    analysis: &'a Analysis,
    project: &Project,
    cursor: Position,
    declaration: bool,
) -> Vec<(&'a str, Span)> {
    let symbols = analysis.symbols();
    let Some(definition) =
        offset(project.source(), cursor).and_then(|at| symbols.definition_at(&project.entry, at))
    else {
        return Vec::new();
    };
    let index = symbols
        .definitions()
        .iter()
        .position(|candidate| std::ptr::eq(candidate, definition));
    let references = symbols
        .references()
        .iter()
        .filter(|reference| Some(reference.definition) == index)
        .map(|reference| (reference.file.as_str(), reference.span));
    declaration
        .then_some((definition.file.as_str(), definition.span))
        .into_iter()
        .chain(references)
        .collect()
}

/// The folded value of a constant, which the compiler records on the entry's contract, an
/// imported one under `Owner.NAME`.
fn constant_value(analysis: &Analysis, project: &Project, constant: &Definition) -> Option<String> {
    let name = match constant.file == project.entry {
        true => constant.name.clone(),
        false => {
            let owner = analysis.symbols().definitions().iter().find(|d| {
                d.file == constant.file && matches!(d.kind, Kind::Contract | Kind::Library)
            })?;
            format!("{}.{}", owner.name, constant.name)
        }
    };
    let declared = analysis
        .contract()?
        .constants
        .iter()
        .find(|c| c.name == name)?;
    match &declared.value.kind {
        ExprKind::Literal(value) => Some(value.clone()),
        _ => None,
    }
}

/// The analysis with `imports` inserted where an import edit would put them, and the cursor's
/// offset in it. A half-typed line rarely parses, so it is retried blank.
fn visible_while_typing(
    project: &Project,
    cursor: Position,
    imports: &[String],
) -> Option<(Analysis, usize)> {
    let source = project.source();
    let at = import_line(source);
    let attempt = |blank: bool| {
        let mut lines: Vec<&str> = source.split('\n').collect();
        let line = cursor.line as usize;
        if blank {
            *lines.get_mut(line)? = "";
        }
        let at = at.min(lines.len());
        lines.splice(at..at, imports.iter().map(String::as_str));
        let text = lines.join("\n");
        let shifted = line + if line >= at { imports.len() } else { 0 };
        let column = if blank { 0 } else { cursor.character };
        let offset = offset(&text, Position::new(shifted as u32, column))?;
        let mut files = project.files.clone();
        files.insert(project.entry.clone(), text);
        let analysis = arkade_compiler::analyze(&project.entry, &files);
        let parsed = analysis
            .symbols()
            .definitions()
            .iter()
            .any(|d| d.file == project.entry);
        parsed.then_some((analysis, offset))
    };
    attempt(false).or_else(|| attempt(true))
}

fn completion_item(label: &str, definition: &Definition) -> CompletionItem {
    let function = definition.kind == Kind::Function;
    CompletionItem {
        label: label.to_string(),
        kind: Some(match definition.kind {
            Kind::Function | Kind::Tapscript => CompletionItemKind::FUNCTION,
            Kind::Constant => CompletionItemKind::CONSTANT,
            Kind::Struct => CompletionItemKind::STRUCT,
            Kind::Library => CompletionItemKind::MODULE,
            Kind::Contract => CompletionItemKind::CLASS,
            Kind::Field => CompletionItemKind::FIELD,
            Kind::Parameter | Kind::Variable => CompletionItemKind::VARIABLE,
        }),
        detail: definition.ty.as_ref().map(ToString::to_string),
        insert_text: function.then(|| format!("{label}($0)")),
        insert_text_format: function.then_some(InsertTextFormat::SNIPPET),
        ..Default::default()
    }
}

fn symbol_kind(kind: Kind) -> SymbolKind {
    match kind {
        Kind::Struct => SymbolKind::STRUCT,
        Kind::Contract => SymbolKind::CLASS,
        Kind::Library => SymbolKind::MODULE,
        Kind::Function | Kind::Tapscript => SymbolKind::FUNCTION,
        Kind::Constant => SymbolKind::CONSTANT,
        Kind::Field => SymbolKind::FIELD,
        Kind::Parameter | Kind::Variable => SymbolKind::VARIABLE,
    }
}

fn publish(uri: Url, diagnostics: Vec<Diagnostic>) -> Notification {
    Notification::new(
        PublishDiagnostics::METHOD.to_string(),
        PublishDiagnosticsParams::new(uri, diagnostics, None),
    )
}

fn word_start(text: &str) -> usize {
    text.rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .map_or(0, |i| i + 1)
}
