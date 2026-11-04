//! Language server for Arkade Script. Every answer comes from the compiler's own analysis of a
//! document's import closure, cached per closure version, over an index of the workspace.

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::error::Error;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::rc::Rc;

mod index;
mod project;
mod rename;

use arkade_compiler::models::ExprKind;
use arkade_compiler::symbols::{Definition, SymbolKind as Kind};
use arkade_compiler::{Analysis, Severity, Span};
use index::{FileId, Index};
use lsp_server::{Connection, ErrorCode, Message, Notification, Request, Response};
use lsp_types::notification::{
    DidChangeTextDocument, DidChangeWatchedFiles, DidCloseTextDocument, DidOpenTextDocument,
    DidSaveTextDocument, Notification as _, PublishDiagnostics,
};
use lsp_types::request::{
    CodeActionRequest, Completion, DocumentHighlightRequest, DocumentSymbolRequest, GotoDefinition,
    HoverRequest, InlayHintRequest, PrepareRenameRequest, References, RegisterCapability, Rename,
    Request as _, WorkspaceSymbolRequest,
};
use lsp_types::{
    CodeAction, CodeActionKind, CodeActionOrCommand, CodeActionParams,
    CodeActionProviderCapability, CompletionItem, CompletionItemKind, CompletionList,
    CompletionOptions, CompletionParams, CompletionTextEdit, Diagnostic,
    DiagnosticRelatedInformation, DiagnosticSeverity, DidChangeWatchedFilesRegistrationOptions,
    DocumentHighlight, DocumentHighlightParams, DocumentSymbol, DocumentSymbolParams,
    FileSystemWatcher, GlobPattern, GotoDefinitionParams, Hover, HoverContents, HoverParams,
    HoverProviderCapability, InitializeParams, InlayHint, InlayHintLabel, InlayHintParams,
    InsertTextFormat, Location, MarkupContent, MarkupKind, NumberOrString, OneOf, Position,
    PublishDiagnosticsParams, Range, ReferenceParams, Registration, RegistrationParams,
    RenameOptions, RenameParams, ServerCapabilities, SymbolKind, TextDocumentPositionParams,
    TextDocumentSyncKind, TextDocumentSyncOptions, TextEdit, Url, WorkspaceEdit, WorkspaceSymbol,
    WorkspaceSymbolParams,
};
use project::{
    first_line, import_line, import_path, offset, range, utf16_len, Analyzed, Cache, Project,
};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

/// Serve one client until it sends `shutdown` and `exit`.
pub fn run(connection: Connection) -> Result<()> {
    let capabilities = ServerCapabilities {
        text_document_sync: Some(
            TextDocumentSyncOptions {
                open_close: Some(true),
                change: Some(TextDocumentSyncKind::FULL),
                save: Some(true.into()),
                ..Default::default()
            }
            .into(),
        ),
        document_symbol_provider: Some(OneOf::Left(true)),
        definition_provider: Some(OneOf::Left(true)),
        references_provider: Some(OneOf::Left(true)),
        document_highlight_provider: Some(OneOf::Left(true)),
        hover_provider: Some(HoverProviderCapability::Simple(true)),
        code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
        workspace_symbol_provider: Some(OneOf::Left(true)),
        inlay_hint_provider: Some(OneOf::Left(true)),
        rename_provider: Some(OneOf::Right(RenameOptions {
            prepare_provider: Some(true),
            work_done_progress_options: Default::default(),
        })),
        completion_provider: Some(CompletionOptions {
            trigger_characters: Some(vec![".".into(), "\"".into(), "/".into()]),
            ..Default::default()
        }),
        ..Default::default()
    };
    let params = connection.initialize(serde_json::to_value(capabilities)?)?;
    let mut server = Server::new(serde_json::from_value(params)?);
    if server.watching {
        connection.sender.send(watch_request().into())?;
    }
    let mut queued = VecDeque::new();
    loop {
        let message = match queued.pop_front() {
            Some(message) => message,
            None => match connection.receiver.recv() {
                Ok(message) => message,
                Err(_) => return Ok(()),
            },
        };
        match message {
            Message::Request(request) => {
                if connection.handle_shutdown(&request)? {
                    return Ok(());
                }
                let id = request.id.clone();
                let response =
                    guarded(&mut server, |s| s.request(request)).unwrap_or_else(|panic| {
                        Response::new_err(id, ErrorCode::InternalError as i32, panic)
                    });
                connection.sender.send(response.into())?;
            }
            Message::Notification(notification) => {
                let burst = burst(&connection, notification, &mut queued);
                for message in server.notify(burst) {
                    connection.sender.send(message.into())?;
                }
            }
            Message::Response(_) => {}
        }
    }
}

/// `first` and the notifications already waiting after it; waiting requests go to `queued`, to
/// be answered once the burst is published.
fn burst(
    connection: &Connection,
    first: Notification,
    queued: &mut VecDeque<Message>,
) -> Vec<Notification> {
    let mut burst = vec![first];
    while let Ok(message) = connection.receiver.try_recv() {
        match message {
            Message::Notification(notification) => burst.push(notification),
            Message::Request(_) => queued.push_back(message),
            Message::Response(_) => {}
        }
    }
    burst
}

/// `handle` on the server, or the panic's message after it panicked. The analysis cache is reset
/// then, since the panic may have interrupted a borrow of it.
fn guarded<T>(
    server: &mut Server,
    handle: impl FnOnce(&mut Server) -> T,
) -> std::result::Result<T, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle(server))).map_err(|panic| {
        server.cache = Cache::default();
        let message = panic
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| panic.downcast_ref::<String>().cloned());
        format!("internal error: {}", message.unwrap_or_default())
    })
}

struct Server {
    index: Index,
    documents: BTreeMap<Url, FileId>,
    cache: Cache,
    /// Whether the client reports file changes; otherwise a save rescans its directory.
    watching: bool,
}

impl Server {
    #[allow(deprecated)]
    fn new(params: InitializeParams) -> Self {
        let watching = params
            .capabilities
            .workspace
            .and_then(|workspace| workspace.did_change_watched_files)
            .and_then(|watch| watch.dynamic_registration)
            .unwrap_or(false);
        let folders = params.workspace_folders.unwrap_or_default();
        let uris = folders.into_iter().map(|f| f.uri).chain(params.root_uri);
        let roots = uris.filter_map(|uri| uri.to_file_path().ok()).collect();
        Self {
            index: Index::new(roots),
            documents: BTreeMap::new(),
            cache: Cache::default(),
            watching,
        }
    }

    /// Apply `notifications`, then publish diagnostics once for the open documents they affect.
    /// A notification that panics is skipped.
    fn notify(&mut self, notifications: Vec<Notification>) -> Vec<Notification> {
        let mut published = Vec::new();
        let mut dirty = Vec::new();
        for notification in notifications {
            let applied = guarded(self, |s| s.apply(notification, &mut published));
            dirty.extend(applied.unwrap_or_default());
        }
        published.extend(guarded(self, |s| s.publish(dirty)).unwrap_or_default());
        published
    }

    /// Apply `notification` to the index; the files whose text changed. A closed document's
    /// cleared diagnostics go to `published`.
    fn apply(
        &mut self,
        notification: Notification,
        published: &mut Vec<Notification>,
    ) -> Vec<FileId> {
        fn parse<N: lsp_types::notification::Notification>(n: Notification) -> Option<N::Params> {
            serde_json::from_value(n.params).ok()
        }
        match notification.method.as_str() {
            DidOpenTextDocument::METHOD => {
                let Some(params) = parse::<DidOpenTextDocument>(notification) else {
                    return Vec::new();
                };
                let document = params.text_document;
                let path = path_of(&document.uri);
                let id =
                    (self.index).open(&path, document.uri.clone(), document.version, document.text);
                self.documents.insert(document.uri, id);
                vec![id]
            }
            DidChangeTextDocument::METHOD => {
                let Some(mut params) = parse::<DidChangeTextDocument>(notification) else {
                    return Vec::new();
                };
                let Some(change) = params.content_changes.pop() else {
                    return Vec::new();
                };
                let document = params.text_document;
                let path = path_of(&document.uri);
                vec![(self.index).open(&path, document.uri, document.version, change.text)]
            }
            DidCloseTextDocument::METHOD => {
                let Some(params) = parse::<DidCloseTextDocument>(notification) else {
                    return Vec::new();
                };
                let uri = params.text_document.uri;
                self.documents.remove(&uri);
                let closed = self.index.close(&path_of(&uri));
                published.push(publish(uri, Vec::new(), None));
                closed.into_iter().collect()
            }
            DidSaveTextDocument::METHOD if !self.watching => {
                let Some(params) = parse::<DidSaveTextDocument>(notification) else {
                    return Vec::new();
                };
                let path = path_of(&params.text_document.uri);
                path.parent()
                    .map(|directory| self.index.rescan(directory))
                    .unwrap_or_default()
            }
            DidChangeWatchedFiles::METHOD => {
                let Some(params) = parse::<DidChangeWatchedFiles>(notification) else {
                    return Vec::new();
                };
                let paths = params.changes.into_iter();
                let paths = paths.filter_map(|change| change.uri.to_file_path().ok());
                paths.filter_map(|path| self.index.refresh(&path)).collect()
            }
            _ => Vec::new(),
        }
    }

    /// Diagnostics for each open document reaching a `dirty` file through its imports. O(the
    /// affected subgraph), plus one analysis per affected document.
    fn publish(&self, dirty: Vec<FileId>) -> Vec<Notification> {
        let affected = self.index.affected(dirty);
        let uris = affected
            .into_iter()
            .filter_map(|id| self.index.file(id).open.clone());
        uris.map(|(uri, version)| {
            let diagnostics = self.diagnostics(&uri);
            publish(uri, diagnostics, Some(version))
        })
        .collect()
    }

    fn request(&self, request: Request) -> Response {
        fn at(params: TextDocumentPositionParams) -> (Url, Position) {
            (params.text_document.uri, params.position)
        }
        let params = request.params;
        if request.method == Rename::METHOD {
            let renamed = serde_json::from_value::<RenameParams>(params).map_err(|e| e.to_string());
            let renamed = renamed.map(|p| self.rename(at(p.text_document_position), &p.new_name));
            return match renamed {
                Ok(Ok(edit)) => Response::new_ok(request.id, edit),
                Ok(Err(error)) => {
                    Response::new_err(request.id, ErrorCode::RequestFailed as i32, error)
                }
                Err(error) => Response::new_err(request.id, ErrorCode::InvalidParams as i32, error),
            };
        }
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
            Completion::METHOD => serde_json::from_value::<CompletionParams>(params).map(|p| {
                match self.completion(at(p.text_document_position)) {
                    (items, false) => serde_json::json!(items),
                    (items, true) => serde_json::json!(CompletionList {
                        is_incomplete: true,
                        items
                    }),
                }
            }),
            CodeActionRequest::METHOD => serde_json::from_value::<CodeActionParams>(params)
                .map(|p| serde_json::json!(self.code_actions(p))),
            WorkspaceSymbolRequest::METHOD => {
                serde_json::from_value::<WorkspaceSymbolParams>(params)
                    .map(|p| serde_json::json!(self.workspace_symbols(&p.query)))
            }
            InlayHintRequest::METHOD => serde_json::from_value::<InlayHintParams>(params)
                .map(|p| serde_json::json!(self.inlay_hints(&p.text_document.uri, p.range))),
            PrepareRenameRequest::METHOD => serde_json::from_value(params)
                .map(|p| serde_json::json!(self.prepare_rename(at(p)))),
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
        Project::new(&self.index, *self.documents.get(uri)?)
    }

    fn analyze(&self, project: &Project) -> Rc<Analyzed> {
        self.cache.analyze(project)
    }

    fn diagnostics(&self, uri: &Url) -> Vec<Diagnostic> {
        let Some(project) = self.project(uri) else {
            return Vec::new();
        };
        let source = project.source();
        let imports = project.imports();
        let analyzed = self.analyze(&project);
        analyzed
            .diagnostics()
            .iter()
            .cloned()
            .map(|diagnostic| {
                let (range, message, related) = if diagnostic.file == project.entry {
                    let range = diagnostic.span.map(|span| range(source, span));
                    let range = range.unwrap_or_else(|| first_line(source));
                    (range, diagnostic.message, None)
                } else {
                    // A dependency's problem shows on the import that reaches it.
                    let via = project.via(&diagnostic.file);
                    let import = imports
                        .iter()
                        .find(|(file, _)| Some(file.as_str()) == via)
                        .or(imports.first());
                    let at = diagnostic.span.zip(project.files.get(&diagnostic.file));
                    let at = at.map(|(span, source)| range(source, span));
                    let related = project.uri(&diagnostic.file).map(|uri| {
                        vec![DiagnosticRelatedInformation {
                            location: Location::new(uri, at.unwrap_or_default()),
                            message: diagnostic.message.clone(),
                        }]
                    });
                    (
                        import.map_or_else(|| first_line(source), |(_, range)| *range),
                        format!("{}: {}", diagnostic.file, diagnostic.message),
                        related,
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
                    related_information: related,
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
            let at = (cursor.line, cursor.character);
            (statement.start.line, statement.start.character) <= at
                && at <= (statement.end.line, statement.end.character)
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
    /// after `Name.`, and names from files not imported yet, with the import that brings them;
    /// and whether some were left out.
    fn completion(&self, (uri, cursor): (Url, Position)) -> (Vec<CompletionItem>, bool) {
        let Some(project) = self.project(&uri) else {
            return (Vec::new(), false);
        };
        let source = project.source();
        let Some(at) = offset(source, cursor) else {
            return (Vec::new(), false);
        };
        let before = &source[source[..at].rfind('\n').map_or(0, |i| i + 1)..at];
        if before.trim_start().starts_with("import") && before.matches('"').count() == 1 {
            let typed = before.rfind('"').map_or(0, |i| i + 1);
            let start = Position::new(cursor.line, utf16_len(&before[..typed]));
            let paths = project
                .workspace(&self.index)
                .filter(|(file, _)| *file != project.entry)
                .map(|(file, _)| {
                    let path = import_path(project.directory(), &file);
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
            return (paths, false);
        }
        let typed = &before[word_start(before)..];
        let prefix = &before[..word_start(before)];
        let owner = prefix
            .trim_end()
            .strip_suffix('.')
            .map(|before| &before[word_start(before)..]);
        let Some((analysis, at)) = self.typing(&project, cursor) else {
            return (Vec::new(), false);
        };
        let symbols = analysis.symbols();
        let visible = symbols.visible_at(&project.entry, at);
        let Some(owner) = owner else {
            let mut items: Vec<_> = visible
                .iter()
                .filter(|(name, d)| !name.contains('.') && offered(d))
                .map(|(name, d)| completion_item(name, d))
                .collect();
            let names = visible.iter().map(|(name, _)| *name).collect();
            let (offers, incomplete) = self.offers(&project, typed, &names);
            items.extend(offers);
            return (items, incomplete);
        };
        let members: Vec<_> = visible
            .iter()
            .filter_map(|(name, d)| Some((name.strip_prefix(owner)?.strip_prefix('.')?, d)))
            .filter(|(_, d)| offered(d))
            .map(|(name, d)| completion_item(name, d))
            .collect();
        if !members.is_empty() {
            return (members, false);
        }
        let members = self.unimported_members(&project, owner);
        if !members.is_empty() {
            return (members, false);
        }
        // A binding of struct type offers the struct's fields.
        let Some(ty) = visible
            .iter()
            .find(|(name, _)| *name == owner)
            .and_then(|(_, d)| d.ty.as_ref())
            .map(ToString::to_string)
        else {
            return (Vec::new(), false);
        };
        let Some(structure) = visible
            .iter()
            .find(|(name, d)| *name == ty && d.kind == Kind::Struct)
        else {
            return (Vec::new(), false);
        };
        let fields = symbols
            .definitions()
            .iter()
            .filter(|d| d.kind == Kind::Field && d.file == structure.1.file)
            .filter(|d| d.owner.as_deref() == Some(structure.0))
            .map(|d| completion_item(&d.name, d))
            .collect();
        (fields, false)
    }

    /// The folded value of each constant declared in `within`, at the end of its line, unless
    /// the declaration already spells it.
    fn inlay_hints(&self, uri: &Url, within: Range) -> Vec<InlayHint> {
        let Some(project) = self.project(uri) else {
            return Vec::new();
        };
        let analysis = self.analyze(&project);
        let source = project.source();
        let constants = analysis.symbols().definitions().iter();
        let constants = constants.filter(|d| d.kind == Kind::Constant && d.file == project.entry);
        let hints = constants.filter_map(|constant| {
            let value = constant_value(&analysis, &project, constant)?;
            let rest = &source[constant.span.end..];
            let line = rest[..rest.find('\n').unwrap_or(rest.len())].trim_end_matches('\r');
            let end = constant.span.end + line.len();
            let initializer = line
                .trim()
                .trim_start_matches('=')
                .trim_end_matches(';')
                .trim();
            let position = range(source, Span { start: end, end }).start;
            let inside = within.start <= position && position <= within.end;
            (initializer != value && inside).then(|| InlayHint {
                position,
                label: InlayHintLabel::String(format!("= {value}")),
                kind: None,
                text_edits: None,
                tooltip: None,
                padding_left: Some(true),
                padding_right: None,
                data: None,
            })
        });
        hints.collect()
    }

    /// Up to `OFFERS` structs, contracts and libraries whose names start with `query`, ignoring
    /// case. O(log names + `OFFERS`), plus reading each one's position.
    fn workspace_symbols(&self, query: &str) -> Vec<WorkspaceSymbol> {
        let declared = self.index.exported(query, OFFERS).into_iter();
        let declared = declared.filter_map(|(name, id)| {
            let file = self.index.file(id);
            let declaration = file.declarations.iter().find(|d| d.name == name)?;
            let span = range(file.text.as_deref()?, declaration.span);
            Some(WorkspaceSymbol {
                name: name.to_string(),
                kind: symbol_kind(declaration.kind),
                tags: None,
                container_name: None,
                location: OneOf::Left(Location::new(project::uri(file)?, span)),
                data: None,
            })
        });
        declared.collect()
    }

    /// For each diagnostic naming an unknown name, an import of each file declaring it. O(log
    /// names) per diagnostic.
    fn code_actions(&self, params: CodeActionParams) -> Vec<CodeActionOrCommand> {
        let uri = params.text_document.uri;
        let Some(project) = self.project(&uri) else {
            return Vec::new();
        };
        let imported: HashSet<String> = project.imports().into_iter().map(|(f, _)| f).collect();
        let mut actions = Vec::new();
        for diagnostic in params.context.diagnostics {
            let at = offset(project.source(), diagnostic.range.start).unwrap_or_default();
            let name = quoted(&diagnostic.message)
                .filter(|_| diagnostic.message.starts_with("unknown"))
                .unwrap_or_else(|| {
                    let rest = &project.source()[at..];
                    &rest[..rest.len() - rest.trim_start_matches(identifier).len()]
                });
            for id in self.index.exporters(name) {
                let Some(file) = project.relative(&self.index.file(id).path) else {
                    continue;
                };
                if file == project.entry || imported.contains(&file) {
                    continue;
                }
                let import = importing(&project, &file).additional_text_edits;
                let changes = HashMap::from([(uri.clone(), import.unwrap_or_default())]);
                actions.push(CodeActionOrCommand::CodeAction(CodeAction {
                    title: format!("Import {name} from {file}"),
                    kind: Some(CodeActionKind::QUICKFIX),
                    diagnostics: Some(vec![diagnostic.clone()]),
                    edit: Some(WorkspaceEdit {
                        changes: Some(changes),
                        ..Default::default()
                    }),
                    ..Default::default()
                }));
            }
        }
        actions
    }

    /// The entry's analysis for completion at `cursor`, and the cursor's offset in its text. A
    /// half-typed line rarely parses, so the entry is then analyzed with that line blank.
    fn typing(&self, project: &Project, cursor: Position) -> Option<(Rc<Analyzed>, usize)> {
        let parsed = |analysis: &Analyzed| {
            let definitions = analysis.symbols().definitions().iter();
            definitions.into_iter().any(|d| d.file == project.entry)
        };
        let analysis = self.analyze(project);
        if parsed(&analysis) {
            return Some((analysis, offset(project.source(), cursor)?));
        }
        let mut lines: Vec<&str> = project.source().split('\n').collect();
        *lines.get_mut(cursor.line as usize)? = "";
        let text = lines.join("\n");
        let at = offset(&text, Position::new(cursor.line, 0))?;
        let mut hasher = DefaultHasher::new();
        (project.key.1, cursor.line).hash(&mut hasher);
        let analysis = self.cache.get((project.key.0, hasher.finish()), || {
            let mut files = project.sources();
            files.insert(project.entry.clone(), text);
            arkade_compiler::analyze(&project.entry, &files)
        });
        parsed(&analysis).then_some((analysis, at))
    }

    /// Names declared by files the entry does not import, starting with `typed`, each with the
    /// import that brings it, and whether more were left out. O(log names + `OFFERS`).
    fn offers(
        &self,
        project: &Project,
        typed: &str,
        visible: &HashSet<&str>,
    ) -> (Vec<CompletionItem>, bool) {
        let exported = self.index.exported(typed, OFFERS);
        let incomplete = exported.len() == OFFERS;
        let imported: HashSet<String> = project.imports().into_iter().map(|(f, _)| f).collect();
        let offers = exported
            .into_iter()
            .filter(|(name, _)| !visible.contains(name));
        let offers = offers.filter_map(|(name, id)| {
            let file = self.index.file(id);
            let relative = project.relative(&file.path)?;
            if relative == project.entry || imported.contains(&relative) {
                return None;
            }
            let declaration = file.declarations.iter().find(|d| d.name == name)?;
            Some(CompletionItem {
                label: name.to_string(),
                kind: Some(item_kind(declaration.kind)),
                ..importing(project, &relative)
            })
        });
        (offers.collect(), incomplete)
    }

    /// Members of `owner`, declared by files the entry does not import, as their importers see
    /// them, from each file's own cached analysis. O(those files' closures).
    fn unimported_members(&self, project: &Project, owner: &str) -> Vec<CompletionItem> {
        let imported: HashSet<String> = project.imports().into_iter().map(|(f, _)| f).collect();
        let mut items = Vec::new();
        for id in self.index.exporters(owner) {
            let Some(relative) = project.relative(&self.index.file(id).path) else {
                continue;
            };
            let library = Project::new(&self.index, id);
            let Some(library) = library.filter(|_| !imported.contains(&relative)) else {
                continue;
            };
            let analysis = self.analyze(&library);
            let exports = analysis.symbols().exports(&library.entry);
            let members = exports
                .into_iter()
                .filter_map(|(name, d)| Some((name.strip_prefix(owner)?.strip_prefix('.')?, d)))
                .filter(|(_, d)| offered(d));
            let import = importing(project, &relative);
            items.extend(members.map(|(name, d)| CompletionItem {
                additional_text_edits: import.additional_text_edits.clone(),
                detail: import.detail.clone(),
                ..completion_item(name, d)
            }));
        }
        items
    }
}

/// The first name quoted in `message` with `'` or a backtick.
fn quoted(message: &str) -> Option<&str> {
    let start = message.find(['\'', '`'])? + 1;
    let length = message[start..].find(['\'', '`'])?;
    Some(&message[start..start + length])
}

fn identifier(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// How many names from files not imported completion offers at once.
const OFFERS: usize = 100;

/// Whether completion offers names of this kind; a tapscript or field is not written bare.
fn offered(definition: &&Definition) -> bool {
    !matches!(definition.kind, Kind::Tapscript | Kind::Field)
}

/// A completion item's import of `file` into the entry, and its detail naming the file.
fn importing(project: &Project, file: &str) -> CompletionItem {
    let path = import_path(project.directory(), file);
    let line = Position::new(import_line(project.source()) as u32, 0);
    let edit = TextEdit::new(Range::new(line, line), format!("import \"{path}\";\n"));
    CompletionItem {
        detail: Some(format!("import from {file}")),
        additional_text_edits: Some(vec![edit]),
        ..Default::default()
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

fn completion_item(label: &str, definition: &Definition) -> CompletionItem {
    let function = definition.kind == Kind::Function;
    CompletionItem {
        label: label.to_string(),
        kind: Some(item_kind(definition.kind)),
        detail: definition.ty.as_ref().map(ToString::to_string),
        insert_text: function.then(|| format!("{label}($0)")),
        insert_text_format: function.then_some(InsertTextFormat::SNIPPET),
        ..Default::default()
    }
}

fn item_kind(kind: Kind) -> CompletionItemKind {
    match kind {
        Kind::Function | Kind::Tapscript => CompletionItemKind::FUNCTION,
        Kind::Constant => CompletionItemKind::CONSTANT,
        Kind::Struct => CompletionItemKind::STRUCT,
        Kind::Library => CompletionItemKind::MODULE,
        Kind::Contract => CompletionItemKind::CLASS,
        Kind::Field => CompletionItemKind::FIELD,
        Kind::Parameter | Kind::Variable => CompletionItemKind::VARIABLE,
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

/// The request registering a watcher of every `.ark` file.
fn watch_request() -> Request {
    let options = DidChangeWatchedFilesRegistrationOptions {
        watchers: vec![FileSystemWatcher {
            glob_pattern: GlobPattern::String("**/*.ark".to_string()),
            kind: None,
        }],
    };
    let registration = Registration {
        id: "arkade-watch".to_string(),
        method: DidChangeWatchedFiles::METHOD.to_string(),
        register_options: serde_json::to_value(options).ok(),
    };
    Request::new(
        "arkade-watch".to_string().into(),
        RegisterCapability::METHOD.to_string(),
        RegistrationParams {
            registrations: vec![registration],
        },
    )
}

/// The file behind `uri`; an unsaved document gets a path no workspace file has.
fn path_of(uri: &Url) -> PathBuf {
    uri.to_file_path().unwrap_or_else(|()| {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hash::hash(uri.as_str(), &mut hasher);
        let name = format!("untitled-{:x}.ark", std::hash::Hasher::finish(&hasher));
        Path::new("/arkade-untitled").join(name)
    })
}

fn publish(uri: Url, diagnostics: Vec<Diagnostic>, version: Option<i32>) -> Notification {
    Notification::new(
        PublishDiagnostics::METHOD.to_string(),
        PublishDiagnosticsParams::new(uri, diagnostics, version),
    )
}

/// The byte offset where the identifier ending `text` starts, always on a char boundary.
fn word_start(text: &str) -> usize {
    text.trim_end_matches(|c: char| c.is_ascii_alphanumeric() || c == '_')
        .len()
}
