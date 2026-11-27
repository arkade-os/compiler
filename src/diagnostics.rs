//! Compiler errors and warnings as structured diagnostics: spans, line and column conversion,
//! the JSON form tools read, and the joined string the `compile*` functions return.

use std::{error, fmt};

use crate::compiler::constants::ConstantError;
use crate::compiler::error::{CompileErrorKind, InternalError};
use crate::errors::ErrorCode;
use crate::imports::LoadError;
use crate::lint::Lint;
use crate::parser::ParseError;

/// A byte-offset range into one file's source text.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

/// The 1-based line and column of byte `offset` in `source`, counting columns in UTF-16 code
/// units as editors do; `None` past the end or inside a character.
pub fn position(source: &str, offset: usize) -> Option<(usize, usize)> {
    let before = source.get(..offset)?;
    let line_start = before.rfind('\n').map_or(0, |newline| newline + 1);
    Some((
        before.matches('\n').count() + 1,
        before[line_start..].encode_utf16().count() + 1,
    ))
}

/// The byte offset of 1-based `line` and UTF-16 `column` in `source`; `None` past its end.
pub fn offset(source: &str, line: usize, column: usize) -> Option<usize> {
    let start = match line {
        0 => return None,
        1 => 0,
        _ => source.match_indices('\n').nth(line - 2)?.0 + 1,
    };
    let text = &source[start..];
    let text = &text[..text.find('\n').unwrap_or(text.len())];
    let mut units = 1;
    for (index, character) in text.char_indices() {
        if units >= column {
            return Some(start + index);
        }
        units += character.len_utf16();
    }
    (units >= column).then_some(start + text.len())
}

/// `diagnostic` as JSON for tools: `severity`, `code`, `message`, `file`, `start` and `end` as
/// `{ line, column }` when it is located and `source` is its file's text, and `suggestions`, each
/// with `message`, `start`, `end` and `replacement`.
pub fn to_json(diagnostic: &Diagnostic, source: Option<&str>) -> serde_json::Value {
    let [start, end] = range_json(source, diagnostic.span);
    serde_json::json!({
        "severity": match diagnostic.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        },
        "code": diagnostic.code,
        "message": diagnostic.message,
        "file": diagnostic.file,
        "start": start,
        "end": end,
        "suggestions": diagnostic.suggestions.iter().map(|suggestion| {
            let [start, end] = range_json(source, Some(suggestion.span));
            serde_json::json!({
                "message": suggestion.message,
                "start": start,
                "end": end,
                "replacement": suggestion.replacement,
            })
        }).collect::<Vec<_>>(),
    })
}

/// `span`'s start and end in `source` as `{ line, column }`, both `null` unless both resolve.
pub(crate) fn range_json(source: Option<&str>, span: Option<Span>) -> [serde_json::Value; 2] {
    let at = |offset| {
        let (line, column) = position(source?, offset)?;
        Some(serde_json::json!({ "line": line, "column": column }))
    };
    span.and_then(|span| Some([at(span.start)?, at(span.end)?]))
        .unwrap_or_default()
}

impl From<pest::Span<'_>> for Span {
    fn from(span: pest::Span<'_>) -> Self {
        Self {
            start: span.start(),
            end: span.end(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

/// One error or warning, tied to its file and, where known, its byte span there.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Diagnostic {
    pub severity: Severity,
    /// A lint's id, an error code's id such as `"unknown-name"` (see [`crate::errors::ErrorCode`]),
    /// or else the pass that raised this: `"validation"` (semantic checks), `"type"` (type
    /// checker), `"emission"` (code generation) or `"internal"` (a compiler bug). `None` for file,
    /// pragma, parse and import errors, and for a library compiled as the entry.
    pub code: Option<String>,
    pub message: String,
    pub file: String,
    pub span: Option<Span>,
    /// The lint this reports, whose level decides its severity.
    pub lint: Option<Lint>,
    /// Edits that may fix it, for editors to offer and agents to apply.
    pub suggestions: Vec<Suggestion>,
}

/// Replacing `span` with `replacement`, described by `message`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Suggestion {
    pub message: String,
    pub span: Span,
    pub replacement: String,
}

impl Diagnostic {
    pub(crate) fn error(file: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            code: None,
            message: message.into(),
            file: file.into(),
            span: None,
            lint: None,
            suggestions: Vec::new(),
        }
    }

    pub(crate) fn warning(file: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            code: None,
            message: message.into(),
            file: file.into(),
            span: None,
            lint: None,
            suggestions: Vec::new(),
        }
    }

    pub(crate) fn with_span(mut self, span: impl Into<Option<Span>>) -> Self {
        self.span = span.into();
        self
    }

    pub(crate) fn with_code(mut self, code: &str) -> Self {
        self.code = Some(code.to_string());
        self
    }

    pub(crate) fn with_suggestions(mut self, suggestions: Vec<Suggestion>) -> Self {
        self.suggestions = suggestions;
        self
    }

    pub(crate) fn with_lint(mut self, lint: Lint) -> Self {
        self.code = Some(lint.id().to_string());
        self.lint = Some(lint);
        self
    }
}

/// A code generation failure: a problem in the source, or a broken compiler invariant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompileError {
    pub kind: CompileErrorKind,
    pub span: Option<Span>,
}

impl CompileError {
    /// Locates the error at `span` unless a narrower span already does.
    pub(crate) fn at(mut self, span: Span) -> Self {
        self.span.get_or_insert(span);
        self
    }

    pub(crate) fn is_internal(&self) -> bool {
        matches!(self.kind, CompileErrorKind::Internal(_))
    }

    pub(crate) fn diagnostic(&self, file: &str) -> Diagnostic {
        Diagnostic::error(file, self.to_string())
            .with_code(if self.is_internal() {
                "internal"
            } else {
                "emission"
            })
            .with_span(self.span)
    }
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(f)
    }
}

impl error::Error for CompileError {}

impl From<CompileErrorKind> for CompileError {
    fn from(kind: CompileErrorKind) -> Self {
        Self { kind, span: None }
    }
}

impl From<InternalError> for CompileError {
    fn from(error: InternalError) -> Self {
        CompileErrorKind::Internal(error).into()
    }
}

impl From<ParseError> for CompileError {
    fn from(error: ParseError) -> Self {
        CompileErrorKind::Parse(error).into()
    }
}

impl From<LoadError> for CompileError {
    fn from(error: LoadError) -> Self {
        CompileErrorKind::Load(Box::new(error)).into()
    }
}

impl From<ConstantError> for CompileError {
    fn from(error: ConstantError) -> Self {
        CompileErrorKind::Constant(error).into()
    }
}

/// The `"; "`-joined error string the `compile*` functions return: each error's message,
/// prefixed by its kind (`validation error: `, `type error: `, `error[<lint>]: `) and, when
/// located, its line and column. Every diagnostic must belong to the file `source` is.
pub(crate) fn render_errors(diagnostics: &[Diagnostic], source: &str) -> String {
    diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .map(|d| {
            let message = located(&d.message, d.span, source);
            match d.code.as_deref() {
                Some(code) if code == "validation" || code.parse::<ErrorCode>().is_ok() => {
                    format!("validation error: {message}")
                }
                Some("type") => format!("type error: {message}"),
                Some(code) if d.lint.is_some() => format!("error[{code}]: {message}"),
                _ => message,
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Prefixes `message` with the 1-based line and column of `span`'s start in `source`.
pub(crate) fn located(message: &str, span: Option<Span>, source: &str) -> String {
    match span.and_then(|s| pest::Position::new(source, s.start)) {
        Some(pos) => {
            let (line, column) = pos.line_col();
            format!("line {line}, column {column}: {message}")
        }
        None => message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_and_positions_round_trip_in_utf16_columns() {
        let source = "ab\né😀x\n\nend";
        for (at, _) in source.char_indices().chain([(source.len(), ' ')]) {
            let (line, column) = position(source, at).unwrap();
            assert_eq!(offset(source, line, column), Some(at), "{line}:{column}");
        }
        assert_eq!(position(source, source.find('x').unwrap()), Some((2, 4)));
        assert_eq!(offset(source, 2, 9), None);
        assert_eq!(offset(source, 9, 1), None);
    }

    #[test]
    fn a_diagnostic_has_both_ends_or_neither() {
        let diagnostic =
            Diagnostic::error("main.ark", "bad").with_span(Some(Span { start: 1, end: 9 }));
        let json = to_json(&diagnostic, Some("abc"));
        assert!(json["start"].is_null() && json["end"].is_null());
        let json = to_json(&diagnostic, Some("abc\ndefgh"));
        assert_eq!(json["end"], serde_json::json!({ "line": 2, "column": 6 }));
    }

    #[test]
    fn compile_errors_keep_the_narrowest_span_and_mark_internal_ones() {
        let narrow = Span { start: 4, end: 9 };
        let error = CompileError::from(CompileErrorKind::InvalidCallMarker)
            .at(narrow)
            .at(Span { start: 0, end: 20 });
        assert_eq!(error.span, Some(narrow));
        assert_eq!(
            error.diagnostic("main.ark").code.as_deref(),
            Some("emission")
        );
        let internal = CompileError::from(InternalError::UnbalancedScope);
        assert_eq!(
            internal.to_string(),
            "internal compiler error: unbalanced generator scope"
        );
        assert_eq!(
            internal.diagnostic("main.ark").code.as_deref(),
            Some("internal")
        );
    }
}
