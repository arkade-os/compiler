//! Structured diagnostics: the data behind compiler errors and warnings,
//! kept as a list instead of being flattened into one string at the first
//! caller. `check()` returns these directly; the string-returning API
//! renders them the same way it always has.

/// A byte-offset range into one file's source text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
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

/// One diagnostic, tied to the file (and, where known, the byte span) that
/// produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: Severity,
    /// Which pass raised this: `"validation"` (semantic checks) or `"type"`
    /// (type checker) today. `None` for parse errors.
    pub code: Option<String>,
    pub message: String,
    pub file: String,
    pub span: Option<Span>,
}

impl Diagnostic {
    pub(crate) fn error(file: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            code: None,
            message: message.into(),
            file: file.into(),
            span: None,
        }
    }

    pub(crate) fn warning(file: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            code: None,
            message: message.into(),
            file: file.into(),
            span: None,
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
}

/// The string `compile`/`compile_file`/`compile_sources` return on failure:
/// error-severity messages, `"; "`-joined, each still prefixed by its kind
/// (`"validation error: "`, `"type error: "`) and, where a span is known, by
/// its 1-based line and column in `source` — the way it was before
/// diagnostics existed. `source` must be the text of the file every
/// diagnostic in `diagnostics` belongs to (`render_errors` is only ever
/// called on one file's diagnostics).
pub(crate) fn render_errors(diagnostics: &[Diagnostic], source: &str) -> String {
    diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .map(|d| {
            let message = located(&d.message, d.span, source);
            match d.code.as_deref() {
                Some("validation") => format!("validation error: {message}"),
                Some("type") => format!("type error: {message}"),
                _ => message,
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Prefix `message` with its 1-based line and column, derived from `span`'s
/// byte offset into `source` — display-only, for the legacy string API;
/// `Diagnostic::span` itself carries the byte range for structured consumers.
pub(crate) fn located(message: &str, span: Option<Span>, source: &str) -> String {
    match span.and_then(|s| pest::Position::new(source, s.start)) {
        Some(pos) => {
            let (line, column) = pos.line_col();
            format!("line {line}, column {column}: {message}")
        }
        None => message.to_string(),
    }
}
