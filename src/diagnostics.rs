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
/// (`"validation error: "`, `"type error: "`) the way it was before
/// diagnostics existed — some tests match on that substring.
pub(crate) fn render_errors(diagnostics: &[Diagnostic]) -> String {
    diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .map(|d| match d.code.as_deref() {
            Some("validation") => format!("validation error: {}", d.message),
            Some("type") => format!("type error: {}", d.message),
            _ => d.message.clone(),
        })
        .collect::<Vec<_>>()
        .join("; ")
}
