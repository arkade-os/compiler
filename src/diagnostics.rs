//! Structured diagnostics: the data behind compiler errors and warnings,
//! kept as a list instead of being flattened into one string at the first
//! caller. `check()` returns these directly; the string-returning API
//! renders them the same way it always has.

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

/// `diagnostic` as JSON for tools: `severity`, `code`, `message`, `file`, and, when it is
/// located and `source` is its file's text, `start` and `end` as `{ line, column }`.
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

/// One diagnostic, tied to the file (and, where known, the byte span) that
/// produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: Severity,
    /// Which pass raised this: `"validation"` (semantic checks), `"type"` (type checker),
    /// `"emission"` (code generation) or `"internal"` (a compiler bug). `None` for parse, import
    /// and file errors.
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

/// A code generation failure: a problem in the source, or a broken compiler invariant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompileError {
    pub message: String,
    pub span: Option<Span>,
    pub internal: bool,
}

impl CompileError {
    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            span: None,
            internal: true,
        }
    }

    /// Locates the error at `span` unless a narrower span already does.
    pub(crate) fn at(mut self, span: Span) -> Self {
        self.span.get_or_insert(span);
        self
    }

    pub(crate) fn diagnostic(&self, file: &str) -> Diagnostic {
        Diagnostic::error(file, self.to_string())
            .with_code(if self.internal {
                "internal"
            } else {
                "emission"
            })
            .with_span(self.span)
    }
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.internal {
            f.write_str("internal compiler error: ")?;
        }
        f.write_str(&self.message)
    }
}

impl From<String> for CompileError {
    fn from(message: String) -> Self {
        Self {
            message,
            span: None,
            internal: false,
        }
    }
}

impl From<&str> for CompileError {
    fn from(message: &str) -> Self {
        message.to_string().into()
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
        let error = CompileError::from("bad index")
            .at(narrow)
            .at(Span { start: 0, end: 20 });
        assert_eq!(error.span, Some(narrow));
        assert_eq!(
            error.diagnostic("main.ark").code.as_deref(),
            Some("emission")
        );
        let internal = CompileError::internal("unbalanced scope");
        assert_eq!(
            internal.to_string(),
            "internal compiler error: unbalanced scope"
        );
        assert_eq!(
            internal.diagnostic("main.ark").code.as_deref(),
            Some("internal")
        );
    }
}
