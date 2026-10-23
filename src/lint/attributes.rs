//! Lint attributes: `@allow`, `@warn`, `@deny` and `@expect` set the level of the lints they name
//! on the node they precede and everything inside it, as rustc's lint attributes do.

use super::{Finding, Level, Lint};
use crate::diagnostics::Span;
use crate::models::{Attribute, AttributeArg, Contract};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Allow,
    Warn,
    Deny,
    /// Allows the lint, and reports when it does not fire.
    Expect,
}

impl Kind {
    fn named(name: &str) -> Option<Kind> {
        Some(match name {
            "allow" => Kind::Allow,
            "warn" => Kind::Warn,
            "deny" => Kind::Deny,
            "expect" => Kind::Expect,
            _ => return None,
        })
    }
}

/// Why `attribute` is malformed: an unknown attribute, no lint, or text other than one closing
/// reason, which `@allow` and `@expect` require.
pub(crate) fn error(attribute: &Attribute) -> Option<(String, Span)> {
    let name = &attribute.name;
    let Some(kind) = Kind::named(name) else {
        let message =
            format!("unknown attribute '@{name}'; expected @allow, @warn, @deny or @expect");
        return Some((message, attribute.name_span));
    };
    let (texts, lints): (Vec<_>, Vec<_>) = attribute
        .args
        .iter()
        .partition(|arg| matches!(arg, AttributeArg::Text(..)));
    let reason = match attribute.args.last() {
        Some(AttributeArg::Text(text, _)) => Some(text),
        _ => None,
    };
    if lints.is_empty() {
        return Some((format!("@{name} needs a lint to name"), attribute.span));
    }
    if texts.len() > usize::from(reason.is_some()) {
        let message = format!("@{name} takes lint names, then one reason");
        return Some((message, attribute.span));
    }
    let silences = matches!(kind, Kind::Allow | Kind::Expect);
    if silences && reason.is_none_or(|reason| reason.trim().is_empty()) {
        let message = format!("@{name} needs a reason: @{name}(lint, \"why\")");
        return Some((message, attribute.span));
    }
    None
}

/// One lint an attribute names, in force over `scope`.
struct Entry {
    scope: Span,
    lint: Lint,
    kind: Kind,
    name_span: Span,
    fulfilled: bool,
}

/// `findings` each with the level `contract`'s attributes give it, or `None` where none does,
/// plus an `unknown-lint` finding for each unknown name and an `unfulfilled-expectation` finding
/// for each `@expect` whose lint did not fire.
pub(super) fn levels(contract: &Contract, findings: Vec<Finding>) -> Vec<(Finding, Option<Level>)> {
    let mut entries = Vec::new();
    let mut unknown = Vec::new();
    for (scope, attributes) in contract.attributed() {
        for attribute in attributes {
            let kind = Kind::named(&attribute.name).expect("validated attribute");
            for arg in &attribute.args {
                let AttributeArg::Name(name, name_span) = arg else {
                    continue;
                };
                match name.parse() {
                    Ok(lint) => entries.push(Entry {
                        scope,
                        lint,
                        kind,
                        name_span: *name_span,
                        fulfilled: false,
                    }),
                    Err(_) => unknown.push(Finding::new(
                        Lint::UnknownLint,
                        *name_span,
                        format!("unknown lint '{name}'"),
                    )),
                }
            }
        }
    }
    let mut leveled = Vec::new();
    for finding in findings.into_iter().chain(unknown) {
        let level = level(&mut entries, &finding);
        leveled.push((finding, level));
    }
    let unfulfilled: Vec<_> = entries
        .iter()
        .filter(|entry| entry.kind == Kind::Expect && !entry.fulfilled)
        .map(|entry| {
            let message = format!("'{}' is expected here but does not fire", entry.lint.id());
            Finding::new(Lint::UnfulfilledExpectation, entry.name_span, message)
        })
        .collect();
    for finding in unfulfilled {
        let level = level(&mut entries, &finding);
        leveled.push((finding, level));
    }
    leveled
}

/// The level of the innermost entry for `finding`'s lint around it; in one scope, the later
/// attribute wins.
fn level(entries: &mut [Entry], finding: &Finding) -> Option<Level> {
    let size = |entry: &Entry| entry.scope.end - entry.scope.start;
    let innermost = entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| {
            entry.lint == finding.lint
                && entry.scope.start <= finding.span.start
                && finding.span.end <= entry.scope.end
        })
        .min_by_key(|(index, entry)| (size(entry), std::cmp::Reverse(*index)))
        .map(|(index, _)| index)?;
    let entry = &mut entries[innermost];
    Some(match entry.kind {
        Kind::Allow => Level::Allow,
        Kind::Warn => Level::Warn,
        Kind::Deny => Level::Deny,
        Kind::Expect => {
            entry.fulfilled = true;
            Level::Allow
        }
    })
}
