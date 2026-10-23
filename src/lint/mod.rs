//! Lints: named checks for code that compiles but is likely wrong or unsafe. They run as their
//! own pass over a validated contract. Each finding's level comes from the innermost `@allow`,
//! `@warn`, `@deny` or `@expect` around it, or else from the caller's [`Levels`].

use std::collections::BTreeMap;

use crate::diagnostics::{Diagnostic, Span};
use crate::models::{Contract, TapItem};

pub(crate) mod attributes;
mod covenants;
mod expressions;
mod inspections;
mod unused;
mod walk;

/// One lint's finding, at the node that reports it.
#[derive(Debug, Clone)]
pub(crate) struct Finding {
    lint: Lint,
    span: Span,
    message: String,
}

impl Finding {
    fn new(lint: Lint, span: Span, message: impl Into<String>) -> Self {
        Self {
            lint,
            span,
            message: message.into(),
        }
    }
}

/// A file's findings, each with the level its attributes give it, if any.
#[derive(Debug, Clone, Default)]
pub(crate) struct Lints(Vec<(Finding, Option<Level>)>);

impl Lints {
    /// The findings of `file` that `levels` does not allow; an imported file's are at most
    /// warnings, since only the file being compiled decides what fails it.
    pub(crate) fn diagnostics(
        &self,
        file: &str,
        levels: &Levels,
        imported: bool,
    ) -> Vec<Diagnostic> {
        self.0
            .iter()
            .filter_map(|(finding, attribute)| {
                let mut level = attribute.unwrap_or_else(|| levels.level(finding.lint));
                if imported {
                    level = level.min(Level::Warn);
                }
                let diagnostic = match level {
                    Level::Allow => return None,
                    Level::Warn => Diagnostic::warning(file, finding.message.clone()),
                    Level::Deny => Diagnostic::error(file, finding.message.clone()),
                };
                Some(diagnostic.with_lint(finding.lint).with_span(finding.span))
            })
            .collect()
    }
}

/// Every lint's findings in a contract that passed validation.
pub(crate) fn check(contract: &Contract) -> Lints {
    let mut findings = Vec::new();
    timelock_units(contract, &mut findings);
    unused::check(contract, &mut findings);
    inspections::check(contract, &mut findings);
    covenants::check(contract, &mut findings);
    expressions::check(contract, &mut findings);
    Lints(attributes::levels(contract, findings))
}

/// A literal or constant timelock without blocks(n) or seconds(n) is pushed raw.
fn timelock_units(contract: &Contract, findings: &mut Vec<Finding>) {
    for tapscript in &contract.tapscripts {
        for item in &tapscript.items {
            let (call, value, raw) = match item {
                TapItem::Older { value, unit: None } => ("older", value, "BIP68 sequence"),
                TapItem::After { value, unit: None } => ("after", value, "nLockTime"),
                _ => continue,
            };
            if value.parse::<i64>().is_ok() {
                let message = format!(
                    "tapscript '{}': {call}({value}) is a raw {raw}; write blocks(n) or seconds(n) to state its unit",
                    tapscript.name
                );
                findings.push(Finding::new(
                    Lint::TimelockWithoutUnit,
                    tapscript.span,
                    message,
                ));
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Allow,
    Warn,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Security,
    Correctness,
    Performance,
    Style,
}

/// Declares every lint: its variant, id, category, default level and summary. Its explanation
/// is `docs/<id>.md`.
macro_rules! lints {
    ($($variant:ident: $id:literal, $category:ident, $level:ident, $summary:literal;)*) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum Lint {
            $($variant),*
        }

        impl Lint {
            pub const ALL: &'static [Lint] = &[$(Lint::$variant),*];

            /// Id, category, default level and summary.
            fn describe(self) -> (&'static str, Category, Level, &'static str) {
                match self {
                    $(Lint::$variant => ($id, Category::$category, Level::$level, $summary)),*
                }
            }

            /// What the lint reports, why it matters and how to fix it, in Markdown.
            pub fn explanation(self) -> &'static str {
                match self {
                    $(Lint::$variant => include_str!(concat!("docs/", $id, ".md"))),*
                }
            }
        }
    };
}

lints! {
    AnyoneCanSpend: "anyone-can-spend", Security, Warn, "a covenant function with no signature check and no output constraint";
    OutputScriptUnchecked: "output-script-unchecked", Security, Warn, "an output whose value is checked but not its scriptPubKey";
    OutputValueUnchecked: "output-value-unchecked", Security, Warn, "an output whose scriptPubKey is checked but not its value or assets";
    OutputsSharedAcrossInputs: "outputs-shared-across-inputs", Security, Warn, "an unsigned function that constrains outputs by index without bounding the inputs, so one output can satisfy two";
    OracleMessageUnbound: "oracle-message-unbound", Security, Warn, "a checkSigFromStack message taken from the witness as given";
    SignerFromWitness: "signer-from-witness", Security, Warn, "a signature key or multisig threshold taken from the witness as given";
    DuplicateMultisigKey: "duplicate-multisig-key", Security, Warn, "a key listed twice in checkMultisig, so one signer counts twice";
    AmbiguousHashConcat: "ambiguous-hash-concat", Security, Warn, "a hash of two concatenated variable-length parameters, which other values can match";
    RevealWithoutTimeout: "reveal-without-timeout", Security, Warn, "a hash preimage reveal with no timeout path, so the coins wait for it forever";
    OffchainLocktime: "offchain-locktime", Correctness, Warn, "tx.locktime in a covenant, which arkd sets to 0 offchain";
    DivideBeforeMultiply: "divide-before-multiply", Correctness, Warn, "(a / b) * c, which truncates before it scales";
    SelfComparison: "self-comparison", Correctness, Warn, "a comparison or logical operator with the same operand on both sides";
    UnusedParameter: "unused-parameter", Correctness, Warn, "a constructor parameter no function reads";
    UnusedVariable: "unused-variable", Correctness, Deny, "a local variable nothing reads";
    TimelockWithoutUnit: "timelock-without-unit", Style, Warn, "older(n) or after(n) with a raw number instead of blocks(n) or seconds(n)";
    RepeatedInspection: "repeated-inspection", Performance, Warn, "a multi-result inspection read more than once instead of bound once";
    UnknownLint: "unknown-lint", Correctness, Warn, "a lint attribute naming a lint that does not exist";
    UnfulfilledExpectation: "unfulfilled-expectation", Correctness, Warn, "an @expect whose lint does not fire where it applies";
}

impl Lint {
    /// The id the diagnostic `code`, the CLI and lint attributes use.
    pub fn id(self) -> &'static str {
        self.describe().0
    }

    pub fn category(self) -> Category {
        self.describe().1
    }

    pub fn level(self) -> Level {
        self.describe().2
    }

    pub fn summary(self) -> &'static str {
        self.describe().3
    }
}

impl std::str::FromStr for Lint {
    type Err = String;

    fn from_str(id: &str) -> Result<Self, String> {
        Lint::ALL
            .iter()
            .copied()
            .find(|lint| lint.id() == id)
            .ok_or_else(|| format!("unknown lint '{id}'"))
    }
}

/// A level for each lint, defaulting to its own.
#[derive(Debug, Clone, Default)]
pub struct Levels(BTreeMap<Lint, Level>);

impl Levels {
    pub fn set(&mut self, lint: Lint, level: Level) {
        self.0.insert(lint, level);
    }

    /// Sets the lints `id` names: one lint, a category (`security`, `correctness`,
    /// `performance`, `style`), `all`, or `warnings` for those at warning level.
    pub fn set_named(&mut self, id: &str, level: Level) -> Result<(), String> {
        let category = match id {
            "security" => Some(Category::Security),
            "correctness" => Some(Category::Correctness),
            "performance" => Some(Category::Performance),
            "style" => Some(Category::Style),
            _ => None,
        };
        let lints: Vec<Lint> = match id {
            "all" => Lint::ALL.to_vec(),
            "warnings" => Lint::ALL
                .iter()
                .copied()
                .filter(|&lint| self.level(lint) == Level::Warn)
                .collect(),
            _ if category.is_some() => Lint::ALL
                .iter()
                .copied()
                .filter(|lint| Some(lint.category()) == category)
                .collect(),
            _ => vec![id.parse()?],
        };
        for lint in lints {
            self.set(lint, level);
        }
        Ok(())
    }

    pub fn level(&self, lint: Lint) -> Level {
        self.0.get(&lint).copied().unwrap_or(lint.level())
    }
}
