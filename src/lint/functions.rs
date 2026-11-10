//! Function lints: what a spending function authorizes and constrains, gathered through the
//! helpers it calls.

use std::collections::{BTreeMap, HashMap, HashSet};

use super::walk::{Visitor, Walk};
use super::{Finding, Lint};
use crate::compiler::tapscript::shared_tweak_func;
use crate::diagnostics::Span;
use crate::models::{
    AssetLookupSource, Contract, ExprKind, Expression, Function, KeyExpr, LocatedStatement,
    Requirement, Statement, TapItem, EMULATOR,
};
use crate::properties::{OutputProperty, ThisProperty, TxProperty};

/// An output the function constrains at a fixed place; outputs at a computed index are not
/// tracked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum OutputIndex {
    Literal(usize),
    ActiveInput,
}

impl OutputIndex {
    fn of(index: &Expression) -> Option<Self> {
        match index.literal_index() {
            Some(literal) => Some(OutputIndex::Literal(literal)),
            None => is_active_input(index).then_some(OutputIndex::ActiveInput),
        }
    }
}

impl std::fmt::Display for OutputIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputIndex::Literal(index) => write!(f, "{index}"),
            OutputIndex::ActiveInput => f.write_str("this.activeInputIndex"),
        }
    }
}

/// What one output has checked.
#[derive(Default)]
struct OutputChecks {
    script: Option<Span>,
    value: Option<Span>,
    assets: bool,
}

/// What holds on every path through the statements walked so far.
///
/// ponytail: a `for` body counts as run, which a zero-count `for` is not, and a helper body
/// as run to its end, which an early `return` cuts short. Track both if a lint needs them.
#[derive(Default, Clone, Copy)]
struct Path {
    /// A transaction signature: `checkSig` or `checkMultisig`.
    signed: bool,
    never_passes: bool,
}

impl Path {
    /// What holds on every path through an `if`: what both arms hold, or what the other arm
    /// holds when one never passes. An absent `else` is an arm that holds nothing.
    fn either(then: Path, other: Path) -> Path {
        match (then, other) {
            (dead, live) | (live, dead) if dead.never_passes => live,
            _ => Path {
                signed: then.signed && other.signed,
                ..Path::default()
            },
        }
    }

    fn followed_by(self, next: Path) -> Path {
        Path {
            signed: self.signed || next.signed,
            never_passes: self.never_passes || next.never_passes,
        }
    }
}

#[derive(Default)]
struct Facts {
    /// A transaction signature anywhere in the function, which commits to every output; a
    /// `checkSigFromStack` message does not.
    signed: bool,
    path: Path,
    /// For each `if` arm being walked, the path before the `if`, and the `then` arm's path
    /// once it is walked.
    arms: Vec<(Path, Option<Path>)>,
    outputs: BTreeMap<OutputIndex, OutputChecks>,
    bounds_inputs: bool,
    locktime: Vec<Span>,
    /// `checkSigFromStack` messages that are a witness parameter as given.
    unbound_messages: Vec<(String, Span)>,
    /// Signature keys that are a witness parameter as given.
    witness_signers: Vec<(String, Span)>,
    /// Multisig thresholds that are a witness parameter as given.
    witness_thresholds: Vec<(String, Span)>,
    /// While inside imported helpers, the outermost call to one and the depth of nesting:
    /// their spans index another file, so their findings sit at the call.
    import_call: Option<(Span, usize)>,
}

impl Facts {
    /// Where a finding at `span` belongs in the walked file.
    fn at(&self, span: Span) -> Span {
        self.import_call.map_or(span, |(call, _)| call)
    }
}

pub(super) fn check(contract: &Contract, findings: &mut Vec<Finding>) {
    let mut covenants = Vec::new();
    for function in contract
        .functions
        .iter()
        .filter(|f| !f.is_private && !f.is_imported())
    {
        let mut facts = Facts::default();
        let witness: HashSet<&str> = function
            .parameters
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        find_witness_choices(&function.statements, &witness, &mut facts);
        Walk::into_helpers(contract).statements(&function.statements, &mut facts);
        report(function, &facts, findings);
        covenants.push((function, facts.path));
    }
    unsigned_spend_path(&covenants, &spending_paths(contract, &covenants), findings);
}

/// A tapscript leaf, or the synthesized leaf of a covenant that no leaf signs for with the
/// emulator: whether it needs a constructor key's signature, and the covenant whose tweaked
/// key it signs with, which must then pass too.
type SpendingPath<'a> = (bool, Option<(&'a Function, Path)>);

fn spending_paths<'a>(
    contract: &Contract,
    covenants: &[(&'a Function, Path)],
) -> Vec<SpendingPath<'a>> {
    let mut paths = Vec::new();
    let mut emulated = HashSet::new();
    for tapscript in &contract.tapscripts {
        let keys = tapscript
            .items
            .iter()
            .find_map(|item| match item {
                TapItem::Sig { keys, .. } => Some(keys.as_slice()),
                _ => None,
            })
            .unwrap_or_default();
        let bound = shared_tweak_func(&tapscript.name, keys).ok().flatten();
        if keys.iter().any(
            |key| matches!(key, KeyExpr::Ident(base) | KeyExpr::Tweak { base, .. } if base == EMULATOR),
        ) {
            emulated.extend(bound.clone());
        }
        // Every key of a leaf signs. The server and emulator co-sign every offchain spend, and a
        // tweaked key's enclave signs whatever its covenant passes, so only a constructor key
        // authorizes the spend.
        let signed = keys.iter().any(|key| {
            matches!(key, KeyExpr::Ident(name) if contract.parameters.iter().any(|p| &p.name == name))
        });
        let covenant = bound.and_then(|name| covenants.iter().find(|(f, _)| f.name == name));
        paths.push((signed, covenant.copied()));
    }
    paths.extend(
        covenants
            .iter()
            .filter(|(f, _)| !emulated.contains(&f.name))
            .map(|&covenant| (false, Some(covenant))),
    );
    paths
}

/// Reports each covenant with a path that checks no transaction signature, through a leaf
/// that needs no constructor key's signature either. Introspection does not count: such a
/// path may still be sound, as a hash lock or a stateful covenant is.
fn unsigned_spend_path(
    covenants: &[(&Function, Path)],
    paths: &[SpendingPath],
    findings: &mut Vec<Finding>,
) {
    for &(function, path) in covenants {
        let unsigned_leaf = paths
            .iter()
            .any(|&(signed, c)| !signed && c.is_some_and(|(f, _)| f.name == function.name));
        if path.never_passes || path.signed || !unsigned_leaf {
            continue;
        }
        findings.push(Finding::new(
            Lint::UnsignedSpendPath,
            function.span,
            format!(
                "function '{}' has a spending path with no transaction signature, so its other \
                 conditions alone authorize the spend",
                function.name
            ),
        ));
    }
}

fn report(function: &Function, facts: &Facts, findings: &mut Vec<Finding>) {
    let name = &function.name;
    if facts.path.never_passes {
        return;
    }
    for (index, checks) in &facts.outputs {
        match (checks.script, checks.value) {
            (None, Some(value)) if !facts.signed => findings.push(Finding::new(
                Lint::OutputScriptUnchecked,
                value,
                format!(
                    "function '{name}' checks the value of tx.outputs[{index}] but not its \
                         scriptPubKey, so that value can be paid to any script"
                ),
            )),
            (Some(script), None) if !checks.assets && !facts.signed => findings.push(Finding::new(
                Lint::OutputValueUnchecked,
                script,
                format!(
                    "function '{name}' checks the scriptPubKey of tx.outputs[{index}] but not \
                         its value or assets, so it can receive a dust amount while the rest goes \
                         elsewhere"
                ),
            )),
            _ => {}
        }
    }
    if !facts.outputs.is_empty() && !facts.bounds_inputs && !facts.signed {
        findings.push(Finding::new(
            Lint::OutputsSharedAcrossInputs,
            function.span,
            format!(
                "function '{name}' constrains outputs by index without bounding tx.numInputs or \
                     the active input, so two inputs locked by this contract can be satisfied by \
                     the same outputs"
            ),
        ));
    }
    for (message, span) in &facts.unbound_messages {
        findings.push(Finding::new(
            Lint::OracleMessageUnbound,
            *span,
            format!(
                "function '{name}' accepts a signature over the witness '{message}' as given, \
                     so one signed message authorizes any spend; derive the message from what the \
                     spend must match, such as its outputs or tx.input.current.outpoint"
            ),
        ));
    }
    for (key, span) in &facts.witness_signers {
        findings.push(Finding::new(
            Lint::SignerFromWitness,
            *span,
            format!(
                "function '{name}' takes '{key}' from the witness and checks a signature \
                     against it, so the spender chooses who must sign; use a constructor \
                     parameter, or bind it, for example with hash160({key}) == hash"
            ),
        ));
    }
    for (threshold, span) in &facts.witness_thresholds {
        findings.push(Finding::new(
            Lint::SignerFromWitness,
            *span,
            format!(
                "function '{name}' takes the multisig threshold '{threshold}' from the \
                     witness, so the spender chooses how many must sign; use a constructor \
                     parameter"
            ),
        ));
    }
    for &span in &facts.locktime {
        findings.push(Finding::new(
            Lint::OffchainLocktime,
            span,
            format!(
                "function '{name}' reads tx.locktime, which arkd sets to 0 when it rebuilds an \
                     offchain spend; use checkTime(t) for time"
            ),
        ));
    }
}

impl<'a> Visitor<'a> for Facts {
    fn statement(&mut self, statement: &'a LocatedStatement) {
        let Statement::Require(requirement) = &statement.statement else {
            return;
        };
        self.path.never_passes |= never_passes(requirement);
        if let Requirement::Comparison { left, right, .. } = requirement {
            self.bounds_inputs |= [left, right].iter().any(|side| is_active_input(side));
        }
    }

    fn enter_arm(&mut self, _id: usize, then: bool, _body: &'a [LocatedStatement]) {
        let before = std::mem::take(&mut self.path);
        if then {
            self.arms.push((before, None));
        }
    }

    fn exit_arm(&mut self) {
        let arm = std::mem::take(&mut self.path);
        let (before, then) = self.arms.last_mut().expect("an arm is being walked");
        match then.take() {
            None => *then = Some(arm),
            Some(then) => {
                self.path = before.followed_by(Path::either(then, arm));
                self.arms.pop();
            }
        }
    }

    fn enter_import(&mut self, call: Span) {
        let (call, depth) = self.import_call.unwrap_or((call, 0));
        self.import_call = Some((call, depth + 1));
    }

    fn exit_import(&mut self) {
        self.import_call = match self.import_call {
            Some((call, depth)) if depth > 1 => Some((call, depth - 1)),
            _ => None,
        };
    }

    fn expression(&mut self, expression: &'a Expression) {
        let facts = self;
        match &expression.kind {
            ExprKind::Builtin { builtin, .. }
                if matches!(builtin.name, "checkSig" | "checkMultisig") =>
            {
                facts.signed = true;
                facts.path.signed = true;
            }
            ExprKind::OutputIntrospection { index, property } => {
                facts.bounds_inputs |= is_active_input(index);
                let Some(index) = OutputIndex::of(index) else {
                    return;
                };
                let at = facts.at(expression.span);
                let checks = facts.outputs.entry(index).or_default();
                match property {
                    OutputProperty::Value => checks.value = Some(at),
                    OutputProperty::Script => checks.script = Some(at),
                    OutputProperty::WitnessVersion => {}
                }
            }
            ExprKind::AssetLookup {
                source: AssetLookupSource::Output,
                index,
                ..
            }
            | ExprKind::AssetHas {
                source: AssetLookupSource::Output,
                index,
                ..
            }
            | ExprKind::AssetTryLookup {
                source: AssetLookupSource::Output,
                index,
                ..
            }
            | ExprKind::AssetCount {
                source: AssetLookupSource::Output,
                index,
            } => {
                if let Some(index) = OutputIndex::of(index) {
                    facts.outputs.entry(index).or_default().assets = true;
                }
            }
            ExprKind::TxIntrospection {
                property: TxProperty::NumInputs,
            } => facts.bounds_inputs = true,
            ExprKind::BinaryOp { left, op, right } if op.compares() => {
                facts.bounds_inputs |= [left, right].iter().any(|side| is_active_input(side))
            }
            ExprKind::InputIntrospection { property, .. } => {
                facts.bounds_inputs |=
                    matches!(property, crate::properties::InputProperty::Outpoint);
            }
            ExprKind::TxIntrospection {
                property: TxProperty::Locktime,
            } => {
                let at = facts.at(expression.span);
                if !facts.locktime.contains(&at) {
                    facts.locktime.push(at);
                }
            }
            _ => {}
        }
    }
}

enum Choice {
    Key,
    Threshold,
    Message,
}

/// Records each signature check whose key, threshold or `checkSigFromStack` message is a
/// witness parameter the function names only as such operands; any other mention of it, even
/// `k != owner`, counts as binding it.
fn find_witness_choices(
    statements: &[LocatedStatement],
    witness: &HashSet<&str>,
    facts: &mut Facts,
) {
    #[derive(Default)]
    struct Choices<'a> {
        found: Vec<(Choice, &'a str, Span)>,
        uses: HashMap<&'a str, usize>,
        chosen: HashMap<&'a str, usize>,
    }
    impl<'a> Visitor<'a> for Choices<'a> {
        fn expression(&mut self, expression: &'a Expression) {
            if let ExprKind::Builtin { builtin, args } = &expression.kind {
                let mut operands: Vec<(Choice, &Expression)> = Vec::new();
                match builtin.name {
                    "checkSig" => operands.extend(args.get(1).map(|key| (Choice::Key, key))),
                    "checkMultisig" => {
                        if let Some(ExprKind::ArrayLiteral(keys)) = args.first().map(|a| &a.kind) {
                            operands.extend(keys.iter().map(|key| (Choice::Key, key)));
                        }
                        operands.extend(args.get(2).map(|n| (Choice::Threshold, n)));
                    }
                    name if name.starts_with("checkSigFromStack") => {
                        operands.extend(args.get(1).map(|key| (Choice::Key, key)));
                        operands.extend(args.get(2).map(|message| (Choice::Message, message)));
                    }
                    _ => {}
                }
                for (choice, operand) in operands {
                    if let ExprKind::Name(path) = &operand.kind {
                        if path.segments.is_empty() {
                            self.found
                                .push((choice, path.root.as_str(), expression.span));
                            *self.chosen.entry(path.root.as_str()).or_default() += 1;
                        }
                    }
                }
            }
            if let ExprKind::Name(path) = &expression.kind {
                *self.uses.entry(path.root.as_str()).or_default() += 1;
            }
        }
    }
    let mut walked = Choices::default();
    Walk::default().statements(statements, &mut walked);
    let Choices {
        found: choices,
        uses,
        chosen,
    } = walked;
    for (choice, name, span) in choices {
        let count = |counts: &HashMap<&str, usize>| counts.get(name).copied().unwrap_or(0);
        if witness.contains(name) && count(&uses) == count(&chosen) {
            let found = match choice {
                Choice::Key => &mut facts.witness_signers,
                Choice::Threshold => &mut facts.witness_thresholds,
                Choice::Message => &mut facts.unbound_messages,
            };
            found.push((name.to_string(), span));
        }
    }
}

/// A requirement the constant folder evaluates to false, as in a disabled function.
fn never_passes(requirement: &Requirement) -> bool {
    let condition = match requirement {
        Requirement::Expression(value) => value.clone(),
        Requirement::Comparison { left, op, right } => left.with_kind(ExprKind::BinaryOp {
            left: Box::new(left.clone()),
            op: *op,
            right: Box::new(right.clone()),
        }),
    };
    let mut no_names = |_: &crate::models::Path| Err(String::new());
    crate::compiler::constants::evaluate(&condition, &mut no_names).as_deref() == Ok("false")
}

fn is_active_input(expression: &Expression) -> bool {
    matches!(
        expression.kind,
        ExprKind::This(ThisProperty::ActiveInputIndex)
    )
}
