//! Covenant lints: what a spending function authorizes and constrains, gathered through the
//! helpers it calls.

use std::collections::{BTreeMap, HashMap, HashSet};

use super::walk::{Visitor, Walk};
use super::{Finding, Lint};
use crate::diagnostics::Span;
use crate::models::{
    AssetLookupSource, Contract, ExprKind, Expression, Function, GroupIOSource, LocatedStatement,
    Requirement, Statement, TapItem,
};
use crate::operators::BinaryOperator;
use crate::properties::{GroupProperty, OutputProperty, ThisProperty, TxProperty};

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

#[derive(Default)]
struct Facts {
    /// A transaction signature, which commits to every output; a `checkSigFromStack` message
    /// does not.
    signed: bool,
    constrains_outputs: bool,
    /// Another input's script is checked, so its contract authorizes this spend.
    co_spent: bool,
    never_passes: bool,
    outputs: BTreeMap<OutputIndex, OutputChecks>,
    bounds_inputs: bool,
    locktime: Vec<Span>,
    /// `checkSigFromStack` messages that are a witness parameter as given.
    unbound_messages: Vec<(String, Span)>,
    /// Signature keys that are a witness parameter as given.
    witness_signers: Vec<(String, Span)>,
    /// Multisig thresholds that are a witness parameter as given.
    witness_thresholds: Vec<(String, Span)>,
    preimage: Option<Span>,
}

pub(super) fn check(contract: &Contract, findings: &mut Vec<Finding>) {
    let mut reveals = Vec::new();
    let mut escapes = false;
    for tapscript in &contract.tapscripts {
        match tapscript
            .items
            .iter()
            .any(|item| matches!(item, TapItem::Hash { .. }))
        {
            true => reveals.push(tapscript.span),
            false => escapes = true,
        }
    }
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
        if !facts.never_passes {
            match facts.preimage {
                Some(span) => reveals.push(span),
                None => escapes = true,
            }
        }
    }
    if !escapes {
        for span in reveals {
            findings.push(Finding::new(
                Lint::RevealWithoutTimeout,
                span,
                "every spending path needs this hash preimage, so the coins stay locked \
                     until it is revealed; add a path after a timeout, such as checkTime(t) or \
                     after(t)",
            ));
        }
    }
}

fn report(function: &Function, facts: &Facts, findings: &mut Vec<Finding>) {
    let name = &function.name;
    if facts.never_passes {
        return;
    }
    if !facts.signed && !facts.constrains_outputs && !facts.co_spent {
        findings.push(
            Finding::new(Lint::AnyoneCanSpend, function.span, format!(
                    "function '{name}' checks no signature and constrains no output, so anyone who \
                     satisfies it can send the coins anywhere; a revealed preimage is no authorization"
                )),
        );
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
            (Some(script), None) if !checks.assets => findings.push(Finding::new(
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
        self.never_passes |= never_passes(requirement);
        if let Requirement::Comparison { left, op, right } = requirement {
            self.bounds_inputs |= [left, right].iter().any(|side| is_active_input(side));
            if *op == BinaryOperator::Eq && [left, right].iter().any(|side| hashes_name(side)) {
                self.preimage.get_or_insert(statement.span);
            }
        }
    }

    fn expression(&mut self, expression: &'a Expression) {
        let facts = self;
        match &expression.kind {
            ExprKind::Builtin { builtin, .. }
                if matches!(builtin.name, "checkSig" | "checkMultisig") =>
            {
                facts.signed = true
            }
            ExprKind::OutputIntrospection { index, property } => {
                facts.constrains_outputs = true;
                facts.bounds_inputs |= is_active_input(index);
                let Some(index) = OutputIndex::of(index) else {
                    return;
                };
                let checks = facts.outputs.entry(index).or_default();
                match property {
                    OutputProperty::Value => checks.value = Some(expression.span),
                    OutputProperty::ScriptPubKey | OutputProperty::Script => {
                        checks.script = Some(expression.span)
                    }
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
                facts.constrains_outputs = true;
                if let Some(index) = OutputIndex::of(index) {
                    facts.outputs.entry(index).or_default().assets = true;
                }
            }
            ExprKind::AssetAt {
                source: AssetLookupSource::Output,
                ..
            }
            | ExprKind::Tunnel { .. }
            | ExprKind::ContractInstance { .. }
            | ExprKind::IntentInspect { .. }
            | ExprKind::GroupIOAccess {
                source: GroupIOSource::Outputs,
                ..
            }
            | ExprKind::GroupProperty {
                property:
                    GroupProperty::SumOutputs | GroupProperty::Delta | GroupProperty::NumOutputs,
                ..
            } => facts.constrains_outputs = true,
            ExprKind::TxIntrospection {
                property: TxProperty::NumInputs,
            } => facts.bounds_inputs = true,
            ExprKind::BinaryOp { left, op, right } if op.compares() => {
                facts.bounds_inputs |= [left, right].iter().any(|side| is_active_input(side))
            }
            ExprKind::InputIntrospection { index, property } => {
                use crate::properties::InputProperty::*;
                facts.bounds_inputs |= matches!(property, Outpoint);
                facts.co_spent |= !is_active_input(index)
                    && matches!(
                        property,
                        ScriptPubKey | Script | ArkadeScriptHash | ArkadeWitnessHash
                    );
            }
            ExprKind::TxIntrospection {
                property: TxProperty::Locktime,
            } => facts.locktime.push(expression.span),
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
/// witness parameter the function uses nowhere else: one also hashed, compared or matched to
/// an output is bound.
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
        if witness.contains(name) && uses[name] == chosen[name] {
            let found = match choice {
                Choice::Key => &mut facts.witness_signers,
                Choice::Threshold => &mut facts.witness_thresholds,
                Choice::Message => &mut facts.unbound_messages,
            };
            found.push((name.to_string(), span));
        }
    }
}

/// `sha256(x)` or another hash of a name, as in a hash lock.
fn hashes_name(expression: &Expression) -> bool {
    matches!(&expression.kind, ExprKind::Builtin { builtin, args }
        if crate::models::HashFn::parse(builtin.name).is_some()
            && matches!(args[0].kind, ExprKind::Name(_)))
}

/// `require(false)` or a comparison of two different literals, as in a disabled function.
fn never_passes(requirement: &Requirement) -> bool {
    let literal = |e: &Expression| match &e.kind {
        ExprKind::Literal(value) => Some(value.clone()),
        _ => None,
    };
    match requirement {
        Requirement::Expression(value) => literal(value).as_deref() == Some("false"),
        Requirement::Comparison { left, op, right } => match (literal(left), literal(right)) {
            (Some(left), Some(right)) => match op {
                BinaryOperator::Eq => left != right,
                BinaryOperator::Ne => left == right,
                _ => false,
            },
            _ => false,
        },
    }
}

fn is_active_input(expression: &Expression) -> bool {
    matches!(
        expression.kind,
        ExprKind::This(ThisProperty::ActiveInputIndex)
    )
}
