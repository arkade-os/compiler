//! Covenant lints: what a spending function authorizes and constrains, gathered through the
//! helpers it calls, and lints on single expressions.

use std::collections::{BTreeMap, HashMap, HashSet};

use super::{Finding, Lint};
use crate::diagnostics::Span;
use crate::models::{
    child_exprs, AssetLookupSource, Contract, ExprKind, Expression, Function, GroupIOSource,
    KeyExpr, LocatedStatement, Requirement, Statement, TapItem, TypeName,
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
        let mut visited = HashSet::new();
        let witness: HashSet<&str> = function
            .parameters
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        find_witness_choices(&function.statements, &witness, &mut facts);
        statements(&function.statements, contract, &mut facts, &mut visited);
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
    for function in contract.functions.iter().filter(|f| !f.is_imported()) {
        check_expressions(contract, function, findings);
    }
    for tapscript in &contract.tapscripts {
        for item in &tapscript.items {
            if let TapItem::Sig { keys, .. } = item {
                if let Some(key) = keys
                    .iter()
                    .enumerate()
                    .find_map(|(at, key)| keys[..at].contains(key).then_some(key))
                {
                    let key = match key {
                        KeyExpr::Ident(name) => format!("'{name}'"),
                        KeyExpr::Tweak { base, func } => format!("tweak({base}, {func})"),
                    };
                    findings.push(duplicate_key(&key, tapscript.span));
                }
            }
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

fn statements(
    statements: &[LocatedStatement],
    contract: &Contract,
    facts: &mut Facts,
    visited: &mut HashSet<String>,
) {
    for statement in statements {
        if let Statement::Require(requirement) = &statement.statement {
            facts.never_passes |= never_passes(requirement);
        }
        if let Statement::Require(Requirement::Comparison { left, op, right }) =
            &statement.statement
        {
            facts.bounds_inputs |= [left, right].iter().any(|side| is_active_input(side));
            if *op == BinaryOperator::Eq && [left, right].iter().any(|side| hashes_name(side)) {
                facts.preimage.get_or_insert(statement.span);
            }
        }
        for value in statement.statement.expressions() {
            expression(value, contract, facts, visited);
        }
        match &statement.statement {
            Statement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                self::statements(then_body, contract, facts, visited);
                let else_body = else_body.as_deref().unwrap_or_default();
                self::statements(else_body, contract, facts, visited);
            }
            Statement::ForIn { body, .. } | Statement::ForCount { body, .. } => {
                self::statements(body, contract, facts, visited)
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
/// witness parameter the function uses nowhere else: one also hashed, compared or matched to
/// an output is bound.
fn find_witness_choices(
    statements: &[LocatedStatement],
    witness: &HashSet<&str>,
    facts: &mut Facts,
) {
    let mut choices = Vec::new();
    let (mut uses, mut chosen) = (HashMap::<&str, usize>::new(), HashMap::<&str, usize>::new());
    each_expression(statements, &mut |expression| {
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
                        choices.push((choice, path.root.as_str(), expression.span));
                        *chosen.entry(path.root.as_str()).or_default() += 1;
                    }
                }
            }
        }
        if let ExprKind::Name(path) = &expression.kind {
            *uses.entry(path.root.as_str()).or_default() += 1;
        }
    });
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

/// Calls `visit` on each expression in `statements`, a parent before its children.
fn each_expression<'a>(statements: &'a [LocatedStatement], visit: &mut impl FnMut(&'a Expression)) {
    fn descend<'a>(expression: &'a Expression, visit: &mut impl FnMut(&'a Expression)) {
        visit(expression);
        for child in child_exprs(expression) {
            descend(child, visit);
        }
    }
    each_statement(statements, &mut |statement| {
        for value in statement.statement.expressions() {
            descend(value, visit);
        }
    });
}

/// Calls `visit` on each statement in `statements`, nested ones included.
fn each_statement<'a>(
    statements: &'a [LocatedStatement],
    visit: &mut impl FnMut(&'a LocatedStatement),
) {
    for statement in statements {
        visit(statement);
        match &statement.statement {
            Statement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                each_statement(then_body, visit);
                each_statement(else_body.as_deref().unwrap_or_default(), visit);
            }
            Statement::ForIn { body, .. } | Statement::ForCount { body, .. } => {
                each_statement(body, visit)
            }
            _ => {}
        }
    }
}

/// `sha256(x)` or another hash of a name, as in a hash lock.
fn hashes_name(expression: &Expression) -> bool {
    matches!(&expression.kind, ExprKind::Builtin { builtin, args }
        if crate::models::HashFn::parse(builtin.name).is_some()
            && matches!(args[0].kind, ExprKind::Name(_)))
}

fn duplicate_key(key: &str, span: Span) -> Finding {
    Finding::new(
        Lint::DuplicateMultisigKey,
        span,
        format!("checkMultisig lists {key} more than once, so its one signature counts for each"),
    )
}

/// Lints on single expressions, in every function and helper.
fn check_expressions(contract: &Contract, function: &Function, findings: &mut Vec<Finding>) {
    let variable_length = |expression: &Expression| match &expression.kind {
        ExprKind::Name(path) if path.segments.is_empty() => contract
            .parameters
            .iter()
            .chain(&function.parameters)
            .any(|p| p.name == path.root && p.param_type == TypeName::Named("bytes".into())),
        _ => false,
    };
    let same = |left: &Expression, right: &Expression| {
        let text = left.source_text();
        !matches!(left.kind, ExprKind::Literal(_))
            && !text.contains("<expr>")
            && text == right.source_text()
    };
    let self_comparison = |span| {
        Finding::new(
            Lint::SelfComparison,
            span,
            "both sides of this comparison are the same, so its result never depends on them",
        )
    };
    each_statement(&function.statements, &mut |statement| {
        if let Statement::Require(Requirement::Comparison { left, right, .. }) =
            &statement.statement
        {
            if same(left, right) {
                findings.push(self_comparison(statement.span));
            }
        }
    });
    each_expression(
        &function.statements,
        &mut |expression| match &expression.kind {
            ExprKind::BinaryOp { left, op, right } => {
                if (op.compares() || matches!(op, BinaryOperator::And | BinaryOperator::Or))
                    && same(left, right)
                {
                    findings.push(self_comparison(expression.span));
                }
                let divides = |side: &Expression| {
                    matches!(
                        side.kind,
                        ExprKind::BinaryOp {
                            op: BinaryOperator::Div,
                            ..
                        }
                    )
                };
                if *op == BinaryOperator::Mul && (divides(left) || divides(right)) {
                    findings.push(Finding::new(
                        Lint::DivideBeforeMultiply,
                        expression.span,
                        "this divides before it multiplies, so the remainder is lost before it \
                         is scaled; multiply first",
                    ));
                }
            }
            ExprKind::Builtin { builtin, args }
                if builtin.name.starts_with("sha256")
                    || crate::models::HashFn::parse(builtin.name).is_some() =>
            {
                for data in args {
                    let mut parts = Vec::new();
                    concatenated(data, &mut parts);
                    let variable: Vec<String> = parts
                        .into_iter()
                        .filter(|part| variable_length(part))
                        .map(Expression::source_text)
                        .collect();
                    if variable.len() >= 2 {
                        findings.push(Finding::new(
                            Lint::AmbiguousHashConcat,
                            data.span,
                            format!(
                                "{} hashes {} joined together, which vary in length, so other \
                                 values joined the same way can give the same bytes; give them a \
                                 fixed length, such as bytes32",
                                builtin.name,
                                variable.join(" + "),
                            ),
                        ));
                    }
                }
            }
            ExprKind::Builtin { builtin, args } if builtin.name == "checkMultisig" => {
                if let Some(ExprKind::ArrayLiteral(keys)) = args.first().map(|keys| &keys.kind) {
                    if let Some(key) = keys.iter().enumerate().find_map(|(at, key)| {
                        keys[..at].iter().any(|k| same(k, key)).then_some(key)
                    }) {
                        findings.push(duplicate_key(
                            &format!("'{}'", key.source_text()),
                            expression.span,
                        ));
                    }
                }
            }
            _ => {}
        },
    );
}

/// The operands of a chain of `+` on bytes, in order.
fn concatenated<'a>(expression: &'a Expression, parts: &mut Vec<&'a Expression>) {
    match &expression.kind {
        ExprKind::BinaryOp {
            left,
            op: BinaryOperator::Add,
            right,
        } if expression.ty != crate::types::ArkType::Int => {
            concatenated(left, parts);
            concatenated(right, parts);
        }
        _ => parts.push(expression),
    }
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

fn expression(
    expression: &Expression,
    contract: &Contract,
    facts: &mut Facts,
    visited: &mut HashSet<String>,
) {
    match &expression.kind {
        ExprKind::Builtin { builtin, .. }
            if matches!(builtin.name, "checkSig" | "checkMultisig") =>
        {
            facts.signed = true
        }
        ExprKind::Call { name, .. } => {
            let helper = contract.functions.iter().find(|f| f.name == *name);
            if let Some(helper) = helper.filter(|_| visited.insert(name.clone())) {
                statements(&helper.statements, contract, facts, visited);
            }
        }
        ExprKind::OutputIntrospection { index, property } => {
            facts.constrains_outputs = true;
            facts.bounds_inputs |= is_active_input(index);
            let Some(index) = OutputIndex::of(index) else {
                return walk_children(expression, contract, facts, visited);
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
            property: GroupProperty::SumOutputs | GroupProperty::Delta | GroupProperty::NumOutputs,
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
    walk_children(expression, contract, facts, visited);
}

fn walk_children(
    expression: &Expression,
    contract: &Contract,
    facts: &mut Facts,
    visited: &mut HashSet<String>,
) {
    for child in child_exprs(expression) {
        self::expression(child, contract, facts, visited);
    }
}
