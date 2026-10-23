//! Reports a function that reads one multi-result inspection more than once, so the
//! author can bind the whole result once instead of repeating the opcode.

use super::walk::{Visitor, Walk};
use super::{Finding, Lint};
use crate::models::{
    AssetLookupSource, AssignmentTarget, Contract, ExprKind, Expression, LocatedStatement,
    Statement,
};
use crate::properties::{InputProperty, OutputProperty, ThisProperty};
use std::collections::HashSet;

/// The `if` arms a read sits in, as (if id, then-arm) pairs.
type Path = Vec<(usize, bool)>;

struct Read {
    whole: String,
    fields: &'static str,
    path: Path,
    span: crate::diagnostics::Span,
}

pub(super) fn check(contract: &Contract, findings: &mut Vec<Finding>) {
    for function in contract.functions.iter().filter(|f| !f.is_imported()) {
        let mut assigned = Assigned::default();
        Walk::default().statements(&function.statements, &mut assigned);
        let mut walk = Reads {
            assigned: assigned.0,
            reads: Vec::new(),
            path: Vec::new(),
        };
        Walk::default().statements(&function.statements, &mut walk);
        let mut warned = HashSet::new();
        for (i, read) in walk.reads.iter().enumerate() {
            if warned.contains(&read.whole) {
                continue;
            }
            let same: Vec<_> = walk.reads[i..]
                .iter()
                .filter(|other| other.whole == read.whole)
                .collect();
            // Reads in opposite arms of one `if` never both run.
            let together = same.iter().enumerate().any(|(j, a)| {
                same[j + 1..]
                    .iter()
                    .any(|b| !a.path.iter().any(|(id, arm)| b.path.contains(&(*id, !arm))))
            });
            if together {
                warned.insert(read.whole.clone());
                findings.push(
                    Finding::new(Lint::RepeatedInspection, read.span, format!(
                        "`{}` is inspected more than once in function '{}'; bind `let x = {};` once and read {}",
                        read.whole,
                        function.name,
                        read.whole,
                        read.fields
                    )),
                );
            }
        }
    }
}

/// The roots of every binding the function assigns.
#[derive(Default)]
struct Assigned(HashSet<String>);

impl<'a> Visitor<'a> for Assigned {
    fn statement(&mut self, statement: &'a LocatedStatement) {
        if let Statement::VarAssign { target, .. } = &statement.statement {
            let name = match target {
                AssignmentTarget::Binding(name) => Some(name.clone()),
                AssignmentTarget::ArrayIndex { array, .. } => Some(array.clone()),
                AssignmentTarget::Access(value) => value.binding_path(),
            };
            self.0.extend(name.map(|name| name.root));
        }
    }
}

struct Reads {
    assigned: HashSet<String>,
    reads: Vec<Read>,
    path: Path,
}

impl<'a> Visitor<'a> for Reads {
    fn expression(&mut self, expression: &'a Expression) {
        if let Some((whole, fields)) = self.whole_read(expression) {
            self.reads.push(Read {
                whole,
                fields,
                path: self.path.clone(),
                span: expression.span,
            });
        }
    }

    fn enter_arm(&mut self, id: usize, then: bool) {
        self.path.push((id, then));
    }

    fn exit_arm(&mut self) {
        self.path.pop();
    }
}

impl Reads {
    /// The whole-result spelling of a single-field multi-result read, when its operands
    /// name the same value wherever they appear in the function.
    fn whole_read(&self, expression: &Expression) -> Option<(String, &'static str)> {
        let source = |source: &AssetLookupSource| match source {
            AssetLookupSource::Input => "inputs",
            AssetLookupSource::Output => "outputs",
        };
        let (whole, fields, operands) = match &expression.kind {
            ExprKind::InputIntrospection {
                index,
                property: InputProperty::ScriptPubKey | InputProperty::WitnessVersion,
            } => {
                let whole = if matches!(index.kind, ExprKind::This(ThisProperty::ActiveInputIndex))
                {
                    "tx.input.current.script".to_string()
                } else {
                    format!("tx.inputs[{}].script", index.source_text())
                };
                (whole, "`x.program` and `x.version`", vec![index])
            }
            ExprKind::OutputIntrospection {
                index,
                property: OutputProperty::ScriptPubKey | OutputProperty::WitnessVersion,
            } => (
                format!("tx.outputs[{}].script", index.source_text()),
                "`x.program` and `x.version`",
                vec![index],
            ),
            ExprKind::AssetAt {
                source: io,
                io_index,
                asset_index,
                property: Some(_),
            } => (
                format!(
                    "tx.{}[{}].assets[{}]",
                    source(io),
                    io_index.source_text(),
                    asset_index.source_text()
                ),
                "`x.assetId` and `x.amount`",
                vec![io_index, asset_index],
            ),
            ExprKind::AssetLookup {
                source: io,
                index,
                asset_txid,
                asset_gidx,
            }
            | ExprKind::AssetHas {
                source: io,
                index,
                asset_txid,
                asset_gidx,
            } => (
                format!(
                    "tx.{}[{}].assets.tryLookup({}, {})",
                    source(io),
                    index.source_text(),
                    asset_txid.source_text(),
                    asset_gidx.source_text()
                ),
                "`x.amount` and `x.found`, adding `require(x.found);` where `lookup` aborted on a missing asset",
                vec![index, asset_txid, asset_gidx],
            ),
            _ => return None,
        };
        operands
            .into_iter()
            .all(|operand| self.stable(operand))
            .then_some((whole, fields))
    }

    fn stable(&self, expression: &Expression) -> bool {
        match &expression.kind {
            ExprKind::Literal(_) | ExprKind::This(_) => true,
            ExprKind::Name(path) => {
                !path.key().contains('[') && !self.assigned.contains(&path.root)
            }
            ExprKind::ArrayIndex { array, index } => {
                !self.assigned.contains(&array.root) && self.stable(index)
            }
            ExprKind::IndexAccess { value, index } => self.stable(value) && self.stable(index),
            ExprKind::FieldAccess { value, .. } => self.stable(value),
            _ => false,
        }
    }
}
