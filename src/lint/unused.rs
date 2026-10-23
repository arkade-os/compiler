//! Constructor parameters and locals nothing reads.

use std::collections::HashSet;

use super::{Finding, Lint};
use crate::models::{Contract, LocatedStatement, Statement};
use crate::validator::references::referenced_parameters;

pub(super) fn check(contract: &Contract, findings: &mut Vec<Finding>) {
    let mut used: HashSet<&str> = contract
        .tapscripts
        .iter()
        .flat_map(crate::validator::tapscript_reads)
        .collect();
    for function in contract.functions.iter().filter(|f| !f.is_imported()) {
        used.extend(referenced_parameters(&function.statements, &[]));
        locals(&function.statements, &function.name, findings);
    }
    for parameter in contract
        .parameters
        .iter()
        .filter(|p| !used.contains(p.name.as_str()))
    {
        findings.push(Finding::new(
            Lint::UnusedParameter,
            parameter.span,
            format!("constructor parameter '{}' is never used", parameter.name),
        ));
    }
}

/// A local is read only by later statements in its own block, since shadowing
/// is rejected; sibling blocks may reuse the name for a separate binding.
// ponytail: rescans the rest of the block per binding, O(n²) in block length;
// index reads per binding in one pass if contract bodies ever grow large.
fn locals(statements: &[LocatedStatement], function: &str, findings: &mut Vec<Finding>) {
    for (index, statement) in statements.iter().enumerate() {
        match &statement.statement {
            Statement::Declaration { name, .. } | Statement::LetBinding { name, .. }
                if !referenced_parameters(&statements[index + 1..], &[])
                    .contains(name.as_str()) =>
            {
                findings.push(Finding::new(
                    Lint::UnusedVariable,
                    statement.span,
                    format!("variable '{name}' in function '{function}' is never used"),
                ));
            }
            Statement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                locals(then_body, function, findings);
                locals(else_body.as_deref().unwrap_or_default(), function, findings);
            }
            Statement::ForIn { body, .. } | Statement::ForCount { body, .. } => {
                locals(body, function, findings)
            }
            _ => {}
        }
    }
}
