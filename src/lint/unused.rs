//! Constructor parameters and locals nothing reads, by the liveness that rejects an unused
//! function parameter: a read by a local or assignment nothing later reads does not count.

use std::collections::HashSet;

use super::{Finding, Lint};
use crate::models::{Contract, Statement};
use crate::validator::references::live_reads;

pub(super) fn check(contract: &Contract, findings: &mut Vec<Finding>) {
    let mut used: HashSet<&str> = contract
        .tapscripts
        .iter()
        .flat_map(crate::validator::tapscript_reads)
        .collect();
    for function in contract.functions.iter().filter(|f| !f.is_imported()) {
        let (live, mut dead) = live_reads(&function.statements);
        used.extend(live);
        dead.sort_by_key(|statement| statement.span.start);
        for statement in dead {
            if let Statement::Declaration { name, .. } | Statement::LetBinding { name, .. } =
                &statement.statement
            {
                findings.push(Finding::new(
                    Lint::UnusedVariable,
                    statement.span,
                    format!(
                        "variable '{name}' in function '{}' is never used",
                        function.name
                    ),
                ));
            }
        }
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
