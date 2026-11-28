//! Constructor parameters and locals nothing reads, by the liveness that rejects an unused
//! function parameter: a read by a local or assignment nothing later reads does not count.

use std::collections::HashSet;

use super::{Finding, FindingKind};
use crate::models::{Contract, Statement};
use crate::validator;
use crate::validator::references::live_reads;

pub(super) fn check(contract: &Contract, findings: &mut Vec<Finding>) {
    let mut used: HashSet<&str> = contract
        .tapscripts
        .iter()
        .flat_map(validator::tapscript_reads)
        .collect();
    for function in contract.functions.iter().filter(|f| !f.is_imported()) {
        let (live, mut dead) = live_reads(&function.statements);
        used.extend(live);
        dead.sort_by_key(|statement| statement.span.start);
        for statement in dead {
            if let Statement::Declaration { name, .. } | Statement::LetBinding { name, .. } =
                &statement.statement
            {
                let kind = FindingKind::UnusedVariable {
                    name: name.clone(),
                    function: function.name.clone(),
                };
                findings.push(Finding::new(statement.span, kind));
            }
        }
    }
    for parameter in contract
        .parameters
        .iter()
        .filter(|p| !used.contains(p.name.as_str()))
    {
        let kind = FindingKind::UnusedParameter {
            name: parameter.name.clone(),
        };
        findings.push(Finding::new(parameter.span, kind));
    }
}
