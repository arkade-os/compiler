//! Rejects bindings that shadow a constructor parameter, a constant, or a binding live in an
//! enclosing scope, and assignments to constructor parameters or constants.

use std::collections::HashSet;

use super::error::Declared;
use super::{ValidationError, ValidationIssue};
use crate::models::{AssignmentTarget, Contract, LocatedStatement, Path, Statement};

pub(super) fn check_shadowing(contract: &Contract, issues: &mut Vec<ValidationIssue>) {
    let ctor_names: HashSet<&str> = contract
        .parameters
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    let const_names: HashSet<&str> = contract.constants.iter().map(|c| c.name.as_str()).collect();

    for tapscript in &contract.tapscripts {
        for input in &tapscript.inputs {
            let (input_name, tapscript) = (input.name.clone(), tapscript.name.clone());
            if ctor_names.contains(input.name.as_str()) {
                let error = ValidationError::InputShadowsParameter {
                    input: input_name.clone(),
                    tapscript: tapscript.clone(),
                };
                issues.push(error.at(input.span));
            }
            if const_names.contains(input.name.as_str()) {
                let error = ValidationError::InputShadowsConstant {
                    input: input_name,
                    tapscript,
                };
                issues.push(error.at(input.span));
            }
        }
    }

    for func in contract.functions.iter().filter(|f| !f.is_imported()) {
        let first = issues.len();
        let mut seed: HashSet<String> = ctor_names
            .iter()
            .chain(&const_names)
            .map(|s| s.to_string())
            .collect();
        for param in &func.parameters {
            let (parameter, function) = (param.name.clone(), func.name.clone());
            if ctor_names.contains(param.name.as_str()) {
                let error = ValidationError::ParameterShadowsParameter {
                    parameter: parameter.clone(),
                    function: function.clone(),
                };
                issues.push(error.into());
            }
            if const_names.contains(param.name.as_str()) {
                let error = ValidationError::ParameterShadowsConstant {
                    parameter,
                    function,
                };
                issues.push(error.into());
            }
            seed.insert(param.name.clone());
        }

        let mut stack: Vec<HashSet<String>> = vec![seed];
        walk_scope(&func.statements, &func.name, &mut stack, issues);

        check_ctor_assignment(
            &func.statements,
            &func.name,
            &ctor_names,
            &const_names,
            issues,
        );
        super::locate(&mut issues[first..], func.span);
    }
}

fn check_ctor_assignment(
    stmts: &[LocatedStatement],
    fname: &str,
    ctor_names: &HashSet<&str>,
    const_names: &HashSet<&str>,
    issues: &mut Vec<ValidationIssue>,
) {
    for stmt in stmts {
        let first = issues.len();
        match &stmt.statement {
            Statement::VarAssign { target, .. } => {
                let name = match target {
                    AssignmentTarget::Access(value) => {
                        value.binding_path().unwrap_or(Path::new(""))
                    }
                    AssignmentTarget::Binding(name) => name.clone(),
                    AssignmentTarget::ArrayIndex { array, .. } => array.clone(),
                };
                let root = name.root.as_str();
                let function = fname.to_string();
                if ctor_names.contains(root) {
                    let error = ValidationError::ConstructorParameterAssigned {
                        name: name.clone(),
                        function: function.clone(),
                    };
                    issues.push(error.into());
                }
                if const_names.contains(root) {
                    issues.push(ValidationError::ConstantAssigned { name, function }.into());
                }
            }
            Statement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                check_ctor_assignment(then_body, fname, ctor_names, const_names, issues);
                if let Some(eb) = else_body {
                    check_ctor_assignment(eb, fname, ctor_names, const_names, issues);
                }
            }
            Statement::ForIn { body, .. }
            | Statement::ForCount { body, .. }
            | Statement::ForRange { body, .. } => {
                check_ctor_assignment(body, fname, ctor_names, const_names, issues);
            }
            Statement::Declaration { .. }
            | Statement::LetBinding { .. }
            | Statement::Require(_)
            | Statement::Call(_)
            | Statement::Return(_) => {}
        }
        super::locate(&mut issues[first..], stmt.span);
    }
}

fn in_scope(stack: &[HashSet<String>], name: &str) -> bool {
    stack.iter().any(|frame| frame.contains(name))
}

/// Each block is its own frame, so bindings in sibling blocks do not conflict.
fn walk_scope(
    stmts: &[LocatedStatement],
    fname: &str,
    stack: &mut Vec<HashSet<String>>,
    issues: &mut Vec<ValidationIssue>,
) {
    for stmt in stmts {
        let first = issues.len();
        match &stmt.statement {
            Statement::Declaration { name, .. } | Statement::LetBinding { name, .. } => {
                let function = fname.to_string();
                let context = Declared::FunctionBinding { function };
                super::validate_source_identifier(name, context, issues);
                if in_scope(stack, name) {
                    let error = ValidationError::ShadowsBinding {
                        name: name.clone(),
                        function: fname.to_string(),
                    };
                    issues.push(error.into());
                } else {
                    stack
                        .last_mut()
                        .expect("non-empty scope stack")
                        .insert(name.clone());
                }
            }
            Statement::ForIn {
                index_var,
                value_var,
                body,
                ..
            } => {
                for name in [index_var, value_var] {
                    let function = fname.to_string();
                    let context = Declared::LoopVariable { function };
                    super::validate_source_identifier(name, context, issues);
                }
                if index_var == value_var {
                    let error = ValidationError::SameLoopVariables {
                        function: fname.to_string(),
                        name: index_var.clone(),
                    };
                    issues.push(error.into());
                }
                for v in [index_var, value_var] {
                    if in_scope(stack, v) {
                        let error = ValidationError::LoopVariableShadows {
                            name: v.clone(),
                            function: fname.to_string(),
                        };
                        issues.push(error.into());
                    }
                }
                let mut frame = HashSet::new();
                frame.insert(index_var.clone());
                frame.insert(value_var.clone());
                stack.push(frame);
                walk_scope(body, fname, stack, issues);
                stack.pop();
            }
            Statement::ForRange {
                index_var, body, ..
            } => {
                let function = fname.to_string();
                let context = Declared::LoopVariable { function };
                super::validate_source_identifier(index_var, context, issues);
                if in_scope(stack, index_var) {
                    let error = ValidationError::LoopVariableShadows {
                        name: index_var.clone(),
                        function: fname.to_string(),
                    };
                    issues.push(error.into());
                }
                stack.push(HashSet::from([index_var.clone()]));
                walk_scope(body, fname, stack, issues);
                stack.pop();
            }
            Statement::ForCount { body, .. } => {
                stack.push(HashSet::new());
                walk_scope(body, fname, stack, issues);
                stack.pop();
            }
            Statement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                stack.push(HashSet::new());
                walk_scope(then_body, fname, stack, issues);
                stack.pop();
                if let Some(eb) = else_body {
                    stack.push(HashSet::new());
                    walk_scope(eb, fname, stack, issues);
                    stack.pop();
                }
            }
            Statement::VarAssign { .. }
            | Statement::Require(_)
            | Statement::Call(_)
            | Statement::Return(_) => {}
        }
        super::locate(&mut issues[first..], stmt.span);
    }
}
