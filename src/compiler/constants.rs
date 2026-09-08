use crate::models::{
    AssignmentTarget, Constant, Contract, Expression, KeyExpr, Requirement, Statement, TapItem,
};
use std::collections::HashMap;

/// Validate constant declarations and fold every reference to them into a literal.
/// Runs before validation so no later stage ever observes a constant identifier.
pub(crate) fn fold(contract: &mut Contract) -> Result<(), String> {
    let values = collect(contract)?;
    if values.is_empty() {
        return Ok(());
    }
    for function in &mut contract.functions {
        fold_statements(&mut function.statements, &values);
    }
    for tapscript in &mut contract.tapscripts {
        for item in &mut tapscript.items {
            match item {
                TapItem::Older { value } | TapItem::After { value } => {
                    if let Some(text) = values.get(value.as_str()) {
                        *value = text.clone();
                    }
                }
                TapItem::Hash { preimage, hash, .. } => {
                    fold_named_index(preimage, &values);
                    fold_named_index(hash, &values);
                }
                TapItem::Sig { keys, sigs, .. } => {
                    for key in keys {
                        if let KeyExpr::Ident(name) = key {
                            fold_named_index(name, &values);
                        }
                    }
                    for name in sigs {
                        fold_named_index(name, &values);
                    }
                }
            }
        }
    }
    Ok(())
}

fn collect(contract: &Contract) -> Result<HashMap<String, String>, String> {
    let mut values: HashMap<String, String> = HashMap::new();
    for Constant {
        name,
        const_type,
        value,
    } in &contract.constants
    {
        if matches!(
            name.as_str(),
            "true" | "false" | "server" | "emulator" | "SERVER_KEY"
        ) {
            return Err(format!("constant name '{name}' is reserved"));
        }
        if values.contains_key(name) {
            return Err(format!("duplicate constant '{name}'"));
        }
        if contract.parameters.iter().any(|p| p.name == *name) {
            return Err(format!(
                "constant '{name}' collides with constructor parameter '{name}'"
            ));
        }
        if contract.functions.iter().any(|f| f.name == *name)
            || contract.tapscripts.iter().any(|t| t.name == *name)
        {
            return Err(format!("constant '{name}' collides with function '{name}'"));
        }
        let Expression::Literal(text) = value else {
            return Err(format!(
                "constant '{name}' must be initialized with a literal"
            ));
        };
        let matches_type = match const_type.as_str() {
            "int" => text.bytes().all(|b| b.is_ascii_digit()),
            "bool" => text == "true" || text == "false",
            _ => return Err(format!("constant '{name}' must be int or bool")),
        };
        if !matches_type {
            return Err(format!(
                "constant '{name}' is not a valid '{const_type}' literal"
            ));
        }
        values.insert(name.clone(), text.clone());
    }
    Ok(values)
}

fn fold_statements(statements: &mut [Statement], values: &HashMap<String, String>) {
    for statement in statements {
        match statement {
            Statement::Call(expression)
            | Statement::Return(Some(expression))
            | Statement::LetBinding {
                value: expression, ..
            } => fold_expression(expression, values),
            Statement::VarAssign { target, value } => {
                if let AssignmentTarget::ArrayIndex { index, .. } = target {
                    fold_expression(index, values);
                }
                fold_expression(value, values);
            }
            Statement::Require(requirement) => fold_requirement(requirement, values),
            Statement::IfElse {
                condition,
                then_body,
                else_body,
            } => {
                fold_expression(condition, values);
                fold_statements(then_body, values);
                if let Some(body) = else_body {
                    fold_statements(body, values);
                }
            }
            Statement::ForIn { iterable, body, .. } => {
                fold_expression(iterable, values);
                fold_statements(body, values);
            }
            Statement::Return(None) => {}
        }
    }
}

fn fold_requirement(requirement: &mut Requirement, values: &HashMap<String, String>) {
    match requirement {
        Requirement::Expression(expression) => fold_expression(expression, values),
        Requirement::Comparison { left, right, .. } => {
            fold_expression(left, values);
            fold_expression(right, values);
        }
        Requirement::CheckSig { signature, pubkey } => {
            fold_named_index(signature, values);
            fold_named_index(pubkey, values);
        }
        Requirement::CheckSigFromStack {
            signature,
            pubkey,
            message,
        } => {
            fold_named_index(signature, values);
            fold_named_index(pubkey, values);
            fold_named_index(message, values);
        }
        Requirement::CheckMultisig {
            pubkeys,
            signatures,
            ..
        } => {
            for name in pubkeys.iter_mut().chain(signatures) {
                fold_named_index(name, values);
            }
        }
        Requirement::HashEqual { preimage, hash, .. } => {
            fold_named_index(preimage, values);
            fold_named_index(hash, values);
        }
    }
}

fn fold_expression(expression: &mut Expression, values: &HashMap<String, String>) {
    match expression {
        Expression::Variable(name) => {
            if let Some(text) = values.get(name.as_str()) {
                *expression = Expression::Literal(text.clone());
                return;
            }
        }
        Expression::Property(name) => fold_named_index(name, values),
        Expression::CheckSigExpr { signature, pubkey } => {
            fold_named_index(signature, values);
            fold_named_index(pubkey, values);
        }
        Expression::CheckSigFromStackExpr {
            signature,
            pubkey,
            message,
        }
        | Expression::CheckSigFromStackVerify {
            signature,
            pubkey,
            message,
        } => {
            fold_named_index(signature, values);
            fold_named_index(pubkey, values);
            fold_named_index(message, values);
        }
        _ => {}
    }
    for child in crate::models::child_exprs_mut(expression) {
        fold_expression(child, values);
    }
}

fn fold_named_index(name: &mut String, values: &HashMap<String, String>) {
    if let Some((array, index)) = name.strip_suffix(']').and_then(|name| name.split_once('[')) {
        if let Some(value) = values.get(index) {
            *name = format!("{array}[{value}]");
        }
    }
}
