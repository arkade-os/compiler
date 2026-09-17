use crate::models::{
    AssignmentTarget, Constant, Contract, Expression, KeyExpr, Requirement, Statement, TapItem,
};
use std::collections::HashMap;

/// Validate constant declarations and fold every reference to them into a literal.
/// Runs before validation so no later stage ever observes a constant identifier.
pub(crate) fn fold(contract: &mut Contract) -> Result<(), String> {
    let values = collect(contract)?;
    for parameter in contract
        .parameters
        .iter_mut()
        .chain(contract.structs.iter_mut().flat_map(|s| &mut s.fields))
    {
        fold_type(&mut parameter.param_type, &values)?;
    }
    for function in contract.functions.iter_mut().filter(|f| !f.is_imported()) {
        for parameter in &mut function.parameters {
            fold_type(&mut parameter.param_type, &values)?;
        }
        if let Some(return_type) = &mut function.return_type {
            fold_type(return_type, &values)?;
        }
        fold_statements(&mut function.statements, &values)?;
    }
    for tapscript in &mut contract.tapscripts {
        for input in &mut tapscript.inputs {
            fold_type(&mut input.param_type, &values)?;
        }
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
    let mut declarations = HashMap::new();
    for constant in &contract.constants {
        let Constant {
            name, const_type, ..
        } = constant;
        if matches!(
            name.as_str(),
            "true" | "false" | "server" | "emulator" | "SERVER_KEY"
        ) {
            return Err(format!("constant name '{name}' is reserved"));
        }
        if declarations.contains_key(name) {
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
        if !matches!(const_type.as_str(), "int" | "bool" | "bytes") {
            return Err(format!("constant '{name}' must be int, bool or bytes"));
        }
        declarations.insert(name.clone(), constant);
    }
    for constant in contract.constants.iter().filter(|c| !c.name.contains('.')) {
        declarations.insert(format!("{}.{}", contract.name, constant.name), constant);
    }
    let mut values = HashMap::new();
    for constant in &contract.constants {
        resolve_value(&constant.name, &declarations, &mut values, &mut Vec::new())?;
    }
    for constant in contract.constants.iter().filter(|c| !c.name.contains('.')) {
        values.insert(
            format!("{}.{}", contract.name, constant.name),
            values[&constant.name].clone(),
        );
    }
    Ok(values)
}

/// Threshold parsing and import exports need evaluated declarations.
pub(crate) fn resolve(contract: &mut Contract) -> Result<(), String> {
    let values = collect(contract)?;
    for constant in &mut contract.constants {
        constant.value = Expression::Literal(values[&constant.name].clone());
    }
    Ok(())
}

fn resolve_value(
    name: &str,
    declarations: &HashMap<String, &Constant>,
    values: &mut HashMap<String, String>,
    active: &mut Vec<String>,
) -> Result<String, String> {
    let constant = declarations
        .get(name)
        .ok_or_else(|| format!("unknown constant '{name}'"))?;
    let name = &constant.name;
    if let Some(value) = values.get(name) {
        return Ok(value.clone());
    }
    if active.contains(name) {
        return Err(format!("cyclic constant reference '{name}'"));
    }
    // Recursive evaluation is bounded; use an iterative traversal for deeper expressions.
    if active.len() >= 128 {
        return Err("constant dependency depth exceeds 128".to_string());
    }
    active.push(name.clone());
    // A nested failure already names the constant it came from; keep that one name.
    let mut resolve = |name: &str| resolve_value(name, declarations, values, active);
    let value = validate_expression(&constant.value, &mut resolve)
        .and_then(|_| evaluate(&constant.value, &mut resolve))
        .map_err(|error| match error.starts_with("constant '") {
            true => error,
            false => format!("constant '{name}': {error}"),
        })?;
    active.pop();
    if kind(&value) != constant.const_type {
        return Err(format!(
            "constant '{name}' is not a valid '{}' literal",
            constant.const_type
        ));
    }
    values.insert(name.clone(), value.clone());
    Ok(value)
}

/// The declared type a folded value belongs to.
fn kind(value: &str) -> &'static str {
    match value {
        "true" | "false" => "bool",
        _ if value.starts_with("0x") => "bytes",
        _ => "int",
    }
}

fn integer(text: &str) -> Result<i64, String> {
    text.parse()
        .map_err(|_| format!("expected a signed 64-bit integer, got '{text}'"))
}

// Validate skipped operands without evaluating their arithmetic.
fn validate_expression(
    expression: &Expression,
    resolve: &mut impl FnMut(&str) -> Result<String, String>,
) -> Result<&'static str, String> {
    match expression {
        Expression::Literal(text) => {
            if kind(text) == "int" {
                integer(text)?;
            }
            Ok(kind(text))
        }
        Expression::Variable(name) | Expression::Property(name) => Ok(kind(&resolve(name)?)),
        Expression::Negate { value } | Expression::Not { value } => {
            let expected = if matches!(expression, Expression::Not { .. }) {
                "bool"
            } else {
                if let Expression::Literal(text) = value.as_ref() {
                    integer(&format!("-{text}"))?;
                    return Ok("int");
                }
                "int"
            };
            if validate_expression(value, resolve)? != expected {
                return Err(if expected == "bool" {
                    "operator '!' requires a bool constant".to_string()
                } else {
                    "expected a signed 64-bit integer".to_string()
                });
            }
            Ok(expected)
        }
        Expression::BinaryOp { left, op, right } => {
            let left = validate_expression(left, resolve)?;
            let right = validate_expression(right, resolve)?;
            let valid = match op.as_str() {
                "&&" | "||" => left == "bool" && right == "bool",
                "==" | "!=" => left == right,
                _ => left == "int" && right == "int",
            };
            if !valid {
                return Err(match op.as_str() {
                    "&&" | "||" => format!("operator '{op}' requires bool constants"),
                    "==" | "!=" => format!("operator '{op}' requires constants of the same type"),
                    _ => "expected a signed 64-bit integer".to_string(),
                });
            }
            Ok(if matches!(op.as_str(), "+" | "-" | "*" | "/") {
                "int"
            } else {
                "bool"
            })
        }
        _ => Err("initializer must be a constant expression".to_string()),
    }
}

fn evaluate(
    expression: &Expression,
    resolve: &mut impl FnMut(&str) -> Result<String, String>,
) -> Result<String, String> {
    let overflow = || "integer overflow in constant expression".to_string();
    match expression {
        Expression::Literal(text) => match kind(text) {
            "int" => Ok(integer(text)?.to_string()),
            _ => Ok(text.clone()),
        },
        Expression::Variable(name) | Expression::Property(name) => resolve(name),
        Expression::Negate { value } => {
            if let Expression::Literal(text) = value.as_ref() {
                return Ok(integer(&format!("-{text}"))?.to_string());
            }
            let value = evaluate(value, resolve)?;
            Ok(integer(&value)?
                .checked_neg()
                .ok_or_else(overflow)?
                .to_string())
        }
        Expression::Not { value } => {
            let value = evaluate(value, resolve)?;
            match value.as_str() {
                "true" => Ok("false".to_string()),
                "false" => Ok("true".to_string()),
                _ => Err("operator '!' requires a bool constant".to_string()),
            }
        }
        Expression::BinaryOp { left, op, right } => {
            let left = evaluate(left, resolve)?;
            if matches!(op.as_str(), "&&" | "||") {
                if (op == "&&" && left == "false") || (op == "||" && left == "true") {
                    return Ok(left);
                }
                return evaluate(right, resolve);
            }
            let right = evaluate(right, resolve)?;
            if matches!(op.as_str(), "==" | "!=") {
                if kind(&left) != kind(&right) {
                    return Err(format!(
                        "operator '{op}' requires constants of the same type"
                    ));
                }
                // Hex literals carry whole byte pairs in either case.
                return Ok((left.eq_ignore_ascii_case(&right) == (op == "==")).to_string());
            }
            let (left, right) = (integer(&left)?, integer(&right)?);
            let value = match op.as_str() {
                "+" => left.checked_add(right),
                "-" => left.checked_sub(right),
                "*" => left.checked_mul(right),
                "/" if right == 0 => {
                    return Err("division by zero in constant expression".to_string())
                }
                "/" => left.checked_div(right),
                "<" => return Ok((left < right).to_string()),
                "<=" => return Ok((left <= right).to_string()),
                ">" => return Ok((left > right).to_string()),
                ">=" => return Ok((left >= right).to_string()),
                _ => return Err(format!("unsupported constant operator '{op}'")),
            };
            Ok(value.ok_or_else(overflow)?.to_string())
        }
        _ => Err("initializer must be a constant expression".to_string()),
    }
}

fn fold_type(declared_type: &mut String, values: &HashMap<String, String>) -> Result<(), String> {
    if let Some((base, size)) = declared_type
        .strip_suffix(']')
        .and_then(|ty| ty.split_once('['))
    {
        let value = values.get(size).map(String::as_str).unwrap_or(size);
        let size = value
            .parse::<usize>()
            .ok()
            .filter(|size| *size > 0)
            .ok_or_else(|| {
                format!("array size '{size}' must be a positive integer literal or int constant")
            })?;
        *declared_type = format!("{base}[{size}]");
    }
    Ok(())
}

fn fold_statements(
    statements: &mut [Statement],
    values: &HashMap<String, String>,
) -> Result<(), String> {
    for statement in statements {
        match statement {
            Statement::Call(expression) | Statement::Return(Some(expression)) => {
                fold_expression(expression, values)
            }
            Statement::LetBinding {
                declared_type,
                value,
                ..
            } => {
                if let Some(declared_type) = declared_type {
                    fold_type(declared_type, values)?;
                }
                fold_expression(value, values);
            }
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
                fold_statements(then_body, values)?;
                if let Some(body) = else_body {
                    fold_statements(body, values)?;
                }
            }
            Statement::ForIn { iterable, body, .. } => {
                fold_expression(iterable, values);
                fold_statements(body, values)?;
            }
            Statement::ForCount { count, body } => {
                fold_expression(count, values);
                if let Ok(value) = evaluate(count, &mut |_| Err("runtime value".to_string())) {
                    *count = Expression::Literal(value);
                }
                fold_statements(body, values)?;
            }
            Statement::Return(None) => {}
        }
    }
    Ok(())
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
        Expression::Variable(name) | Expression::Property(name) if values.contains_key(name) => {
            *expression = Expression::Literal(values[name].clone());
            return;
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
    if let Some(value) = values.get(name).filter(|value| value.starts_with("0x")) {
        *name = value.clone();
        return;
    }
    if let Some((array, index)) = name.strip_suffix(']').and_then(|name| name.split_once('[')) {
        if let Some(value) = values.get(index) {
            *name = format!("{array}[{value}]");
        }
    }
}
