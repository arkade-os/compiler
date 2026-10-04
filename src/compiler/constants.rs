use crate::models::{
    AssignmentTarget, Constant, Contract, ExprKind, Expression, KeyExpr, LocatedStatement,
    Requirement, Statement, TapItem,
};
use crate::operators::{BinaryOperator, OperatorClass, UnaryOperator};
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
        constant.value = constant
            .value
            .with_kind(ExprKind::Literal(values[&constant.name].clone()));
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

// ponytail: constants are i64 while the VM allows 520-byte numbers, so results past i64
// (e.g. 1 << 63) are rejected; widen to a bignum here if contracts need them.
fn integer(text: &str) -> Result<i64, String> {
    text.parse()
        .map_err(|_| format!("expected a signed 64-bit integer, got '{text}'"))
}

// Validate skipped operands without evaluating their arithmetic.
fn validate_expression(
    expression: &Expression,
    resolve: &mut impl FnMut(&str) -> Result<String, String>,
) -> Result<&'static str, String> {
    match &expression.kind {
        ExprKind::Literal(text) => {
            if kind(text) == "int" {
                integer(text)?;
            }
            Ok(kind(text))
        }
        ExprKind::Variable(name) | ExprKind::Property(name) => Ok(kind(&resolve(name)?)),
        ExprKind::Unary { op, value } => {
            let expected = match op {
                UnaryOperator::Invert => {
                    return Err(format!(
                        "operator '{}' is not supported in constant expressions",
                        op.symbol()
                    ))
                }
                UnaryOperator::Not => "bool",
                UnaryOperator::Neg => {
                    if let ExprKind::Literal(text) = &value.as_ref().kind {
                        integer(&format!("-{text}"))?;
                        return Ok("int");
                    }
                    "int"
                }
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
        ExprKind::BinaryOp { left, op, right } => {
            let left = validate_expression(left, resolve)?;
            let right = validate_expression(right, resolve)?;
            let valid = match op.class() {
                OperatorClass::Logical => left == "bool" && right == "bool",
                OperatorClass::Equality => left == right,
                OperatorClass::Bytewise => {
                    return Err(format!(
                        "operator '{op}' is not supported in constant expressions"
                    ))
                }
                OperatorClass::Arithmetic | OperatorClass::Shift | OperatorClass::Ordering => {
                    left == "int" && right == "int"
                }
            };
            if !valid {
                return Err(match op.class() {
                    OperatorClass::Logical => format!("operator '{op}' requires bool constants"),
                    OperatorClass::Equality => {
                        format!("operator '{op}' requires constants of the same type")
                    }
                    _ => "expected a signed 64-bit integer".to_string(),
                });
            }
            Ok(
                if matches!(op.class(), OperatorClass::Arithmetic | OperatorClass::Shift) {
                    "int"
                } else {
                    "bool"
                },
            )
        }
        _ => Err("initializer must be a constant expression".to_string()),
    }
}

fn evaluate(
    expression: &Expression,
    resolve: &mut impl FnMut(&str) -> Result<String, String>,
) -> Result<String, String> {
    let overflow = || "integer overflow in constant expression".to_string();
    match &expression.kind {
        ExprKind::Literal(text) => match kind(text) {
            "int" => Ok(integer(text)?.to_string()),
            _ => Ok(text.clone()),
        },
        ExprKind::Variable(name) | ExprKind::Property(name) => resolve(name),
        ExprKind::Unary {
            op: UnaryOperator::Neg,
            value,
        } => {
            if let ExprKind::Literal(text) = &value.as_ref().kind {
                return Ok(integer(&format!("-{text}"))?.to_string());
            }
            let value = evaluate(value, resolve)?;
            Ok(integer(&value)?
                .checked_neg()
                .ok_or_else(overflow)?
                .to_string())
        }
        ExprKind::Unary {
            op: UnaryOperator::Not,
            value,
        } => {
            let value = evaluate(value, resolve)?;
            match value.as_str() {
                "true" => Ok("false".to_string()),
                "false" => Ok("true".to_string()),
                _ => Err("operator '!' requires a bool constant".to_string()),
            }
        }
        ExprKind::BinaryOp { left, op, right } => {
            let left = evaluate(left, resolve)?;
            if op.class() == OperatorClass::Logical {
                if (*op == BinaryOperator::And && left == "false")
                    || (*op == BinaryOperator::Or && left == "true")
                {
                    return Ok(left);
                }
                return evaluate(right, resolve);
            }
            let right = evaluate(right, resolve)?;
            if op.class() == OperatorClass::Equality {
                if kind(&left) != kind(&right) {
                    return Err(format!(
                        "operator '{op}' requires constants of the same type"
                    ));
                }
                // Hex literals carry whole byte pairs in either case.
                return Ok(
                    (left.eq_ignore_ascii_case(&right) == (*op == BinaryOperator::Eq)).to_string(),
                );
            }
            let (left, right) = (integer(&left)?, integer(&right)?);
            let value = match op {
                BinaryOperator::Add => left.checked_add(right),
                BinaryOperator::Sub => left.checked_sub(right),
                BinaryOperator::Mul => left.checked_mul(right),
                BinaryOperator::Div if right == 0 => {
                    return Err("division by zero in constant expression".to_string())
                }
                BinaryOperator::Div => left.checked_div(right),
                BinaryOperator::Shl | BinaryOperator::Shr if right < 0 => {
                    return Err("negative shift count in constant expression".to_string())
                }
                // OP_LSHIFT and OP_RSHIFT read the count as a 4-byte script number.
                BinaryOperator::Shl | BinaryOperator::Shr if right > i64::from(i32::MAX) => {
                    return Err("shift count exceeds 4-byte script number".to_string())
                }
                // OP_LSHIFT leaves zero as zero for any count.
                BinaryOperator::Shl if left == 0 => Some(0),
                // The shift overflowed if shifting back does not restore the operand.
                BinaryOperator::Shl => u32::try_from(right).ok().and_then(|count| {
                    left.checked_shl(count)
                        .filter(|value| value >> count == left)
                }),
                // Arithmetic shift rounds toward negative infinity, as OP_RSHIFT does.
                BinaryOperator::Shr => Some(left >> right.min(63)),
                BinaryOperator::Lt => return Ok((left < right).to_string()),
                BinaryOperator::Le => return Ok((left <= right).to_string()),
                BinaryOperator::Gt => return Ok((left > right).to_string()),
                BinaryOperator::Ge => return Ok((left >= right).to_string()),
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
    statements: &mut [LocatedStatement],
    values: &HashMap<String, String>,
) -> Result<(), String> {
    for statement in statements {
        match &mut statement.statement {
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
                if let AssignmentTarget::ArrayIndex { index, .. }
                | AssignmentTarget::Access(index) = target
                {
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
                    *count = count.with_kind(ExprKind::Literal(value));
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
            fold_expression(signature, values);
            fold_expression(pubkey, values);
        }
        Requirement::CheckSigFromStack {
            signature,
            pubkey,
            message,
        } => {
            for operand in [signature, pubkey, message] {
                fold_expression(operand, values);
            }
        }
        Requirement::CheckMultisig {
            pubkeys,
            signatures,
            ..
        } => {
            for operand in pubkeys.iter_mut().chain(signatures) {
                fold_expression(operand, values);
            }
        }
        Requirement::HashEqual { preimage, hash, .. } => {
            fold_expression(preimage, values);
            fold_expression(hash, values);
        }
    }
}

fn fold_expression(expression: &mut Expression, values: &HashMap<String, String>) {
    if let ExprKind::Variable(name) | ExprKind::Property(name) = &expression.kind {
        if let Some(value) = values.get(name) {
            *expression = expression.with_kind(ExprKind::Literal(value.clone()));
            return;
        }
    }
    if let ExprKind::Tunnel { policy, .. } = &mut expression.kind {
        for value in policy.iter_mut() {
            if let Ok(literal) = evaluate(value, &mut |name| {
                values
                    .get(name)
                    .cloned()
                    .ok_or_else(|| format!("unknown constant '{name}'"))
            }) {
                *value = value.with_kind(ExprKind::Literal(literal));
            }
        }
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
    let mut cursor = 0;
    while let Some(open) = name[cursor..].find('[').map(|offset| cursor + offset + 1) {
        let Some(close) = name[open..].find(']').map(|offset| open + offset) else {
            break;
        };
        cursor = if let Some(value) = values.get(&name[open..close]) {
            name.replace_range(open..close, value);
            open + value.len() + 1
        } else {
            close + 1
        };
    }
}
