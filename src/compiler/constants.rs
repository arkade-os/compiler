//! Constant folding: evaluates `const` declarations and replaces every reference to one with a
//! literal. Runs before validation, so no later stage sees a constant name.

use std::collections::HashMap;
use std::{error, fmt, result};

use crate::diagnostics::{CompileError, Span};
use crate::models::{
    self, ArraySize, AssignmentTarget, Constant, Contract, ExprKind, Expression, LocatedStatement,
    Path, Statement, TypeName, RESERVED_NAMES, RESERVED_PLACEHOLDERS,
};
use crate::operators::{BinaryOperator, OperatorClass, UnaryOperator};

type Result<T, E = ConstantError> = result::Result<T, E>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConstantError {
    ReservedName {
        name: String,
    },
    Duplicate {
        name: String,
    },
    CollidesWithParameter {
        name: String,
    },
    CollidesWithFunction {
        name: String,
    },
    UnsupportedType {
        name: String,
    },
    UnknownConstant {
        name: String,
    },
    Cyclic {
        name: String,
    },
    TooDeep,
    InConstant {
        name: String,
        error: Box<ConstantError>,
    },
    InvalidLiteral {
        name: String,
        ty: TypeName,
    },
    ExpectedIntegerGot {
        value: String,
    },
    ExpectedInteger,
    IntegerTooWide {
        value: String,
    },
    UnsupportedOperator {
        op: &'static str,
    },
    NotRequiresBool,
    RequiresBool {
        op: BinaryOperator,
    },
    RequiresSameType {
        op: BinaryOperator,
    },
    NotConstantExpression,
    Overflow,
    DivisionByZero,
    ModuloByZero,
    NegativeShift,
    ShiftTooWide,
    UnsupportedConstantOperator {
        op: BinaryOperator,
    },
    ArraySizeNotPositive {
        written: String,
    },
}

impl ConstantError {
    pub(crate) fn unknown(path: &Path) -> Self {
        ConstantError::UnknownConstant { name: path.key() }
    }
}

/// A resolver for expressions that may name no constant.
pub(crate) fn no_names(path: &Path) -> Result<String> {
    Err(ConstantError::unknown(path))
}

impl fmt::Display for ConstantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConstantError::ReservedName { name } => write!(f, "constant name '{name}' is reserved"),
            ConstantError::Duplicate { name } => write!(f, "duplicate constant '{name}'"),
            ConstantError::CollidesWithParameter { name } => write!(
                f,
                "constant '{name}' collides with constructor parameter '{name}'"
            ),
            ConstantError::CollidesWithFunction { name } => {
                write!(f, "constant '{name}' collides with function '{name}'")
            }
            ConstantError::UnsupportedType { name } => write!(
                f,
                "constant '{name}' must be int, bool, bytes, bytes20, bytes32 or pubkey"
            ),
            ConstantError::UnknownConstant { name } => write!(f, "unknown constant '{name}'"),
            ConstantError::Cyclic { name } => write!(f, "cyclic constant reference '{name}'"),
            ConstantError::TooDeep => f.write_str("constant dependency depth exceeds 128"),
            ConstantError::InConstant { name, error } => write!(f, "constant '{name}': {error}"),
            ConstantError::InvalidLiteral { name, ty } => {
                write!(f, "constant '{name}' is not a valid '{ty}' literal")
            }
            ConstantError::ExpectedIntegerGot { value } => {
                write!(f, "expected an integer, got '{value}'")
            }
            ConstantError::ExpectedInteger => f.write_str("expected an integer"),
            ConstantError::IntegerTooWide { value } => {
                write!(f, "constant arithmetic exceeds 128 bits, got '{value}'")
            }
            ConstantError::UnsupportedOperator { op } => {
                write!(
                    f,
                    "operator '{op}' is not supported in constant expressions"
                )
            }
            ConstantError::NotRequiresBool => f.write_str("operator '!' requires a bool constant"),
            ConstantError::RequiresBool { op } => {
                write!(f, "operator '{op}' requires bool constants")
            }
            ConstantError::RequiresSameType { op } => {
                write!(f, "operator '{op}' requires constants of the same type")
            }
            ConstantError::NotConstantExpression => {
                f.write_str("initializer must be a constant expression")
            }
            ConstantError::Overflow => f.write_str("integer overflow in constant expression"),
            ConstantError::DivisionByZero => f.write_str("division by zero in constant expression"),
            ConstantError::ModuloByZero => f.write_str("modulo by zero in constant expression"),
            ConstantError::NegativeShift => {
                f.write_str("negative shift count in constant expression")
            }
            ConstantError::ShiftTooWide => f.write_str("shift count exceeds 4-byte script number"),
            ConstantError::UnsupportedConstantOperator { op } => {
                write!(f, "unsupported constant operator '{op}'")
            }
            ConstantError::ArraySizeNotPositive { written } => write!(
                f,
                "array size '{written}' must be a positive integer literal or int constant"
            ),
        }
    }
}

impl error::Error for ConstantError {}

/// Returns the path and span of each reference folded inside an expression.
pub(crate) fn fold(contract: &mut Contract) -> Result<Vec<(Path, Span)>, CompileError> {
    let values = collect(contract)?;
    let mut uses = Vec::new();
    for parameter in contract
        .parameters
        .iter_mut()
        .chain(contract.structs.iter_mut().flat_map(|s| &mut s.fields))
    {
        fold_type(&mut parameter.param_type, &values).map_err(at(parameter.span))?;
    }
    for function in contract.functions.iter_mut().filter(|f| !f.is_imported()) {
        for parameter in &mut function.parameters {
            fold_type(&mut parameter.param_type, &values).map_err(at(parameter.span))?;
        }
        if let Some(return_type) = &mut function.return_type {
            fold_type(return_type, &values).map_err(at(function.span))?;
        }
        fold_statements(&mut function.statements, &values, &mut uses)?;
    }
    for tapscript in &mut contract.tapscripts {
        for input in &mut tapscript.inputs {
            fold_type(&mut input.param_type, &values).map_err(at(input.span))?;
        }
    }
    Ok(uses)
}

fn at(span: Span) -> impl Fn(ConstantError) -> CompileError {
    move |error| CompileError::from(error).at(span)
}

/// An imported constant (a dotted name) is declared in another file, so its errors carry no span.
fn at_constant(constant: &Constant) -> impl Fn(ConstantError) -> CompileError + '_ {
    move |error| match constant.name.contains('.') {
        true => CompileError::from(error),
        false => CompileError::from(error).at(constant.span),
    }
}

fn collect(contract: &Contract) -> Result<HashMap<String, String>, CompileError> {
    let mut declarations = HashMap::new();
    for constant in &contract.constants {
        let Constant {
            name, const_type, ..
        } = constant;
        let error = at_constant(constant);
        let name = name.clone();
        if matches!(name.as_str(), "true" | "false")
            || RESERVED_NAMES.contains(&name.as_str())
            || RESERVED_PLACEHOLDERS.contains(&name.as_str())
        {
            return Err(error(ConstantError::ReservedName { name }));
        }
        if declarations.contains_key(&name) {
            return Err(error(ConstantError::Duplicate { name }));
        }
        if contract.parameters.iter().any(|p| p.name == name) {
            return Err(error(ConstantError::CollidesWithParameter { name }));
        }
        if contract.functions.iter().any(|f| f.name == name)
            || contract.tapscripts.iter().any(|t| t.name == name)
        {
            return Err(error(ConstantError::CollidesWithFunction { name }));
        }
        if !matches!(
            const_type.name(),
            Some("int" | "bool" | "bytes" | "bytes20" | "bytes32" | "pubkey")
        ) {
            return Err(error(ConstantError::UnsupportedType { name }));
        }
        declarations.insert(name, constant);
    }
    for constant in contract.constants.iter().filter(|c| !c.name.contains('.')) {
        declarations.insert(format!("{}.{}", contract.name, constant.name), constant);
    }
    let mut values = HashMap::new();
    for constant in &contract.constants {
        resolve_value(&constant.name, &declarations, &mut values, &mut Vec::new())
            .map_err(at_constant(constant))?;
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
pub(crate) fn resolve(contract: &mut Contract) -> Result<(), CompileError> {
    let values = collect(contract)?;
    for constant in &mut contract.constants {
        constant.value.kind = ExprKind::Literal(values[&constant.name].clone());
    }
    Ok(())
}

fn resolve_value(
    name: &str,
    declarations: &HashMap<String, &Constant>,
    values: &mut HashMap<String, String>,
    active: &mut Vec<String>,
) -> Result<String> {
    let constant = declarations
        .get(name)
        .ok_or_else(|| ConstantError::UnknownConstant {
            name: name.to_string(),
        })?;
    let name = &constant.name;
    if let Some(value) = values.get(name) {
        return Ok(value.clone());
    }
    if active.contains(name) {
        return Err(ConstantError::Cyclic { name: name.clone() });
    }
    // Recursive evaluation is bounded; use an iterative traversal for deeper expressions.
    if active.len() >= 128 {
        return Err(ConstantError::TooDeep);
    }
    active.push(name.clone());
    // A nested failure already names the constant it came from; keep that one name.
    let mut resolve = |path: &Path| resolve_value(&path.key(), declarations, values, active);
    let value = validate_expression(&constant.value, &mut resolve)
        .and_then(|_| evaluate(&constant.value, &mut resolve))
        .map_err(|error| match error {
            ConstantError::InConstant { .. } | ConstantError::InvalidLiteral { .. } => error,
            _ => ConstantError::InConstant {
                name: name.clone(),
                error: Box::new(error),
            },
        })?;
    active.pop();
    let width = value.strip_prefix("0x").map(|hex| hex.len() / 2);
    let valid = match constant.const_type.name() {
        Some("bytes20") => width == Some(20),
        Some("bytes32") => width == Some(32),
        Some("pubkey") => width.is_some_and(|width| width > 0),
        declared => declared == Some(kind(&value)),
    };
    if !valid {
        return Err(ConstantError::InvalidLiteral {
            name: name.clone(),
            ty: constant.const_type.clone(),
        });
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

// LIMITATION: literals, negation and equality are unbounded like BigNum, but arithmetic and
// ordering fold in i128, so larger operands are rejected; use a bignum if contracts need them.
fn integer(text: &str) -> Result<i128> {
    if kind(text) != "int" {
        return Err(ConstantError::ExpectedIntegerGot {
            value: text.to_string(),
        });
    }
    text.parse().map_err(|_| ConstantError::IntegerTooWide {
        value: text.to_string(),
    })
}

/// Type-checks the operands `evaluate` short-circuits past, without evaluating arithmetic.
fn validate_expression(
    expression: &Expression,
    resolve: &mut impl FnMut(&Path) -> Result<String>,
) -> Result<&'static str> {
    match &expression.kind {
        ExprKind::Literal(text) => Ok(kind(text)),
        ExprKind::Name(path) => Ok(kind(&resolve(path)?)),
        ExprKind::Unary { op, value } => {
            let expected = match op {
                UnaryOperator::Invert => {
                    return Err(ConstantError::UnsupportedOperator { op: op.symbol() })
                }
                UnaryOperator::Not => "bool",
                UnaryOperator::Neg => "int",
            };
            if validate_expression(value, resolve)? != expected {
                return Err(if expected == "bool" {
                    ConstantError::NotRequiresBool
                } else {
                    ConstantError::ExpectedInteger
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
                    return Err(ConstantError::UnsupportedOperator { op: op.symbol() })
                }
                OperatorClass::Arithmetic | OperatorClass::Shift | OperatorClass::Ordering => {
                    left == "int" && right == "int"
                }
            };
            if !valid {
                return Err(match op.class() {
                    OperatorClass::Logical => ConstantError::RequiresBool { op: *op },
                    OperatorClass::Equality => ConstantError::RequiresSameType { op: *op },
                    _ => ConstantError::ExpectedInteger,
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
        _ => Err(ConstantError::NotConstantExpression),
    }
}

pub(crate) fn evaluate(
    expression: &Expression,
    resolve: &mut impl FnMut(&Path) -> Result<String>,
) -> Result<String> {
    match &expression.kind {
        ExprKind::Literal(text) => Ok(text.clone()),
        ExprKind::Name(path) => resolve(path),
        ExprKind::Unary {
            op: UnaryOperator::Neg,
            value,
        } => {
            let value = evaluate(value, resolve)?;
            if kind(&value) != "int" {
                return Err(ConstantError::ExpectedIntegerGot { value });
            }
            Ok(match value.strip_prefix('-') {
                Some(magnitude) => magnitude.to_string(),
                None if value == "0" => value,
                None => format!("-{value}"),
            })
        }
        ExprKind::Unary {
            op: UnaryOperator::Not,
            value,
        } => {
            let value = evaluate(value, resolve)?;
            match value.as_str() {
                "true" => Ok("false".to_string()),
                "false" => Ok("true".to_string()),
                _ => Err(ConstantError::NotRequiresBool),
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
                    return Err(ConstantError::RequiresSameType { op: *op });
                }
                return Ok(((left == right) == (*op == BinaryOperator::Eq)).to_string());
            }
            let (left, right) = (integer(&left)?, integer(&right)?);
            let value = match op {
                BinaryOperator::Add => left.checked_add(right),
                BinaryOperator::Sub => left.checked_sub(right),
                BinaryOperator::Mul => left.checked_mul(right),
                BinaryOperator::Div if right == 0 => return Err(ConstantError::DivisionByZero),
                BinaryOperator::Div => left.checked_div(right),
                BinaryOperator::Rem if right == 0 => return Err(ConstantError::ModuloByZero),
                BinaryOperator::Rem => Some(left.wrapping_rem(right)),
                BinaryOperator::Shl | BinaryOperator::Shr if right < 0 => {
                    return Err(ConstantError::NegativeShift)
                }
                // OP_LSHIFT and OP_RSHIFT read the count as a 4-byte script number.
                BinaryOperator::Shl | BinaryOperator::Shr if right > i128::from(i32::MAX) => {
                    return Err(ConstantError::ShiftTooWide)
                }
                // OP_LSHIFT leaves zero as zero for any count.
                BinaryOperator::Shl if left == 0 => Some(0),
                // The shift overflowed if shifting back does not restore the operand.
                BinaryOperator::Shl => u32::try_from(right).ok().and_then(|count| {
                    left.checked_shl(count)
                        .filter(|value| value >> count == left)
                }),
                // Arithmetic shift rounds toward negative infinity, as OP_RSHIFT does.
                BinaryOperator::Shr => Some(left >> right.min(127)),
                BinaryOperator::Lt => return Ok((left < right).to_string()),
                BinaryOperator::Le => return Ok((left <= right).to_string()),
                BinaryOperator::Gt => return Ok((left > right).to_string()),
                BinaryOperator::Ge => return Ok((left >= right).to_string()),
                _ => return Err(ConstantError::UnsupportedConstantOperator { op: *op }),
            };
            Ok(value.ok_or(ConstantError::Overflow)?.to_string())
        }
        _ => Err(ConstantError::NotConstantExpression),
    }
}

fn fold_type(declared_type: &mut TypeName, values: &HashMap<String, String>) -> Result<()> {
    let TypeName::Array(element, size) = declared_type else {
        return Ok(());
    };
    let length = match size {
        ArraySize::Fixed(length) => Some(*length),
        ArraySize::Const(name) => values
            .get(name.as_str())
            .and_then(|value| value.parse().ok()),
    };
    *size = ArraySize::Fixed(length.filter(|length| *length > 0).ok_or_else(|| {
        let written = match size {
            ArraySize::Fixed(length) => length.to_string(),
            ArraySize::Const(name) => name.clone(),
        };
        ConstantError::ArraySizeNotPositive { written }
    })?);
    fold_type(element, values)
}

fn fold_statements(
    statements: &mut [LocatedStatement],
    values: &HashMap<String, String>,
    uses: &mut Vec<(Path, Span)>,
) -> Result<(), CompileError> {
    for statement in statements {
        let at = at(statement.span);
        match &mut statement.statement {
            Statement::Call(expression)
            | Statement::Return(Some(expression))
            | Statement::Require(expression) => fold_expression(expression, values, uses),
            Statement::Declaration { declared_type, .. } => {
                fold_type(declared_type, values).map_err(at)?
            }
            Statement::LetBinding {
                declared_type,
                value,
                ..
            } => {
                if let Some(declared_type) = declared_type {
                    fold_type(declared_type, values).map_err(at)?;
                }
                fold_expression(value, values, uses);
            }
            Statement::VarAssign { target, value } => {
                if let AssignmentTarget::ArrayIndex { index, .. }
                | AssignmentTarget::Access(index) = target
                {
                    fold_expression(index, values, uses);
                }
                fold_expression(value, values, uses);
            }
            Statement::IfElse {
                condition,
                then_body,
                else_body,
            } => {
                fold_expression(condition, values, uses);
                fold_statements(then_body, values, uses)?;
                if let Some(body) = else_body {
                    fold_statements(body, values, uses)?;
                }
            }
            Statement::ForIn { iterable, body, .. } => {
                fold_expression(iterable, values, uses);
                fold_statements(body, values, uses)?;
            }
            Statement::ForCount { count, body } => {
                fold_count(count, values, uses);
                fold_statements(body, values, uses)?;
            }
            Statement::ForRange {
                start, end, body, ..
            } => {
                fold_count(start, values, uses);
                fold_count(end, values, uses);
                fold_statements(body, values, uses)?;
            }
            Statement::Return(None) => {}
        }
    }
    Ok(())
}

fn fold_count(
    count: &mut Expression,
    values: &HashMap<String, String>,
    uses: &mut Vec<(Path, Span)>,
) {
    fold_expression(count, values, uses);
    if let Ok(value) = evaluate(count, &mut no_names) {
        count.kind = ExprKind::Literal(value);
    }
}

fn fold_expression(
    expression: &mut Expression,
    values: &HashMap<String, String>,
    uses: &mut Vec<(Path, Span)>,
) {
    if let ExprKind::Name(path) = &expression.kind {
        if let Some(value) = values.get(&path.key()) {
            uses.push((path.clone(), expression.span));
            expression.kind = ExprKind::Literal(value.clone());
            return;
        }
        if let Some((constant, "length")) = path.split_last() {
            if let Some(value) = values.get(&constant.key()) {
                uses.push((constant, expression.span));
                let value = Box::new(expression.with_kind(ExprKind::Literal(value.clone())));
                let field = "length".to_string();
                expression.kind = ExprKind::FieldAccess { value, field };
                return;
            }
        }
    }
    if let ExprKind::Tunnel { policy, .. } = &mut expression.kind {
        for value in policy.iter_mut() {
            if let Ok(literal) = evaluate(value, &mut |path| {
                values
                    .get(&path.key())
                    .cloned()
                    .ok_or_else(|| ConstantError::unknown(path))
            }) {
                value.kind = ExprKind::Literal(literal);
            }
        }
    }
    for child in models::child_exprs_mut(expression) {
        fold_expression(child, values, uses);
    }
}
