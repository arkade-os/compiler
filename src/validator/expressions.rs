//! Per-expression checks over the types `types::annotate` stored: operand types, constant operand
//! domains, casts, literal positions, constant index bounds, and resolution of names and paths.
//! An expression over an invalid operand reports only the operand's fault.

use super::bindings::{
    find_binding, validate_named_binding, BindingInfo, BindingScopes, BindingSource,
};
use super::error::ValueContext;
use super::{operands, ValidationError, ValidationIssue};
use crate::builtins;
use crate::compiler::constants::{self, ConstantError};
use crate::compiler::Op;
use crate::diagnostics::Span;
use crate::models::{self, ExprKind, Expression, GroupIOSource, Path, Segment};
use crate::operators::{BinaryOperator, OperatorClass, UnaryOperator};
use crate::properties::GroupIoProperty;
use crate::types::{self, ArkType};

pub(super) fn validate_binding_requirement(
    expression: &Expression,
    scopes: &BindingScopes,
    issues: &mut Vec<ValidationIssue>,
) {
    let before = issues.len();
    validate_binding_expression(expression, scopes, issues, true);
    let condition = expression.ty.clone();
    // A bare group lookup verifies the asset group exists; its index is dropped.
    if issues.len() == before
        && !matches!(&expression.kind, ExprKind::GroupLookup { .. })
        && condition != ArkType::Bool
    {
        let actual = (&condition).into();
        issues.push(ValidationError::RequireConditionNotBool { actual }.at(expression.span));
    }
}

/// Arrays and structs compare only with `==` and `!=`, against the same type.
fn validate_comparison(
    left: &Expression,
    op: BinaryOperator,
    right: &Expression,
    span: Span,
    scopes: &BindingScopes,
    issues: &mut Vec<ValidationIssue>,
) {
    let before = issues.len();
    let mut composite = false;
    for operand in [left, right] {
        let whole = matches!(operand.ty, ArkType::Array(..) | ArkType::Struct(..));
        validate_binding_expression(operand, scopes, issues, !whole);
        composite |= whole;
    }
    let (left, right) = (&left.ty, &right.ty);
    let bytes_like = ArkType::is_bytes_like;
    let compatible = match op.class() {
        class if composite && class != OperatorClass::Equality => false,
        _ if issues.len() != before => return,
        // An array literal takes its type only from a typed array peer, and emission needs every
        // element's type; against a struct it is a mismatch instead.
        _ if matches!((left, right), (ArkType::Array(..), ArkType::Array(..)))
            && !(types::resolved(left) && types::resolved(right)) =>
        {
            issues.push(ValidationError::UntypedComparedLiterals.at(span));
            return;
        }
        OperatorClass::Equality if composite => left == right,
        OperatorClass::Equality => {
            left == right
                || (bytes_like(left) && *right == ArkType::Bytes)
                || (bytes_like(right) && *left == ArkType::Bytes)
        }
        // A bool is a script number on the stack, but ordering booleans is meaningless.
        OperatorClass::Ordering => *left == ArkType::Int && *right == ArkType::Int,
        _ => true,
    };
    if !compatible {
        let (left, right) = (left.into(), right.into());
        issues.push(ValidationError::UndefinedComparison { op, left, right }.at(span));
    }
}

pub(super) fn validate_value_expression(
    expression: &Expression,
    scopes: &BindingScopes,
    issues: &mut Vec<ValidationIssue>,
) {
    let scalar = !matches!(
        expression.ty.clone(),
        ArkType::Array(..) | ArkType::Struct(..)
    ) && !matches!(
        &expression.kind,
        ExprKind::StructLiteral { .. } | ExprKind::ArrayLiteral(_)
    );
    validate_binding_expression(expression, scopes, issues, scalar);
}

pub(super) fn validate_binding_expression(
    expression: &Expression,
    scopes: &BindingScopes,
    issues: &mut Vec<ValidationIssue>,
    value_position: bool,
) {
    let first = issues.len();
    let expression_type = expression.ty.clone();
    if value_position && matches!(expression_type, ArkType::Array(..) | ArkType::Struct(..)) {
        let what = if matches!(expression_type, ArkType::Struct(..)) {
            "struct"
        } else {
            "array"
        };
        issues.push(ValidationError::CompositeValue { what }.into());
    }
    if let (true, ArkType::Void, ExprKind::Call { name, .. }) =
        (value_position, &expression_type, &expression.kind)
    {
        let name = name.clone();
        issues.push(ValidationError::NoReturnValue { name }.into());
    }
    // Only outputs are rejected: an input's kind is known only at runtime, so `txid` on a
    // local input fails the spend, like `controlAssetId` without control.
    if matches!(
        &expression.kind,
        ExprKind::GroupIOAccess {
            source: GroupIOSource::Outputs,
            property: Some(GroupIoProperty::Txid),
            ..
        }
    ) {
        issues.push(ValidationError::OutputRecordTxid.into());
    }
    // A record value leaves out the txid, which only a proof input has.
    let record = match &expression.kind {
        ExprKind::FieldAccess { value, field } if field == "txid" => Some(value.ty.clone()),
        ExprKind::Name(path) => path
            .split_last()
            .filter(|&(_, field)| field == "txid")
            .and_then(|(record, _)| find_binding(scopes, &record.key()))
            .map(|binding| binding.binding_type.clone()),
        _ => None,
    };
    match record.as_ref().map(ArkType::as_str).as_deref() {
        Some("AssetGroupInput") => issues.push(ValidationError::InputRecordTxid.into()),
        Some("AssetGroupOutput") => issues.push(ValidationError::OutputRecordTxid.into()),
        _ => {}
    }

    if let ExprKind::FieldAccess { value, .. } | ExprKind::IndexAccess { value, .. } =
        &expression.kind
    {
        if matches!(
            &value.kind,
            ExprKind::StructLiteral { .. } | ExprKind::ArrayLiteral(_)
        ) {
            issues.push(ValidationError::LiteralAccess.into());
        }
    }

    // Operands are checked first, and an expression over an invalid one reports nothing
    // more; comparisons and accesses check their own operands.
    let compares = matches!(&expression.kind, ExprKind::BinaryOp { op, .. } if op.compares());
    if !compares
        && !matches!(
            &expression.kind,
            ExprKind::FieldAccess { .. } | ExprKind::IndexAccess { .. }
        )
    {
        validate_operands(expression, scopes, issues);
    }
    if issues.len() != first {
        super::locate(&mut issues[first..], expression.span);
        return;
    }
    let registered_builtin = operands::operands(expression);

    match &expression.kind {
        ExprKind::BinaryOp { left, op, right } if op.class() == OperatorClass::Bytewise => {
            for operand in [left, right] {
                let actual = operand.ty.clone();
                if !ArkType::Bytes.accepts(&actual) {
                    let (op, actual) = (*op, (&actual).into());
                    let error = ValidationError::BytewiseOperandType { op, actual };
                    issues.push(error.at(operand.span));
                }
            }
            // The VM aborts on operands of different lengths.
            let widths = [left, right].map(|operand| types::static_byte_width(operand));
            if let [Some(left), Some(right)] = widths {
                if left != right {
                    let op = *op;
                    issues.push(ValidationError::BytewiseLengths { op, left, right }.into());
                }
            }
        }
        ExprKind::BinaryOp { left, op, right }
            if matches!(
                op.class(),
                OperatorClass::Logical | OperatorClass::Arithmetic | OperatorClass::Shift
            ) =>
        {
            let expected = match op.class() {
                OperatorClass::Logical => ArkType::Bool,
                _ => ArkType::Int,
            };
            let types = [left, right].map(|operand| operand.ty.clone());
            let concat = *op == BinaryOperator::Add && types.iter().any(ArkType::is_bytes_like);
            if concat {
                // The width and byte order of a converted number are consensus-visible, so the author picks them.
                for ((side, operand), actual) in
                    [("left", left), ("right", right)].iter().zip(&types)
                {
                    if !actual.is_bytes_like() {
                        let (side, actual) = (*side, actual.into());
                        let error = ValidationError::ConcatenateNonBytes { side, actual };
                        issues.push(error.at(operand.span));
                    }
                }
            }
            for (operand, actual) in [left, right].iter().zip(&types).filter(|_| !concat) {
                if *actual != expected {
                    let error = ValidationError::OperandType {
                        op: *op,
                        actual: actual.into(),
                        expected: (&expected).into(),
                    };
                    issues.push(error.at(operand.span));
                }
            }
            if matches!(op, BinaryOperator::Div | BinaryOperator::Rem)
                && literal_index(right).is_some_and(|(_, value)| value == "0")
            {
                issues.push(ValidationError::DivisionByZero { op: *op }.at(right.span));
            }
            if op.class() == OperatorClass::Shift
                && literal_index(right).is_some_and(|(negative, value)| negative && value != "0")
            {
                issues.push(ValidationError::NegativeShift.at(right.span));
            }
        }
        ExprKind::BinaryOp { left, op, right } if op.compares() => {
            validate_comparison(left, *op, right, expression.span, scopes, issues);
        }
        ExprKind::Unary { op, value } => {
            let expected = ArkType::parse(op.operand_type());
            let actual = value.ty.clone();
            if !expected.accepts(&actual) {
                let error = ValidationError::UnaryOperandType {
                    op: *op,
                    actual: (&actual).into(),
                    expected: (&expected).into(),
                };
                issues.push(error.at(value.span));
            }
        }
        _ if registered_builtin.is_some() => {
            let (name, operands) = registered_builtin.expect("guarded by the arm");
            let params = operands::find(name)
                .unwrap_or_else(|| unreachable!("{name} has no registered signature"));
            assert!(
                builtins::find(name).map_or(operands.len() == params.len(), |builtin| {
                    builtin.accepts_arity(operands.len())
                }),
                "{name}: operands() and its signature disagree on arity"
            );
            let mut length = None;
            for (operand, declared) in operands.iter().zip(params) {
                let actual = operand.ty.clone();
                let expected = match declared.strip_suffix("[]") {
                    Some(element) => {
                        let length = *length.get_or_insert(match actual {
                            ArkType::Array(_, length) => length,
                            _ => 1,
                        });
                        ArkType::Array(Box::new(ArkType::parse(element)), length)
                    }
                    None => ArkType::parse(declared),
                };
                // A struct literal is checked against the parameter type; signatures name
                // only native structs.
                if matches!(&operand.kind, ExprKind::StructLiteral { .. }) {
                    super::functions::validate_value(
                        &(&expected).into(),
                        operand,
                        &[],
                        ValueContext::Operand { builtin: name },
                        issues,
                    );
                    continue;
                }
                if let (ExprKind::ArrayLiteral(elements), ArkType::Array(element, length)) =
                    (&operand.kind, &expected)
                {
                    for (index, value) in elements.iter().enumerate() {
                        let actual = &value.ty;
                        if matches!(&value.kind, ExprKind::StructLiteral { .. }) {
                            let of = Box::new(ValueContext::Operand { builtin: name });
                            super::functions::validate_value(
                                &(&**element).into(),
                                value,
                                &[],
                                ValueContext::Element { of, index },
                                issues,
                            );
                        } else if !element.accepts(actual) {
                            let error = ValidationError::BuiltinElementType {
                                builtin: name,
                                value: value.source_text(),
                                actual: actual.into(),
                                expected: (&**element).into(),
                            };
                            issues.push(error.at(value.span));
                        }
                    }
                    if elements.len() != *length {
                        let error = ValidationError::BuiltinElementCount {
                            builtin: name,
                            got: elements.len(),
                            expected: *length,
                        };
                        issues.push(error.at(operand.span));
                    }
                    continue;
                }
                if !expected.accepts(&actual) {
                    let error = ValidationError::BuiltinOperandType {
                        builtin: name,
                        actual: (&actual).into(),
                        expected: (&expected).into(),
                    };
                    issues.push(error.at(operand.span));
                }
            }
            for &(_, index, operand_name, ranges) in operands::CONSTANT_DOMAINS
                .iter()
                .filter(|(builtin, ..)| *builtin == name)
            {
                let Some(operand) = operands.get(index) else {
                    continue;
                };
                let Ok(value) = constants::evaluate(operand, &mut constants::no_names) else {
                    continue;
                };
                let accepted = value.parse::<i128>().map_or_else(
                    |_| {
                        // An i128::MAX upper bound denotes an unbounded domain.
                        !value.starts_with('-') && ranges.iter().any(|(_, high)| *high == i128::MAX)
                    },
                    |value| {
                        ranges
                            .iter()
                            .any(|(low, high)| (*low..=*high).contains(&value))
                    },
                );
                if !accepted {
                    let error = ValidationError::OperandDomain {
                        builtin: name,
                        operand: operand_name,
                        ranges,
                        value,
                    };
                    issues.push(error.at(operand.span));
                }
            }
            if name == "modExp" {
                for (operand, label) in operands.iter().zip(["base", "exponent", "modulus"]) {
                    if operand.ty != ArkType::Int {
                        continue;
                    }
                    if let Ok(value) = constants::evaluate(operand, &mut constants::no_names) {
                        if Op::Push(value).pushes_more_than(64) {
                            let error = ValidationError::ModExpOperandSize { operand: label };
                            issues.push(error.at(operand.span));
                        }
                    }
                }
            }
            // Checked here rather than in emission, which folding can skip.
            if let ("checkMultisig", Some(ArkType::Array(_, count)), Some(threshold)) =
                (name, operands.first().map(|keys| &keys.ty), operands.get(2))
            {
                if let Ok(value) = constants::evaluate(threshold, &mut constants::no_names) {
                    if value
                        .parse::<usize>()
                        .map_or(true, |t| t == 0 || t > *count)
                    {
                        let error = ValidationError::MultisigThreshold { value };
                        issues.push(error.at(threshold.span));
                    }
                }
            }
            let width = |index: usize| {
                operands
                    .get(index)
                    .and_then(|o| types::static_byte_width(o))
            };
            let byte_rule = match name {
                "checkSigFromStack" | "checkSigFromStackVerify" => width(2)
                    .filter(|&width| width != 32)
                    .map(|width| ValidationError::MessageWidth {
                        builtin: name,
                        width,
                    }),
                "merkleRoot" => width(2).filter(|width| width % 32 != 0).map(|width| {
                    ValidationError::ProofWidth {
                        builtin: name,
                        width,
                    }
                }),
                _ => None,
            };
            if let Some(error) = byte_rule {
                issues.push(error.at(expression.span));
            }
            // OP_ECPAIRING bounds its work at 16 pairs.
            if let Some(pairs) = length.filter(|&pairs| name == "ecPairing" && pairs > 16) {
                issues.push(ValidationError::TooManyPairs { pairs }.into());
            }
        }
        ExprKind::Cast { target, data } => {
            let actual = data.ty.clone();
            let source = match target.as_str() {
                "int" => ArkType::Bool,
                "bool" | "bytes" => ArkType::Int,
                _ => ArkType::Bytes,
            };
            // Same-type casts are no-ops; emission drops them.
            if actual != source
                && !ArkType::parse(target).accepts(&actual)
                && !(target == "bytes" && actual == ArkType::Bool)
            {
                let error = ValidationError::InvalidCast {
                    actual: (&actual).into(),
                    target: target.clone(),
                };
                issues.push(error.into());
            }
        }
        ExprKind::Tunnel {
            output_index,
            policy,
            exceptions,
        } => {
            let actual = output_index.ty.clone();
            if actual != ArkType::Int {
                let actual = (&actual).into();
                issues.push(ValidationError::TunnelIndexType { actual }.into());
            }
            if policy.iter().any(|value| !matches!(&value.kind, ExprKind::Literal(literal) if literal == "true" || literal == "false")) {
                issues.push(ValidationError::TunnelPolicyNotConstant.into());
            }
            if !policy
                .iter()
                .any(|value| matches!(&value.kind, ExprKind::Literal(literal) if literal == "true"))
            {
                issues.push(ValidationError::TunnelPolicyEmpty.into());
            }
            if !exceptions.is_empty()
                && !matches!(&policy[2].kind, ExprKind::Literal(literal) if literal == "true")
            {
                issues.push(ValidationError::TunnelExceptionsWithoutAssets.into());
            }
            for exception in exceptions {
                if exception.ty != ArkType::Struct("AssetId".to_string()) {
                    issues.push(ValidationError::TunnelExceptionType.into());
                }
            }
        }

        ExprKind::StructLiteral { name: None, .. } if value_position => {
            issues.push(ValidationError::UntypedStructLiteral.into());
        }
        // `tx` and `this` are reserved, so no binding resolves a path under them.
        ExprKind::Name(path) | ExprKind::ArrayIndex { array: path, .. }
            if matches!(path.root.as_str(), "tx" | "this") =>
        {
            issues.push(unknown_member(path).into());
        }
        ExprKind::Name(path) if path.segments.is_empty() => {
            validate_named_binding(&path.root, None, "binding", scopes, issues);
        }
        ExprKind::Name(path) | ExprKind::ArrayIndex { array: path, .. }
            if find_binding(scopes, &path.root).is_none() =>
        {
            validate_named_binding(&path.root, None, "binding", scopes, issues);
        }
        // A root of unknown type was reported where its type was lost.
        _ if expression.binding_path().is_some_and(|path| {
            find_binding(scopes, &path.root)
                .is_some_and(|root| root.binding_type == ArkType::Unknown)
        }) => {}
        // Inner accesses are validated first so a bad path reports only its first fault.
        ExprKind::FieldAccess { value, field } => {
            if let Some(array) = expression.binding_path().and_then(|path| {
                let (array, field) = path.split_last()?;
                (field == "length" && find_binding(scopes, &path.key()).is_none()).then_some(array)
            }) {
                let indexed = array
                    .segments
                    .iter()
                    .any(|segment| matches!(segment, Segment::Index(_)));
                if !indexed && find_binding(scopes, &array.key()).is_some() {
                    validate_array_length(&array.key(), scopes, issues);
                    return;
                }
            }
            let before = issues.len();
            validate_value_expression(value, scopes, issues);
            if issues.len() == before {
                if let Some(path) = expression.binding_path() {
                    let name = path.key();
                    if let Some((array, _)) = path
                        .split_last()
                        .filter(|&(_, field)| field == "length")
                        .filter(|_| find_binding(scopes, &name).is_none())
                    {
                        validate_array_length(&array.key(), scopes, issues);
                    } else if find_binding(scopes, &name).is_none() {
                        let text = expression.source_text();
                        issues.push(ValidationError::UndefinedField { text }.into());
                    }
                } else if expression.ty == ArkType::Unknown {
                    let (ty, field) = ((&value.ty).into(), field.clone());
                    issues.push(ValidationError::NoSuchField { ty, field }.into());
                }
            }
        }
        ExprKind::IndexAccess { value, index } => {
            let before = issues.len();
            validate_value_expression(value, scopes, issues);
            validate_binding_expression(index, scopes, issues, true);
            if issues.len() == before {
                match (value.binding_path(), &value.ty) {
                    (Some(array), _) => {
                        validate_array_index(
                            &array.key(),
                            &value.source_text(),
                            index,
                            scopes,
                            issues,
                        );
                    }
                    (None, ArkType::Array(_, length)) => {
                        validate_index(index, Some((value.ty.as_str(), *length)), scopes, issues)
                    }
                    (None, actual) => {
                        let ty = actual.into();
                        issues.push(ValidationError::NotAnArrayValue { ty }.into())
                    }
                }
            }
        }
        ExprKind::ArrayIndex { array, index } => {
            validate_array_index(&array.key(), &array.key(), index, scopes, issues);
        }
        ExprKind::Name(path) => match path.split_last() {
            Some((array, "length")) if find_binding(scopes, &path.key()).is_none() => {
                validate_array_length(&array.key(), scopes, issues);
            }
            _ => validate_named_binding(&path.key(), None, "field", scopes, issues),
        },
        ExprKind::ContractInstance { args, .. } => {
            for argument in args {
                match &argument.kind {
                    ExprKind::Name(Path {
                        root: name,
                        segments,
                    }) if segments.is_empty() => {
                        if let Some(binding) = find_binding(scopes, name) {
                            if !matches!(binding.source, BindingSource::Constructor) {
                                let name = name.clone();
                                let error = ValidationError::RuntimeContractArgument { name };
                                issues.push(error.into());
                            }
                        }
                    }
                    ExprKind::Literal(_) => {}
                    _ => issues.push(ValidationError::ComputedContractArgument.into()),
                }
            }
        }
        _ => {}
    }
    // An untyped expression's error is reported where it arises: a name by the checks
    // above, an unknown function by `validate_calls`, a literal by the check of its
    // position, anything else by the backstop in `validate_ast`. The marker keeps
    // enclosing checks from reporting it again.
    if issues.len() == first
        && expression.ty == ArkType::Unknown
        && !matches!(&expression.kind, ExprKind::StructLiteral { .. })
    {
        issues.push(ValidationError::Reported.into());
    }
    super::locate(&mut issues[first..], expression.span);
}

fn validate_operands(
    expression: &Expression,
    scopes: &BindingScopes,
    issues: &mut Vec<ValidationIssue>,
) {
    for child in models::child_exprs(expression) {
        if matches!(
            &expression.kind,
            ExprKind::Call { .. }
                | ExprKind::Builtin { .. }
                | ExprKind::StructLiteral { .. }
                | ExprKind::ArrayLiteral(_)
                | ExprKind::Tunnel { .. }
                // Their AssetId operand is a whole struct.
                | ExprKind::AssetLookup { .. }
                | ExprKind::AssetHas { .. }
                | ExprKind::AssetTryLookup { .. }
                | ExprKind::GroupLookup { .. }
                | ExprKind::GroupHas { .. }
                | ExprKind::GroupControlIs { .. }
        ) {
            validate_value_expression(child, scopes, issues);
        } else {
            validate_binding_expression(
                child,
                scopes,
                issues,
                !matches!(&expression.kind, ExprKind::ContractInstance { .. }),
            );
        }
    }
}

fn validate_array_length(array: &str, scopes: &BindingScopes, issues: &mut Vec<ValidationIssue>) {
    if !matches!(
        find_binding(scopes, array).map(|binding| &binding.binding_type),
        Some(ArkType::Array(..))
    ) {
        let array = array.to_string();
        issues.push(ValidationError::LengthOfNonArray { array }.into());
    }
}

/// Validate `array[index]`; `written` is the array as spelled in source.
pub(super) fn validate_array_index(
    array: &str,
    written: &str,
    index: &Expression,
    scopes: &BindingScopes,
    issues: &mut Vec<ValidationIssue>,
) -> Option<(ArkType, BindingSource)> {
    if find_binding(scopes, array).is_some_and(|binding| !binding.initialized) {
        validate_named_binding(array, None, "array", scopes, issues);
    }
    let array_info = match find_binding(scopes, array) {
        None => {
            let array = written.to_string();
            issues.push(ValidationError::UndefinedArray { array }.into());
            None
        }
        Some(BindingInfo {
            binding_type: ArkType::Array(element, length),
            source,
            ..
        }) => Some(((**element).clone(), *length, *source)),
        Some(_) => {
            let binding = written.to_string();
            issues.push(ValidationError::NotAnArray { binding }.into());
            None
        }
    };
    validate_index(
        index,
        array_info
            .as_ref()
            .map(|(_, length, _)| (format!("{written}[{length}]"), *length)),
        scopes,
        issues,
    );
    array_info.map(|(element_type, _, source)| (element_type, source))
}

/// `array` is the indexed array as diagnostics spell it, with its length; without it the index is
/// not range-checked.
fn validate_index(
    index: &Expression,
    array: Option<(String, usize)>,
    scopes: &BindingScopes,
    issues: &mut Vec<ValidationIssue>,
) {
    let index_type = index.ty.clone();
    if index_type != ArkType::Int {
        let actual = (&index_type).into();
        issues.push(ValidationError::IndexType { actual }.at(index.span));
    }
    let evaluated = constants::evaluate(index, &mut |path| {
        let array = path
            .split_last()
            .filter(|&(_, field)| field == "length" && find_binding(scopes, &path.key()).is_none());
        match array.and_then(|(array, _)| find_binding(scopes, &array.key())) {
            Some(BindingInfo {
                binding_type: ArkType::Array(_, length),
                ..
            }) => Ok(length.to_string()),
            _ => Err(ConstantError::unknown(path)),
        }
    })
    .ok()
    .filter(|_| index_type == ArkType::Int);
    if let (Some(value), Some((array, length))) = (evaluated, array) {
        let (negative, literal) = match value.strip_prefix('-') {
            Some(magnitude) => (true, magnitude),
            None => (false, value.as_str()),
        };
        let in_bounds = if negative {
            literal == "0"
        } else {
            literal.parse::<usize>().is_ok_and(|index| index < length)
        };
        if !in_bounds {
            let error = ValidationError::IndexOutOfRange { value, array };
            issues.push(error.at(index.span));
        }
    }
}

fn literal_index(mut expression: &Expression) -> Option<(bool, &str)> {
    let mut negative = false;
    while let ExprKind::Unary {
        op: UnaryOperator::Neg,
        value,
    } = &expression.kind
    {
        negative = !negative;
        expression = value;
    }
    match &expression.kind {
        ExprKind::Literal(value) => Some(match value.strip_prefix('-') {
            Some(magnitude) => (!negative, magnitude),
            None => (negative, value),
        }),
        _ => None,
    }
}

/// Why `path`, under `tx` or `this`, names no value: its first member the builtin docs
/// lack, with those they list at that level, or else that it needs an access or a call.
fn unknown_member(path: &Path) -> ValidationError {
    // A `tx` or `this` chain the parser resolves to no member keeps its indexes and calls,
    // as in `outputs[0]`.
    let text = path.key();
    // `text` without index and argument contents, and where each of its dots is in `text`.
    let (mut flat, mut dots, mut depth) = (String::new(), Vec::new(), 0);
    for (at, c) in text.char_indices() {
        if matches!(c, ']' | ')') {
            depth -= 1;
        }
        if depth == 0 {
            flat.push(c);
            if c == '.' {
                dots.push(at);
            }
        }
        if matches!(c, '[' | '(') {
            depth += 1;
        }
    }
    let mut owner = path.root.clone();
    for (segment, dot) in flat.split('.').skip(1).zip(dots) {
        let name = segment.split(['[', '(']).next().unwrap_or_default();
        let members = builtins::members_of(&owner);
        if !members.iter().any(|member| member == name) {
            return ValidationError::UnknownMember {
                name: name.to_string(),
                owner: text[..dot].to_string(),
                members,
            };
        }
        owner = format!("{owner}.{}", segment.replace("()", ""));
    }
    ValidationError::NotAValue { text }
}
