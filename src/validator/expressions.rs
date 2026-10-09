use super::bindings::{
    find_binding, validate_named_binding, BindingInfo, BindingScopes, BindingSource,
};
use super::*;

pub(super) fn validate_binding_requirement(
    requirement: &Requirement,
    function_name: &str,
    scopes: &BindingScopes,
    issues: &mut Vec<ValidationIssue>,
) {
    match requirement {
        Requirement::Expression(expression) => {
            let produces_value = !matches!(&expression.kind, ExprKind::Builtin { builtin, .. } if builtin.result.is_none());
            let before = issues.len();
            validate_binding_expression(expression, function_name, scopes, issues, produces_value);
            let condition = expression.ty.clone();
            // A bare find verifies the asset group exists; its index is dropped.
            if issues.len() == before
                && produces_value
                && !matches!(&expression.kind, ExprKind::GroupFind { .. })
                && !matches!(condition, ArkType::Bool | ArkType::Unknown)
            {
                issues.push(ValidationIssue::type_error(format!(
                    "function '{function_name}': require condition has type '{}', expected bool",
                    condition.as_str()
                )));
            }
        }
        Requirement::Comparison { left, op, right } => {
            let left_type = left.ty.clone();
            let right_type = right.ty.clone();
            let composite = matches!(left_type, ArkType::Array(..) | ArkType::Struct(..))
                || matches!(right_type, ArkType::Array(..) | ArkType::Struct(..));
            if composite {
                if op.class() != OperatorClass::Equality {
                    issues.push(ValidationIssue::error(format!(
                        "function '{}': '{}' is not defined for composite values",
                        function_name, op
                    )));
                } else if left_type != ArkType::Unknown
                    && right_type != ArkType::Unknown
                    && left_type != right_type
                {
                    issues.push(ValidationIssue::error(format!(
                        "function '{}': comparison '{}' is not defined between '{}' and '{}'",
                        function_name,
                        op,
                        left_type.as_str(),
                        right_type.as_str()
                    )));
                }
            }
            let before = issues.len();
            validate_binding_expression(left, function_name, scopes, issues, !composite);
            validate_binding_expression(right, function_name, scopes, issues, !composite);
            if issues.len() == before {
                let span = crate::diagnostics::Span {
                    start: left.span.start,
                    end: right.span.end,
                };
                validate_scalar_comparison(
                    *op,
                    [left_type, right_type],
                    span,
                    function_name,
                    issues,
                );
            }
        }
    }
}

/// Scalar operand types of a comparison; composite operands are checked where they are bound.
fn validate_scalar_comparison(
    op: BinaryOperator,
    [left, right]: [ArkType; 2],
    span: crate::diagnostics::Span,
    function_name: &str,
    issues: &mut Vec<ValidationIssue>,
) {
    let scalar = |t: &ArkType| {
        !matches!(
            t,
            ArkType::Unknown | ArkType::Array(..) | ArkType::Struct(..)
        )
    };
    if !scalar(&left) || !scalar(&right) {
        return;
    }
    let bytes_like = crate::types::is_bytes_like;
    let compatible = match op.class() {
        OperatorClass::Equality => {
            left == right
                || (bytes_like(&left) && right == ArkType::Bytes)
                || (bytes_like(&right) && left == ArkType::Bytes)
        }
        // A bool is a script number on the stack, but ordering booleans is meaningless.
        OperatorClass::Ordering => left == ArkType::Int && right == ArkType::Int,
        _ => true,
    };
    if !compatible {
        issues.push(
            ValidationIssue::type_error(format!(
                "function '{function_name}': comparison '{op}' is not defined between '{}' and '{}'",
                left.as_str(),
                right.as_str()
            ))
            .at(span),
        );
    }
}

pub(super) fn validate_value_expression(
    expression: &Expression,
    function_name: &str,
    scopes: &BindingScopes,
    issues: &mut Vec<ValidationIssue>,
) {
    let scalar = !matches!(
        expression.ty.clone(),
        ArkType::Array(..) | ArkType::Struct(..)
    ) && !matches!(
        &expression.kind,
        ExprKind::StructLiteral(_) | ExprKind::ArrayLiteral(_)
    );
    validate_binding_expression(expression, function_name, scopes, issues, scalar);
}

pub(super) fn validate_binding_expression(
    expression: &Expression,
    function_name: &str,
    scopes: &BindingScopes,
    issues: &mut Vec<ValidationIssue>,
    value_position: bool,
) {
    let first = issues.len();
    let expression_type = expression.ty.clone();
    if value_position && matches!(expression_type, ArkType::Array(..) | ArkType::Struct(..)) {
        let kind = if matches!(expression_type, ArkType::Struct(..)) {
            "struct"
        } else {
            "array"
        };
        issues.push(ValidationIssue::error(format!(
            "function '{}': {kind} expressions are composite values and cannot be used here",
            function_name,
        )));
    }
    if value_position
        && (matches!(
            &expression.kind,
            ExprKind::GroupIOAccess { property: None, .. }
        ) || matches!(&expression.kind, ExprKind::Builtin { builtin, .. } if builtin.result.is_none()))
    {
        issues.push(ValidationIssue::error(format!(
            "function '{}': expression does not produce one stack item",
            function_name
        )));
    }
    if matches!(
        &expression.kind,
        ExprKind::GroupIOAccess {
            source: crate::models::GroupIOSource::Outputs,
            property: Some(crate::properties::GroupIoProperty::Txid),
            ..
        }
    ) {
        issues.push(ValidationIssue::error(format!(
            "function '{function_name}': asset group output records have no txid"
        )));
    }

    let registered_builtin = operands::operands(expression);
    let mut children_checked = false;

    match &expression.kind {
        ExprKind::BinaryOp { left, op, right } if op.class() == OperatorClass::Bytewise => {
            for operand in [left, right] {
                let actual = operand.ty.clone();
                if actual != ArkType::Unknown && !binding_types_compatible(&ArkType::Bytes, &actual)
                {
                    issues.push(
                        ValidationIssue::error(format!(
                            "function '{function_name}': bytewise '{op}' operand has type '{}', expected 'bytes'",
                            actual.as_str()
                        ))
                        .at(operand.span),
                    );
                }
            }
            // The VM aborts on operands of different lengths.
            let widths = [left, right].map(|operand| crate::types::static_byte_width(operand));
            if let [Some(left), Some(right)] = widths {
                if left != right {
                    issues.push(ValidationIssue::error(format!(
                        "function '{function_name}': bytewise '{op}' operands must have equal lengths, got {left} and {right} bytes"
                    )));
                }
            }
        }
        ExprKind::BinaryOp { left, op, right }
            if matches!(
                op.class(),
                OperatorClass::Logical | OperatorClass::Arithmetic | OperatorClass::Shift
            ) =>
        {
            let (kind, expected) = match op.class() {
                OperatorClass::Logical => ("logical", ArkType::Bool),
                OperatorClass::Shift => ("shift", ArkType::Int),
                _ => ("arithmetic", ArkType::Int),
            };
            let types = [left, right].map(|operand| operand.ty.clone());
            // Bytes-like `+` is concatenation.
            let concat =
                *op == BinaryOperator::Add && types.iter().any(crate::types::is_bytes_like);
            if concat {
                // The width and byte order of a converted number are consensus-visible, so the author picks them.
                for ((side, operand), actual) in
                    [("left", left), ("right", right)].iter().zip(&types)
                {
                    if *actual != ArkType::Unknown && !crate::types::is_bytes_like(actual) {
                        let hint = if matches!(actual, ArkType::Int | ArkType::Bool) {
                            "convert it explicitly with num2bin(value, width) — the compiler will not choose a width for you"
                        } else {
                            "both operands must be bytes-like"
                        };
                        issues.push(
                            ValidationIssue::type_error(format!(
                                "function '{function_name}': cannot concatenate bytes with the {side} `{}` operand of `+`; {hint}",
                                actual.as_str()
                            ))
                            .at(operand.span),
                        );
                    }
                }
            }
            for (operand, actual) in [left, right].iter().zip(&types).filter(|_| !concat) {
                if *actual != expected && *actual != ArkType::Unknown {
                    issues.push(
                        ValidationIssue::error(format!(
                            "function '{}': {kind} '{}' operand has type '{}', expected '{}'",
                            function_name,
                            op,
                            actual.as_str(),
                            expected.as_str()
                        ))
                        .at(operand.span),
                    );
                }
            }
            if matches!(op, BinaryOperator::Div | BinaryOperator::Rem)
                && literal_index(right).is_some_and(|(_, value)| value == "0")
            {
                let what = if *op == BinaryOperator::Rem {
                    "modulo"
                } else {
                    "division"
                };
                issues.push(
                    ValidationIssue::error(format!("function '{function_name}': {what} by zero"))
                        .at(right.span),
                );
            }
            if op.class() == OperatorClass::Shift
                && literal_index(right).is_some_and(|(negative, value)| negative && value != "0")
            {
                issues.push(
                    ValidationIssue::error(format!(
                        "function '{function_name}': shift count must not be negative"
                    ))
                    .at(right.span),
                );
            }
        }
        ExprKind::BinaryOp { left, op, right } if op.compares() => {
            let types = [left, right].map(|operand| operand.ty.clone());
            validate_scalar_comparison(*op, types, expression.span, function_name, issues);
        }
        ExprKind::Unary { op, value } => {
            let (operator, expected) = (op.symbol(), ArkType::parse(op.operand_type()));
            let actual = value.ty.clone();
            if actual != ArkType::Unknown && !binding_types_compatible(&expected, &actual) {
                issues.push(
                    ValidationIssue::error(format!(
                        "function '{}': unary '{}' operand has type '{}', expected '{}'",
                        function_name,
                        operator,
                        actual.as_str(),
                        expected.as_str()
                    ))
                    .at(value.span),
                );
            }
        }
        _ if registered_builtin.is_some() => {
            let (name, operands) = registered_builtin.unwrap();
            let params = operands::find(name)
                .unwrap_or_else(|| panic!("{name} has no registered signature"));
            assert!(
                crate::builtins::find(name).map_or(operands.len() == params.len(), |builtin| {
                    builtin.accepts_arity(operands.len())
                }),
                "{name}: operands() and its signature disagree on arity"
            );
            // Every `[]` operand takes the length of the first one.
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
                // Composite operands are emitted field by field, so their type must be known.
                let known = actual != ArkType::Unknown
                    || matches!(expected, ArkType::Struct(_) | ArkType::Array(..));
                // A hex literal carries its own width, so 32 bytes need no cast.
                let literal_bytes32 = expected == ArkType::Bytes32
                    && matches!(&operand.kind, ExprKind::Literal(value) if value.starts_with("0x") && value.len() == 66);
                if let (ExprKind::ArrayLiteral(elements), ArkType::Array(element, length)) =
                    (&operand.kind, &expected)
                {
                    for value in elements {
                        let actual = &value.ty;
                        if actual != &ArkType::Unknown && !binding_types_compatible(element, actual)
                        {
                            issues.push(ValidationIssue::error(format!(
                                "function '{function_name}': {name} '{}' has type '{}', expected '{}'",
                                value.source_text(), actual.as_str(), element.as_str()
                            )).at(value.span));
                        }
                    }
                    if elements.len() != *length {
                        issues.push(ValidationIssue::error(format!(
                            "function '{function_name}': {name} operand has {} elements, expected {length}",
                            elements.len()
                        )).at(operand.span));
                    }
                    continue;
                }
                if known && !literal_bytes32 && !binding_types_compatible(&expected, &actual) {
                    issues.push(
                        ValidationIssue::error(format!(
                            "function '{function_name}': {name} operand has type '{}', expected '{}'",
                            actual.as_str(),
                            expected.as_str()
                        ))
                        .at(operand.span),
                    );
                }
            }
            // OP_ECPAIRING bounds its work at 16 pairs.
            if let Some(pairs) = length.filter(|&pairs| name == "ecPairing" && pairs > 16) {
                issues.push(ValidationIssue::error(format!(
                    "function '{function_name}': ecPairing supports at most 16 pairs, got {pairs}"
                )));
            }
        }
        ExprKind::Cast { target, data } => {
            let actual = data.ty.clone();
            let (source, hint) = match target.as_str() {
                "int" => (
                    ArkType::Bool,
                    "only bool converts to int; use int(0x..) for a hex constant or bin2num for bytes",
                ),
                "bool" => (ArkType::Int, "only int converts to bool"),
                _ => (ArkType::Bytes, "only bytes can be cast"),
            };
            // Same-type casts are no-ops; emission drops them.
            if actual != source && actual != ArkType::parse(target) && actual != ArkType::Unknown {
                issues.push(ValidationIssue::error(format!(
                    "function '{function_name}': cannot cast '{}' to '{target}'; {hint}",
                    actual.as_str()
                )));
            }
        }
        ExprKind::Tunnel {
            output_index,
            policy,
            exceptions,
        } => {
            let actual = output_index.ty.clone();
            if actual != ArkType::Int {
                issues.push(ValidationIssue::error(format!(
                    "function '{function_name}': tunnel output index must be int, got '{}'",
                    actual.as_str()
                )));
            }
            if policy.iter().any(|value| !matches!(&value.kind, ExprKind::Literal(literal) if literal == "true" || literal == "false")) {
                issues.push(ValidationIssue::error("tunnel policy fields must be compile-time bool constants"));
            }
            if !policy
                .iter()
                .any(|value| matches!(&value.kind, ExprKind::Literal(literal) if literal == "true"))
            {
                issues.push(ValidationIssue::error(
                    "tunnel policy must preserve at least one property",
                ));
            }
            if !exceptions.is_empty()
                && !matches!(&policy[2].kind, ExprKind::Literal(literal) if literal == "true")
            {
                issues.push(ValidationIssue::error(
                    "tunnel exceptions require asset preservation",
                ));
            }
            for exception in exceptions {
                if exception.ty != ArkType::Struct("AssetId".to_string()) {
                    issues.push(ValidationIssue::error(
                        "tunnel exceptions must be AssetId values",
                    ));
                }
            }
        }

        ExprKind::StructLiteral(_) if value_position => {
            issues.push(ValidationIssue::error(format!(
                "function '{}': struct literals may only initialize typed struct declarations",
                function_name
            )));
        }
        ExprKind::Variable(name) => {
            validate_named_binding(name, None, "binding", function_name, scopes, issues);
        }
        // Inner accesses are validated first so a bad path reports only its first fault.
        ExprKind::FieldAccess { value, .. } => {
            let before = issues.len();
            validate_value_expression(value, function_name, scopes, issues);
            if issues.len() == before {
                if let Some(name) = expression.binding_path() {
                    if let Some(array) = name
                        .strip_suffix(".length")
                        .filter(|_| find_binding(scopes, &name).is_none())
                    {
                        validate_array_length(array, function_name, scopes, issues);
                    } else if find_binding(scopes, &name).is_none() {
                        issues.push(ValidationIssue::error(format!(
                            "function '{function_name}': field '{}' is undefined",
                            expression.source_text()
                        )));
                    }
                }
            }
            children_checked = true;
        }
        ExprKind::IndexAccess { value, index } => {
            let before = issues.len();
            validate_value_expression(value, function_name, scopes, issues);
            validate_binding_expression(index, function_name, scopes, issues, true);
            if issues.len() == before {
                if let Some(array) = value.binding_path() {
                    validate_array_index(
                        &array,
                        &value.source_text(),
                        index,
                        function_name,
                        scopes,
                        issues,
                    );
                }
            }
            children_checked = true;
        }
        ExprKind::ArrayIndex { array, index } => {
            validate_array_index(array, array, index, function_name, scopes, issues);
        }
        ExprKind::Property(name)
            if name.ends_with(".length") && find_binding(scopes, name).is_none() =>
        {
            let array = name.strip_suffix(".length").expect("checked suffix");
            validate_array_length(array, function_name, scopes, issues);
        }
        ExprKind::Property(name) => {
            let root = name.split('.').next().unwrap_or(name);
            if name.contains('.') && find_binding(scopes, root).is_some() {
                validate_named_binding(name, None, "field", function_name, scopes, issues);
            }
        }
        ExprKind::ContractInstance { args, .. } => {
            for argument in args {
                match &argument.kind {
                    ExprKind::Variable(name) => {
                        if let Some(binding) = find_binding(scopes, name) {
                            if !matches!(binding.source, BindingSource::Constructor) {
                                issues.push(ValidationIssue::error(format!(
                                    "function '{}': contract instance argument '{}' is a runtime value; only constructor parameters and literals are supported",
                                function_name, name
                            )));
                            }
                        }
                    }
                    ExprKind::Literal(_) => {}
                    _ => issues.push(ValidationIssue::error(format!(
                        "function '{}': computed contract arguments are not supported",
                        function_name
                    ))),
                }
            }
        }
        _ => {}
    }

    locate(&mut issues[first..], expression.span);
    if children_checked {
        return;
    }
    for child in child_exprs(expression) {
        if matches!(
            &expression.kind,
            ExprKind::Call { .. }
                | ExprKind::Builtin { .. }
                | ExprKind::StructLiteral(_)
                | ExprKind::ArrayLiteral(_)
                | ExprKind::Tunnel { .. }
                | ExprKind::FieldAccess { .. }
                | ExprKind::IndexAccess { .. }
        ) {
            validate_value_expression(child, function_name, scopes, issues);
        } else {
            validate_binding_expression(
                child,
                function_name,
                scopes,
                issues,
                !matches!(&expression.kind, ExprKind::ContractInstance { .. }),
            );
        }
    }
}

fn validate_array_length(
    array: &str,
    function_name: &str,
    scopes: &BindingScopes,
    issues: &mut Vec<ValidationIssue>,
) {
    if !matches!(
        find_binding(scopes, array).map(|binding| &binding.binding_type),
        Some(ArkType::Array(..))
    ) {
        issues.push(ValidationIssue::error(format!(
            "function '{function_name}': '{array}' is not an array; '.length' is undefined"
        )));
    }
}

/// Validate `array[index]`; `written` is the array as spelled in source.
pub(super) fn validate_array_index(
    array: &str,
    written: &str,
    index: &Expression,
    function_name: &str,
    scopes: &BindingScopes,
    issues: &mut Vec<ValidationIssue>,
) -> Option<(ArkType, BindingSource)> {
    let array_info = match find_binding(scopes, array) {
        None => {
            issues.push(ValidationIssue::error(format!(
                "function '{}': array '{}' is undefined",
                function_name, written
            )));
            None
        }
        Some(BindingInfo {
            binding_type: ArkType::Array(element, length),
            source,
        }) => Some(((**element).clone(), *length, *source)),
        Some(_) => {
            issues.push(ValidationIssue::error(format!(
                "function '{}': binding '{}' is not an array",
                function_name, written
            )));
            None
        }
    };

    let index_type = index.ty.clone();
    if !matches!(index_type, ArkType::Int | ArkType::Unknown) {
        issues.push(
            ValidationIssue::error(format!(
                "function '{}': array index has type '{}', expected 'int'",
                function_name,
                index_type.as_str()
            ))
            .at(index.span),
        );
    }
    if let (Some((negative, literal)), Some((_, length, _))) =
        (literal_index(index), array_info.as_ref())
    {
        let in_bounds = if negative {
            literal == "0"
        } else {
            literal.parse::<usize>().is_ok_and(|index| index < *length)
        };
        if !in_bounds {
            let sign = if negative { "-" } else { "" };
            issues.push(
                ValidationIssue::error(format!(
                    "function '{}': array index '{}{}' is out of range for '{}[{}]'",
                    function_name, sign, literal, written, length
                ))
                .at(index.span),
            );
        }
    }

    array_info.map(|(element_type, _, source)| (element_type, source))
}

fn literal_index(mut expression: &Expression) -> Option<(bool, &str)> {
    let mut negative = false;
    while let ExprKind::Unary {
        op: crate::operators::UnaryOperator::Neg,
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
