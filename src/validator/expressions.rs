use super::bindings::{
    find_binding, validate_named_binding, BindingInfo, BindingScopes, BindingSource,
};
use super::*;

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
        issues.push(
            ValidationIssue::type_error(format!(
                "require condition has type '{}', expected bool",
                condition.as_str()
            ))
            .at(expression.span),
        );
    }
}

/// Arrays and structs compare only with `==` and `!=`, against the same type.
fn validate_comparison(
    left: &Expression,
    op: BinaryOperator,
    right: &Expression,
    span: crate::diagnostics::Span,
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
    let bytes_like = crate::types::is_bytes_like;
    let compatible = match op.class() {
        class if composite && class != OperatorClass::Equality => false,
        _ if issues.len() != before => return,
        // An array literal takes its type only from a typed array peer, and emission needs every
        // element's type; against a struct it is a mismatch instead.
        _ if matches!((left, right), (ArkType::Array(..), ArkType::Array(..)))
            && !(crate::types::resolved(left) && crate::types::resolved(right)) =>
        {
            issues.push(
                ValidationIssue::error(
                    "cannot determine the type of compared literals; declare one with a type first",
                )
                .at(span),
            );
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
        issues.push(
            ValidationIssue::type_error(format!(
                "comparison '{op}' is not defined between '{}' and '{}'",
                left.as_str(),
                right.as_str()
            ))
            .at(span),
        );
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
        let kind = if matches!(expression_type, ArkType::Struct(..)) {
            "struct"
        } else {
            "array"
        };
        issues.push(ValidationIssue::error(format!(
            "{kind} expressions are composite values and cannot be used here",
        )));
    }
    if let (true, ArkType::Void, ExprKind::Call { name, .. }) =
        (value_position, &expression_type, &expression.kind)
    {
        issues.push(ValidationIssue::error(format!(
            "function '{name}' does not return a value"
        )));
    }
    // An input's kind is only known at runtime, so `txid` on a local input fails the
    // spend like `controlAssetId` without control; a type check before `||`/`&&` guards it.
    if matches!(
        &expression.kind,
        ExprKind::GroupIOAccess {
            source: crate::models::GroupIOSource::Outputs,
            property: Some(crate::properties::GroupIoProperty::Txid),
            ..
        }
    ) {
        issues.push(ValidationIssue::error(
            "asset group output records have no txid",
        ));
    }
    // A record value leaves out the txid, which only an intent input has.
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
        Some("AssetGroupInput") => issues.push(ValidationIssue::error(
            "asset group input records have no txid; read it with g.inputs[j].txid, which fails the spend on a local input",
        )),
        Some("AssetGroupOutput") => issues.push(ValidationIssue::error(
            "asset group output records have no txid",
        )),
        _ => {}
    }

    if let ExprKind::FieldAccess { value, .. } | ExprKind::IndexAccess { value, .. } =
        &expression.kind
    {
        if matches!(
            &value.kind,
            ExprKind::StructLiteral { .. } | ExprKind::ArrayLiteral(_)
        ) {
            issues.push(ValidationIssue::error(
                "cannot read a field or element of a literal; declare it with a type first",
            ));
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
        locate(&mut issues[first..], expression.span);
        return;
    }
    let registered_builtin = operands::operands(expression);

    match &expression.kind {
        ExprKind::BinaryOp { left, op, right } if op.class() == OperatorClass::Bytewise => {
            for operand in [left, right] {
                let actual = operand.ty.clone();
                if !binding_types_compatible(&ArkType::Bytes, &actual) {
                    issues.push(
                        ValidationIssue::error(format!(
                            "bytewise '{op}' operand has type '{}', expected 'bytes'",
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
                        "bytewise '{op}' operands must have equal lengths, got {left} and {right} bytes"
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
                    if !crate::types::is_bytes_like(actual) {
                        let hint = match actual {
                            ArkType::Int => "convert it explicitly with bytes(value) for minimal Script-number encoding or int2bytes(value, width) for fixed-width encoding",
                            ArkType::Bool => "convert it explicitly with bytes(value) for minimal Script-number encoding",
                            _ => "both operands must be bytes-like",
                        };
                        issues.push(
                            ValidationIssue::type_error(format!(
                                "cannot concatenate bytes with the {side} `{}` operand of `+`; {hint}",
                                actual.as_str()
                            ))
                            .at(operand.span),
                        );
                    }
                }
            }
            for (operand, actual) in [left, right].iter().zip(&types).filter(|_| !concat) {
                if *actual != expected {
                    issues.push(
                        ValidationIssue::error(format!(
                            "{kind} '{}' operand has type '{}', expected '{}'",
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
                issues.push(ValidationIssue::error(format!("{what} by zero")).at(right.span));
            }
            if op.class() == OperatorClass::Shift
                && literal_index(right).is_some_and(|(negative, value)| negative && value != "0")
            {
                issues.push(
                    ValidationIssue::error("shift count must not be negative").at(right.span),
                );
            }
        }
        ExprKind::BinaryOp { left, op, right } if op.compares() => {
            validate_comparison(left, *op, right, expression.span, scopes, issues);
        }
        ExprKind::Unary { op, value } => {
            let (operator, expected) = (op.symbol(), ArkType::parse(op.operand_type()));
            let actual = value.ty.clone();
            if !binding_types_compatible(&expected, &actual) {
                issues.push(
                    ValidationIssue::error(format!(
                        "unary '{}' operand has type '{}', expected '{}'",
                        operator,
                        actual.as_str(),
                        expected.as_str()
                    ))
                    .at(value.span),
                );
            }
        }
        _ if registered_builtin.is_some() => {
            let (name, operands) = registered_builtin.expect("guarded by the arm");
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
                // A struct literal is checked against the parameter type; signatures name
                // only native structs.
                if matches!(&operand.kind, ExprKind::StructLiteral { .. }) {
                    super::functions::validate_value(
                        &(&expected).into(),
                        operand,
                        &[],
                        &format!("{name} operand"),
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
                            super::functions::validate_value(
                                &(&**element).into(),
                                value,
                                &[],
                                &format!("{name} operand, element {index}"),
                                issues,
                            );
                        } else if !binding_types_compatible(element, actual) {
                            issues.push(
                                ValidationIssue::error(format!(
                                    "{name} '{}' has type '{}', expected '{}'",
                                    value.source_text(),
                                    actual.as_str(),
                                    element.as_str()
                                ))
                                .at(value.span),
                            );
                        }
                    }
                    if elements.len() != *length {
                        issues.push(
                            ValidationIssue::error(format!(
                                "{name} operand has {} elements, expected {length}",
                                elements.len()
                            ))
                            .at(operand.span),
                        );
                    }
                    continue;
                }
                if !binding_types_compatible(&expected, &actual) {
                    issues.push(
                        ValidationIssue::error(format!(
                            "{name} operand has type '{}', expected '{}'",
                            actual.as_str(),
                            expected.as_str()
                        ))
                        .at(operand.span),
                    );
                }
            }
            for &(_, index, operand_name, ranges) in operands::CONSTANT_DOMAINS
                .iter()
                .filter(|(builtin, ..)| *builtin == name)
            {
                let Some(operand) = operands.get(index) else {
                    continue;
                };
                let Ok(value) =
                    crate::compiler::constants::evaluate(operand, &mut |path| Err(path.key()))
                else {
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
                    let allowed = ranges
                        .iter()
                        .map(|(low, high)| match (*low, *high) {
                            (low, i128::MAX) => format!("at least {low}"),
                            (low, high) if low == high => low.to_string(),
                            (low, high) => format!("{low} to {high}"),
                        })
                        .collect::<Vec<_>>()
                        .join(" or ");
                    issues.push(
                        ValidationIssue::error(format!(
                            "{name} {operand_name} must be {allowed}, got {value}"
                        ))
                        .at(operand.span),
                    );
                }
            }
            if name == "modExp" {
                for (operand, label) in operands.iter().zip(["base", "exponent", "modulus"]) {
                    if operand.ty != ArkType::Int {
                        continue;
                    }
                    if let Ok(value) =
                        crate::compiler::constants::evaluate(operand, &mut |path| Err(path.key()))
                    {
                        if crate::compiler::Op::Push(value).pushes_more_than(64) {
                            issues.push(
                                ValidationIssue::error(format!(
                                    "modExp {label} must fit in 64 Script-number bytes"
                                ))
                                .at(operand.span),
                            );
                        }
                    }
                }
            }
            // Checked here rather than in emission, which folding can skip.
            if let ("checkMultisig", Some(ArkType::Array(_, count)), Some(threshold)) =
                (name, operands.first().map(|keys| &keys.ty), operands.get(2))
            {
                if let Ok(value) =
                    crate::compiler::constants::evaluate(threshold, &mut |path| Err(path.key()))
                {
                    if value
                        .parse::<usize>()
                        .map_or(true, |t| t == 0 || t > *count)
                    {
                        issues.push(ValidationIssue::error(format!(
                            "checkMultisig threshold must be between 1 and the number of public keys, got {value}"
                        )).at(threshold.span));
                    }
                }
            }
            let width = |index: usize| {
                operands
                    .get(index)
                    .and_then(|o| crate::types::static_byte_width(o))
            };
            let byte_rule = match name {
                "checkSigFromStack" | "checkSigFromStackVerify" => width(2)
                    .filter(|&width| width != 32)
                    .map(|width| format!("message must be 32 bytes, got {width}")),
                "merkleRoot" => width(2)
                    .filter(|width| width % 32 != 0)
                    .map(|width| format!("proof must be a multiple of 32 bytes, got {width}")),
                _ => None,
            };
            if let Some(rule) = byte_rule {
                issues.push(ValidationIssue::error(format!("{name} {rule}")).at(expression.span));
            }
            // OP_ECPAIRING bounds its work at 16 pairs.
            if let Some(pairs) = length.filter(|&pairs| name == "ecPairing" && pairs > 16) {
                issues.push(ValidationIssue::error(format!(
                    "ecPairing supports at most 16 pairs, got {pairs}"
                )));
            }
        }
        ExprKind::Cast { target, data } => {
            let actual = data.ty.clone();
            let (source, hint) = match target.as_str() {
                "int" => (
                    ArkType::Bool,
                    "only bool converts to int; use int(0x..) for a hex constant or bytes2int for bytes",
                ),
                "bool" => (ArkType::Int, "only int converts to bool"),
                "bytes" => (ArkType::Int, "only int, bool or bytes-like values convert to bytes"),
                _ => (ArkType::Bytes, "only bytes can be cast"),
            };
            // Same-type casts are no-ops; emission drops them.
            if actual != source
                && !binding_types_compatible(&ArkType::parse(target), &actual)
                && !(target == "bytes" && actual == ArkType::Bool)
            {
                issues.push(ValidationIssue::error(format!(
                    "cannot cast '{}' to '{target}'; {hint}",
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
                    "tunnel output index must be int, got '{}'",
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

        ExprKind::StructLiteral { name: None, .. } if value_position => {
            issues.push(ValidationIssue::error(
                "struct literals may only initialize typed struct declarations",
            ));
        }
        // `tx` and `this` are reserved, so no binding resolves a path under them.
        ExprKind::Name(path) | ExprKind::ArrayIndex { array: path, .. }
            if matches!(path.root.as_str(), "tx" | "this") =>
        {
            issues.push(ValidationIssue::error(unknown_member(path)));
        }
        ExprKind::Name(path) if path.segments.is_empty() => {
            validate_named_binding(&path.root, None, "binding", scopes, issues);
        }
        // A path under an unbound root reports the root.
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
                    .any(|segment| matches!(segment, crate::models::Segment::Index(_)));
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
                        issues.push(ValidationIssue::error(format!(
                            "field '{}' is undefined",
                            expression.source_text()
                        )));
                    }
                } else if expression.ty == ArkType::Unknown {
                    issues.push(ValidationIssue::error(format!(
                        "value of type '{}' has no field '{field}'",
                        value.ty.as_str()
                    )));
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
                    (None, actual) => issues.push(ValidationIssue::error(format!(
                        "value of type '{}' is not an array",
                        actual.as_str()
                    ))),
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
                                issues.push(ValidationIssue::error(format!(
                                    "contract instance argument '{name}' is a runtime value; only constructor parameters and literals are supported"
                            )));
                            }
                        }
                    }
                    ExprKind::Literal(_) => {}
                    _ => issues.push(ValidationIssue::error(
                        "computed contract arguments are not supported",
                    )),
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
        issues.push(ValidationIssue::reported());
    }
    locate(&mut issues[first..], expression.span);
}

/// Validate the operands of `expression`, each as a value unless the operator takes it whole.
fn validate_operands(
    expression: &Expression,
    scopes: &BindingScopes,
    issues: &mut Vec<ValidationIssue>,
) {
    for child in child_exprs(expression) {
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
        issues.push(ValidationIssue::error(format!(
            "'{array}' is not an array; '.length' is undefined"
        )));
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
            issues.push(ValidationIssue::error(format!(
                "array '{written}' is undefined"
            )));
            None
        }
        Some(BindingInfo {
            binding_type: ArkType::Array(element, length),
            source,
            ..
        }) => Some(((**element).clone(), *length, *source)),
        Some(_) => {
            issues.push(ValidationIssue::error(format!(
                "binding '{written}' is not an array"
            )));
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

/// Validate an int index into `array`: how diagnostics spell it, and its length.
fn validate_index(
    index: &Expression,
    array: Option<(String, usize)>,
    scopes: &BindingScopes,
    issues: &mut Vec<ValidationIssue>,
) {
    let index_type = index.ty.clone();
    if index_type != ArkType::Int {
        issues.push(
            ValidationIssue::error(format!(
                "array index has type '{}', expected 'int'",
                index_type.as_str()
            ))
            .at(index.span),
        );
    }
    let evaluated = crate::compiler::constants::evaluate(index, &mut |path| {
        let array = path
            .split_last()
            .filter(|&(_, field)| field == "length" && find_binding(scopes, &path.key()).is_none());
        match array.and_then(|(array, _)| find_binding(scopes, &array.key())) {
            Some(BindingInfo {
                binding_type: ArkType::Array(_, length),
                ..
            }) => Ok(length.to_string()),
            _ => Err(path.key()),
        }
    })
    .ok()
    .filter(|_| index_type == ArkType::Int);
    if let (Some(literal), Some((array, length))) = (evaluated.as_deref(), array) {
        let (negative, literal) = match literal.strip_prefix('-') {
            Some(magnitude) => (true, magnitude),
            None => (false, literal),
        };
        let in_bounds = if negative {
            literal == "0"
        } else {
            literal.parse::<usize>().is_ok_and(|index| index < length)
        };
        if !in_bounds {
            let sign = if negative { "-" } else { "" };
            issues.push(
                ValidationIssue::error(format!(
                    "array index '{sign}{literal}' is out of range for '{array}'"
                ))
                .at(index.span),
            );
        }
    }
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

/// Why `path`, under `tx` or `this`, names no value: its first member the builtin docs
/// lack, with those they list at that level, or else that it needs an access or a call.
fn unknown_member(path: &crate::models::Path) -> String {
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
        let members = crate::builtins::members_of(&owner);
        if !members.iter().any(|member| member == name) {
            let expected = if members.is_empty() {
                String::new()
            } else {
                format!("; expected one of {}", members.join(", "))
            };
            return format!("unknown member '{name}' of '{}'{expected}", &text[..dot]);
        }
        owner = format!("{owner}.{}", segment.replace("()", ""));
    }
    format!("'{text}' is not a value on its own")
}
