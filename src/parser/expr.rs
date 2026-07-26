use super::Rule;
#[allow(unused_imports)]
use super::*;
use crate::models::*;
use pest::iterators::Pair;

// Parse general expression (with operator precedence)
pub(crate) fn parse_general_expression(pair: Pair<Rule>) -> Result<Expression, String> {
    match pair.as_rule() {
        Rule::general_expression | Rule::comparison_expr => {
            // Unwrap and parse the inner expression
            let mut inner = pair.into_inner();
            if let Some(first) = inner.next() {
                let left = parse_additive_expr(first)?;

                // Check for comparison operator
                if let Some(op_pair) = inner.next() {
                    let op = op_pair.as_str().to_string();
                    let right_pair = inner.next().ok_or("Missing right side of comparison")?;
                    let right = parse_additive_expr(right_pair)?;
                    Ok(Expression::BinaryOp {
                        left: Box::new(left),
                        op,
                        right: Box::new(right),
                    })
                } else {
                    Ok(left)
                }
            } else {
                Err("Empty expression".to_string())
            }
        }
        Rule::additive_expr => parse_additive_expr(pair),
        Rule::multiplicative_expr => parse_multiplicative_expr(pair),
        Rule::unary_expr | Rule::primary_expr => parse_primary_expr(pair),
        Rule::identifier => Ok(Expression::Variable(pair.as_str().to_string())),
        Rule::number_literal => Ok(Expression::Literal(pair.as_str().to_string())),
        Rule::tx_property_access => parse_tx_property_to_expr(pair),
        Rule::this_property_access => Ok(Expression::Property(pair.as_str().to_string())),
        _ => {
            // Try to parse as a primary expression
            parse_primary_expr(pair)
        }
    }
}

// Parse additive expression (+ and -)
pub(crate) fn parse_additive_expr(pair: Pair<Rule>) -> Result<Expression, String> {
    match pair.as_rule() {
        Rule::additive_expr => {
            let mut inner = pair.into_inner();
            let first = inner
                .next()
                .ok_or("Missing first operand in additive expression")?;
            let mut result = parse_multiplicative_expr(first)?;

            // Process remaining operands
            while let Some(op_pair) = inner.next() {
                let op = op_pair.as_str().to_string();
                let right_pair = inner
                    .next()
                    .ok_or("Missing right operand in additive expression")?;
                let right = parse_multiplicative_expr(right_pair)?;
                result = Expression::BinaryOp {
                    left: Box::new(result),
                    op,
                    right: Box::new(right),
                };
            }

            Ok(result)
        }
        _ => parse_multiplicative_expr(pair),
    }
}

// Parse multiplicative expression (* and /)
pub(crate) fn parse_multiplicative_expr(pair: Pair<Rule>) -> Result<Expression, String> {
    match pair.as_rule() {
        Rule::multiplicative_expr => {
            let mut inner = pair.into_inner();
            let first = inner
                .next()
                .ok_or("Missing first operand in multiplicative expression")?;
            let mut result = parse_primary_expr(first)?;

            // Process remaining operands
            while let Some(op_pair) = inner.next() {
                let op = op_pair.as_str().to_string();
                let right_pair = inner
                    .next()
                    .ok_or("Missing right operand in multiplicative expression")?;
                let right = parse_primary_expr(right_pair)?;
                result = Expression::BinaryOp {
                    left: Box::new(result),
                    op,
                    right: Box::new(right),
                };
            }

            Ok(result)
        }
        _ => parse_primary_expr(pair),
    }
}

// Parse primary expression (atoms)
pub(crate) fn reject_reserved_function_call(pair: &Pair<Rule>) -> Result<(), String> {
    if pair.as_rule() != Rule::function_call {
        return Ok(());
    }

    let name = pair
        .clone()
        .into_inner()
        .next()
        .ok_or("Missing call name")?
        .as_str()
        .to_string();

    if let Some(signature) = reserved_function_signature(&name) {
        return Err(format!(
            "malformed reserved function call `{name}(...)`; expected {signature}"
        ));
    }

    Ok(())
}

pub(crate) fn reserved_function_signature(name: &str) -> Option<&'static str> {
    match name {
        "checkSig" => Some("checkSig(signature, pubkey)"),
        "checkSigFromStack" => Some("checkSigFromStack(signature, pubkey, message)"),
        "checkSigFromStackVerify" => Some("checkSigFromStackVerify(signature, pubkey, message)"),
        "checkMultisig" => Some("checkMultisig([pubkeys], [sigs]?, threshold?)"),
        "sha256" => Some("sha256(data)"),
        "hash160" => Some("hash160(data)"),
        "hash256" => Some("hash256(data)"),
        "ripemd160" => Some("ripemd160(data)"),
        "sha256Initialize" => Some("sha256Initialize(data)"),
        "sha256Update" => Some("sha256Update(ctx, chunk)"),
        "sha256Finalize" => Some("sha256Finalize(ctx, lastChunk)"),
        "neg64" => Some("neg64(value)"),
        "le64ToScriptNum" => Some("le64ToScriptNum(value)"),
        "le32ToLe64" => Some("le32ToLe64(value)"),
        "ecMulScalarVerify" => Some("ecMulScalarVerify(k, P, Q)"),
        "tweakVerify" => Some("tweakVerify(P, k, Q)"),
        "older" => Some("older(value)"),
        "after" => Some("after(value)"),
        _ => None,
    }
}

pub(crate) fn parse_primary_expr(pair: Pair<Rule>) -> Result<Expression, String> {
    match pair.as_rule() {
        Rule::primary_expr | Rule::unary_expr => {
            let inner = pair.into_inner().next().ok_or("Empty primary expression")?;
            parse_primary_expr(inner)
        }
        Rule::general_expression | Rule::comparison_expr => {
            // Parenthesized expression
            parse_general_expression(pair)
        }
        Rule::identifier => Ok(Expression::Variable(pair.as_str().to_string())),
        Rule::number_literal => Ok(Expression::Literal(pair.as_str().to_string())),
        Rule::tx_property_access => parse_tx_property_to_expr(pair),
        Rule::this_property_access => Ok(Expression::Property(pair.as_str().to_string())),
        Rule::check_sig => {
            let mut inner = pair.into_inner();
            let signature = inner
                .next()
                .ok_or("Missing signature")?
                .as_str()
                .to_string();
            let pubkey = inner.next().ok_or("Missing pubkey")?.as_str().to_string();
            Ok(Expression::CheckSigExpr { signature, pubkey })
        }
        Rule::check_sig_from_stack => {
            let mut inner = pair.into_inner();
            let signature = inner
                .next()
                .ok_or("Missing signature")?
                .as_str()
                .to_string();
            let pubkey = inner.next().ok_or("Missing pubkey")?.as_str().to_string();
            let message = inner.next().ok_or("Missing message")?.as_str().to_string();
            Ok(Expression::CheckSigFromStackExpr {
                signature,
                pubkey,
                message,
            })
        }
        Rule::sha256_func => {
            // sha256(data) → one-shot OP_SHA256 over the inner expression.
            let inner = pair.into_inner().next().ok_or("Missing sha256 argument")?;
            let data = parse_additive_expr(inner)?;
            Ok(Expression::Sha256 {
                data: Box::new(data),
            })
        }
        // Streaming SHA256
        Rule::sha256_initialize => parse_sha256_initialize(pair),
        Rule::sha256_update => parse_sha256_update(pair),
        Rule::sha256_finalize => parse_sha256_finalize(pair),
        // Conversion & Arithmetic
        Rule::neg64_func => parse_neg64(pair),
        Rule::le64_to_script_num => parse_le64_to_script_num(pair),
        Rule::le32_to_le64 => parse_le32_to_le64(pair),
        // Crypto Opcodes
        Rule::ec_mul_scalar_verify => parse_ec_mul_scalar_verify(pair),
        Rule::tweak_verify => parse_tweak_verify(pair),
        Rule::check_sig_from_stack_verify => parse_check_sig_from_stack_verify_expr(pair),
        // Byte-string manipulation
        Rule::substr_func => parse_substr(pair),
        Rule::cat_func => parse_cat(pair),
        Rule::bin2num_func => parse_bin2num(pair),
        Rule::num2bin_func => parse_num2bin(pair),
        Rule::size_func => parse_size(pair),
        // Packet introspection
        Rule::packet_inspect => parse_packet_inspect(pair),
        Rule::input_packet_inspect => parse_input_packet_inspect(pair),
        Rule::asset_lookup => parse_asset_lookup_to_expression(pair),
        Rule::asset_has => parse_asset_has_to_expression(pair),
        Rule::asset_count => parse_asset_count_to_expression(pair),
        Rule::asset_at => parse_asset_at_to_expression(pair),
        Rule::group_control_is => parse_group_control_is_to_expression(pair),
        Rule::input_introspection => parse_input_introspection_to_expression(pair),
        Rule::output_introspection => parse_output_introspection_to_expression(pair),
        Rule::tx_introspection => parse_tx_introspection_to_expression(pair),
        Rule::constructor => parse_constructor_to_expression(pair),
        Rule::function_call => {
            reject_reserved_function_call(&pair)?;
            Ok(Expression::Property(pair.as_str().to_string()))
        }
        Rule::additive_expr => parse_additive_expr(pair),
        Rule::multiplicative_expr => parse_multiplicative_expr(pair),
        _ => {
            // Default to treating as a property string
            Ok(Expression::Property(pair.as_str().to_string()))
        }
    }
}

/// Parse a complex expression into a Requirement AST node
pub(crate) fn parse_complex_expression(pair: Pair<Rule>) -> Result<Requirement, String> {
    match pair.as_rule() {
        Rule::check_sig => parse_check_sig(pair),
        Rule::check_sig_from_stack => parse_check_sig_from_stack(pair),
        Rule::check_multisig => parse_check_multisig(pair),
        Rule::time_comparison => parse_time_comparison(pair),
        Rule::identifier_comparison => parse_identifier_comparison(pair),
        Rule::property_comparison => parse_property_comparison(pair),
        Rule::reversed_property_comparison => parse_reversed_property_comparison(pair),
        Rule::hash_comparison => parse_hash_comparison(pair),
        Rule::byte_expr_comparison => parse_byte_expr_comparison(pair),
        Rule::binary_operation => parse_binary_operation(pair),
        Rule::asset_lookup_comparison => parse_asset_lookup_comparison(pair),
        Rule::asset_count_comparison => parse_asset_count_comparison(pair),
        Rule::asset_has_comparison => parse_asset_has_comparison(pair),
        Rule::group_control_is_comparison => parse_group_control_is_comparison(pair),
        Rule::asset_at_comparison => parse_asset_at_comparison(pair),
        Rule::input_introspection_comparison => parse_input_introspection_comparison(pair),
        Rule::output_introspection_comparison => parse_output_introspection_comparison(pair),
        Rule::tx_introspection_comparison => parse_tx_introspection_comparison(pair),
        Rule::input_introspection => parse_standalone_input_introspection(pair),
        Rule::output_introspection => parse_standalone_output_introspection(pair),
        Rule::tx_introspection => parse_standalone_tx_introspection(pair),
        Rule::asset_lookup => parse_standalone_asset_lookup(pair),
        Rule::asset_has => parse_standalone_asset_has(pair),
        Rule::asset_count => parse_standalone_asset_count(pair),
        Rule::asset_at => parse_standalone_asset_at(pair),
        Rule::asset_group_access => parse_asset_group_access(pair),
        Rule::group_control_is => parse_standalone_group_control_is(pair),
        Rule::group_property_comparison => parse_group_property_comparison(pair),
        // Streaming SHA256
        Rule::sha256_initialize => {
            let expr = parse_sha256_initialize(pair)?;
            Ok(Requirement::Comparison {
                left: expr,
                op: "==".to_string(),
                right: Expression::Literal("true".to_string()),
            })
        }
        Rule::sha256_update => {
            let expr = parse_sha256_update(pair)?;
            Ok(Requirement::Comparison {
                left: expr,
                op: "==".to_string(),
                right: Expression::Literal("true".to_string()),
            })
        }
        Rule::sha256_finalize => {
            let expr = parse_sha256_finalize(pair)?;
            Ok(Requirement::Comparison {
                left: expr,
                op: "==".to_string(),
                right: Expression::Literal("true".to_string()),
            })
        }
        // Conversion & Arithmetic
        Rule::neg64_func => {
            let expr = parse_neg64(pair)?;
            Ok(Requirement::Comparison {
                left: expr,
                op: "==".to_string(),
                right: Expression::Literal("true".to_string()),
            })
        }
        Rule::le64_to_script_num => {
            let expr = parse_le64_to_script_num(pair)?;
            Ok(Requirement::Comparison {
                left: expr,
                op: "==".to_string(),
                right: Expression::Literal("true".to_string()),
            })
        }
        Rule::le32_to_le64 => {
            let expr = parse_le32_to_le64(pair)?;
            Ok(Requirement::Comparison {
                left: expr,
                op: "==".to_string(),
                right: Expression::Literal("true".to_string()),
            })
        }
        // Crypto Opcodes
        Rule::ec_mul_scalar_verify => {
            let expr = parse_ec_mul_scalar_verify(pair)?;
            Ok(Requirement::Comparison {
                left: expr,
                op: "==".to_string(),
                right: Expression::Literal("true".to_string()),
            })
        }
        Rule::tweak_verify => {
            let expr = parse_tweak_verify(pair)?;
            Ok(Requirement::Comparison {
                left: expr,
                op: "==".to_string(),
                right: Expression::Literal("true".to_string()),
            })
        }
        Rule::check_sig_from_stack_verify => parse_check_sig_from_stack_verify(pair),
        // Byte-string manipulation — wrap as truthy assertions in require contexts.
        Rule::substr_func => {
            let expr = parse_substr(pair)?;
            Ok(Requirement::Comparison {
                left: expr,
                op: "==".to_string(),
                right: Expression::Literal("true".to_string()),
            })
        }
        Rule::cat_func => {
            let expr = parse_cat(pair)?;
            Ok(Requirement::Comparison {
                left: expr,
                op: "==".to_string(),
                right: Expression::Literal("true".to_string()),
            })
        }
        Rule::bin2num_func => {
            let expr = parse_bin2num(pair)?;
            Ok(Requirement::Comparison {
                left: expr,
                op: "==".to_string(),
                right: Expression::Literal("true".to_string()),
            })
        }
        Rule::num2bin_func => {
            let expr = parse_num2bin(pair)?;
            Ok(Requirement::Comparison {
                left: expr,
                op: "==".to_string(),
                right: Expression::Literal("true".to_string()),
            })
        }
        Rule::size_func => {
            let expr = parse_size(pair)?;
            Ok(Requirement::Comparison {
                left: expr,
                op: "==".to_string(),
                right: Expression::Literal("true".to_string()),
            })
        }
        Rule::packet_inspect => {
            let expr = parse_packet_inspect(pair)?;
            Ok(Requirement::Comparison {
                left: expr,
                op: "==".to_string(),
                right: Expression::Literal("true".to_string()),
            })
        }
        Rule::input_packet_inspect => {
            let expr = parse_input_packet_inspect(pair)?;
            Ok(Requirement::Comparison {
                left: expr,
                op: "==".to_string(),
                right: Expression::Literal("true".to_string()),
            })
        }
        Rule::constructor => {
            let expr = parse_constructor_to_expression(pair)?;
            Ok(Requirement::Comparison {
                left: expr,
                op: "==".to_string(),
                right: Expression::Literal("true".to_string()),
            })
        }
        Rule::tx_property_access | Rule::this_property_access => {
            parse_property_access_as_requirement(pair)
        }
        Rule::function_call => {
            reject_reserved_function_call(&pair)?;
            let function_call = pair.as_str().to_string();
            Ok(Requirement::Comparison {
                left: Expression::Property(function_call),
                op: "==".to_string(),
                right: Expression::Literal("true".to_string()),
            })
        }
        Rule::identifier => {
            let identifier = pair.as_str().to_string();
            Ok(Requirement::Comparison {
                left: Expression::Variable(identifier),
                op: "==".to_string(),
                right: Expression::Literal("true".to_string()),
            })
        }
        Rule::array_literal => {
            let array_literal = pair.as_str().to_string();
            Ok(Requirement::Comparison {
                left: Expression::Property(array_literal),
                op: "==".to_string(),
                right: Expression::Literal("true".to_string()),
            })
        }
        _ => Err(format!(
            "Unexpected rule in complex expression: {:?}",
            pair.as_rule()
        )),
    }
}

/// Parse a `byte_expr_term` rule into an Expression
/// (sha256/substr/cat/bin2num/num2bin/size).
pub(crate) fn parse_byte_expr_term(pair: Pair<Rule>) -> Result<Expression, String> {
    // byte_expr_term is a single-alternative wrapper — descend into the inner rule.
    let inner = pair.into_inner().next().ok_or("Empty byte_expr_term")?;
    match inner.as_rule() {
        Rule::sha256_func => {
            // sha256_func's child is always an additive_expr (see grammar), so
            // route it through parse_additive_expr to recover the structured
            // inner expression (substr/packet/cat/…) and wrap with
            // Expression::Sha256 so the compiler emits inline OP_SHA256.
            let arg_pair = inner.into_inner().next().ok_or("Missing sha256 argument")?;
            let data = parse_additive_expr(arg_pair)?;
            Ok(Expression::Sha256 {
                data: Box::new(data),
            })
        }
        Rule::substr_func => parse_substr(inner),
        Rule::cat_func => parse_cat(inner),
        Rule::bin2num_func => parse_bin2num(inner),
        Rule::num2bin_func => parse_num2bin(inner),
        Rule::size_func => parse_size(inner),
        r => Err(format!("Unsupported byte_expr_term rule: {:?}", r)),
    }
}

/// Parse a `byte_expr_atom` rule (one operand of byte_expr_arith).
pub(crate) fn parse_byte_expr_atom(pair: Pair<Rule>) -> Result<Expression, String> {
    let inner = pair.into_inner().next().ok_or("Empty byte_expr_atom")?;
    match inner.as_rule() {
        Rule::bin2num_func => parse_bin2num(inner),
        Rule::size_func => parse_size(inner),
        Rule::identifier => Ok(Expression::Variable(inner.as_str().to_string())),
        Rule::number_literal => Ok(Expression::Literal(inner.as_str().to_string())),
        r => Err(format!("Unsupported byte_expr_atom rule: {:?}", r)),
    }
}

/// Parse a `byte_expr_arith` rule into a BinaryOp.
pub(crate) fn parse_byte_expr_arith(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();
    let left = parse_byte_expr_atom(inner.next().ok_or("Missing left of byte_expr_arith")?)?;
    let op = inner
        .next()
        .ok_or("Missing op in byte_expr_arith")?
        .as_str()
        .to_string();
    let right = parse_byte_expr_atom(inner.next().ok_or("Missing right of byte_expr_arith")?)?;
    Ok(Expression::BinaryOp {
        left: Box::new(left),
        op,
        right: Box::new(right),
    })
}

/// Parse a `byte_expr_rhs` rule into an Expression.
pub(crate) fn parse_byte_expr_rhs(pair: Pair<Rule>) -> Result<Expression, String> {
    let inner = pair.into_inner().next().ok_or("Empty byte_expr_rhs")?;
    match inner.as_rule() {
        Rule::byte_expr_arith => parse_byte_expr_arith(inner),
        Rule::byte_expr_term => parse_byte_expr_term(inner),
        Rule::identifier => Ok(Expression::Variable(inner.as_str().to_string())),
        Rule::number_literal => Ok(Expression::Literal(inner.as_str().to_string())),
        r => Err(format!("Unsupported byte_expr_rhs rule: {:?}", r)),
    }
}

/// Parse `byte_expr_comparison` → Requirement::Comparison.
pub(crate) fn parse_byte_expr_comparison(pair: Pair<Rule>) -> Result<Requirement, String> {
    let mut inner = pair.into_inner();
    let left = parse_byte_expr_term(inner.next().ok_or("Missing left of byte_expr_comparison")?)?;
    let op = inner
        .next()
        .ok_or("Missing op in byte_expr_comparison")?
        .as_str()
        .to_string();
    let right = parse_byte_expr_rhs(
        inner
            .next()
            .ok_or("Missing right of byte_expr_comparison")?,
    )?;
    Ok(Requirement::Comparison { left, op, right })
}

/// Parse binary operation: expr op expr → Comparison requirement
pub(crate) fn parse_binary_operation(pair: Pair<Rule>) -> Result<Requirement, String> {
    let mut inner = pair.into_inner();
    let left_expr = inner.next().ok_or("Missing left side expression")?;
    let op = inner
        .next()
        .ok_or("Missing binary opcode")?
        .as_str()
        .to_string();
    let right_expr = inner.next().ok_or("Missing right side expression")?;

    let left = match left_expr.as_rule() {
        Rule::identifier => Expression::Variable(left_expr.as_str().to_string()),
        Rule::number_literal => Expression::Literal(left_expr.as_str().to_string()),
        _ => return Err("Unexpected left expression in binary operation".to_string()),
    };

    let right = match right_expr.as_rule() {
        Rule::identifier => Expression::Variable(right_expr.as_str().to_string()),
        Rule::number_literal => Expression::Literal(right_expr.as_str().to_string()),
        _ => return Err("Unexpected right expression in binary operation".to_string()),
    };

    Ok(Requirement::Comparison { left, op, right })
}

/// Parse an arithmetic expression in asset lookup context (e.g., lookup + amount)
pub(crate) fn parse_arith_expr_to_expression(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();

    let left_pair = inner.next().ok_or("Missing left operand")?;
    let left = match left_pair.as_rule() {
        Rule::asset_lookup => parse_asset_lookup_to_expression(left_pair)?,
        Rule::identifier => Expression::Variable(left_pair.as_str().to_string()),
        Rule::number_literal => Expression::Literal(left_pair.as_str().to_string()),
        _ => {
            return Err(format!(
                "Unexpected left operand in arithmetic: {:?}",
                left_pair.as_rule()
            ))
        }
    };

    let op = inner
        .next()
        .ok_or("Missing arithmetic operator")?
        .as_str()
        .to_string();

    let right_pair = inner.next().ok_or("Missing right operand")?;
    let right = match right_pair.as_rule() {
        Rule::asset_lookup => parse_asset_lookup_to_expression(right_pair)?,
        Rule::identifier => Expression::Variable(right_pair.as_str().to_string()),
        Rule::number_literal => Expression::Literal(right_pair.as_str().to_string()),
        _ => {
            return Err(format!(
                "Unexpected right operand in arithmetic: {:?}",
                right_pair.as_rule()
            ))
        }
    };

    Ok(Expression::BinaryOp {
        left: Box::new(left),
        op,
        right: Box::new(right),
    })
}

// ─── Byte-string Manipulation Parsing ──────────────────────────────────

/// Helper: convert an inner pair to an Expression for the byte-string
/// and packet primitives. Identifiers → Variable, numbers → Literal,
/// everything else → Property.
pub(crate) fn parse_atom_pair(pair: Pair<Rule>) -> Expression {
    match pair.as_rule() {
        Rule::identifier => Expression::Variable(pair.as_str().to_string()),
        Rule::number_literal => Expression::Literal(pair.as_str().to_string()),
        _ => Expression::Property(pair.as_str().to_string()),
    }
}

/// Parse a `byte_value` rule into an Expression. Used wherever the grammar
/// accepts an arbitrary byte-producing operand (substr/cat/bin2num/size args).
pub(crate) fn parse_byte_value(pair: Pair<Rule>) -> Result<Expression, String> {
    // byte_value wraps exactly one inner rule.
    let inner = pair.into_inner().next().ok_or("Empty byte_value")?;
    match inner.as_rule() {
        Rule::substr_func => parse_substr(inner),
        Rule::cat_func => parse_cat(inner),
        Rule::num2bin_func => parse_num2bin(inner),
        Rule::packet_inspect => parse_packet_inspect(inner),
        Rule::input_packet_inspect => parse_input_packet_inspect(inner),
        Rule::input_introspection => parse_input_introspection_to_expression(inner),
        Rule::output_introspection => parse_output_introspection_to_expression(inner),
        Rule::asset_at => parse_asset_at_to_expression(inner),
        Rule::identifier => Ok(Expression::Variable(inner.as_str().to_string())),
        r => Err(format!("Unsupported byte_value rule: {:?}", r)),
    }
}

// ─── Constructor Parsing ───────────────────────────────────────────────────────

/// Parse a `constructor` rule pair into an `Expression::ContractInstance`.
///
/// Handles `new ContractName(arg1, arg2, ...)` and produces
/// `ContractInstance { contract_name, args }` which the compiler lowers to
/// a `<VTXO:ContractName(...)>` scriptPubKey placeholder.
pub(crate) fn parse_constructor_to_expression(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();

    // First child: contract name identifier
    let contract_name = inner
        .next()
        .ok_or("Parse error: Missing contract name in constructor")?
        .as_str()
        .to_string();

    // Second child (optional): constructor_args rule
    let args = if let Some(args_pair) = inner.next() {
        parse_constructor_args(args_pair)?
    } else {
        Vec::new()
    };

    Ok(Expression::ContractInstance {
        contract_name,
        args,
    })
}

/// Parse constructor arguments into a Vec<Expression>.
///
/// `constructor_args` is a named (non-silent) rule whose children are the
/// alternatives matched by the silent `complex_expression` rule — so we
/// see the raw inner rules (identifier, number_literal, etc.) directly.
pub(crate) fn parse_constructor_args(pair: Pair<Rule>) -> Result<Vec<Expression>, String> {
    let mut args = Vec::new();

    for inner in pair.into_inner() {
        let expr = match inner.as_rule() {
            Rule::identifier => Expression::Variable(inner.as_str().to_string()),
            Rule::number_literal => Expression::Literal(inner.as_str().to_string()),
            Rule::constructor => parse_constructor_to_expression(inner)?,
            Rule::input_introspection => parse_input_introspection_to_expression(inner)?,
            Rule::output_introspection => parse_output_introspection_to_expression(inner)?,
            Rule::tx_introspection => parse_tx_introspection_to_expression(inner)?,
            _ => {
                // Fall back to treating as a variable/property reference
                Expression::Variable(inner.as_str().to_string())
            }
        };
        args.push(expr);
    }

    Ok(args)
}

// ─── Helper Functions ──────────────────────────────────────────────────────────

/// Parse tx_property_access into the appropriate Expression type
/// Handles special patterns like tx.assetGroups[idx].sumInputs/sumOutputs
/// Reject malformed asset-API calls that fell through to the generic property
/// path. A well-formed `.assets.lookup`/`.assets.has` matches the dedicated
/// `asset_lookup`/`asset_has` rules (which require exactly two operands) before
/// any property fallback, so seeing one of these method names in a property
/// string means a legacy single-argument or otherwise malformed call.
pub(crate) fn reject_malformed_asset_call(text: &str) -> Result<(), String> {
    if text.contains(".assets.lookup(") {
        return Err(format!(
            "asset lookup requires two operands `lookup(txid, gidx)`: {text}"
        ));
    }
    if text.contains(".assets.has(") {
        return Err(format!(
            "asset presence check requires two operands `has(txid, gidx)`: {text}"
        ));
    }
    Ok(())
}
