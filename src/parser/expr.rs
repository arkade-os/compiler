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
        Rule::bool_literal => Ok(Expression::Literal(pair.as_str().to_string())),
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

    if name == "negate" {
        return Err(
            "`negate(value)` was replaced by the unary minus operator; write `-value`".to_string(),
        );
    }

    if matches!(name.as_str(), "neg64" | "le64ToScriptNum" | "le32ToLe64") {
        return Err(format!(
            "`{name}` was removed with fixed-width arithmetic; use BigNum arithmetic or bin2num/num2bin"
        ));
    }

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
        "checkMultisig" => Some("checkMultisig([pubkeys], [sigs], threshold?)"),
        "sha256" => Some("sha256(data)"),
        "hash160" => Some("hash160(data)"),
        "hash256" => Some("hash256(data)"),
        "ripemd160" => Some("ripemd160(data)"),
        "sha256Initialize" => Some("sha256Initialize(data)"),
        "sha256Update" => Some("sha256Update(ctx, chunk)"),
        "sha256Finalize" => Some("sha256Finalize(ctx, lastChunk)"),
        "digest" => Some("digest(data, hashType)"),
        "sighash" => Some("sighash(hashType)"),
        "modExp" => Some("modExp(base, exponent, modulus)"),
        "ecAdd" => Some("ecAdd(x1, y1, x2, y2, curveId)"),
        "ecMul" => Some("ecMul(x, y, scalar, curveId)"),
        "ecPairing" => Some("ecPairing(g1X, g1Y, g2Xc1, g2Xc0, g2Yc1, g2Yc0, curveId)"),
        "reverseBytes" => Some("reverseBytes(data)"),
        "ecMulScalarVerify" => Some("ecMulScalarVerify(k, P, Q)"),
        "tweakVerify" => Some("tweakVerify(P, k, Q)"),
        "older" => Some("older(value)"),
        "after" => Some("after(value)"),
        _ => None,
    }
}

pub(crate) fn parse_primary_expr(pair: Pair<Rule>) -> Result<Expression, String> {
    match pair.as_rule() {
        Rule::primary_expr => {
            let inner = pair.into_inner().next().ok_or("Empty primary expression")?;
            parse_primary_expr(inner)
        }
        // `-operand` negates; without the leading `-` this is a pass-through.
        Rule::unary_expr => {
            let mut inner = pair.into_inner();
            let first = inner.next().ok_or("Empty unary expression")?;
            if first.as_rule() != Rule::sub_op {
                return parse_primary_expr(first);
            }
            let operand = inner.next().ok_or("Missing operand after unary `-`")?;
            Ok(Expression::Negate {
                value: Box::new(parse_primary_expr(operand)?),
            })
        }
        Rule::general_expression | Rule::comparison_expr => {
            // Parenthesized expression
            parse_general_expression(pair)
        }
        Rule::identifier => Ok(Expression::Variable(pair.as_str().to_string())),
        Rule::bool_literal => Ok(Expression::Literal(pair.as_str().to_string())),
        Rule::number_literal => Ok(Expression::Literal(pair.as_str().to_string())),
        Rule::array_index_access => {
            let mut inner = pair.into_inner();
            let array = inner
                .next()
                .ok_or("Missing array name")?
                .as_str()
                .to_string();
            let index = inner.next().ok_or("Missing array index")?;
            Ok(Expression::ArrayIndex {
                array,
                index: Box::new(parse_general_expression(index)?),
            })
        }
        Rule::array_literal => Ok(Expression::ArrayLiteral(
            pair.into_inner()
                .map(parse_general_expression)
                .collect::<Result<Vec<_>, _>>()?,
        )),
        Rule::array_length_access => {
            let array = pair
                .into_inner()
                .next()
                .ok_or("Missing array name")?
                .as_str()
                .to_string();
            Ok(Expression::Property(format!("{array}.length")))
        }
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
        Rule::digest_func => parse_digest(pair),
        Rule::sighash_func => parse_sighash(pair),
        // Arithmetic
        Rule::mod_exp_func => parse_mod_exp(pair),
        // Crypto Opcodes
        Rule::ec_add => parse_ec_add(pair),
        Rule::ec_mul => parse_ec_mul(pair),
        Rule::ec_pairing => parse_ec_pairing(pair),
        Rule::ec_mul_scalar_verify => parse_ec_mul_scalar_verify(pair),
        Rule::tweak_verify => parse_tweak_verify(pair),
        Rule::check_sig_from_stack_verify => parse_check_sig_from_stack_verify_expr(pair),
        // Byte-string manipulation
        Rule::substr_func => parse_substr(pair),
        Rule::cat_func => parse_cat(pair),
        Rule::bin2num_func => parse_bin2num(pair),
        Rule::num2bin_func => parse_num2bin(pair),
        Rule::reverse_bytes_func => parse_reverse_bytes(pair),
        Rule::size_func => parse_size(pair),
        // Packet introspection
        Rule::packet_inspect => parse_packet_inspect(pair),
        Rule::input_packet_inspect => parse_input_packet_inspect(pair),
        Rule::asset_lookup => parse_asset_lookup_to_expression(pair),
        Rule::asset_has => parse_asset_has_to_expression(pair),
        Rule::asset_count => parse_asset_count_to_expression(pair),
        Rule::asset_at => parse_asset_at_to_expression(pair),
        Rule::group_control_is => parse_group_control_is_to_expression(pair),
        Rule::identifier_property_access => {
            let mut inner = pair.into_inner();
            Ok(Expression::GroupProperty {
                group: inner
                    .next()
                    .ok_or("Missing group name")?
                    .as_str()
                    .to_string(),
                property: inner
                    .next()
                    .ok_or("Missing group property")?
                    .as_str()
                    .to_string(),
            })
        }
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
        Rule::general_expression => {
            let expression = parse_general_expression(pair)?;
            if let Expression::BinaryOp { left, op, right } = expression {
                if matches!(op.as_str(), "==" | "!=" | ">=" | "<=" | ">" | "<") {
                    return Ok(Requirement::Comparison {
                        left: *left,
                        op,
                        right: *right,
                    });
                }
                return Ok(Requirement::Expression(Expression::BinaryOp {
                    left,
                    op,
                    right,
                }));
            }
            Ok(Requirement::Expression(expression))
        }
        Rule::check_sig => parse_check_sig(pair),
        Rule::check_sig_from_stack => parse_check_sig_from_stack(pair),
        Rule::check_sig_from_stack_verify => parse_check_sig_from_stack_verify(pair),
        Rule::check_multisig => parse_check_multisig(pair),
        Rule::time_comparison => parse_time_comparison(pair),
        Rule::hash_comparison => parse_hash_comparison(pair),
        _ => Err(format!(
            "Unexpected rule in complex expression: {:?}",
            pair.as_rule()
        )),
    }
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
        Rule::reverse_bytes_func => parse_reverse_bytes(inner),
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
