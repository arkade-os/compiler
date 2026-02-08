use pest::Parser;
use pest_derive::Parser;
use pest::iterators::{Pair, Pairs};
use crate::models::{
    Contract, Function, Parameter, Requirement, Expression, Statement,
    AssetLookupSource, GroupSumSource,
};

/// Pest parser generated from grammar.pest
#[derive(Parser)]
#[grammar = "parser/grammar.pest"]
pub struct ArkadeParser;

/// Parse Arkade Script source code into a Contract AST.
///
/// This is the main entry point for the parser. It tokenizes the source code
/// using the Pest grammar and builds a typed AST.
pub fn parse(source_code: &str) -> Result<Contract, Box<dyn std::error::Error>> {
    let pairs = ArkadeParser::parse(Rule::main, source_code)?;
    let ast = build_ast(pairs)?;
    Ok(ast)
}

/// Build a Contract AST from parsed Pest pairs
fn build_ast(pairs: Pairs<Rule>) -> Result<Contract, String> {
    let mut contract = Contract {
        name: String::new(),
        parameters: Vec::new(),
        renewal_timelock: None,
        exit_timelock: None,
        server_key_param: None,
        functions: Vec::new(),
    };

    for pair in pairs {
        match pair.as_rule() {
            Rule::main => {
                for inner_pair in pair.into_inner() {
                    if inner_pair.as_rule() == Rule::contract {
                        parse_contract(&mut contract, inner_pair)?;
                    }
                }
            }
            Rule::contract => {
                parse_contract(&mut contract, pair)?;
            }
            _ => {}
        }
    }

    Ok(contract)
}

/// Parse a contract definition including options block, name, parameters, and functions
fn parse_contract(contract: &mut Contract, pair: Pair<Rule>) -> Result<(), String> {
    let mut inner_pairs = pair.into_inner().peekable();

    // Optional options block
    if inner_pairs.peek().map_or(false, |p| p.as_rule() == Rule::options_block) {
        if let Some(options_block) = inner_pairs.next() {
            parse_options_block(contract, options_block)?;
        }
    }

    // Contract name (required)
    contract.name = match inner_pairs.next() {
        Some(name) => name.as_str().to_string(),
        None => return Err("Missing contract name".to_string()),
    };

    // Parameters (optional)
    if let Some(param_list) = inner_pairs.next() {
        contract.parameters = parse_parameters(param_list)?;
    }

    // Functions
    for func_pair in inner_pairs {
        if func_pair.as_rule() == Rule::function {
            let func = parse_function(func_pair)?;
            contract.functions.push(func);
        }
    }
    Ok(())
}

/// Parse the options block (server key, exit timelock, renewal timelock)
fn parse_options_block(contract: &mut Contract, pair: Pair<Rule>) -> Result<(), String> {
    for option_pair in pair.into_inner() {
        if option_pair.as_rule() == Rule::option_setting {
            let mut inner = option_pair.into_inner();
            let option_name = match inner.next() {
                Some(name) => name.as_str(),
                None => continue,
            };
            let option_value = match inner.next() {
                Some(value) => value.as_str(),
                None => return Err(format!("Missing {} option value", option_name)),
            };

            match option_name {
                "server" => {
                    contract.server_key_param = Some(option_value.to_string());
                }
                "renew" => {
                    if let Ok(value) = option_value.parse::<u64>() {
                        contract.renewal_timelock = Some(value);
                    }
                }
                "exit" => {
                    if let Ok(value) = option_value.parse::<u64>() {
                        contract.exit_timelock = Some(value);
                    }
                }
                _ => {} // Ignore unknown options
            }
        }
    }
    Ok(())
}

/// Parse a function definition
fn parse_function(pair: Pair<Rule>) -> Result<Function, String> {
    let mut func = Function {
        name: String::new(),
        parameters: Vec::new(),
        statements: Vec::new(),
        is_internal: false,
    };

    let mut inner_pairs = pair.into_inner();

    // Function name (required)
    func.name = match inner_pairs.next() {
        Some(name) => name.as_str().to_string(),
        None => return Err("Missing function name".to_string()),
    };

    // Parameters
    if let Some(param_list) = inner_pairs.next() {
        func.parameters = parse_parameters(param_list)?;
    }

    // Check for function modifier (internal) and body
    match inner_pairs.next() {
        Some(next_pair) => {
            if next_pair.as_rule() == Rule::function_modifier {
                func.is_internal = true;
                for req_pair in inner_pairs {
                    parse_function_body(&mut func, req_pair)?;
                }
            } else {
                parse_function_body(&mut func, next_pair)?;
                for req_pair in inner_pairs {
                    parse_function_body(&mut func, req_pair)?;
                }
            }
        }
        None => {} // Empty function body
    };

    Ok(func)
}

/// Parse a statement in a function body (require, let binding, function call, variable declaration)
fn parse_function_body(func: &mut Function, pair: Pair<Rule>) -> Result<(), String> {
    match pair.as_rule() {
        Rule::require_stmt => {
            let mut inner = pair.into_inner();
            let expr = match inner.next() {
                Some(expr) => expr,
                None => return Err(format!("Parse error: Invalid arguments to function {}", func.name)),
            };
            let requirement = parse_complex_expression(expr)?;

            // Capture optional error message (stored in requirement metadata)
            let _message = inner.next().map(|p| p.as_str().to_string());

            // Wrap the requirement in a Statement::Require
            func.statements.push(Statement::Require(requirement));
            Ok(())
        }
        Rule::let_binding => {
            let mut inner = pair.into_inner();
            let name = inner.next().ok_or_else(|| "Parse error: Missing variable name in let binding".to_string())?.as_str().to_string();
            let value_pair = inner.next().ok_or_else(|| "Parse error: Missing value in let binding".to_string())?;
            let value = parse_general_expression(value_pair)?;

            func.statements.push(Statement::LetBinding { name, value });
            Ok(())
        }
        Rule::var_assign => {
            let mut inner = pair.into_inner();
            let name = inner.next().ok_or_else(|| "Parse error: Missing variable name in assignment".to_string())?.as_str().to_string();
            let value_pair = inner.next().ok_or_else(|| "Parse error: Missing value in assignment".to_string())?;
            let value = parse_general_expression(value_pair)?;

            func.statements.push(Statement::VarAssign { name, value });
            Ok(())
        }
        Rule::if_stmt => {
            let mut inner = pair.into_inner();
            let condition_pair = inner.next().ok_or_else(|| "Parse error: Missing condition in if statement".to_string())?;
            let condition = parse_general_expression(condition_pair)?;

            let then_block = inner.next().ok_or_else(|| "Parse error: Missing then block in if statement".to_string())?;
            let then_body = parse_block(then_block)?;

            let else_body = if let Some(else_block) = inner.next() {
                Some(parse_block(else_block)?)
            } else {
                None
            };

            func.statements.push(Statement::IfElse { condition, then_body, else_body });
            Ok(())
        }
        Rule::for_stmt => {
            let mut inner = pair.into_inner();
            let index_var = inner.next().ok_or_else(|| "Parse error: Missing index variable in for loop".to_string())?.as_str().to_string();
            let value_var = inner.next().ok_or_else(|| "Parse error: Missing value variable in for loop".to_string())?.as_str().to_string();
            let iterable_pair = inner.next().ok_or_else(|| "Parse error: Missing iterable in for loop".to_string())?;
            let iterable = parse_general_expression(iterable_pair)?;
            let body_block = inner.next().ok_or_else(|| "Parse error: Missing body in for loop".to_string())?;
            let body = parse_block(body_block)?;

            func.statements.push(Statement::ForIn { index_var, value_var, iterable, body });
            Ok(())
        }
        Rule::function_call_stmt => {
            // Function calls to internal helpers — not yet fully supported
            Ok(())
        }
        Rule::variable_declaration => {
            // Legacy typed variable declaration - treat like let binding
            let mut inner = pair.into_inner();
            let _data_type = inner.next(); // Skip data type
            let name = inner.next().ok_or_else(|| "Parse error: Missing variable name".to_string())?.as_str().to_string();
            let value_pair = inner.next().ok_or_else(|| "Parse error: Missing value".to_string())?;
            // For legacy variable declarations, wrap the expression
            let value = Expression::Property(value_pair.as_str().to_string());

            func.statements.push(Statement::LetBinding { name, value });
            Ok(())
        }
        _ => Ok(()),
    }
}

// ─── Expression Parsing ────────────────────────────────────────────────────────

// Parse a block of statements
fn parse_block(pair: Pair<Rule>) -> Result<Vec<Statement>, String> {
    let mut statements = Vec::new();

    for inner in pair.into_inner() {
        // Create a temporary function to collect statements
        let mut temp_func = Function {
            name: String::new(),
            parameters: Vec::new(),
            statements: Vec::new(),
            is_internal: false,
        };

        parse_function_body(&mut temp_func, inner)?;
        statements.extend(temp_func.statements);
    }

    Ok(statements)
}

// Parse general expression (with operator precedence)
fn parse_general_expression(pair: Pair<Rule>) -> Result<Expression, String> {
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
fn parse_additive_expr(pair: Pair<Rule>) -> Result<Expression, String> {
    match pair.as_rule() {
        Rule::additive_expr => {
            let mut inner = pair.into_inner();
            let first = inner.next().ok_or("Missing first operand in additive expression")?;
            let mut result = parse_multiplicative_expr(first)?;

            // Process remaining operands
            while let Some(op_pair) = inner.next() {
                let op = op_pair.as_str().to_string();
                let right_pair = inner.next().ok_or("Missing right operand in additive expression")?;
                let right = parse_multiplicative_expr(right_pair)?;
                result = Expression::BinaryOp {
                    left: Box::new(result),
                    op,
                    right: Box::new(right),
                };
            }

            Ok(result)
        }
        _ => parse_multiplicative_expr(pair)
    }
}

// Parse multiplicative expression (* and /)
fn parse_multiplicative_expr(pair: Pair<Rule>) -> Result<Expression, String> {
    match pair.as_rule() {
        Rule::multiplicative_expr => {
            let mut inner = pair.into_inner();
            let first = inner.next().ok_or("Missing first operand in multiplicative expression")?;
            let mut result = parse_primary_expr(first)?;

            // Process remaining operands
            while let Some(op_pair) = inner.next() {
                let op = op_pair.as_str().to_string();
                let right_pair = inner.next().ok_or("Missing right operand in multiplicative expression")?;
                let right = parse_primary_expr(right_pair)?;
                result = Expression::BinaryOp {
                    left: Box::new(result),
                    op,
                    right: Box::new(right),
                };
            }

            Ok(result)
        }
        _ => parse_primary_expr(pair)
    }
}

// Parse primary expression (atoms)
fn parse_primary_expr(pair: Pair<Rule>) -> Result<Expression, String> {
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
            let signature = inner.next().ok_or("Missing signature")?.as_str().to_string();
            let pubkey = inner.next().ok_or("Missing pubkey")?.as_str().to_string();
            Ok(Expression::CheckSigExpr { signature, pubkey })
        }
        Rule::check_sig_from_stack => {
            let mut inner = pair.into_inner();
            let signature = inner.next().ok_or("Missing signature")?.as_str().to_string();
            let pubkey = inner.next().ok_or("Missing pubkey")?.as_str().to_string();
            let message = inner.next().ok_or("Missing message")?.as_str().to_string();
            Ok(Expression::CheckSigFromStackExpr { signature, pubkey, message })
        }
        Rule::sha256_func => {
            // For now, represent as property
            Ok(Expression::Property(pair.as_str().to_string()))
        }
        Rule::p2tr_constructor => {
            Ok(Expression::Property(pair.as_str().to_string()))
        }
        Rule::function_call => {
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
fn parse_complex_expression(pair: Pair<Rule>) -> Result<Requirement, String> {
    match pair.as_rule() {
        Rule::check_sig => parse_check_sig(pair),
        Rule::check_sig_from_stack => parse_check_sig_from_stack(pair),
        Rule::check_multisig => parse_check_multisig(pair),
        Rule::time_comparison => parse_time_comparison(pair),
        Rule::identifier_comparison => parse_identifier_comparison(pair),
        Rule::property_comparison => parse_property_comparison(pair),
        Rule::hash_comparison => parse_hash_comparison(pair),
        Rule::binary_operation => parse_binary_operation(pair),
        Rule::asset_lookup_comparison => parse_asset_lookup_comparison(pair),
        Rule::asset_lookup => parse_standalone_asset_lookup(pair),
        Rule::asset_group_access => parse_asset_group_access(pair),
        Rule::group_property_comparison => parse_group_property_comparison(pair),
        Rule::p2tr_constructor => {
            let constructor = pair.as_str().to_string();
            Ok(Requirement::Comparison {
                left: Expression::Property(constructor),
                op: "==".to_string(),
                right: Expression::Literal("true".to_string()),
            })
        }
        Rule::tx_property_access | Rule::this_property_access => {
            parse_property_access_as_requirement(pair)
        }
        Rule::function_call => {
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

/// Parse checkSig(sig, pubkey) → CheckSig requirement
fn parse_check_sig(pair: Pair<Rule>) -> Result<Requirement, String> {
    let mut inner = pair.into_inner();
    let signature = inner
        .next()
        .ok_or("Missing signature")?
        .as_str()
        .to_string();
    let pubkey = inner
        .next()
        .ok_or("Missing public key")?
        .as_str()
        .to_string();
    Ok(Requirement::CheckSig { signature, pubkey })
}

/// Parse checkSigFromStack(sig, pubkey, message) → CheckSig requirement
fn parse_check_sig_from_stack(pair: Pair<Rule>) -> Result<Requirement, String> {
    let mut inner = pair.into_inner();
    let signature = inner
        .next()
        .ok_or("Missing signature")?
        .as_str()
        .to_string();
    let pubkey = inner
        .next()
        .ok_or("Missing public key")?
        .as_str()
        .to_string();
    let _message = inner
        .next()
        .ok_or("Missing message")?
        .as_str()
        .to_string();
    Ok(Requirement::CheckSig { signature, pubkey })
}

/// Parse checkMultisig([pubkeys], [sigs]) → CheckMultisig requirement
fn parse_check_multisig(pair: Pair<Rule>) -> Result<Requirement, String> {
    let mut inner = pair.into_inner();
    let pubkeys_array = inner.next().ok_or("Missing public keys")?;
    let signatures_array = inner.next().ok_or("Missing signatures")?;

    let pubkeys = pubkeys_array
        .into_inner()
        .map(|p| p.as_str().to_string())
        .collect();
    let signatures = signatures_array
        .into_inner()
        .map(|s| s.as_str().to_string())
        .collect();

    Ok(Requirement::CheckMultisig {
        signatures,
        pubkeys,
    })
}

/// Parse tx.time >= variable → After requirement
fn parse_time_comparison(pair: Pair<Rule>) -> Result<Requirement, String> {
    let mut inner = pair.into_inner();
    let timelock_var = inner
        .next()
        .ok_or("Missing timelock")?
        .as_str()
        .to_string();
    Ok(Requirement::After {
        blocks: 0,
        timelock_var: Some(timelock_var),
    })
}

/// Parse identifier op identifier → After or Comparison requirement
fn parse_identifier_comparison(pair: Pair<Rule>) -> Result<Requirement, String> {
    let mut inner = pair.into_inner();
    let left = inner
        .next()
        .ok_or("Missing left side expression")?
        .as_str()
        .to_string();
    let op = inner
        .next()
        .ok_or("Missing comparison opcode")?
        .as_str()
        .to_string();
    let right = inner
        .next()
        .ok_or("Missing right side expression")?
        .as_str()
        .to_string();

    // Special case for time comparisons
    if left == "tx.time" && op == ">=" {
        return Ok(Requirement::After {
            blocks: 0,
            timelock_var: Some(right),
        });
    }

    Ok(Requirement::Comparison {
        left: Expression::Variable(left),
        op,
        right: Expression::Variable(right),
    })
}

/// Parse property comparison: tx_property op expression
fn parse_property_comparison(pair: Pair<Rule>) -> Result<Requirement, String> {
    let mut inner = pair.into_inner();
    let left_expr = inner.next().ok_or("Missing left side expression")?;
    let op = inner
        .next()
        .ok_or("Missing comparison opcode")?
        .as_str()
        .to_string();
    let right_expr = inner.next().ok_or("Missing right side expression")?;

    let left = match left_expr.as_rule() {
        Rule::tx_property_access | Rule::this_property_access => {
            parse_tx_property_to_expression(left_expr)
        }
        _ => return Err("Unexpected left expression in property comparison".to_string()),
    };

    let right = match right_expr.as_rule() {
        Rule::identifier => Expression::Variable(right_expr.as_str().to_string()),
        Rule::number_literal => Expression::Literal(right_expr.as_str().to_string()),
        Rule::tx_property_access | Rule::this_property_access => {
            parse_tx_property_to_expression(right_expr)
        }
        Rule::p2tr_constructor => Expression::Property(right_expr.as_str().to_string()),
        Rule::asset_lookup => parse_asset_lookup_to_expression(right_expr)?,
        _ => return Err("Unexpected right expression in property comparison".to_string()),
    };

    Ok(Requirement::Comparison { left, op, right })
}

/// Parse sha256(preimage) == hash → HashEqual requirement
fn parse_hash_comparison(pair: Pair<Rule>) -> Result<Requirement, String> {
    let mut inner = pair.into_inner();
    let sha256_func = inner.next().ok_or("Missing hash function")?;
    let mut sha256_inner = sha256_func.into_inner();
    let preimage = sha256_inner
        .next()
        .ok_or("Missing preimage")?
        .as_str()
        .to_string();
    let hash = inner
        .next()
        .ok_or("Missing the hash")?
        .as_str()
        .to_string();

    Ok(Requirement::HashEqual { preimage, hash })
}

/// Parse binary operation: expr op expr → Comparison requirement
fn parse_binary_operation(pair: Pair<Rule>) -> Result<Requirement, String> {
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

// ─── Asset Lookup Parsing ──────────────────────────────────────────────────────

/// Parse asset_lookup_comparison: asset_lookup op (arith_expr | asset_lookup | identifier | literal)
fn parse_asset_lookup_comparison(pair: Pair<Rule>) -> Result<Requirement, String> {
    let mut inner = pair.into_inner();

    let left_pair = inner.next().ok_or("Missing left asset lookup")?;
    let left = parse_asset_lookup_to_expression(left_pair)?;

    let op = inner
        .next()
        .ok_or("Missing comparison operator")?
        .as_str()
        .to_string();

    let right_pair = inner.next().ok_or("Missing right expression")?;
    let right = match right_pair.as_rule() {
        Rule::asset_lookup_arith_expr => parse_arith_expr_to_expression(right_pair)?,
        Rule::asset_lookup => parse_asset_lookup_to_expression(right_pair)?,
        Rule::identifier => Expression::Variable(right_pair.as_str().to_string()),
        Rule::number_literal => Expression::Literal(right_pair.as_str().to_string()),
        _ => {
            return Err(format!(
                "Unexpected right side in asset lookup comparison: {:?}",
                right_pair.as_rule()
            ))
        }
    };

    Ok(Requirement::Comparison { left, op, right })
}

/// Parse a standalone asset_lookup (not in a comparison context)
fn parse_standalone_asset_lookup(pair: Pair<Rule>) -> Result<Requirement, String> {
    let expr = parse_asset_lookup_to_expression(pair)?;
    // Wrap in a dummy comparison for standalone usage
    Ok(Requirement::Comparison {
        left: expr,
        op: "==".to_string(),
        right: Expression::Literal("true".to_string()),
    })
}

/// Parse an asset_lookup pair into an Expression::AssetLookup
fn parse_asset_lookup_to_expression(pair: Pair<Rule>) -> Result<Expression, String> {
    let mut inner = pair.into_inner();

    // Parse source: "inputs" or "outputs"
    let source_pair = inner.next().ok_or("Missing asset lookup source")?;
    let source = match source_pair.as_str() {
        "inputs" => AssetLookupSource::Input,
        "outputs" => AssetLookupSource::Output,
        _ => return Err(format!("Invalid asset lookup source: {}", source_pair.as_str())),
    };

    // Parse array access index
    let array_access = inner.next().ok_or("Missing array index")?;
    let index_pair = array_access
        .into_inner()
        .next()
        .ok_or("Missing index value")?;
    let index = match index_pair.as_rule() {
        Rule::number_literal => Expression::Literal(index_pair.as_str().to_string()),
        Rule::identifier => Expression::Variable(index_pair.as_str().to_string()),
        _ => Expression::Literal(index_pair.as_str().to_string()),
    };

    // Parse asset ID
    let asset_id = inner
        .next()
        .ok_or("Missing asset ID")?
        .as_str()
        .to_string();

    Ok(Expression::AssetLookup {
        source,
        index: Box::new(index),
        asset_id,
    })
}

/// Parse an arithmetic expression in asset lookup context (e.g., lookup + amount)
fn parse_arith_expr_to_expression(pair: Pair<Rule>) -> Result<Expression, String> {
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

// ─── Asset Group Parsing ───────────────────────────────────────────────────────

/// Parse asset_group_access: tx.assetGroups.find(id), tx.assetGroups.length,
/// tx.assetGroups[k].property
fn parse_asset_group_access(pair: Pair<Rule>) -> Result<Requirement, String> {
    let text = pair.as_str();
    let mut inner = pair.into_inner();

    // Determine which variant of asset group access
    if text.contains(".find(") {
        // tx.assetGroups.find(assetId)
        let asset_id = inner
            .next()
            .ok_or("Missing asset ID in group find")?
            .as_str()
            .to_string();
        Ok(Requirement::Comparison {
            left: Expression::GroupFind { asset_id },
            op: "==".to_string(),
            right: Expression::Literal("true".to_string()),
        })
    } else if text.contains(".length") {
        // tx.assetGroups.length
        Ok(Requirement::Comparison {
            left: Expression::AssetGroupsLength,
            op: "==".to_string(),
            right: Expression::Literal("true".to_string()),
        })
    } else {
        // tx.assetGroups[k].property
        let array_access = inner.next().ok_or("Missing group index")?;
        let index_pair = array_access
            .into_inner()
            .next()
            .ok_or("Missing index value")?;
        let index = match index_pair.as_rule() {
            Rule::number_literal => Expression::Literal(index_pair.as_str().to_string()),
            Rule::identifier => Expression::Variable(index_pair.as_str().to_string()),
            _ => Expression::Literal(index_pair.as_str().to_string()),
        };

        let property = inner
            .next()
            .ok_or("Missing group property")?
            .as_str()
            .to_string();

        let expr = match property.as_str() {
            "sumInputs" => Expression::GroupSum {
                index: Box::new(index),
                source: GroupSumSource::Inputs,
            },
            "sumOutputs" => Expression::GroupSum {
                index: Box::new(index),
                source: GroupSumSource::Outputs,
            },
            _ => Expression::GroupProperty {
                group: format!("assetGroups[{}]", index_pair_to_string(&index)),
                property,
            },
        };

        Ok(Requirement::Comparison {
            left: expr,
            op: "==".to_string(),
            right: Expression::Literal("true".to_string()),
        })
    }
}

/// Parse group_property_comparison: variable.property op expression
fn parse_group_property_comparison(pair: Pair<Rule>) -> Result<Requirement, String> {
    let mut inner = pair.into_inner();

    let group_name = inner
        .next()
        .ok_or("Missing group variable name")?
        .as_str()
        .to_string();

    let property = inner
        .next()
        .ok_or("Missing group property")?
        .as_str()
        .to_string();

    let op = inner
        .next()
        .ok_or("Missing comparison operator")?
        .as_str()
        .to_string();

    let right_pair = inner.next().ok_or("Missing right side expression")?;
    let right = match right_pair.as_rule() {
        Rule::asset_lookup => parse_asset_lookup_to_expression(right_pair)?,
        Rule::asset_group_access => {
            // Parse the group access and extract the expression
            let req = parse_asset_group_access(right_pair)?;
            if let Requirement::Comparison { left, .. } = req {
                left
            } else {
                return Err("Expected expression from asset group access".to_string());
            }
        }
        Rule::identifier_property_access => {
            // Parse variable.property (e.g., group.sumInputs)
            let mut prop_inner = right_pair.into_inner();
            let var_name = prop_inner
                .next()
                .ok_or("Missing variable name in property access")?
                .as_str()
                .to_string();
            let prop_name = prop_inner
                .next()
                .ok_or("Missing property name in property access")?
                .as_str()
                .to_string();
            Expression::GroupProperty {
                group: var_name,
                property: prop_name,
            }
        }
        Rule::identifier => Expression::Variable(right_pair.as_str().to_string()),
        Rule::number_literal => Expression::Literal(right_pair.as_str().to_string()),
        _ => {
            return Err(format!(
                "Unexpected right side in group property comparison: {:?}",
                right_pair.as_rule()
            ))
        }
    };

    let left = Expression::GroupProperty {
        group: group_name,
        property,
    };

    Ok(Requirement::Comparison { left, op, right })
}

// ─── Helper Functions ──────────────────────────────────────────────────────────

/// Parse tx_property_access into the appropriate Expression type
/// Handles special patterns like tx.assetGroups[idx].sumInputs/sumOutputs
fn parse_tx_property_to_expr(pair: Pair<Rule>) -> Result<Expression, String> {
    let text = pair.as_str();

    // Handle tx.assetGroups[idx].sumInputs or tx.assetGroups[idx].sumOutputs
    if text.starts_with("tx.assetGroups[") {
        if let Some(bracket_start) = text.find('[') {
            if let Some(bracket_end) = text.find(']') {
                let idx_str = &text[bracket_start + 1..bracket_end];
                let index = if idx_str.chars().all(|c| c.is_ascii_digit()) {
                    Expression::Literal(idx_str.to_string())
                } else {
                    Expression::Variable(idx_str.to_string())
                };

                if text.ends_with(".sumInputs") {
                    return Ok(Expression::GroupSum {
                        index: Box::new(index),
                        source: GroupSumSource::Inputs,
                    });
                } else if text.ends_with(".sumOutputs") {
                    return Ok(Expression::GroupSum {
                        index: Box::new(index),
                        source: GroupSumSource::Outputs,
                    });
                }
            }
        }
    }

    // Handle tx.input.current
    if text.starts_with("tx.input.current") {
        let property = if text == "tx.input.current" {
            None
        } else if let Some(rest) = text.strip_prefix("tx.input.current.") {
            Some(rest.to_string())
        } else {
            None
        };
        return Ok(Expression::CurrentInput(property));
    }

    // Default: treat as a property string
    Ok(Expression::Property(text.to_string()))
}

/// Convert a tx_property_access or this_property_access pair into an Expression
fn parse_tx_property_to_expression(pair: Pair<Rule>) -> Expression {
    let property_access = pair.as_str().to_string();

    // Special handling for tx.input.current
    if property_access.starts_with("tx.input.current") {
        let property = if property_access == "tx.input.current" {
            None
        } else {
            let parts: Vec<&str> = property_access.split('.').collect();
            if parts.len() >= 4 {
                Some(parts[3].to_string())
            } else {
                None
            }
        };
        Expression::CurrentInput(property)
    } else {
        Expression::Property(property_access)
    }
}

/// Parse a tx_property_access or this_property_access as a standalone Requirement
fn parse_property_access_as_requirement(pair: Pair<Rule>) -> Result<Requirement, String> {
    let expr = parse_tx_property_to_expression(pair);
    Ok(Requirement::Comparison {
        left: expr,
        op: "==".to_string(),
        right: Expression::Literal("true".to_string()),
    })
}

/// Helper to convert an Expression index to a string representation
fn index_pair_to_string(expr: &Expression) -> String {
    match expr {
        Expression::Literal(s) => s.clone(),
        Expression::Variable(s) => s.clone(),
        _ => "?".to_string(),
    }
}

/// Parse parameter list from contracts or functions
fn parse_parameters(params: Pair<Rule>) -> Result<Vec<Parameter>, String> {
    let mut parameters = Vec::new();
    for param_pair in params.into_inner() {
        if param_pair.as_rule() == Rule::parameter {
            let mut param_inner = param_pair.into_inner();
            let param_type = match param_inner.next() {
                Some(type_pair) => {
                    // data_type is now a compound rule: base_type ~ ("[]")?
                    // Extract the base type and check for array suffix
                    let type_text = type_pair.as_str().trim();
                    if type_text.ends_with("[]") {
                        type_text.to_string()
                    } else {
                        // Parse inner to get just the base type
                        let mut type_inner = type_pair.into_inner();
                        if let Some(base) = type_inner.next() {
                            base.as_str().to_string()
                        } else {
                            type_text.to_string()
                        }
                    }
                }
                None => return Err("Parameter is missing data type".to_string()),
            };
            let param_name = match param_inner.next() {
                Some(param_name) => param_name.as_str().to_string(),
                None => return Err("Missing parameter name after data type".to_string()),
            };

            parameters.push(Parameter {
                name: param_name,
                param_type,
            });
        }
    }
    Ok(parameters)
}
