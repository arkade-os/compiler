use pest::Parser;
use pest_derive::Parser;
use pest::iterators::{Pair, Pairs};
use crate::models::{Contract, Function, Parameter, Requirement, Expression, Statement};

// Grammar definition for pest parser
#[derive(Parser)]
#[grammar = "parser/grammar.pest"]
pub struct ArkadeParser;

pub fn parse(source_code: &str) -> Result<Contract, Box<dyn std::error::Error>> {
    let pairs = ArkadeParser::parse(Rule::main, source_code)?;
    let ast = build_ast(pairs)?;
    Ok(ast)
}

// Parse pest output into AST
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
            // Main rule contains the contract
            Rule::main => {
                // Find the contract inside main
                for inner_pair in pair.into_inner() {
                    if inner_pair.as_rule() == Rule::contract {
                        parse_contract(&mut contract, inner_pair)?;
                    }
                }
            }
            // Direct contract rule (for backward compatibility)
            Rule::contract => {
                parse_contract(&mut contract, pair)?;
            }
            // Skip other rules
            _ => {}
        }
    }
    
    Ok(contract)
}

// Helper function to parse contract details
fn parse_contract(contract: &mut Contract, pair: Pair<Rule>) -> Result<(), String> {
    let mut inner_pairs = pair.into_inner().peekable();

    // Check for options block before the contract keyword
    if inner_pairs.peek().map_or(false, |p| p.as_rule() == Rule::options_block) {
        match inner_pairs.next() {
            Some(options_block) =>  {
                parse_options_block(contract, options_block)?;
            }
            None => {
                // Ignore missing options block because it is optional
            }
        }
    }
    
    // Contract name
    contract.name = match inner_pairs.next() {
        Some(name) => name.as_str().to_string(),
        None =>  {
            // A contract cannot continue without a name
            return Err("Missing contract name".to_string());
        }
    };

    // Parameters
    match inner_pairs.next() {
        Some(param_list) => {
            contract.parameters = parse_parameters(param_list)?
        },
        None => {
            // Ignore missing parameters, this means the contract has no parameters
        }
    };

    // Functions
    for func_pair in inner_pairs {
        if func_pair.as_rule() == Rule::function {
            let func = parse_function(func_pair)?;
            contract.functions.push(func);
        }
    }
    Ok(())
}

// Parse options block
fn parse_options_block(contract: &mut Contract, pair: Pair<Rule>) -> Result<(), String> {
    for option_pair in pair.into_inner() {
        if option_pair.as_rule() == Rule::option_setting {
            let mut inner = option_pair.into_inner();
            let option_name = match inner.next() {
                Some(name) => name.as_str(),
                None => {
                    // No option name means no option at all, we can just skip
                    continue;
                }
            };

            let option_value = match inner.next() {
                Some(value) => value.as_str(),
                None => {
                    return Err(format!("Missing {} option value", option_name));
                }
            };

            match option_name {
                "server" => {
                    contract.server_key_param = Some(option_value.to_string());
                },
                "renew" => {
                    if let Ok(value) = option_value.parse::<u64>() {
                        contract.renewal_timelock = Some(value);
                    }
                },
                "exit" => {
                    if let Ok(value) = option_value.parse::<u64>() {
                        contract.exit_timelock = Some(value);
                    }
                },
                _ => {
                    // Ignore unknown options
                }
            }
        }
    }
    Ok(())
}

// Parse function from pest output
fn parse_function(pair: Pair<Rule>) -> Result<Function, String> {
    let mut func = Function {
        name: String::new(),
        parameters: Vec::new(),
        statements: Vec::new(),
        is_internal: false,
    };
    
    let mut inner_pairs = pair.into_inner();
    
    // Function name
    func.name = match inner_pairs.next() {
        Some(name) => name.as_str().to_string(),
        None => {
            // Cannot continue with function without name
            return Err("Missing function name".to_string());
        }
    };

    // Parameters
    match inner_pairs.next() {
        Some(param_list) => {
            func.parameters = parse_parameters(param_list)?
        }
        None => {
            // Ignore missing parameters because parameters can be optional
        }
    };

    // Check for function modifier (internal)
    match inner_pairs.next() {
        Some(next_pair) => {
            if next_pair.as_rule() == Rule::function_modifier {
                func.is_internal = true;
                // Get the next pair for requirements
                for req_pair in inner_pairs {
                    parse_function_body(&mut func, req_pair)?;
                }
            } else {
                // No modifier, this is already a requirement or function call
                parse_function_body(&mut func, next_pair)?;

                // Continue with the rest of the requirements
                for req_pair in inner_pairs {
                    parse_function_body(&mut func, req_pair)?;
                }
            }

        },
        None => {
            // Ignore missing function modifier, this means the function is a spending path
        }
    };

    Ok(func)
}

// Parse function body (requirements and function calls)
fn parse_function_body(func: &mut Function, pair: Pair<Rule>) -> Result<(), String> {
    // The pair is already a statement (require_stmt, function_call_stmt, etc.)
    match pair.as_rule() {
        Rule::require_stmt => {
            let mut inner = pair.into_inner();
            let expr = match inner.next() {
                Some(expr) => expr,
                None => {
                    // Cannot continue compilation if `require` input expression is malformed
                    return Err(format!("Invalid arguments to function {}", func.name));
                }
            };
            let requirement = parse_complex_expression(expr)?;

            // Check if there's an optional error message (ignore it for now)
            let _message = inner.next().map(|p| p.as_str().to_string());

            // Wrap the requirement in a Statement::Require
            func.statements.push(Statement::Require(requirement));
            Ok(())
        }
        Rule::let_binding => {
            let mut inner = pair.into_inner();
            let name = inner.next().ok_or("Missing variable name in let binding")?.as_str().to_string();
            let value_pair = inner.next().ok_or("Missing value in let binding")?;
            let value = parse_general_expression(value_pair)?;

            func.statements.push(Statement::LetBinding { name, value });
            Ok(())
        }
        Rule::var_assign => {
            let mut inner = pair.into_inner();
            let name = inner.next().ok_or("Missing variable name in assignment")?.as_str().to_string();
            let value_pair = inner.next().ok_or("Missing value in assignment")?;
            let value = parse_general_expression(value_pair)?;

            func.statements.push(Statement::VarAssign { name, value });
            Ok(())
        }
        Rule::if_stmt => {
            let mut inner = pair.into_inner();
            let condition_pair = inner.next().ok_or("Missing condition in if statement")?;
            let condition = parse_general_expression(condition_pair)?;

            let then_block = inner.next().ok_or("Missing then block in if statement")?;
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
            let index_var = inner.next().ok_or("Missing index variable in for loop")?.as_str().to_string();
            let value_var = inner.next().ok_or("Missing value variable in for loop")?.as_str().to_string();
            let iterable_pair = inner.next().ok_or("Missing iterable in for loop")?;
            let iterable = parse_general_expression(iterable_pair)?;
            let body_block = inner.next().ok_or("Missing body in for loop")?;
            let body = parse_block(body_block)?;

            func.statements.push(Statement::ForIn { index_var, value_var, iterable, body });
            Ok(())
        }
        Rule::function_call_stmt => {
            // In a more complete implementation, we would handle function calls
            // For now, we just ignore them
            Ok(())
        }
        Rule::variable_declaration => {
            // Legacy typed variable declaration - treat like let binding
            let mut inner = pair.into_inner();
            let _data_type = inner.next(); // Skip data type
            let name = inner.next().ok_or("Missing variable name")?.as_str().to_string();
            let value_pair = inner.next().ok_or("Missing value")?;
            // For legacy variable declarations, wrap the expression
            let value = Expression::Property(value_pair.as_str().to_string());

            func.statements.push(Statement::LetBinding { name, value });
            Ok(())
        }
        _ => Ok(())
    }
}

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
        Rule::tx_property_access => Ok(Expression::Property(pair.as_str().to_string())),
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
        Rule::tx_property_access => Ok(Expression::Property(pair.as_str().to_string())),
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

// Parse complex expression from pest output
fn parse_complex_expression(pair: Pair<Rule>) -> Result<Requirement, String> {
    match pair.as_rule() {
        Rule::check_sig => {
            let mut inner = pair.into_inner();
            let signature = inner.next().ok_or_else(|| "Missing signature")?.as_str().to_string();
            let pubkey = inner.next().ok_or_else(|| "Missing public key")?.as_str().to_string();
            Ok(Requirement::CheckSig { signature, pubkey })
        }
        Rule::check_sig_from_stack => {
            let mut inner = pair.into_inner();
            let signature = inner.next().ok_or_else(|| "Missing signature")?.as_str().to_string();
            let pubkey = inner.next().ok_or_else(|| "Missing public key")?.as_str().to_string();
            let _message = inner.next().ok_or_else(|| "Missing message")?.as_str().to_string();
            // For now, we'll treat this as a special case of CheckSig
            Ok(Requirement::CheckSig { signature, pubkey })
        }
        Rule::check_multisig => {
            let mut inner = pair.into_inner();
            let pubkeys_array = inner.next().ok_or_else(|| "Missing public keys")?;
            let signatures_array = inner.next().ok_or_else(|| "Missing signatures")?;
            
            let pubkeys = pubkeys_array.into_inner()
                .map(|p| p.as_str().to_string())
                .collect();
            
            let signatures = signatures_array.into_inner()
                .map(|s| s.as_str().to_string())
                .collect();
            
            Ok(Requirement::CheckMultisig { signatures, pubkeys })
        }
        Rule::time_comparison => {
            let mut inner = pair.into_inner();
            let timelock_var = inner.next().ok_or_else(|| "Missing timelock")?.as_str().to_string();
            Ok(Requirement::After {
                blocks: 0, // This will be filled in by the compiler
                timelock_var: Some(timelock_var)
            })
        }
        Rule::identifier_comparison => {
            let mut inner = pair.into_inner();
            let left = inner.next().ok_or_else(|| "Missing left side expression")?.as_str().to_string();
            let op = inner.next().ok_or_else(|| "Missing comparison opcode")?.as_str().to_string();
            let right = inner.next().ok_or_else(|| "Missing right side expression")?.as_str().to_string();
            
            // Special case for time comparisons
            if left == "tx.time" && op == ">=" {
                return Ok(Requirement::After {
                    blocks: 0,
                    timelock_var: Some(right)
                });
            }
            
            Ok(Requirement::Comparison {
                left: Expression::Variable(left),
                op,
                right: Expression::Variable(right)
            })
        }
        Rule::property_comparison => {
            let mut inner = pair.into_inner();
            let left_expr = inner.next().ok_or_else(|| "Missing left side expression")?;
            let op = inner.next().ok_or_else(|| "Missing comparison opcode")?.as_str().to_string();
            let right_expr = inner.next().ok_or_else(|| "Missing right side expression")?;
            
            let left = match left_expr.as_rule() {
                Rule::tx_property_access | Rule::this_property_access => 
                    Expression::Property(left_expr.as_str().to_string()),
                _ => return Err("Unexpected left expression in property comparison".to_string())
            };
            
            let right = match right_expr.as_rule() {
                Rule::identifier => Expression::Variable(right_expr.as_str().to_string()),
                Rule::number_literal => Expression::Literal(right_expr.as_str().to_string()),
                Rule::tx_property_access | Rule::this_property_access => 
                    Expression::Property(right_expr.as_str().to_string()),
                Rule::p2tr_constructor =>
                    Expression::Property(right_expr.as_str().to_string()),
                _ => return Err("Unexpected right expression in property comparison".to_string())
            };
            
            Ok(Requirement::Comparison {
                left,
                op,
                right
            })
        }
        Rule::hash_comparison => {
            let mut inner = pair.into_inner();
            let sha256_func = inner.next().ok_or_else(|| "Missing hash function")?;
            let mut sha256_inner = sha256_func.into_inner();
            let preimage = sha256_inner.next().ok_or_else(|| "Missing preimage")?.as_str().to_string();
            let hash = inner.next().ok_or_else(|| "Missing the hash")?.as_str().to_string();
            
            Ok(Requirement::HashEqual { preimage, hash })
        }
        Rule::binary_operation => {
            let mut inner = pair.into_inner();
            let left_expr = inner.next().ok_or_else(|| "Missing left side expression")?;
            let op = inner.next().ok_or_else(|| "Missing binary opcode")?.as_str().to_string();
            let right_expr = inner.next().ok_or_else(|| "Missing right side expression")?;
            
            let left = match left_expr.as_rule() {
                Rule::identifier => Expression::Variable(left_expr.as_str().to_string()),
                Rule::number_literal => Expression::Literal(left_expr.as_str().to_string()),
                _ => return Err("Unexpected left expression in binary operation".to_string())
            };
            
            let right = match right_expr.as_rule() {
                Rule::identifier => Expression::Variable(right_expr.as_str().to_string()),
                Rule::number_literal => Expression::Literal(right_expr.as_str().to_string()),
                _ => return Err("Unexpected right expression in binary operation".to_string())
            };
            
            Ok(Requirement::Comparison { left, op, right })
        }
        Rule::p2tr_constructor => {
            // For now, we'll just capture the full expression as a string
            // and handle it during compilation
            let constructor = pair.as_str().to_string();

            Ok(Requirement::Comparison {
                left: Expression::Property(constructor),
                op: "==".to_string(),
                right: Expression::Literal("true".to_string())
            })
        }
        Rule::tx_property_access | Rule::this_property_access => {
            // For now, we'll just capture the full expression as a string
            // and handle it during compilation
            let property_access = pair.as_str().to_string();
            
            // Special handling for tx.input.current
            Ok(if property_access.starts_with("tx.input.current") {
                // Extract the property after tx.input.current if any
                // Format is tx.input.current.property or just tx.input.current
                let property = if property_access == "tx.input.current" {
                    // If just tx.input.current, default to the entire input
                    None
                } else {
                    // Extract the property after tx.input.current.
                    let parts: Vec<&str> = property_access.split('.').collect();
                    if parts.len() >= 4 {
                        Some(parts[3].to_string())
                    } else {
                        None
                    }
                };
                
                // Create a CurrentInput expression that directly represents the current input
                Requirement::Comparison {
                    left: Expression::CurrentInput(property),
                    op: "==".to_string(),
                    right: Expression::Literal("true".to_string())
                }
            } else {
                Requirement::Comparison {
                    left: Expression::Property(property_access),
                    op: "==".to_string(),
                    right: Expression::Literal("true".to_string())
                }
            })
        }
        Rule::function_call => {
            // For now, we'll just capture the full expression as a string
            // and handle it during compilation
            let function_call = pair.as_str().to_string();
            
            Ok(Requirement::Comparison {
                left: Expression::Property(function_call),
                op: "==".to_string(),
                right: Expression::Literal("true".to_string())
            })
        }
        Rule::identifier => {
            let identifier = pair.as_str().to_string();
            
            Ok(Requirement::Comparison {
                left: Expression::Variable(identifier),
                op: "==".to_string(),
                right: Expression::Literal("true".to_string())
            })
        }
        Rule::array_literal => {
            // For now, we'll just capture the full expression as a string
            // and handle it during compilation
            let array_literal = pair.as_str().to_string();
            
            Ok(Requirement::Comparison {
                left: Expression::Property(array_literal),
                op: "==".to_string(),
                right: Expression::Literal("true".to_string())
            })
        }
        _ => Err(format!("Unexpected rule in complex expression: {:?}", pair.as_rule()))
    }
}

// Parse parameters from contracts or functions
fn parse_parameters(params: Pair<Rule>) -> Result<Vec<Parameter>, String> {
    let mut parameters = Vec::new();
    for param_pair in params.into_inner() {
        if param_pair.as_rule() == Rule::parameter {
            let mut param_inner = param_pair.into_inner();
            let param_type = match param_inner.next() {
                Some(param_type) => param_type.as_str().to_string(),
                None => {
                    // Parameter missing data type
                    return  Err("Parameter is missing data type".to_string());
                }
            };

            let param_name = match param_inner.next() {
                Some(param_name) => param_name.as_str().to_string(),
                None => {
                    // Missing parameter name
                    return  Err("Missing parameter name after data type".to_string());
                }
            };

            parameters.push(Parameter {
                name: param_name,
                param_type,
            });
        }
    }
    Ok(parameters)
}