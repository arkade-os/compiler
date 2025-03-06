use pest::Parser;
use pest_derive::Parser;
use pest::iterators::{Pair, Pairs};
use crate::models::{Contract, Function, Parameter, Requirement, Expression};

// Include the elements opcodes module
pub mod elements_opcodes;
pub mod debug;

// Grammar definition for pest parser
#[derive(Parser)]
#[grammar = "parser/grammar.pest"]
pub struct TapLangParser;

pub fn parse(source_code: &str) -> Result<Contract, Box<dyn std::error::Error>> {
    let pairs = TapLangParser::parse(Rule::main, source_code)?;
    let ast = build_ast(pairs);
    Ok(ast)
}

// Parse pest output into AST
fn build_ast(pairs: Pairs<Rule>) -> Contract {
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
                        parse_contract(&mut contract, inner_pair);
                    }
                }
            }
            // Direct contract rule (for backward compatibility)
            Rule::contract => {
                parse_contract(&mut contract, pair);
            }
            // Skip other rules
            _ => {}
        }
    }
    
    contract
}

// Helper function to parse contract details
fn parse_contract(contract: &mut Contract, pair: Pair<Rule>) {
    let mut inner_pairs = pair.into_inner().peekable();
    
    // Check for options block before the contract keyword
    if inner_pairs.peek().map_or(false, |p| p.as_rule() == Rule::options_block) {
        let options_block = inner_pairs.next().unwrap();
        parse_options_block(contract, options_block);
    }
    
    // Contract name
    contract.name = inner_pairs.next().unwrap().as_str().to_string();
    
    // Parameters
    let param_list = inner_pairs.next().unwrap();
    for param_pair in param_list.into_inner() {
        if param_pair.as_rule() == Rule::parameter {
            let mut param_inner = param_pair.into_inner();
            let param_type = param_inner.next().unwrap().as_str().to_string();
            let param_name = param_inner.next().unwrap().as_str().to_string();
            
            contract.parameters.push(Parameter {
                name: param_name,
                param_type: param_type,
            });
        }
    }
    
    // Functions
    for func_pair in inner_pairs {
        if func_pair.as_rule() == Rule::function {
            let func = parse_function(func_pair);
            contract.functions.push(func);
        }
    }
}

// Parse options block
fn parse_options_block(contract: &mut Contract, pair: Pair<Rule>) {
    for option_pair in pair.into_inner() {
        if option_pair.as_rule() == Rule::option_setting {
            let mut inner = option_pair.into_inner();
            let option_name = inner.next().unwrap().as_str();
            let option_value = inner.next().unwrap().as_str();
            
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
}

// Parse function from pest output
fn parse_function(pair: Pair<Rule>) -> Function {
    let mut func = Function {
        name: String::new(),
        parameters: Vec::new(),
        requirements: Vec::new(),
        is_internal: false,
    };
    
    let mut inner_pairs = pair.into_inner();
    
    // Function name
    func.name = inner_pairs.next().unwrap().as_str().to_string();
    
    // Parameters
    let param_list = inner_pairs.next().unwrap();
    for param_pair in param_list.into_inner() {
        if param_pair.as_rule() == Rule::parameter {
            let mut param_inner = param_pair.into_inner();
            let param_type = param_inner.next().unwrap().as_str().to_string();
            let param_name = param_inner.next().unwrap().as_str().to_string();
            
            func.parameters.push(Parameter {
                name: param_name,
                param_type: param_type,
            });
        }
    }
    
    // Check for function modifier (internal)
    let next_pair = inner_pairs.next().unwrap();
    if next_pair.as_rule() == Rule::function_modifier {
        func.is_internal = true;
        // Get the next pair for requirements
        for req_pair in inner_pairs {
            parse_function_body(&mut func, req_pair);
        }
    } else {
        // No modifier, this is already a requirement or function call
        parse_function_body(&mut func, next_pair);
        
        // Continue with the rest of the requirements
        for req_pair in inner_pairs {
            parse_function_body(&mut func, req_pair);
        }
    }
    
    func
}

// Parse function body (requirements and function calls)
fn parse_function_body(func: &mut Function, pair: Pair<Rule>) {
    for p in pair.into_inner() {
        match p.as_rule() {
            Rule::require_stmt => {
                let mut inner = p.into_inner();
                let expr = inner.next().unwrap();
                let requirement = parse_complex_expression(expr);
                
                // Check if there's an error message
                let _message = inner.next().unwrap().as_str().to_string();
                
                func.requirements.push(requirement);
            }
            Rule::function_call_stmt => {
                // In a more complete implementation, we would handle function calls
                // For now, we just ignore them
            }
            Rule::variable_declaration => {
                // In a more complete implementation, we would handle variable declarations
                // For now, we just ignore them
            }
            _ => {}
        }
    }
}

// Parse complex expression from pest output
fn parse_complex_expression(pair: Pair<Rule>) -> Requirement {
    match pair.as_rule() {
        Rule::check_sig => {
            let mut inner = pair.into_inner();
            let signature = inner.next().unwrap().as_str().to_string();
            let pubkey = inner.next().unwrap().as_str().to_string();
            Requirement::CheckSig { signature, pubkey }
        }
        Rule::check_sig_from_stack => {
            let mut inner = pair.into_inner();
            let signature = inner.next().unwrap().as_str().to_string();
            let pubkey = inner.next().unwrap().as_str().to_string();
            let _message = inner.next().unwrap().as_str().to_string();
            // For now, we'll treat this as a special case of CheckSig
            Requirement::CheckSig { signature, pubkey }
        }
        Rule::check_multisig => {
            let mut inner = pair.into_inner();
            let pubkeys_array = inner.next().unwrap();
            let signatures_array = inner.next().unwrap();
            
            let pubkeys = pubkeys_array.into_inner()
                .map(|p| p.as_str().to_string())
                .collect();
            
            let signatures = signatures_array.into_inner()
                .map(|s| s.as_str().to_string())
                .collect();
            
            Requirement::CheckMultisig { signatures, pubkeys }
        }
        Rule::time_comparison => {
            let mut inner = pair.into_inner();
            let timelock_var = inner.next().unwrap().as_str().to_string();
            Requirement::After { 
                blocks: 0, // This will be filled in by the compiler
                timelock_var: Some(timelock_var)
            }
        }
        Rule::identifier_comparison => {
            let mut inner = pair.into_inner();
            let left = inner.next().unwrap().as_str().to_string();
            let op = inner.next().unwrap().as_str().to_string();
            let right = inner.next().unwrap().as_str().to_string();
            
            // Special case for time comparisons
            if left == "tx.time" && op == ">=" {
                return Requirement::After {
                    blocks: 0,
                    timelock_var: Some(right)
                };
            }
            
            Requirement::Comparison {
                left: Expression::Variable(left),
                op,
                right: Expression::Variable(right)
            }
        }
        Rule::property_comparison => {
            let mut inner = pair.into_inner();
            let left_expr = inner.next().unwrap();
            let op = inner.next().unwrap().as_str().to_string();
            let right_expr = inner.next().unwrap();
            
            let left = match left_expr.as_rule() {
                Rule::tx_property_access | Rule::this_property_access => 
                    Expression::Property(left_expr.as_str().to_string()),
                _ => panic!("Unexpected left expression in property comparison")
            };
            
            let right = match right_expr.as_rule() {
                Rule::identifier => Expression::Variable(right_expr.as_str().to_string()),
                Rule::number_literal => Expression::Literal(right_expr.as_str().to_string()),
                Rule::tx_property_access | Rule::this_property_access => 
                    Expression::Property(right_expr.as_str().to_string()),
                Rule::p2tr_constructor =>
                    Expression::Property(right_expr.as_str().to_string()),
                _ => panic!("Unexpected right expression in property comparison")
            };
            
            Requirement::Comparison {
                left,
                op,
                right
            }
        }
        Rule::hash_comparison => {
            let mut inner = pair.into_inner();
            let sha256_func = inner.next().unwrap();
            let mut sha256_inner = sha256_func.into_inner();
            let preimage = sha256_inner.next().unwrap().as_str().to_string();
            let hash = inner.next().unwrap().as_str().to_string();
            
            Requirement::HashEqual { preimage, hash }
        }
        Rule::binary_operation => {
            let mut inner = pair.into_inner();
            let left_expr = inner.next().unwrap();
            let op = inner.next().unwrap().as_str().to_string();
            let right_expr = inner.next().unwrap();
            
            let left = match left_expr.as_rule() {
                Rule::identifier => Expression::Variable(left_expr.as_str().to_string()),
                Rule::number_literal => Expression::Literal(left_expr.as_str().to_string()),
                _ => panic!("Unexpected left expression in binary operation")
            };
            
            let right = match right_expr.as_rule() {
                Rule::identifier => Expression::Variable(right_expr.as_str().to_string()),
                Rule::number_literal => Expression::Literal(right_expr.as_str().to_string()),
                _ => panic!("Unexpected right expression in binary operation")
            };
            
            Requirement::Comparison { left, op, right }
        }
        Rule::p2tr_constructor => {
            // For now, we'll just capture the full expression as a string
            // and handle it during compilation
            let constructor = pair.as_str().to_string();
            
            Requirement::Comparison {
                left: Expression::Property(constructor),
                op: "==".to_string(),
                right: Expression::Literal("true".to_string())
            }
        }
        Rule::tx_property_access | Rule::this_property_access => {
            // For now, we'll just capture the full expression as a string
            // and handle it during compilation
            let property_access = pair.as_str().to_string();
            
            // Special handling for tx.currentInput
            if property_access.starts_with("tx.currentInput") {
                // Extract the property after tx.currentInput if any
                // Format is tx.currentInput.property or just tx.currentInput
                let property = if property_access == "tx.currentInput" {
                    // If just tx.currentInput, default to the entire input
                    None
                } else {
                    // Extract the property after tx.currentInput.
                    let parts: Vec<&str> = property_access.split('.').collect();
                    if parts.len() >= 3 {
                        Some(parts[2].to_string())
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
            }
        }
        Rule::function_call => {
            // For now, we'll just capture the full expression as a string
            // and handle it during compilation
            let function_call = pair.as_str().to_string();
            
            Requirement::Comparison {
                left: Expression::Property(function_call),
                op: "==".to_string(),
                right: Expression::Literal("true".to_string())
            }
        }
        Rule::identifier => {
            let identifier = pair.as_str().to_string();
            
            Requirement::Comparison {
                left: Expression::Variable(identifier),
                op: "==".to_string(),
                right: Expression::Literal("true".to_string())
            }
        }
        Rule::array_literal => {
            // For now, we'll just capture the full expression as a string
            // and handle it during compilation
            let array_literal = pair.as_str().to_string();
            
            Requirement::Comparison {
                left: Expression::Property(array_literal),
                op: "==".to_string(),
                right: Expression::Literal("true".to_string())
            }
        }
        _ => panic!("Unexpected rule in complex expression: {:?}", pair.as_rule())
    }
} 