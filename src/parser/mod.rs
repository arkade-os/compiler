use crate::models::{Contract, Function, Parameter, Statement};
use pest::iterators::{Pair, Pairs};
use pest::Parser;
use pest_derive::Parser;

/// Pest parser generated from grammar.pest
#[derive(Parser)]
#[grammar = "parser/grammar.pest"]
pub struct ArkadeParser;

// Parser split into domain submodules. Each declares its pub(crate)
// parse_* helpers; siblings reach them via `use super::*`.
mod asset;
mod checksig;
mod comparison;
mod crypto;
mod expr;
mod introspection;
mod tapscript;

pub(crate) use asset::*;
pub(crate) use checksig::*;
pub(crate) use comparison::*;
pub(crate) use crypto::*;
pub(crate) use expr::*;
pub(crate) use introspection::*;
pub(crate) use tapscript::*;

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
        functions: Vec::new(),
        tapscripts: Vec::new(),
        imports: Vec::new(),
    };

    for pair in pairs {
        match pair.as_rule() {
            Rule::main => {
                for inner_pair in pair.into_inner() {
                    match inner_pair.as_rule() {
                        Rule::import_stmt => {
                            // Extract the import path (string literal without quotes)
                            if let Some(path_pair) = inner_pair.into_inner().next() {
                                let raw = path_pair.as_str();
                                // Strip surrounding double-quotes
                                let path = raw.trim_matches('"').to_string();
                                contract.imports.push(path);
                            }
                        }
                        Rule::contract => {
                            parse_contract(&mut contract, inner_pair)?;
                        }
                        _ => {}
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

/// Parse a contract definition: name, parameters, and functions
fn parse_contract(contract: &mut Contract, pair: Pair<Rule>) -> Result<(), String> {
    let mut inner_pairs = pair.into_inner().peekable();

    // Contract name (required)
    contract.name = match inner_pairs.next() {
        Some(name) => name.as_str().to_string(),
        None => return Err("Missing contract name".to_string()),
    };

    // Parameters (optional)
    if let Some(param_list) = inner_pairs.next() {
        contract.parameters = parse_parameters(param_list)?;
    }

    // Functions (covenant) and tapscript declarations share the `function` rule;
    // a tapscript carries a `tapscript_block` body.
    for func_pair in inner_pairs {
        if func_pair.as_rule() != Rule::function {
            continue;
        }
        if function_pair_is_tapscript(&func_pair) {
            let ts = parse_named_tapscript(func_pair)?;
            contract.tapscripts.push(ts);
        } else {
            let func = parse_function(func_pair)?;
            contract.functions.push(func);
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
    if let Some(next_pair) = inner_pairs.next() {
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

    Ok(func)
}

/// Parse a statement in a function body (require, let binding, function call, variable declaration)
fn parse_function_body(func: &mut Function, pair: Pair<Rule>) -> Result<(), String> {
    match pair.as_rule() {
        Rule::require_stmt => {
            let mut inner = pair.into_inner();
            let expr = match inner.next() {
                Some(expr) => expr,
                None => {
                    return Err(format!(
                        "Parse error: Invalid arguments to function {}",
                        func.name
                    ))
                }
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
            let name = inner
                .next()
                .ok_or_else(|| "Parse error: Missing variable name in let binding".to_string())?
                .as_str()
                .to_string();
            let value_pair = inner
                .next()
                .ok_or_else(|| "Parse error: Missing value in let binding".to_string())?;
            let value = parse_general_expression(value_pair)?;

            func.statements.push(Statement::LetBinding { name, value });
            Ok(())
        }
        Rule::var_assign => {
            let mut inner = pair.into_inner();
            let name = inner
                .next()
                .ok_or_else(|| "Parse error: Missing variable name in assignment".to_string())?
                .as_str()
                .to_string();
            let value_pair = inner
                .next()
                .ok_or_else(|| "Parse error: Missing value in assignment".to_string())?;
            let value = parse_general_expression(value_pair)?;

            func.statements.push(Statement::VarAssign { name, value });
            Ok(())
        }
        Rule::if_stmt => {
            let mut inner = pair.into_inner();
            let condition_pair = inner
                .next()
                .ok_or_else(|| "Parse error: Missing condition in if statement".to_string())?;
            let condition = parse_general_expression(condition_pair)?;

            let then_block = inner
                .next()
                .ok_or_else(|| "Parse error: Missing then block in if statement".to_string())?;
            let then_body = parse_block(then_block)?;

            let else_body = if let Some(else_block) = inner.next() {
                Some(parse_block(else_block)?)
            } else {
                None
            };

            func.statements.push(Statement::IfElse {
                condition,
                then_body,
                else_body,
            });
            Ok(())
        }
        Rule::for_stmt => {
            let mut inner = pair.into_inner();
            let index_var = inner
                .next()
                .ok_or_else(|| "Parse error: Missing index variable in for loop".to_string())?
                .as_str()
                .to_string();
            let value_var = inner
                .next()
                .ok_or_else(|| "Parse error: Missing value variable in for loop".to_string())?
                .as_str()
                .to_string();
            let iterable_pair = inner
                .next()
                .ok_or_else(|| "Parse error: Missing iterable in for loop".to_string())?;
            let iterable = parse_general_expression(iterable_pair)?;
            let body_block = inner
                .next()
                .ok_or_else(|| "Parse error: Missing body in for loop".to_string())?;
            let body = parse_block(body_block)?;

            func.statements.push(Statement::ForIn {
                index_var,
                value_var,
                iterable,
                body,
            });
            Ok(())
        }
        Rule::function_call_stmt => {
            // Function calls to internal helpers — not yet fully supported
            Ok(())
        }
        Rule::variable_declaration => {
            // Typed variable declaration - treat like let binding
            let mut inner = pair.into_inner();
            let _data_type = inner.next(); // Skip data type
            let name = inner
                .next()
                .ok_or_else(|| "Parse error: Missing variable name".to_string())?
                .as_str()
                .to_string();
            let value_pair = inner
                .next()
                .ok_or_else(|| "Parse error: Missing value".to_string())?;
            let value = parse_general_expression(value_pair)?;

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

/// Parse parameter list from contracts or functions
pub(crate) fn parse_parameters(params: Pair<Rule>) -> Result<Vec<Parameter>, String> {
    let mut parameters = Vec::new();
    for param_pair in params.into_inner() {
        if param_pair.as_rule() == Rule::parameter {
            let mut param_inner = param_pair.into_inner();
            let param_type = match param_inner.next() {
                Some(type_pair) => {
                    // Extract the base type and check for an array suffix.
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
