use crate::models::{AssignmentTarget, Contract, Function, Parameter, Statement, StructDefinition};
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
        structs: Vec::new(),
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
                        Rule::struct_definition => {
                            contract.structs.push(parse_struct_definition(inner_pair)?);
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

fn parse_struct_definition(pair: Pair<Rule>) -> Result<StructDefinition, String> {
    let mut inner = pair.into_inner();
    let name = inner
        .next()
        .ok_or_else(|| "Missing struct name".to_string())?
        .as_str()
        .to_string();
    let fields = inner
        .map(|field| {
            let mut field = field.into_inner();
            let param_type = parse_data_type(
                field
                    .next()
                    .ok_or_else(|| format!("struct '{name}' field is missing a type"))?,
            );
            let name = field
                .next()
                .ok_or_else(|| format!("struct '{name}' field is missing a name"))?
                .as_str()
                .to_string();
            Ok(Parameter { name, param_type })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(StructDefinition { name, fields })
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
    let mut inner = pair.into_inner().peekable();
    let is_private = if inner
        .peek()
        .is_some_and(|p| p.as_rule() == Rule::function_visibility)
    {
        inner.next().expect("visibility").as_str() == "private"
    } else {
        false
    };
    let name = inner
        .next()
        .ok_or("Missing function name")?
        .as_str()
        .to_string();
    if is_private
        && (expr::reserved_function_signature(&name).is_some()
            || matches!(
                name.as_str(),
                "require" | "return" | "negate" | "neg64" | "le64ToScriptNum" | "le32ToLe64"
            ))
    {
        return Err(format!("function name '{name}' is reserved"));
    }
    let parameters = parse_parameters(inner.next().ok_or("Missing parameter list")?)?;
    let return_type = if inner.peek().is_some_and(|p| p.as_rule() == Rule::data_type) {
        Some(parse_data_type(inner.next().expect("return type")))
    } else {
        None
    };
    let mut func = Function {
        name,
        parameters,
        statements: Vec::new(),
        is_private,
        return_type,
    };
    for statement in inner {
        parse_function_body(&mut func, statement)?;
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

            func.statements.push(Statement::LetBinding {
                name,
                declared_type: None,
                value,
            });
            Ok(())
        }
        Rule::var_assign => {
            let mut inner = pair.into_inner();
            let target = parse_assignment_target(
                inner
                    .next()
                    .ok_or_else(|| "Parse error: Missing assignment target".to_string())?,
            )?;
            let value_pair = inner
                .next()
                .ok_or_else(|| "Parse error: Missing value in assignment".to_string())?;
            let value = parse_general_expression(value_pair)?;

            func.statements.push(Statement::VarAssign { target, value });
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
            let call = pair.into_inner().next().ok_or("Missing function call")?;
            func.statements
                .push(Statement::Call(parse_general_expression(call)?));
            Ok(())
        }
        Rule::return_stmt => {
            let value = pair
                .into_inner()
                .nth(1)
                .map(parse_general_expression)
                .transpose()?;
            func.statements.push(Statement::Return(value));
            Ok(())
        }
        Rule::variable_declaration => {
            let mut inner = pair.into_inner();
            let declared_type = parse_data_type(
                inner
                    .next()
                    .ok_or_else(|| "Parse error: Missing variable type".to_string())?,
            );
            let name = inner
                .next()
                .ok_or_else(|| "Parse error: Missing variable name".to_string())?
                .as_str()
                .to_string();
            let value_pair = inner
                .next()
                .ok_or_else(|| "Parse error: Missing value".to_string())?;
            let value = parse_general_expression(value_pair)?;

            func.statements.push(Statement::LetBinding {
                name,
                declared_type: Some(declared_type),
                value,
            });
            Ok(())
        }
        _ => Ok(()),
    }
}

fn parse_assignment_target(pair: Pair<Rule>) -> Result<AssignmentTarget, String> {
    let mut path = Vec::new();
    let mut index = None;
    for part in pair.into_inner() {
        match part.as_rule() {
            Rule::identifier => path.push(part.as_str().to_string()),
            Rule::general_expression => index = Some(parse_general_expression(part)?),
            rule => return Err(format!("Unexpected rule in assignment target: {rule:?}")),
        }
    }
    let name = path.join(".");
    if name.is_empty() {
        return Err("Parse error: Missing assignment target".to_string());
    }
    Ok(match index {
        Some(index) => AssignmentTarget::ArrayIndex {
            array: name,
            index: Box::new(index),
        },
        None => AssignmentTarget::Binding(name),
    })
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
            is_private: false,
            return_type: None,
        };

        parse_function_body(&mut temp_func, inner)?;
        statements.extend(temp_func.statements);
    }

    Ok(statements)
}

/// Canonical declared-type text: `pubkey`, or `pubkey[3]` for array types.
pub(crate) fn parse_data_type(type_pair: Pair<Rule>) -> String {
    let text = type_pair.as_str().trim().to_string();
    let mut inner = type_pair.into_inner();
    let Some(base) = inner.next() else {
        return text;
    };
    match inner.next() {
        Some(size) => format!("{}[{}]", base.as_str(), size.as_str()),
        None => base.as_str().to_string(),
    }
}

/// Parse parameter list from contracts or functions
pub(crate) fn parse_parameters(params: Pair<Rule>) -> Result<Vec<Parameter>, String> {
    let mut parameters = Vec::new();
    for param_pair in params.into_inner() {
        if param_pair.as_rule() == Rule::parameter {
            let mut param_inner = param_pair.into_inner();
            let param_type = match param_inner.next() {
                Some(type_pair) => parse_data_type(type_pair),
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

#[cfg(test)]
mod tests {
    use super::parse;
    use crate::models::{AssignmentTarget, Expression, Requirement, Statement};

    #[test]
    fn parses_private_visibility_return_types_and_call_arguments() {
        use crate::models::Expression;
        let contract = parse(
            r#"contract C() {
            public function spend(int amount) { check(amount + 1 * 2); }
            private function check(int value) { let returnValue = value; return; }
            private function sufficient(int value) bool { return value >= 1; }
            function other() { require(true); }
        }"#,
        )
        .unwrap();
        assert!(!contract.functions[0].is_private);
        assert!(contract.functions[1].is_private);
        assert_eq!(contract.functions[2].return_type.as_deref(), Some("bool"));
        assert!(!contract.functions[3].is_private);
        assert!(
            matches!(&contract.functions[0].statements[0], Statement::Call(Expression::Call { name, args, .. }) if name == "check" && matches!(&args[0], Expression::BinaryOp { op, .. } if op == "+"))
        );
        assert!(matches!(
            &contract.functions[1].statements[1],
            Statement::Return(None)
        ));
        assert!(matches!(
            &contract.functions[2].statements[0],
            Statement::Return(Some(_))
        ));
    }

    #[test]
    fn parses_unary_prefix_order_and_boolean_boundaries() {
        let contract = parse("contract Unary() { function spend() { let result = -!true != false; let truth = !trueValue; } }").unwrap();
        let Statement::LetBinding {
            value: Expression::BinaryOp { left, op, right },
            ..
        } = &contract.functions[0].statements[0]
        else {
            panic!("comparison must be the outer expression");
        };
        assert_eq!(op, "!=");
        let Expression::Negate { value } = left.as_ref() else {
            panic!("minus must be the outer prefix");
        };
        let Expression::Not { value } = value.as_ref() else {
            panic!("not must be the inner prefix");
        };
        assert!(matches!(value.as_ref(), Expression::Literal(value) if value == "true"));
        assert!(matches!(right.as_ref(), Expression::Literal(value) if value == "false"));
        assert!(
            matches!(&contract.functions[0].statements[1], Statement::LetBinding { value: Expression::Not { value }, .. } if matches!(value.as_ref(), Expression::Variable(name) if name == "trueValue"))
        );
    }

    #[test]
    fn parses_structured_assignment_targets() {
        let contract = parse(
            r#"
struct State {
    bool enabled;
    int[3] values;
}

contract Demo() {
    function spend(State state, int index) {
        state.enabled = true;
        state.values[index + 1] = 9;
        index = 0;
        require(true);
    }
}
"#,
        )
        .expect("contract should parse");

        let statements = &contract.functions[0].statements;
        assert!(matches!(
            &statements[0],
            Statement::VarAssign {
                target: AssignmentTarget::Binding(name),
                ..
            } if name == "state.enabled"
        ));
        assert!(matches!(
            &statements[1],
            Statement::VarAssign {
                target: AssignmentTarget::ArrayIndex { array, index },
                ..
            } if array == "state.values"
                && matches!(index.as_ref(), Expression::BinaryOp { op, .. } if op == "+")
        ));
        assert!(matches!(
            &statements[2],
            Statement::VarAssign {
                target: AssignmentTarget::Binding(name),
                ..
            } if name == "index"
        ));
    }

    #[test]
    fn retains_declared_local_types_and_multisig_signatures() {
        let contract = parse(
            r#"
contract Demo(pubkey first, pubkey second) {
    function spend(signature firstSig, signature secondSig) {
        let inferred = 1;
        int explicit = inferred + 1;
        require(checkMultisig([first, second], [firstSig, secondSig]));
    }
}
"#,
        )
        .expect("contract should parse");

        let statements = &contract.functions[0].statements;
        assert!(matches!(
            &statements[0],
            Statement::LetBinding {
                name,
                declared_type: None,
                ..
            } if name == "inferred"
        ));
        assert!(matches!(
            &statements[1],
            Statement::LetBinding {
                name,
                declared_type: Some(declared_type),
                ..
            } if name == "explicit" && declared_type == "int"
        ));
        assert!(matches!(
            &statements[2],
            Statement::Require(Requirement::CheckMultisig {
                pubkeys,
                signatures,
                threshold: 2,
            }) if pubkeys == &["first", "second"] && signatures == &["firstSig", "secondSig"]
        ));
    }

    #[test]
    fn rejects_multisig_without_explicit_signatures() {
        for call in [
            "checkMultisig([first, second])",
            "checkMultisig([first, second], 2)",
        ] {
            for modifier in ["", " tapscript"] {
                let source = format!(
                    r#"
contract Demo(pubkey first, pubkey second) {{
    function spend(signature firstSig, signature secondSig){modifier} {{
        require({call});
    }}
}}
"#
                );
                assert!(
                    parse(&source).is_err(),
                    "checkMultisig without signatures must fail for `{modifier}` functions"
                );
            }
        }
    }
}
