use crate::models::{
    AssignmentTarget, Constant, Contract, Function, Parameter, Statement, StructDefinition,
};
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
#[cfg(any(feature = "wasm", test))]
mod symbols;
mod tapscript;

pub(crate) use asset::*;
pub(crate) use checksig::*;
pub(crate) use comparison::*;
pub(crate) use crypto::*;
pub(crate) use expr::*;
pub(crate) use introspection::*;
#[cfg(any(feature = "wasm", test))]
pub(crate) use symbols::{symbols, Symbol};
pub(crate) use tapscript::*;

#[cfg(test)]
pub fn parse(source: &str) -> Result<Contract, String> {
    parse_with_constants(source, &[])
}

pub(crate) fn imports(source: &str) -> Result<Vec<String>, String> {
    let mut pairs =
        ArkadeParser::parse(Rule::main, source).map_err(|e| format!("Parse error: {e}"))?;
    pairs
        .next()
        .expect("main")
        .into_inner()
        .filter(|p| p.as_rule() == Rule::import_stmt)
        .map(|p| parse_string_literal(p.into_inner().next().expect("import path").as_str()))
        .collect()
}

pub(crate) fn parse_with_constants(
    source: &str,
    constants: &[Constant],
) -> Result<Contract, String> {
    let pairs = ArkadeParser::parse(Rule::main, source).map_err(|e| format!("Parse error: {e}"))?;
    build_ast(pairs, constants)
}

/// Build a Contract AST from parsed Pest pairs
fn build_ast(pairs: Pairs<Rule>, constants: &[Constant]) -> Result<Contract, String> {
    let mut contract = Contract {
        name: String::new(),
        is_library: false,
        structs: Vec::new(),
        parameters: Vec::new(),
        functions: Vec::new(),
        tapscripts: Vec::new(),
        imports: Vec::new(),
        constants: constants.to_vec(),
    };

    for pair in pairs {
        match pair.as_rule() {
            Rule::main => {
                for inner_pair in pair.into_inner() {
                    match inner_pair.as_rule() {
                        Rule::import_stmt => {
                            // Extract the import path (string literal without quotes)
                            if let Some(path_pair) = inner_pair.into_inner().next() {
                                let path = parse_string_literal(path_pair.as_str())?;
                                contract.imports.push(path);
                            }
                        }
                        Rule::contract | Rule::library => {
                            parse_contract(&mut contract, inner_pair)?;
                        }
                        Rule::struct_definition => {
                            contract.structs.push(parse_struct_definition(inner_pair)?);
                        }
                        _ => {}
                    }
                }
            }
            Rule::contract | Rule::library => {
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

/// Parse a contract or library definition.
fn parse_contract(contract: &mut Contract, pair: Pair<Rule>) -> Result<(), String> {
    contract.is_library = pair.as_rule() == Rule::library;
    let mut inner_pairs = pair.into_inner().peekable();

    // Contract name (required)
    contract.name = match inner_pairs.next() {
        Some(name) => name.as_str().to_string(),
        None => return Err("Missing contract name".to_string()),
    };

    // Parameters (optional)
    if !contract.is_library {
        if let Some(param_list) = inner_pairs.next() {
            contract.parameters = parse_parameters(param_list)?;
        }
    }

    let constants = inner_pairs
        .clone()
        .filter(|pair| pair.as_rule() == Rule::const_decl)
        .map(parse_const_decl)
        .collect::<Result<Vec<_>, _>>()?;
    contract.constants.extend(constants);
    crate::compiler::resolve_constants(contract)?;
    let mut parsing_constants = contract.constants.clone();
    parsing_constants.extend(
        contract
            .constants
            .iter()
            .filter(|c| !c.name.contains('.'))
            .cloned()
            .map(|mut constant| {
                constant.name = format!("{}.{}", contract.name, constant.name);
                constant
            }),
    );

    // Functions (covenant) and tapscript declarations share the `function` rule;
    // a tapscript carries a `tapscript_block` body.
    for func_pair in inner_pairs {
        if func_pair.as_rule() != Rule::function {
            continue;
        }
        if function_pair_is_tapscript(&func_pair) {
            if contract.is_library {
                return Err("libraries cannot declare tapscript functions".to_string());
            }
            let ts = parse_named_tapscript(func_pair, &parsing_constants)?;
            contract.tapscripts.push(ts);
        } else {
            let func = parse_function(func_pair, &parsing_constants, contract.is_library)?;
            contract.functions.push(func);
        }
    }
    Ok(())
}

fn parse_const_decl(pair: Pair<Rule>) -> Result<Constant, String> {
    let mut inner = pair
        .into_inner()
        .filter(|p| p.as_rule() != Rule::const_keyword);
    let const_type = parse_data_type(inner.next().ok_or("Missing constant type")?);
    let name = inner
        .next()
        .ok_or("Missing constant name")?
        .as_str()
        .to_string();
    let value = parse_general_expression(inner.next().ok_or("Missing constant value")?)?;
    Ok(Constant {
        name,
        const_type,
        value,
    })
}

/// Parse a function definition
fn parse_function(
    pair: Pair<Rule>,
    constants: &[Constant],
    is_library: bool,
) -> Result<Function, String> {
    let mut inner = pair.into_inner().peekable();
    let visibility = if inner
        .peek()
        .is_some_and(|p| p.as_rule() == Rule::function_visibility)
    {
        inner.next().expect("visibility").as_str()
    } else {
        "public"
    };
    let is_static = is_library || visibility == "static";
    let is_private = is_library || visibility != "public";
    let is_exported = is_static && visibility != "private";
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
        is_static,
        is_exported,
        return_type,
    };
    for statement in inner {
        parse_function_body(&mut func, statement, constants)?;
    }
    Ok(func)
}

/// Parse a statement in a function body (require, let binding, function call, variable declaration)
fn parse_function_body(
    func: &mut Function,
    pair: Pair<Rule>,
    constants: &[Constant],
) -> Result<(), String> {
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
            let requirement = parse_complex_expression(expr, constants)?;

            if let Some(message) = inner.next() {
                parse_string_literal(message.as_str())?;
            }

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
            let then_body = parse_block(then_block, constants)?;

            let else_body = if let Some(else_block) = inner.next() {
                Some(parse_block(else_block, constants)?)
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
            let loop_statement = pair
                .into_inner()
                .next()
                .ok_or_else(|| "Parse error: Missing for loop".to_string())?;
            let loop_rule = loop_statement.as_rule();
            let mut inner = loop_statement.into_inner();
            match loop_rule {
                Rule::for_in_stmt => {
                    let index_var = inner
                        .next()
                        .ok_or_else(|| {
                            "Parse error: Missing index variable in for loop".to_string()
                        })?
                        .as_str()
                        .to_string();
                    let value_var = inner
                        .next()
                        .ok_or_else(|| {
                            "Parse error: Missing value variable in for loop".to_string()
                        })?
                        .as_str()
                        .to_string();
                    let iterable =
                        parse_general_expression(inner.next().ok_or_else(|| {
                            "Parse error: Missing iterable in for loop".to_string()
                        })?)?;
                    let body = parse_block(
                        inner
                            .next()
                            .ok_or_else(|| "Parse error: Missing body in for loop".to_string())?,
                        constants,
                    )?;
                    func.statements.push(Statement::ForIn {
                        index_var,
                        value_var,
                        iterable,
                        body,
                    });
                }
                Rule::for_count_stmt => {
                    let count =
                        parse_general_expression(inner.next().ok_or_else(|| {
                            "Parse error: Missing count in for loop".to_string()
                        })?)?;
                    let body = parse_block(
                        inner
                            .next()
                            .ok_or_else(|| "Parse error: Missing body in for loop".to_string())?,
                        constants,
                    )?;
                    func.statements.push(Statement::ForCount { count, body });
                }
                _ => return Err("Parse error: Invalid for loop".to_string()),
            }
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
fn parse_block(pair: Pair<Rule>, constants: &[Constant]) -> Result<Vec<Statement>, String> {
    let mut statements = Vec::new();

    for inner in pair.into_inner() {
        // Create a temporary function to collect statements
        let mut temp_func = Function {
            name: String::new(),
            parameters: Vec::new(),
            statements: Vec::new(),
            is_private: false,
            is_static: false,
            is_exported: false,
            return_type: None,
        };

        parse_function_body(&mut temp_func, inner, constants)?;
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
    fn parses_version_pragmas_without_enforcing_compatibility() {
        for version in [
            "0.1.0",
            "=0.1.0",
            "^0.1.0",
            "~0.1.0",
            ">=0.1.0 <0.2.0",
            ">0.0.0 <=0.1.0",
            "^0.1.0 || >=1.0.0 <2.0.0",
            "99.0.0",
            "^ // constraint\n 0.1.0",
        ] {
            let source = format!("// header\npragma arkade {version}; contract C() {{}}");
            assert_eq!(parse(&source).unwrap().name, "C", "{version}");
        }
    }

    #[test]
    fn rejects_malformed_or_misplaced_pragmas() {
        for header in [
            "pragma arkade;",
            "pragma other ^0.1.0;",
            "pragmaarkade ^0.1.0;",
            "pragma arkade0.1.0;",
            "pragma arkade ^0.1;",
            "pragma arkade 0.1.*;",
            "pragma arkade 0.1.0-beta;",
            "pragma arkade 0.1.0+build;",
            "pragma arkade ^0.1.0",
            "pragma arkade ^01.1.0;",
            "pragma arkade ^0.01.0;",
            "pragma arkade ^0.1.00;",
            "pragma arkade 0.1.00.2.0;",
            "pragma arkade 0.1.0.0;",
            "pragma arkade 0 .1.0;",
            "pragma arkade =>0.1.0;",
            "pragma arkade ^0.1.0 ||;",
            "pragma arkade ^0.1.0; pragma arkade ^0.1.0;",
            "import \"a.ark\"; pragma arkade ^0.1.0;",
            "struct S { int value; } pragma arkade ^0.1.0;",
        ] {
            assert!(
                parse(&format!("{header} contract C() {{}}")).is_err(),
                "{header}"
            );
        }
        assert!(parse("contract C() { pragma arkade ^0.1.0; }").is_err());
        assert!(parse("contract C() {} pragma arkade ^0.1.0;").is_err());
    }

    #[test]
    fn parses_constant_array_sizes_without_changing_index_expressions() {
        let contract = parse(
            "struct State { int[N] values; } contract C(pubkey[C.N] keys) { const int N = 2; function spend(int[N] values) { int[N] local = [1, 2]; local[N - 1] = values[0]; require(true); } }",
        ).unwrap();
        assert_eq!(contract.structs[0].fields[0].param_type, "int[N]");
        assert_eq!(contract.parameters[0].param_type, "pubkey[C.N]");
        assert_eq!(contract.functions[0].parameters[0].param_type, "int[N]");
        assert!(
            matches!(&contract.functions[0].statements[0], Statement::LetBinding { declared_type: Some(ty), .. } if ty == "int[N]")
        );
        assert!(
            matches!(&contract.functions[0].statements[1], Statement::VarAssign { target: AssignmentTarget::ArrayIndex { index, .. }, .. } if matches!(index.as_ref(), Expression::BinaryOp { op, .. } if op == "-"))
        );
        for size in ["", "0", "-1", "1 2", "N + 1"] {
            assert!(
                parse(&format!("contract C(int[{size}] values) {{}}")).is_err(),
                "{size}"
            );
        }
    }

    #[test]
    fn parses_bytes_literals_before_decimal_and_preserves_utf8() {
        let contract = parse(
            r#"contract C() { function spend() {
            bytes x = 0xDEADbeef;
            bytes y = "ž\n";
            require("hello" == 0x68656c6c6f);
        } }"#,
        )
        .unwrap();
        let statements = &contract.functions[0].statements;
        assert!(
            matches!(&statements[0], Statement::LetBinding { value: Expression::Literal(value), .. } if value == "0xDEADbeef")
        );
        assert!(
            matches!(&statements[1], Statement::LetBinding { value: Expression::Literal(value), .. } if value == "0xc5be0a")
        );
        assert!(
            matches!(&statements[2], Statement::Require(Requirement::Comparison { left: Expression::Literal(left), right: Expression::Literal(right), .. }) if left == "0x68656c6c6f" && left == right)
        );
    }

    #[test]
    fn distinguishes_property_access_from_qualified_calls() {
        let contract = parse(
            "contract C() { function spend() { let field = x.field; let call = Helper.value(); } }",
        )
        .unwrap();
        let statements = &contract.functions[0].statements;
        assert!(
            matches!(&statements[0], Statement::LetBinding { value: Expression::Property(name), .. } if name == "x.field")
        );
        assert!(
            matches!(&statements[1], Statement::LetBinding { value: Expression::Call { name, args, .. }, .. } if name == "Helper.value" && args.is_empty())
        );
    }

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
    fn parses_logical_precedence_and_grouping() {
        let contract = parse("contract C() { function spend() { let value = !a == b || c && d && e; require((a || b) && !(c < d)); } }").unwrap();
        let Statement::LetBinding {
            value: Expression::BinaryOp { left, op, right },
            ..
        } = &contract.functions[0].statements[0]
        else {
            panic!("expected logical expression");
        };
        assert_eq!(op, "||");
        assert!(
            matches!(left.as_ref(), Expression::BinaryOp { left, op, .. }
            if op == "==" && matches!(left.as_ref(), Expression::Not { .. }))
        );
        assert!(
            matches!(right.as_ref(), Expression::BinaryOp { left, op, .. }
            if op == "&&" && matches!(left.as_ref(), Expression::BinaryOp { op, .. } if op == "&&"))
        );
        assert!(matches!(&contract.functions[0].statements[1],
            Statement::Require(Requirement::Expression(Expression::BinaryOp { left, op, right }))
            if op == "&&"
                && matches!(left.as_ref(), Expression::BinaryOp { op, .. } if op == "||")
                && matches!(right.as_ref(), Expression::Not { value }
                    if matches!(value.as_ref(), Expression::BinaryOp { op, .. } if op == "<"))));
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
    fn resolves_constant_thresholds_in_nested_helper_bodies() {
        let contract = parse(
            r#"
contract Demo() {
    static function authorize(pubkey key, signature sig, bool choose) {
        if (choose) { require(checkMultisig([key], [sig], QUORUM)); }
        else { require(checkMultisig([key], [sig], QUORUM)); }
    }
    const int QUORUM = 1;
}
"#,
        )
        .unwrap();
        let Statement::IfElse {
            then_body,
            else_body: Some(else_body),
            ..
        } = &contract.functions[0].statements[0]
        else {
            panic!("expected if/else");
        };
        for body in [then_body, else_body] {
            assert!(matches!(
                body[0],
                Statement::Require(Requirement::CheckMultisig { threshold: 1, .. })
            ));
        }
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
