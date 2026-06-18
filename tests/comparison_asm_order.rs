use arkade_compiler::compile;
use arkade_compiler::opcodes::{OP_EQUAL, OP_GREATERTHANOREQUAL, OP_TXWEIGHT};

#[test]
fn test_variable_greater_or_equal_to_literal() {
    let code = r#"
        contract VariableLiteralComparison() {
            function variableGreaterOrEqualToLiteral(int variable) {
                require(variable >= 12);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse compare: {:?}",
        result.err()
    );

    let output = result.unwrap();

    let function = output
        .functions
        .iter()
        .find(|f| f.name == "variableGreaterOrEqualToLiteral")
        .expect("Missing function");

    assert_eq!(function.asm.len(), 3);
    assert_eq!(function.asm[0], "<variable>");
    assert_eq!(function.asm[1], "12");
    assert_eq!(function.asm[2], OP_GREATERTHANOREQUAL);
}

#[test]
fn test_variable_equal_to_variable() {
    let code = r#"
        contract VariableVariableComparison() {
            function variableEqualToVariable(int variable, int variable2) {
                require(variable == variable2);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse compare: {:?}",
        result.err()
    );

    let output = result.unwrap();

    let function = output
        .functions
        .iter()
        .find(|f| f.name == "variableEqualToVariable")
        .expect("Missing function");

    assert_eq!(function.asm.len(), 3);
    assert_eq!(function.asm[0], "<variable>");
    assert_eq!(function.asm[1], "<variable2>");
    assert_eq!(function.asm[2], OP_EQUAL);
}

#[test]
fn test_variable_greater_or_equal_to_variable() {
    let code = r#"
        contract VariableVariableComparison() {
            function variableGreaterOrEqualToVariable(int variable, int variable2) {
                require(variable >= variable2);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse compare: {:?}",
        result.err()
    );

    let output = result.unwrap();

    let function = output
        .functions
        .iter()
        .find(|f| f.name == "variableGreaterOrEqualToVariable")
        .expect("Missing function");

    assert_eq!(function.asm.len(), 3);
    assert_eq!(function.asm[0], "<variable>");
    assert_eq!(function.asm[1], "<variable2>");
    assert_eq!(function.asm[2], OP_GREATERTHANOREQUAL);
}

#[test]
fn test_literal_equal_to_variable() {
    let code = r#"
        contract LiteralVariableComparison() {
            function literalEqualToVariable(int variable) {
                require(12 == variable);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse compare: {:?}",
        result.err()
    );

    let output = result.unwrap();

    let function = output
        .functions
        .iter()
        .find(|f| f.name == "literalEqualToVariable")
        .expect("Missing function");

    assert_eq!(function.asm.len(), 3);
    assert_eq!(function.asm[0], "12");
    assert_eq!(function.asm[1], "<variable>");
    assert_eq!(function.asm[2], OP_EQUAL);
}

#[test]
fn test_literal_greater_or_equal_to_variable() {
    let code = r#"
        contract LiteralVariableComparison() {
            function literalGreaterOrEqualToVariable(int variable) {
                require(12 >= variable);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse compare: {:?}",
        result.err()
    );

    let output = result.unwrap();

    let function = output
        .functions
        .iter()
        .find(|f| f.name == "literalGreaterOrEqualToVariable")
        .expect("Missing function");

    assert_eq!(function.asm.len(), 3);
    assert_eq!(function.asm[0], "12");
    assert_eq!(function.asm[1], "<variable>");
    assert_eq!(function.asm[2], OP_GREATERTHANOREQUAL);
}

#[test]
fn test_literal_equal_to_literal() {
    let code = r#"
        contract LiteralLiteralComparison() {
            function literalEqualToLiteral() {
                require(12 == 144);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse compare: {:?}",
        result.err()
    );

    let output = result.unwrap();

    let function = output
        .functions
        .iter()
        .find(|f| f.name == "literalEqualToLiteral")
        .expect("Missing function");

    assert_eq!(function.asm.len(), 3);
    assert_eq!(function.asm[0], "12");
    assert_eq!(function.asm[1], "144");
    assert_eq!(function.asm[2], OP_EQUAL);
}

#[test]
fn test_literal_greater_or_equal_to_literal() {
    let code = r#"
        contract LiteralLiteralComparison() {
            function literalGreaterOrEqualToLiteral() {
                require(12 >= 144);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse compare: {:?}",
        result.err()
    );

    let output = result.unwrap();

    let function = output
        .functions
        .iter()
        .find(|f| f.name == "literalGreaterOrEqualToLiteral")
        .expect("Missing function");

    assert_eq!(function.asm.len(), 3);
    assert_eq!(function.asm[0], "12");
    assert_eq!(function.asm[1], "144");
    assert_eq!(function.asm[2], OP_GREATERTHANOREQUAL);
}

#[test]
fn test_property_equal_to_variable() {
    let code = r#"
        contract PropertyVariableComparison() {
            function propertyEqualToVariable(int variable) {
                require(tx.weight == variable);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse compare: {:?}",
        result.err()
    );

    let output = result.unwrap();

    let function = output
        .functions
        .iter()
        .find(|f| f.name == "propertyEqualToVariable")
        .expect("Missing function");

    assert_eq!(function.asm.len(), 3);
    assert_eq!(function.asm[0], OP_TXWEIGHT);
    assert_eq!(function.asm[1], "<variable>");
    assert_eq!(function.asm[2], OP_EQUAL);
}

#[test]
fn test_property_greater_or_equal_to_variable() {
    let code = r#"
        contract PropertyVariableComparison() {
            function propertyGreaterOrEqualToVariable(int variable) {
                require(tx.weight >= variable);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse compare: {:?}",
        result.err()
    );

    let output = result.unwrap();

    let function = output
        .functions
        .iter()
        .find(|f| f.name == "propertyGreaterOrEqualToVariable")
        .expect("Missing function");

    assert_eq!(function.asm.len(), 3);
    assert_eq!(function.asm[0], OP_TXWEIGHT);
    assert_eq!(function.asm[1], "<variable>");
    assert_eq!(function.asm[2], OP_GREATERTHANOREQUAL);
}

#[test]
fn test_property_equal_to_literal() {
    let code = r#"
        contract PropertyLiteralComparison() {
            function propertyEqualToLiteral() {
                require(tx.weight == 12);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse compare: {:?}",
        result.err()
    );

    let output = result.unwrap();

    let function = output
        .functions
        .iter()
        .find(|f| f.name == "propertyEqualToLiteral")
        .expect("Missing function");

    assert_eq!(function.asm.len(), 3);
    assert_eq!(function.asm[0], OP_TXWEIGHT);
    assert_eq!(function.asm[1], "12");
    assert_eq!(function.asm[2], OP_EQUAL);
}

#[test]
fn test_property_greater_or_equal_to_literal() {
    let code = r#"
        contract PropertyLiteralComparison() {
            function propertyGreaterOrEqualToLiteral() {
                require(tx.weight >= 12);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse compare: {:?}",
        result.err()
    );

    let output = result.unwrap();

    let function = output
        .functions
        .iter()
        .find(|f| f.name == "propertyGreaterOrEqualToLiteral")
        .expect("Missing function");

    assert_eq!(function.asm.len(), 3);
    assert_eq!(function.asm[0], OP_TXWEIGHT);
    assert_eq!(function.asm[1], "12");
    assert_eq!(function.asm[2], OP_GREATERTHANOREQUAL);
}
