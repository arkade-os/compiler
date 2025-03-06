// Parser extensions for Elements opcodes
// This file extends the parser to support the new Elements opcodes

use crate::models::{Requirement, Expression};

/// Represents a transaction introspection expression
#[derive(Debug, Clone)]
pub enum TxIntrospection {
    // Input introspection
    InputOutpoint { index: Expression },
    InputAsset { index: Expression },
    InputValue { index: Expression },
    InputScriptPubKey { index: Expression },
    InputSequence { index: Expression },
    InputIssuance { index: Expression },
    CurrentInputIndex,
    
    // Output introspection
    OutputAsset { index: Expression },
    OutputValue { index: Expression },
    OutputNonce { index: Expression },
    OutputScriptPubKey { index: Expression },
    
    // Transaction introspection
    Version,
    LockTime,
    NumInputs,
    NumOutputs,
    Weight,
}

/// Represents a 64-bit arithmetic expression
#[derive(Debug, Clone)]
pub enum Arithmetic64 {
    Add { left: Expression, right: Expression },
    Sub { left: Expression, right: Expression },
    Mul { left: Expression, right: Expression },
    Div { left: Expression, right: Expression },
    Neg { value: Expression },
    LessThan { left: Expression, right: Expression },
    LessThanOrEqual { left: Expression, right: Expression },
    GreaterThan { left: Expression, right: Expression },
    GreaterThanOrEqual { left: Expression, right: Expression },
}

/// Represents a conversion expression
#[derive(Debug, Clone)]
pub enum Conversion {
    ScriptNumToLE64 { value: Expression },
    LE64ToScriptNum { value: Expression },
    LE32ToLE64 { value: Expression },
}

/// Represents a crypto operation
#[derive(Debug, Clone)]
pub enum CryptoOp {
    ECMulScalarVerify { scalar: Expression, point_p: Expression, point_q: Expression },
    TweakVerify { internal_key: Expression, tweak: Expression, output_key: Expression },
    CheckSigFromStack { pubkey: Expression, message: Expression, signature: Expression },
}

/// Represents a streaming SHA256 operation
#[derive(Debug, Clone)]
pub enum StreamingSHA256 {
    Initialize { data: Expression },
    Update { context: Expression, data: Expression },
    Finalize { context: Expression, data: Expression },
    LargeData { data: Expression }, // Helper for hashing large data
}

/// Convert a transaction introspection expression to a requirement
pub fn tx_introspection_to_requirement(introspection: TxIntrospection, op: &str, right: Expression) -> Requirement {
    // Convert the introspection to an expression
    let left = match introspection {
        TxIntrospection::InputOutpoint { index } => 
            Expression::Property(format!("tx.input[{}].outpoint", expression_to_string(&index))),
        TxIntrospection::InputAsset { index } => 
            Expression::Property(format!("tx.input[{}].asset", expression_to_string(&index))),
        TxIntrospection::InputValue { index } => 
            Expression::Property(format!("tx.input[{}].value", expression_to_string(&index))),
        TxIntrospection::InputScriptPubKey { index } => 
            Expression::Property(format!("tx.input[{}].scriptPubKey", expression_to_string(&index))),
        TxIntrospection::InputSequence { index } => 
            Expression::Property(format!("tx.input[{}].sequence", expression_to_string(&index))),
        TxIntrospection::InputIssuance { index } => 
            Expression::Property(format!("tx.input[{}].issuance", expression_to_string(&index))),
        TxIntrospection::CurrentInputIndex => 
            Expression::Property("tx.currentInputIndex".to_string()),
        TxIntrospection::OutputAsset { index } => 
            Expression::Property(format!("tx.output[{}].asset", expression_to_string(&index))),
        TxIntrospection::OutputValue { index } => 
            Expression::Property(format!("tx.output[{}].value", expression_to_string(&index))),
        TxIntrospection::OutputNonce { index } => 
            Expression::Property(format!("tx.output[{}].nonce", expression_to_string(&index))),
        TxIntrospection::OutputScriptPubKey { index } => 
            Expression::Property(format!("tx.output[{}].scriptPubKey", expression_to_string(&index))),
        TxIntrospection::Version => 
            Expression::Property("tx.version".to_string()),
        TxIntrospection::LockTime => 
            Expression::Property("tx.locktime".to_string()),
        TxIntrospection::NumInputs => 
            Expression::Property("tx.numInputs".to_string()),
        TxIntrospection::NumOutputs => 
            Expression::Property("tx.numOutputs".to_string()),
        TxIntrospection::Weight => 
            Expression::Property("tx.weight".to_string()),
    };
    
    // Create a comparison requirement
    Requirement::Comparison { left, op: op.to_string(), right }
}

/// Convert an arithmetic expression to a requirement
pub fn arithmetic_to_requirement(arithmetic: Arithmetic64) -> Requirement {
    match arithmetic {
        Arithmetic64::Add { left, right } => {
            // For add, we'll use a comparison with the result
            let result_var = "result".to_string();
            Requirement::Comparison { 
                left: Expression::Variable(result_var), 
                op: "==".to_string(), 
                right: Expression::Property(format!("{}+{}", expression_to_string(&left), expression_to_string(&right)))
            }
        },
        Arithmetic64::Sub { left, right } => {
            let result_var = "result".to_string();
            Requirement::Comparison { 
                left: Expression::Variable(result_var), 
                op: "==".to_string(), 
                right: Expression::Property(format!("{}-{}", expression_to_string(&left), expression_to_string(&right)))
            }
        },
        Arithmetic64::Mul { left, right } => {
            let result_var = "result".to_string();
            Requirement::Comparison { 
                left: Expression::Variable(result_var), 
                op: "==".to_string(), 
                right: Expression::Property(format!("{}*{}", expression_to_string(&left), expression_to_string(&right)))
            }
        },
        Arithmetic64::Div { left, right } => {
            let result_var = "result".to_string();
            Requirement::Comparison { 
                left: Expression::Variable(result_var), 
                op: "==".to_string(), 
                right: Expression::Property(format!("{}/{}", expression_to_string(&left), expression_to_string(&right)))
            }
        },
        Arithmetic64::Neg { value } => {
            let result_var = "result".to_string();
            Requirement::Comparison { 
                left: Expression::Variable(result_var), 
                op: "==".to_string(), 
                right: Expression::Property(format!("-{}", expression_to_string(&value)))
            }
        },
        Arithmetic64::LessThan { left, right } => {
            Requirement::Comparison { 
                left, 
                op: "<".to_string(), 
                right 
            }
        },
        Arithmetic64::LessThanOrEqual { left, right } => {
            Requirement::Comparison { 
                left, 
                op: "<=".to_string(), 
                right 
            }
        },
        Arithmetic64::GreaterThan { left, right } => {
            Requirement::Comparison { 
                left, 
                op: ">".to_string(), 
                right 
            }
        },
        Arithmetic64::GreaterThanOrEqual { left, right } => {
            Requirement::Comparison { 
                left, 
                op: ">=".to_string(), 
                right 
            }
        },
    }
}

/// Convert a crypto operation to a requirement
pub fn crypto_to_requirement(crypto: CryptoOp) -> Requirement {
    match crypto {
        CryptoOp::CheckSigFromStack { pubkey, message, signature } => {
            // Create a custom requirement for checksig from stack
            Requirement::Comparison { 
                left: Expression::Property(format!("checkSigFromStack({}, {}, {})", 
                    expression_to_string(&signature),
                    expression_to_string(&message),
                    expression_to_string(&pubkey)
                )), 
                op: "==".to_string(), 
                right: Expression::Literal("true".to_string())
            }
        },
        CryptoOp::ECMulScalarVerify { scalar, point_p, point_q } => {
            // Create a custom requirement for ecmulscalar verify
            Requirement::Comparison { 
                left: Expression::Property(format!("ecmulscalarVerify({}, {}, {})", 
                    expression_to_string(&scalar),
                    expression_to_string(&point_p),
                    expression_to_string(&point_q)
                )), 
                op: "==".to_string(), 
                right: Expression::Literal("true".to_string())
            }
        },
        CryptoOp::TweakVerify { internal_key, tweak, output_key } => {
            // Create a custom requirement for tweak verify
            Requirement::Comparison { 
                left: Expression::Property(format!("tweakVerify({}, {}, {})", 
                    expression_to_string(&internal_key),
                    expression_to_string(&tweak),
                    expression_to_string(&output_key)
                )), 
                op: "==".to_string(), 
                right: Expression::Literal("true".to_string())
            }
        },
    }
}

/// Convert a streaming SHA256 operation to a requirement
pub fn sha256_to_requirement(sha256: StreamingSHA256) -> Requirement {
    match sha256 {
        StreamingSHA256::LargeData { data } => {
            // For large data, we'll use a regular SHA256 requirement
            Requirement::HashEqual { 
                preimage: expression_to_string(&data), 
                hash: "hash".to_string() 
            }
        },
        // For the other operations, we'll create custom requirements
        StreamingSHA256::Initialize { data } => {
            Requirement::Comparison { 
                left: Expression::Property(format!("sha256Initialize({})", expression_to_string(&data))), 
                op: "==".to_string(), 
                right: Expression::Variable("context".to_string())
            }
        },
        StreamingSHA256::Update { context, data } => {
            Requirement::Comparison { 
                left: Expression::Property(format!("sha256Update({}, {})", 
                    expression_to_string(&context),
                    expression_to_string(&data)
                )), 
                op: "==".to_string(), 
                right: Expression::Variable("updatedContext".to_string())
            }
        },
        StreamingSHA256::Finalize { context, data } => {
            Requirement::Comparison { 
                left: Expression::Property(format!("sha256Finalize({}, {})", 
                    expression_to_string(&context),
                    expression_to_string(&data)
                )), 
                op: "==".to_string(), 
                right: Expression::Variable("hash".to_string())
            }
        },
    }
}

/// Convert an expression to a string representation
fn expression_to_string(expr: &Expression) -> String {
    match expr {
        Expression::Variable(var) => var.clone(),
        Expression::Literal(lit) => lit.clone(),
        Expression::Property(prop) => prop.clone(),
        Expression::Sha256(data) => format!("sha256({})", data),
        Expression::CurrentInput(prop) => {
            if let Some(p) = prop {
                format!("tx.input.current.{}", p)
            } else {
                "tx.input.current".to_string()
            }
        },
    }
} 