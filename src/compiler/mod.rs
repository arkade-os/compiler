use crate::models::{Requirement, Expression, ContractJson, AbiFunction, FunctionInput, RequireStatement, CompilerInfo};
use crate::parser;
use chrono::Utc;

// Include the opcodes module
pub mod opcodes;

/// Compiles a TapLang contract AST into a JSON-serializable structure.
/// 
/// This function takes a parsed Contract AST and transforms it into a ContractJson
/// structure that can be serialized to JSON. The output includes:
/// 
/// - Contract name
/// - Constructor inputs (parameters)
/// - Functions with their inputs, requirements, and assembly code
/// 
/// Contracts can include an options block to specify additional behaviors:
/// 
/// Example:
/// 
/// ```text
/// // Contract configuration options
/// options {
///   // Server key parameter from contract parameters
///   server = server;
///   
///   // Renewal timelock: 7 days (1008 blocks)
///   renew = 1008;
///   
///   // Exit timelock: 24 hours (144 blocks)
///   exit = 144;
/// }
/// 
/// contract MyContract(pubkey user, pubkey server) {
///   // functions...
/// }
/// ```
/// 
/// The `server` option specifies which parameter contains the server public key.
/// The `renew` option specifies the renewal timelock in blocks.
/// The `exit` option specifies the exit timelock in blocks.
/// 
/// If these options are not specified, default values will be used.
/// 
/// Each script path includes a serverVariant flag. When using the script:
/// - If serverVariant is true, use the script as-is (cooperative path with server)
/// - If serverVariant is false, use the exit path (unilateral exit after timelock)
/// 
/// # Arguments
/// 
/// * `source_code` - The source code of the contract
/// 
/// # Returns
/// 
/// A Result containing a ContractJson structure that can be serialized to JSON or an error message
pub fn compile(source_code: &str) -> Result<ContractJson, String> {
    // Parse the contract
    let contract = match parser::parse(source_code) {
        Ok(contract) => contract,
        Err(e) => return Err(format!("Parse error: {}", e)),
    };

    // Create the JSON output
    let mut json = ContractJson {
        name: contract.name.clone(),
        parameters: contract.parameters.clone(),
        functions: Vec::new(),
        source: Some(source_code.to_string()),
        compiler: Some(CompilerInfo {
            name: "taplang".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }),
        updated_at: Some(Utc::now().to_rfc3339()),
    };
    
    // Process each function
    for function in &contract.functions {
        // Generate collaborative path (with server signature)
        let collaborative_function = generate_function(function, &contract, true);
        json.functions.push(collaborative_function);
        
        // Generate exit path (with timelock)
        let exit_function = generate_function(function, &contract, false);
        json.functions.push(exit_function);
    }
    
    Ok(json)
}

/// Generate a function with server variant flag
fn generate_function(function: &crate::models::Function, contract: &crate::models::Contract, server_variant: bool) -> AbiFunction {
    // Convert function parameters to function inputs
    let function_inputs = function.parameters.iter()
        .map(|param| FunctionInput {
            name: param.name.clone(),
            param_type: param.param_type.clone(),
        })
        .collect();
    
    // Generate requirements
    let mut require = generate_requirements(function);
    
    // Add server signature or exit timelock requirement
    if server_variant {
        // Add server signature requirement
        if let Some(_server_key) = &contract.server_key_param {
            require.push(RequireStatement {
                req_type: "serverSignature".to_string(),
                message: None,
            });
        }
    } else {
        // Add exit timelock requirement
        if let Some(exit_timelock) = contract.exit_timelock {
            require.push(RequireStatement {
                req_type: "older".to_string(),
                message: Some(format!("Exit timelock of {} blocks", exit_timelock)),
            });
        }
    }
    
    // Generate assembly instructions
    let mut asm = generate_base_asm_instructions(&function.requirements);
    
    // Add server signature or exit timelock check
    if server_variant {
        // Add server signature check
        if let Some(_server_key) = &contract.server_key_param {
            asm.push("<SERVER_KEY>".to_string());
            asm.push("<serverSig>".to_string());
            asm.push("OP_CHECKSIG".to_string());
        }
    } else {
        // Add exit timelock check
        if let Some(exit_timelock) = contract.exit_timelock {
            asm.push(format!("{}", exit_timelock));
            asm.push("OP_CHECKLOCKTIMEVERIFY".to_string());
            asm.push("OP_DROP".to_string());
        }
    }
    
    AbiFunction {
        name: function.name.clone(),
        function_inputs,
        server_variant,
        require,
        asm,
    }
}

/// Generate requirements from function requirements
fn generate_requirements(function: &crate::models::Function) -> Vec<RequireStatement> {
    let mut requirements = Vec::new();
    
    for req in &function.requirements {
        match req {
            Requirement::CheckSig { signature: _, pubkey: _ } => {
                requirements.push(RequireStatement {
                    req_type: "signature".to_string(),
                    message: None,
                });
            },
            Requirement::CheckMultisig { signatures: _, pubkeys: _ } => {
                requirements.push(RequireStatement {
                    req_type: "multisig".to_string(),
                    message: None,
                });
            },
            Requirement::After { blocks, timelock_var: _ } => {
                requirements.push(RequireStatement {
                    req_type: "older".to_string(),
                    message: Some(format!("Timelock of {} blocks", blocks)),
                });
            },
            Requirement::HashEqual { preimage: _, hash: _ } => {
                requirements.push(RequireStatement {
                    req_type: "hash".to_string(),
                    message: None,
                });
            },
            Requirement::Comparison { left: _, op: _, right: _ } => {
                requirements.push(RequireStatement {
                    req_type: "comparison".to_string(),
                    message: None,
                });
            },
        }
    }
    
    requirements
}

/// Generate assembly instructions for a requirement
fn generate_base_asm_instructions(requirements: &[Requirement]) -> Vec<String> {
    let mut asm = Vec::new();
    
    for req in requirements {
        match req {
            Requirement::CheckSig { signature, pubkey } => {
                asm.push(format!("<{}>", pubkey));
                asm.push(format!("<{}>", signature));
                asm.push("OP_CHECKSIG".to_string());
            },
            Requirement::CheckMultisig { signatures, pubkeys } => {
                // Number of pubkeys
                asm.push(format!("OP_{}", pubkeys.len()));
                
                // Pubkeys
                for pubkey in pubkeys {
                    asm.push(format!("<{}>", pubkey));
                }
                
                // Number of signatures
                asm.push(format!("OP_{}", signatures.len()));
                
                // Signatures
                for signature in signatures {
                    asm.push(format!("<{}>", signature));
                }
                
                asm.push("OP_CHECKMULTISIG".to_string());
            },
            Requirement::After { blocks, timelock_var } => {
                // If we have a variable name, use it, otherwise use the blocks value
                if let Some(var) = timelock_var {
                    asm.push(format!("<{}>", var));
                } else {
                    asm.push(format!("{}", blocks));
                }
                asm.push("OP_CHECKLOCKTIMEVERIFY".to_string());
                asm.push("OP_DROP".to_string());
            },
            Requirement::HashEqual { preimage, hash } => {
                asm.push(format!("<{}>", preimage));
                asm.push("OP_SHA256".to_string());
                asm.push(format!("<{}>", hash));
                asm.push("OP_EQUAL".to_string());
            },
            Requirement::Comparison { left, op, right } => {
                match (left, op.as_str(), right) {
                    (Expression::Variable(var), ">=", Expression::Literal(value)) => {
                        asm.push(format!("<{}>", var));
                        asm.push("OP_GREATERTHANOREQUAL".to_string());
                        asm.push(value.clone());
                    },
                    (Expression::Variable(var), "==", Expression::Variable(var2)) => {
                        asm.push(format!("<{}>", var));
                        asm.push("OP_EQUAL".to_string());
                        asm.push(format!("<{}>", var2));
                    },
                    (Expression::Variable(var), ">=", Expression::Variable(var2)) => {
                        asm.push(format!("<{}>", var));
                        asm.push("OP_GREATERTHANOREQUAL".to_string());
                        asm.push(format!("<{}>", var2));
                    },
                    (Expression::Variable(var), "==", Expression::Property(prop)) => {
                        asm.push(format!("<{}>", var));
                        asm.push("OP_EQUAL".to_string());
                        asm.push(format!("<{}>", prop));
                    },
                    (Expression::Variable(var), ">=", Expression::Property(prop)) => {
                        asm.push(format!("<{}>", var));
                        asm.push("OP_GREATERTHANOREQUAL".to_string());
                        asm.push(format!("<{}>", prop));
                    },
                    (Expression::Variable(var), "==", Expression::Sha256(var2)) => {
                        asm.push(format!("<{}>", var));
                        asm.push("OP_EQUAL".to_string());
                        asm.push(format!("<{}>", var2));
                        asm.push("OP_SHA256".to_string());
                    },
                    (Expression::Variable(var), ">=", Expression::Sha256(var2)) => {
                        asm.push(format!("<{}>", var));
                        asm.push("OP_GREATERTHANOREQUAL".to_string());
                        asm.push(format!("<{}>", var2));
                        asm.push("OP_SHA256".to_string());
                    },
                    (Expression::Literal(lit), "==", Expression::Variable(var)) => {
                        asm.push(lit.clone());
                        asm.push("OP_EQUAL".to_string());
                        asm.push(format!("<{}>", var));
                    },
                    (Expression::Literal(lit), ">=", Expression::Variable(var)) => {
                        asm.push(lit.clone());
                        asm.push("OP_GREATERTHANOREQUAL".to_string());
                        asm.push(format!("<{}>", var));
                    },
                    (Expression::Literal(lit), "==", Expression::Literal(value)) => {
                        asm.push(lit.clone());
                        asm.push("OP_EQUAL".to_string());
                        asm.push(value.clone());
                    },
                    (Expression::Literal(lit), ">=", Expression::Literal(value)) => {
                        asm.push(lit.clone());
                        asm.push("OP_GREATERTHANOREQUAL".to_string());
                        asm.push(value.clone());
                    },
                    (Expression::Literal(lit), "==", Expression::Property(prop)) => {
                        asm.push(lit.clone());
                        asm.push("OP_EQUAL".to_string());
                        asm.push(format!("<{}>", prop));
                    },
                    (Expression::Literal(lit), ">=", Expression::Property(prop)) => {
                        asm.push(lit.clone());
                        asm.push("OP_GREATERTHANOREQUAL".to_string());
                        asm.push(format!("<{}>", prop));
                    },
                    (Expression::Literal(lit), "==", Expression::Sha256(var)) => {
                        asm.push(lit.clone());
                        asm.push("OP_EQUAL".to_string());
                        asm.push(format!("<{}>", var));
                        asm.push("OP_SHA256".to_string());
                    },
                    (Expression::Literal(lit), ">=", Expression::Sha256(var)) => {
                        asm.push(lit.clone());
                        asm.push("OP_GREATERTHANOREQUAL".to_string());
                        asm.push(format!("<{}>", var));
                        asm.push("OP_SHA256".to_string());
                    },
                    (Expression::Property(prop), "==", Expression::Variable(var)) => {
                        // Handle different property types based on their prefix
                        if prop.starts_with("tx.input[") {
                            // Extract the input index and property
                            let parts: Vec<&str> = prop.split(']').collect();
                            if parts.len() >= 2 {
                                let index_part = parts[0].trim_start_matches("tx.input[");
                                let property_part = parts[1].trim_start_matches('.');
                                
                                // Push the index
                                asm.push(format!("{}", index_part));
                                
                                // Add the appropriate opcode based on the property
                                match property_part {
                                    "outpoint" => asm.push("OP_INSPECTINPUTOUTPOINT".to_string()),
                                    "asset" => asm.push("OP_INSPECTINPUTASSET".to_string()),
                                    "value" => asm.push("OP_INSPECTINPUTVALUE".to_string()),
                                    "scriptPubKey" => asm.push("OP_INSPECTINPUTSCRIPTPUBKEY".to_string()),
                                    "sequence" => asm.push("OP_INSPECTINPUTSEQUENCE".to_string()),
                                    "issuance" => asm.push("OP_INSPECTINPUTISSUANCE".to_string()),
                                    _ => asm.push("OP_FALSE".to_string()), // Unsupported property
                                }
                            }
                        } else if prop.starts_with("tx.output[") {
                            // Extract the output index and property
                            let parts: Vec<&str> = prop.split(']').collect();
                            if parts.len() >= 2 {
                                let index_part = parts[0].trim_start_matches("tx.output[");
                                let property_part = parts[1].trim_start_matches('.');
                                
                                // Push the index
                                asm.push(format!("{}", index_part));
                                
                                // Add the appropriate opcode based on the property
                                match property_part {
                                    "asset" => asm.push("OP_INSPECTOUTPUTASSET".to_string()),
                                    "value" => asm.push("OP_INSPECTOUTPUTVALUE".to_string()),
                                    "nonce" => asm.push("OP_INSPECTOUTPUTNONCE".to_string()),
                                    "scriptPubKey" => asm.push("OP_INSPECTOUTPUTSCRIPTPUBKEY".to_string()),
                                    _ => asm.push("OP_FALSE".to_string()), // Unsupported property
                                }
                            }
                        } else if prop == "tx.currentInputIndex" {
                            // Push the current input index
                            asm.push("OP_PUSHCURRENTINPUTINDEX".to_string());
                        } else if prop == "tx.version" {
                            // Push the transaction version
                            asm.push("OP_INSPECTVERSION".to_string());
                        } else if prop == "tx.locktime" {
                            // Push the transaction locktime
                            asm.push("OP_INSPECTLOCKTIME".to_string());
                        } else if prop == "tx.numInputs" {
                            // Push the number of inputs
                            asm.push("OP_INSPECTNUMINPUTS".to_string());
                        } else if prop == "tx.numOutputs" {
                            // Push the number of outputs
                            asm.push("OP_INSPECTNUMOUTPUTS".to_string());
                        } else if prop == "tx.weight" {
                            // Push the transaction weight
                            asm.push("OP_TXWEIGHT".to_string());
                        } else if prop.contains('+') {
                            // Handle addition
                            let parts: Vec<&str> = prop.split('+').collect();
                            if parts.len() == 2 {
                                let left = parts[0].trim();
                                let right = parts[1].trim();
                                
                                // Push the operands
                                asm.push(format!("<{}>", left));
                                asm.push(format!("<{}>", right));
                                
                                // Add the ADD64 opcode
                                asm.push("OP_ADD64".to_string());
                            }
                        } else if prop.contains('-') {
                            // Handle subtraction
                            let parts: Vec<&str> = prop.split('-').collect();
                            if parts.len() == 2 {
                                let left = parts[0].trim();
                                let right = parts[1].trim();
                                
                                // Push the operands
                                asm.push(format!("<{}>", left));
                                asm.push(format!("<{}>", right));
                                
                                // Add the SUB64 opcode
                                asm.push("OP_SUB64".to_string());
                            }
                        } else if prop.contains('*') {
                            // Handle multiplication
                            let parts: Vec<&str> = prop.split('*').collect();
                            if parts.len() == 2 {
                                let left = parts[0].trim();
                                let right = parts[1].trim();
                                
                                // Push the operands
                                asm.push(format!("<{}>", left));
                                asm.push(format!("<{}>", right));
                                
                                // Add the MUL64 opcode
                                asm.push("OP_MUL64".to_string());
                            }
                        } else if prop.contains('/') {
                            // Handle division
                            let parts: Vec<&str> = prop.split('/').collect();
                            if parts.len() == 2 {
                                let left = parts[0].trim();
                                let right = parts[1].trim();
                                
                                // Push the operands
                                asm.push(format!("<{}>", left));
                                asm.push(format!("<{}>", right));
                                
                                // Add the DIV64 opcode
                                asm.push("OP_DIV64".to_string());
                            }
                        } else if prop.starts_with('-') {
                            // Handle negation
                            let value = prop.trim_start_matches('-');
                            
                            // Push the operand
                            asm.push(format!("<{}>", value));
                            
                            // Add the NEG64 opcode
                            asm.push("OP_NEG64".to_string());
                        } else if prop.starts_with("sha256Initialize") {
                            // Handle SHA256 initialization
                            let data = prop.trim_start_matches("sha256Initialize(").trim_end_matches(')');
                            
                            // Push the data
                            asm.push(format!("<{}>", data));
                            
                            // Add the SHA256INITIALIZE opcode
                            asm.push("OP_SHA256INITIALIZE".to_string());
                        } else if prop.starts_with("sha256Update") {
                            // Handle SHA256 update
                            let args = prop.trim_start_matches("sha256Update(").trim_end_matches(')');
                            let parts: Vec<&str> = args.split(',').collect();
                            if parts.len() == 2 {
                                let context = parts[0].trim();
                                let data = parts[1].trim();
                                
                                // Push the context and data
                                asm.push(format!("<{}>", context));
                                asm.push(format!("<{}>", data));
                                
                                // Add the SHA256UPDATE opcode
                                asm.push("OP_SHA256UPDATE".to_string());
                            }
                        } else if prop.starts_with("sha256Finalize") {
                            // Handle SHA256 finalization
                            let args = prop.trim_start_matches("sha256Finalize(").trim_end_matches(')');
                            let parts: Vec<&str> = args.split(',').collect();
                            if parts.len() == 2 {
                                let context = parts[0].trim();
                                let data = parts[1].trim();
                                
                                // Push the context and data
                                asm.push(format!("<{}>", context));
                                asm.push(format!("<{}>", data));
                                
                                // Add the SHA256FINALIZE opcode
                                asm.push("OP_SHA256FINALIZE".to_string());
                            }
                        } else if prop.starts_with("checkSigFromStack") && var == "true" {
                            // Handle checkSigFromStack
                            let args = prop.trim_start_matches("checkSigFromStack(").trim_end_matches(')');
                            let parts: Vec<&str> = args.split(',').collect();
                            if parts.len() == 3 {
                                let signature = parts[0].trim();
                                let message = parts[1].trim();
                                let pubkey = parts[2].trim();
                                
                                // Push the signature, message, and pubkey
                                asm.push(format!("<{}>", signature));
                                asm.push(format!("<{}>", message));
                                asm.push(format!("<{}>", pubkey));
                                
                                // Add the CHECKSIGFROMSTACK opcode
                                asm.push("OP_CHECKSIGFROMSTACK".to_string());
                            }
                        } else if prop.starts_with("ecmulscalarVerify") && var == "true" {
                            // Handle ecmulscalarVerify
                            let args = prop.trim_start_matches("ecmulscalarVerify(").trim_end_matches(')');
                            let parts: Vec<&str> = args.split(',').collect();
                            if parts.len() == 3 {
                                let scalar = parts[0].trim();
                                let point_p = parts[1].trim();
                                let point_q = parts[2].trim();
                                
                                // Push the scalar, point_p, and point_q
                                asm.push(format!("<{}>", scalar));
                                asm.push(format!("<{}>", point_p));
                                asm.push(format!("<{}>", point_q));
                                
                                // Add the ECMULSCALARVERIFY opcode
                                asm.push("OP_ECMULSCALARVERIFY".to_string());
                            }
                        } else if prop.starts_with("tweakVerify") && var == "true" {
                            // Handle tweakVerify
                            let args = prop.trim_start_matches("tweakVerify(").trim_end_matches(')');
                            let parts: Vec<&str> = args.split(',').collect();
                            if parts.len() == 3 {
                                let internal_key = parts[0].trim();
                                let tweak = parts[1].trim();
                                let output_key = parts[2].trim();
                                
                                // Push the internal_key, tweak, and output_key
                                asm.push(format!("<{}>", internal_key));
                                asm.push(format!("<{}>", tweak));
                                asm.push(format!("<{}>", output_key));
                                
                                // Add the TWEAKVERIFY opcode
                                asm.push("OP_TWEAKVERIFY".to_string());
                            }
                        } else {
                            // Default case for other properties
                            asm.push(format!("<{}>", prop));
                        }
                        
                        // Compare with the variable
                        asm.push("OP_EQUAL".to_string());
                        asm.push(format!("<{}>", var));
                    },
                    
                    // Handle Sha256 expressions
                    (Expression::Sha256(var), "==", Expression::Variable(var2)) => {
                        asm.push(format!("<{}>", var));
                        asm.push("OP_SHA256".to_string());
                        asm.push("OP_EQUAL".to_string());
                        asm.push(format!("<{}>", var2));
                    },
                    (Expression::Sha256(var), "==", Expression::Literal(value)) => {
                        asm.push(format!("<{}>", var));
                        asm.push("OP_SHA256".to_string());
                        asm.push("OP_EQUAL".to_string());
                        asm.push(value.clone());
                    },
                    (Expression::Sha256(var), "==", Expression::Property(prop)) => {
                        asm.push(format!("<{}>", var));
                        asm.push("OP_SHA256".to_string());
                        asm.push("OP_EQUAL".to_string());
                        asm.push(format!("<{}>", prop));
                    },
                    (Expression::Sha256(var), ">=", Expression::Variable(var2)) => {
                        asm.push(format!("<{}>", var));
                        asm.push("OP_SHA256".to_string());
                        asm.push("OP_GREATERTHANOREQUAL".to_string());
                        asm.push(format!("<{}>", var2));
                    },
                    (Expression::Sha256(var), ">=", Expression::Literal(value)) => {
                        asm.push(format!("<{}>", var));
                        asm.push("OP_SHA256".to_string());
                        asm.push("OP_GREATERTHANOREQUAL".to_string());
                        asm.push(value.clone());
                    },
                    (Expression::Sha256(var), ">=", Expression::Property(prop)) => {
                        asm.push(format!("<{}>", var));
                        asm.push("OP_SHA256".to_string());
                        asm.push("OP_GREATERTHANOREQUAL".to_string());
                        asm.push(format!("<{}>", prop));
                    },
                    
                    // Handle CurrentInput expressions
                    (Expression::CurrentInput(property), "==", Expression::Literal(value)) => {
                        if value == "true" {
                            // Handle tx.currentInput
                            // No need for OP_ACTIVEBYTECODESTART as we're directly accessing the current input
                            
                            // If there's a property, access it specifically
                            if let Some(prop) = property {
                                match prop.as_str() {
                                    "scriptPubKey" => {
                                        // Get the current input's script pubkey
                                        asm.push("OP_INPUTBYTECODE".to_string());
                                    },
                                    "value" => {
                                        // Get the current input's value
                                        asm.push("OP_INPUTVALUE".to_string());
                                    },
                                    "sequence" => {
                                        // Get the current input's sequence number
                                        asm.push("OP_INPUTSEQUENCE".to_string());
                                    },
                                    "outpoint" => {
                                        // Get the current input's outpoint (txid + vout)
                                        asm.push("OP_INPUTOUTPOINT".to_string());
                                    },
                                    // Add other properties as needed
                                    _ => {
                                        // Default to script pubkey for unknown properties
                                        asm.push("OP_INPUTBYTECODE".to_string());
                                    }
                                }
                            } else {
                                // If no property specified, default to the entire input
                                // This could be a composite of all input properties or just the most commonly used one
                                asm.push("OP_INPUTBYTECODE".to_string());
                            }
                        }
                    },
                    
                    // Add a catch-all pattern to fix the non-exhaustive patterns error
                    _ => {
                        // Default handling for unmatched patterns
                        asm.push("OP_FALSE".to_string());
                    }
                }
            },
        }
    }
    
    asm
} 