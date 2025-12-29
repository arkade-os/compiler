use crate::models::{Requirement, Expression, ContractJson, AbiFunction, FunctionInput, RequireStatement, CompilerInfo};
use crate::parser;
use chrono::Utc;

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
            name: "arkade-compiler".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }),
        updated_at: Some(Utc::now().to_rfc3339()),
    };
    
    // Process each function (skip internal functions)
    for function in &contract.functions {
        // Internal functions are helpers and don't generate spending paths
        if function.is_internal {
            continue;
        }

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
                    (Expression::Property(prop), "==", Expression::Variable(var)) => {
                        asm.push(format!("<{}>", prop));
                        asm.push("OP_EQUAL".to_string());
                        asm.push(format!("<{}>", var));
                    },
                    (Expression::Property(prop), ">=", Expression::Variable(var)) => {
                        asm.push(format!("<{}>", prop));
                        asm.push("OP_GREATERTHANOREQUAL".to_string());
                        asm.push(format!("<{}>", var));
                    },
                    (Expression::Property(prop), "==", Expression::Literal(value)) => {
                        asm.push(format!("<{}>", prop));
                        asm.push("OP_EQUAL".to_string());
                        asm.push(value.clone());
                    },
                    (Expression::Property(prop), ">=", Expression::Literal(value)) => {
                        asm.push(format!("<{}>", prop));
                        asm.push("OP_GREATERTHANOREQUAL".to_string());
                        asm.push(value.clone());
                    },
                    (Expression::Property(prop), "==", Expression::Property(prop2)) => {
                        asm.push(format!("<{}>", prop));
                        asm.push("OP_EQUAL".to_string());
                        asm.push(format!("<{}>", prop2));
                    },
                    (Expression::Property(prop), ">=", Expression::Property(prop2)) => {
                        asm.push(format!("<{}>", prop));
                        asm.push("OP_GREATERTHANOREQUAL".to_string());
                        asm.push(format!("<{}>", prop2));
                    },
                    (Expression::CurrentInput(property), "==", Expression::Literal(value)) => {
                        if value == "true" {
                            // Handle tx.input.current
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