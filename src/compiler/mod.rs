use crate::models::{
    Requirement, Expression, Statement, ContractJson, AbiFunction, FunctionInput,
    RequireStatement, CompilerInfo, AssetLookupSource, GroupSumSource, Function,
};
use crate::parser;
use chrono::Utc;

// ─── Introspection Detection ────────────────────────────────────────────────────
//
// These helpers detect if a function uses introspection opcodes (OP_INSPECT*).
// When introspection is detected, the exit path requires N-of-N signatures
// instead of the normal user sig + timelock pattern.

/// Check if a function uses any introspection opcodes
fn function_uses_introspection(function: &Function) -> bool {
    function.statements.iter().any(|s| statement_uses_introspection(s))
}

/// Check if a statement uses introspection
fn statement_uses_introspection(stmt: &Statement) -> bool {
    match stmt {
        Statement::Require(req) => requirement_uses_introspection(req),
        Statement::IfElse { condition, then_body, else_body } => {
            expression_uses_introspection(condition)
                || then_body.iter().any(|s| statement_uses_introspection(s))
                || else_body.as_ref().map_or(false, |b| b.iter().any(|s| statement_uses_introspection(s)))
        }
        Statement::ForIn { iterable, body, .. } => {
            expression_uses_introspection(iterable)
                || body.iter().any(|s| statement_uses_introspection(s))
        }
        Statement::LetBinding { value, .. } | Statement::VarAssign { value, .. } => {
            expression_uses_introspection(value)
        }
    }
}

/// Check if a requirement uses introspection
fn requirement_uses_introspection(req: &Requirement) -> bool {
    match req {
        Requirement::Comparison { left, right, .. } => {
            expression_uses_introspection(left) || expression_uses_introspection(right)
        }
        _ => false,
    }
}

/// Check if an expression uses introspection opcodes
fn expression_uses_introspection(expr: &Expression) -> bool {
    match expr {
        // Direct introspection opcodes
        Expression::TxIntrospection { .. } => true,
        Expression::InputIntrospection { .. } => true,
        Expression::OutputIntrospection { .. } => true,
        Expression::AssetLookup { .. } => true,
        Expression::AssetCount { .. } => true,
        Expression::AssetAt { .. } => true,
        Expression::GroupFind { .. } => true,
        Expression::GroupProperty { .. } => true,
        Expression::AssetGroupsLength => true,
        Expression::GroupSum { .. } => true,
        Expression::CurrentInput(_) => true,

        // Recursive checks for compound expressions
        Expression::BinaryOp { left, right, .. } => {
            expression_uses_introspection(left) || expression_uses_introspection(right)
        }
        Expression::ArrayIndex { array, index } => {
            expression_uses_introspection(array) || expression_uses_introspection(index)
        }
        Expression::Sha256Initialize { data } => expression_uses_introspection(data),
        Expression::Sha256Update { context, chunk } => {
            expression_uses_introspection(context) || expression_uses_introspection(chunk)
        }
        Expression::Sha256Finalize { context, last_chunk } => {
            expression_uses_introspection(context) || expression_uses_introspection(last_chunk)
        }
        Expression::Neg64 { value } => expression_uses_introspection(value),
        Expression::Le64ToScriptNum { value } => expression_uses_introspection(value),
        Expression::Le32ToLe64 { value } => expression_uses_introspection(value),
        Expression::EcMulScalarVerify { scalar, point_p, point_q } => {
            expression_uses_introspection(scalar)
                || expression_uses_introspection(point_p)
                || expression_uses_introspection(point_q)
        }
        Expression::TweakVerify { point_p, tweak, point_q } => {
            expression_uses_introspection(point_p)
                || expression_uses_introspection(tweak)
                || expression_uses_introspection(point_q)
        }

        // Check for P2TR constructor in Property strings (e.g., "new P2TR(...)")
        Expression::Property(prop) => prop.starts_with("new P2TR"),

        // Non-introspection expressions
        Expression::Variable(_) => false,
        Expression::Literal(_) => false,
        Expression::ArrayLength(_) => false,
        Expression::CheckSigExpr { .. } => false,
        Expression::CheckSigFromStackExpr { .. } => false,
        Expression::CheckSigFromStackVerify { .. } => false,
    }
}

/// Collect all pubkey parameters from constructor and function for N-of-N fallback
/// Excludes the server key (which comes from options, not constructor)
fn collect_all_pubkeys(contract: &crate::models::Contract, function: &Function) -> Vec<String> {
    let server_key = contract.server_key_param.as_ref();

    contract.parameters.iter()
        .chain(function.parameters.iter())
        .filter(|p| p.param_type == "pubkey")
        // Exclude server key from N-of-N (it's for cooperative path only)
        .filter(|p| server_key.map_or(true, |sk| &p.name != sk))
        .map(|p| p.name.clone())
        .collect()
}

/// Compiles an Arkade Script contract into a JSON-serializable structure.
///
/// Takes source code, parses it into an AST, and transforms it into a ContractJson
/// structure. The output includes contract name, constructor inputs (with asset ID
/// decomposition for lookup parameters), functions with inputs, requirements, and
/// assembly code.
///
/// Each non-internal function produces two variants:
/// - `serverVariant: true` — cooperative path (user sig + server sig)
/// - `serverVariant: false` — exit path (user sig + timelock)
///
/// # Arguments
///
/// * `source_code` - The Arkade Script source code
///
/// # Returns
///
/// A Result containing a ContractJson or an error message
pub fn compile(source_code: &str) -> Result<ContractJson, String> {
    let contract = match parser::parse(source_code) {
        Ok(contract) => contract,
        Err(e) => return Err(format!("Parse error: {}", e)),
    };

    // Note: Server key is injected externally via getInfo(), not required in constructor.
    // The `server = serverPk` in options references an external key, not a constructor param.

    // Collect asset IDs used in lookups for constructor param decomposition
    let lookup_asset_ids = collect_lookup_asset_ids(&contract);

    // Build constructor inputs with asset ID decomposition
    let parameters = decompose_constructor_params(&contract.parameters, &lookup_asset_ids);

    let mut json = ContractJson {
        name: contract.name.clone(),
        parameters,
        functions: Vec::new(),
        source: Some(source_code.to_string()),
        compiler: Some(CompilerInfo {
            name: "arkade-compiler".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }),
        updated_at: Some(Utc::now().to_rfc3339()),
    };

    for function in &contract.functions {
        if function.is_internal {
            continue;
        }

        let collaborative = generate_function(function, &contract, true);
        json.functions.push(collaborative);

        let exit = generate_function(function, &contract, false);
        json.functions.push(exit);
    }

    Ok(json)
}

/// Collect all asset ID parameter names used in AssetLookup expressions
fn collect_lookup_asset_ids(contract: &crate::models::Contract) -> Vec<String> {
    let mut ids = Vec::new();
    for function in &contract.functions {
        for stmt in &function.statements {
            collect_asset_ids_from_statement(stmt, &mut ids);
        }
    }
    ids.sort();
    ids.dedup();
    ids
}

fn collect_asset_ids_from_statement(stmt: &Statement, ids: &mut Vec<String>) {
    match stmt {
        Statement::Require(req) => {
            collect_asset_ids_from_requirement(req, ids);
        }
        Statement::IfElse { condition, then_body, else_body } => {
            collect_asset_ids_from_expression(condition, ids);
            for s in then_body {
                collect_asset_ids_from_statement(s, ids);
            }
            if let Some(else_stmts) = else_body {
                for s in else_stmts {
                    collect_asset_ids_from_statement(s, ids);
                }
            }
        }
        Statement::ForIn { body, .. } => {
            for s in body {
                collect_asset_ids_from_statement(s, ids);
            }
        }
        Statement::LetBinding { value, .. } | Statement::VarAssign { value, .. } => {
            collect_asset_ids_from_expression(value, ids);
        }
    }
}

fn collect_asset_ids_from_requirement(req: &Requirement, ids: &mut Vec<String>) {
    match req {
        Requirement::Comparison { left, op: _, right } => {
            collect_asset_ids_from_expression(left, ids);
            collect_asset_ids_from_expression(right, ids);
        }
        _ => {}
    }
}

fn collect_asset_ids_from_expression(expr: &Expression, ids: &mut Vec<String>) {
    match expr {
        Expression::AssetLookup { asset_id, .. } => {
            ids.push(asset_id.clone());
        }
        Expression::BinaryOp { left, right, .. } => {
            collect_asset_ids_from_expression(left, ids);
            collect_asset_ids_from_expression(right, ids);
        }
        Expression::GroupFind { asset_id } => {
            ids.push(asset_id.clone());
        }
        _ => {}
    }
}

/// Default array length for flattening (when not specified by numGroups or similar)
const DEFAULT_ARRAY_LENGTH: usize = 3;

/// Decompose constructor params: bytes32 params used in asset lookups become _txid + _gidx pairs
/// Array types (e.g., pubkey[]) are flattened to name_0, name_1, name_2, etc.
fn decompose_constructor_params(
    params: &[crate::models::Parameter],
    lookup_asset_ids: &[String],
) -> Vec<crate::models::Parameter> {
    let mut result = Vec::new();
    for param in params {
        if lookup_asset_ids.contains(&param.name) && param.param_type == "bytes32" {
            // Decompose into txid (bytes32) + gidx (int)
            result.push(crate::models::Parameter {
                name: format!("{}_txid", param.name),
                param_type: "bytes32".to_string(),
            });
            result.push(crate::models::Parameter {
                name: format!("{}_gidx", param.name),
                param_type: "int".to_string(),
            });
        } else if param.param_type.ends_with("[]") {
            // Array type: flatten to name_0, name_1, name_2, etc.
            let base_type = param.param_type.trim_end_matches("[]");
            for i in 0..DEFAULT_ARRAY_LENGTH {
                result.push(crate::models::Parameter {
                    name: format!("{}_{}", param.name, i),
                    param_type: base_type.to_string(),
                });
            }
        } else {
            result.push(param.clone());
        }
    }
    result
}

/// Generate a function ABI with server variant flag
///
/// For functions using introspection opcodes:
/// - Cooperative path: normal ASM + introspection + server signature
/// - Exit path: N-of-N CHECKSIG chain (pure Bitcoin) + exit timelock
///
/// For functions without introspection:
/// - Cooperative path: normal ASM + server signature
/// - Exit path: normal ASM + exit timelock
fn generate_function(
    function: &crate::models::Function,
    contract: &crate::models::Contract,
    server_variant: bool,
) -> AbiFunction {
    let uses_introspection = function_uses_introspection(function);
    let all_pubkeys = collect_all_pubkeys(contract, function);

    // Flatten array types in function inputs (e.g., signature[] → signature_0, signature_1, etc.)
    let mut function_inputs: Vec<FunctionInput> = function
        .parameters
        .iter()
        .flat_map(|param| {
            if param.param_type.ends_with("[]") {
                let base_type = param.param_type.trim_end_matches("[]");
                (0..DEFAULT_ARRAY_LENGTH)
                    .map(|i| FunctionInput {
                        name: format!("{}_{}", param.name, i),
                        param_type: base_type.to_string(),
                    })
                    .collect::<Vec<_>>()
            } else {
                vec![FunctionInput {
                    name: param.name.clone(),
                    param_type: param.param_type.clone(),
                }]
            }
        })
        .collect();

    // For exit path with introspection, add signature inputs for all constructor pubkeys
    // that aren't already in function params
    if !server_variant && uses_introspection {
        let existing_sig_names: Vec<String> = function_inputs
            .iter()
            .filter(|i| i.param_type == "signature")
            .map(|i| i.name.clone())
            .collect();

        for pk in &all_pubkeys {
            let sig_name = format!("{}Sig", pk);
            // Check if we already have a signature for this pubkey
            let has_sig = existing_sig_names.iter().any(|s| s.contains(pk) || s == &sig_name);
            if !has_sig {
                function_inputs.push(FunctionInput {
                    name: sig_name,
                    param_type: "signature".to_string(),
                });
            }
        }
    }

    let mut require = if !server_variant && uses_introspection {
        // For exit path with introspection, generate requirements for N-of-N
        let mut reqs = Vec::new();
        reqs.push(RequireStatement {
            req_type: "nOfNMultisig".to_string(),
            message: Some(format!("{}-of-{} signatures required (introspection fallback)",
                                  all_pubkeys.len(), all_pubkeys.len())),
        });
        reqs
    } else {
        generate_requirements(function)
    };

    if server_variant {
        if contract.server_key_param.is_some() {
            require.push(RequireStatement {
                req_type: "serverSignature".to_string(),
                message: None,
            });
        }
    } else if let Some(exit_timelock) = contract.exit_timelock {
        require.push(RequireStatement {
            req_type: "older".to_string(),
            message: Some(format!("Exit timelock of {} blocks", exit_timelock)),
        });
    }

    // Generate assembly instructions
    let mut asm = if !server_variant && uses_introspection {
        // Exit path with introspection: generate N-of-N CHECKSIG chain (pure Bitcoin)
        generate_nofn_checksig_asm(&all_pubkeys, function)
    } else {
        // Normal path: generate ASM from statements (includes introspection opcodes)
        generate_asm_from_statements(&function.statements)
    };

    // Add server signature or exit timelock check
    if server_variant {
        if contract.server_key_param.is_some() {
            asm.push("<SERVER_KEY>".to_string());
            asm.push("<serverSig>".to_string());
            asm.push("OP_CHECKSIG".to_string());
        }
    } else if let Some(exit_timelock) = contract.exit_timelock {
        asm.push(format!("{}", exit_timelock));
        asm.push("OP_CHECKSEQUENCEVERIFY".to_string());
        asm.push("OP_DROP".to_string());
    }

    AbiFunction {
        name: function.name.clone(),
        function_inputs,
        server_variant,
        require,
        asm,
    }
}

/// Generate N-of-N CHECKSIG chain assembly (Tapscript style)
///
/// For N pubkeys, generates pure Bitcoin script with no introspection:
/// ```text
/// <pk1> <pk1Sig> OP_CHECKSIGVERIFY
/// <pk2> <pk2Sig> OP_CHECKSIGVERIFY
/// ...
/// <pkN> <pkNSig> OP_CHECKSIG
/// ```
///
/// This is the fallback for exit paths when introspection is used.
/// All parties must agree to spend - no introspection opcodes are included.
fn generate_nofn_checksig_asm(pubkeys: &[String], _function: &Function) -> Vec<String> {
    let mut asm = Vec::new();

    // Generate ONLY N-of-N CHECKSIG chain - no original requirements
    // This is pure Bitcoin script with no Arkade-specific opcodes
    for (i, pk) in pubkeys.iter().enumerate() {
        asm.push(format!("<{}>", pk));
        asm.push(format!("<{}Sig>", pk));
        if i < pubkeys.len() - 1 {
            asm.push("OP_CHECKSIGVERIFY".to_string());
        } else {
            asm.push("OP_CHECKSIG".to_string());
        }
    }

    asm
}

/// Generate requirements from function statements
fn generate_requirements(function: &crate::models::Function) -> Vec<RequireStatement> {
    let mut requirements = Vec::new();

    // Recursively collect requirements from statements
    collect_requirements_from_statements(&function.statements, &mut requirements);

    requirements
}

fn contains_asset_lookup(expr: &Expression) -> bool {
    matches!(expr, Expression::AssetLookup { .. })
        || matches!(expr, Expression::BinaryOp { left, .. } if contains_asset_lookup(left))
}

fn contains_group_expression(expr: &Expression) -> bool {
    matches!(
        expr,
        Expression::GroupFind { .. }
            | Expression::GroupProperty { .. }
            | Expression::GroupSum { .. }
            | Expression::AssetGroupsLength
    )
}
/// Recursively collect requirements from a list of statements
fn collect_requirements_from_statements(statements: &[Statement], requirements: &mut Vec<RequireStatement>) {
    for stmt in statements {
        match stmt {
            Statement::Require(req) => {
                let req_statement = requirement_to_statement(req);
                requirements.push(req_statement);
            },
            Statement::IfElse { then_body, else_body, .. } => {
                collect_requirements_from_statements(then_body, requirements);
                if let Some(else_stmts) = else_body {
                    collect_requirements_from_statements(else_stmts, requirements);
                }
            },
            Statement::ForIn { body, .. } => {
                collect_requirements_from_statements(body, requirements);
            },
            Statement::LetBinding { .. } | Statement::VarAssign { .. } => {
                // Variable bindings and assignments don't generate requirements
            }
        }
    }
}

/// Convert a Requirement to a RequireStatement
fn requirement_to_statement(req: &Requirement) -> RequireStatement {
    match req {
        Requirement::CheckSig { .. } => {
            RequireStatement {
                req_type: "signature".to_string(),
                message: None,
            }
        },
        Requirement::CheckMultisig { .. } => {
            RequireStatement {
                req_type: "multisig".to_string(),
                message: None,
            }
        },
        Requirement::After { blocks, .. } => {
            RequireStatement {
                req_type: "older".to_string(),
                message: Some(format!("Timelock of {} blocks", blocks)),
            }
        },
        Requirement::HashEqual { .. } => {
            RequireStatement {
                req_type: "hash".to_string(),
                message: None,
            }
        },
        Requirement::Comparison { left, .. } => {
            // Detect asset-related comparisons
            let req_type = if contains_asset_lookup(left) {
                "assetCheck"
            } else if contains_group_expression(left) {
                "groupCheck"
            } else {
                "comparison"
            };
            RequireStatement {
                req_type: req_type.to_string(),
                message: None,
            }
        },
    }
}

/// Generate assembly instructions from statements
fn generate_asm_from_statements(statements: &[Statement]) -> Vec<String> {
    let mut asm = Vec::new();
    generate_asm_from_statements_recursive(statements, &mut asm);
    asm
}

/// Recursively generate assembly from statements
fn generate_asm_from_statements_recursive(statements: &[Statement], asm: &mut Vec<String>) {
    for stmt in statements {
        match stmt {
            Statement::Require(req) => {
                generate_requirement_asm(req, asm);
            },
            Statement::IfElse { condition, then_body, else_body } => {
                // Generate condition expression
                generate_expression_asm(condition, asm);
                asm.push("OP_IF".to_string());

                // Generate then branch
                generate_asm_from_statements_recursive(then_body, asm);

                // Generate else branch if present
                if let Some(else_stmts) = else_body {
                    asm.push("OP_ELSE".to_string());
                    generate_asm_from_statements_recursive(else_stmts, asm);
                }

                asm.push("OP_ENDIF".to_string());
            },
            Statement::ForIn { index_var, value_var, iterable, body } => {
                // Commit 5 & 6: Compile-time loop unrolling
                // Determine if this is iterating over tx.assetGroups or an array variable
                let is_asset_groups = match iterable {
                    Expression::Property(prop) => prop == "tx.assetGroups",
                    _ => false,
                };

                // Check if iterating over an array variable (e.g., oracleSigs)
                let array_name = match iterable {
                    Expression::Variable(name) => Some(name.clone()),
                    _ => None,
                };

                if is_asset_groups {
                    // Default to 3 iterations (can be overridden by numGroups param)
                    let num_iterations = DEFAULT_ARRAY_LENGTH;

                    for k in 0..num_iterations {
                        // Substitute loop variables and generate ASM for each iteration
                        let substituted_body = substitute_loop_body(body, index_var, value_var, k, None);
                        generate_asm_from_statements_recursive(&substituted_body, asm);
                    }
                } else if array_name.is_some() {
                    // Iterating over an array variable - unroll with array substitution
                    let num_iterations = DEFAULT_ARRAY_LENGTH;

                    for k in 0..num_iterations {
                        // Substitute loop variables and generate ASM for each iteration
                        // Pass the array name so value_var can be substituted to array_name_{k}
                        let substituted_body = substitute_loop_body(body, index_var, value_var, k, array_name.as_ref());
                        generate_asm_from_statements_recursive(&substituted_body, asm);
                    }
                } else {
                    // For other iterables, process body once (fallback)
                    generate_asm_from_statements_recursive(body, asm);
                }
            },
            Statement::LetBinding { name: _, value } => {
                // Emit the expression value onto the stack
                // TODO: Implement proper variable binding with stack tracking
                generate_expression_asm(value, asm);
            },
            Statement::VarAssign { name: _, value: _ } => {
                // TODO: Implement variable reassignment
            },
        }
    }
}

/// Generate assembly for a single requirement
fn generate_requirement_asm(req: &Requirement, asm: &mut Vec<String>) {
    match req {
        Requirement::CheckSig { signature, pubkey } => {
            asm.push(format!("<{}>", pubkey));
            asm.push(format!("<{}>", signature));
            asm.push("OP_CHECKSIG".to_string());
        },
        Requirement::CheckMultisig { signatures, pubkeys } => {
            asm.push(format!("OP_{}", pubkeys.len()));
            for pubkey in pubkeys {
                asm.push(format!("<{}>", pubkey));
            }
            asm.push(format!("OP_{}", signatures.len()));
            for signature in signatures {
                asm.push(format!("<{}>", signature));
            }
            asm.push("OP_CHECKMULTISIG".to_string());
        },
        Requirement::After { blocks, timelock_var } => {
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
            generate_comparison_asm(left, op, right, asm);
        },
    }
}

/// Generate assembly for expression (for use in if conditions)
fn generate_expression_asm(expr: &Expression, asm: &mut Vec<String>) {
    match expr {
        Expression::Variable(var) => {
            asm.push(format!("<{}>", var));
        },
        Expression::Literal(lit) => {
            asm.push(lit.clone());
        },
        Expression::Property(prop) => {
            asm.push(format!("<{}>", prop));
        },
        Expression::BinaryOp { left, op, right } => {
            generate_expression_asm(left, asm);
            generate_expression_asm(right, asm);
            match op.as_str() {
                "+" => asm.push("OP_ADD64".to_string()),
                "-" => asm.push("OP_SUB64".to_string()),
                "*" => asm.push("OP_MUL64".to_string()),
                "/" => asm.push("OP_DIV64".to_string()),
                ">=" => asm.push("OP_GREATERTHANOREQUAL64".to_string()),
                "<=" => asm.push("OP_LESSTHANOREQUAL64".to_string()),
                ">" => asm.push("OP_GREATERTHAN64".to_string()),
                "<" => asm.push("OP_LESSTHAN64".to_string()),
                "==" => asm.push("OP_EQUAL".to_string()),
                "!=" => {
                    asm.push("OP_EQUAL".to_string());
                    asm.push("OP_NOT".to_string());
                },
                _ => asm.push("OP_FALSE".to_string()),
            }
        },
        Expression::CurrentInput(property) => {
            if let Some(prop) = property {
                match prop.as_str() {
                    "scriptPubKey" => asm.push("OP_INPUTBYTECODE".to_string()),
                    "value" => asm.push("OP_INPUTVALUE".to_string()),
                    "sequence" => asm.push("OP_INPUTSEQUENCE".to_string()),
                    "outpoint" => asm.push("OP_INPUTOUTPOINT".to_string()),
                    _ => asm.push("OP_INPUTBYTECODE".to_string()),
                }
            } else {
                asm.push("OP_INPUTBYTECODE".to_string());
            }
        },
        Expression::ArrayIndex { array, index } => {
            // TODO: Implement array indexing in Commit 6
            generate_expression_asm(array, asm);
            generate_expression_asm(index, asm);
        },
        Expression::ArrayLength(_) => {
            // TODO: Implement array length in Commit 6
        },
        Expression::CheckSigExpr { signature, pubkey } => {
            asm.push(format!("<{}>", pubkey));
            asm.push(format!("<{}>", signature));
            asm.push("OP_CHECKSIG".to_string());
        },
        Expression::CheckSigFromStackExpr { signature, pubkey, message } => {
            asm.push(format!("<{}>", message));
            asm.push(format!("<{}>", pubkey));
            asm.push(format!("<{}>", signature));
            asm.push("OP_CHECKSIGFROMSTACK".to_string());
        },
        // Streaming SHA256
        Expression::Sha256Initialize { data } => {
            generate_expression_asm(data, asm);
            asm.push("OP_SHA256INITIALIZE".to_string());
        },
        Expression::Sha256Update { context, chunk } => {
            generate_expression_asm(context, asm);
            generate_expression_asm(chunk, asm);
            asm.push("OP_SHA256UPDATE".to_string());
        },
        Expression::Sha256Finalize { context, last_chunk } => {
            generate_expression_asm(context, asm);
            generate_expression_asm(last_chunk, asm);
            asm.push("OP_SHA256FINALIZE".to_string());
        },
        // Conversion & Arithmetic
        Expression::Neg64 { value } => {
            generate_expression_asm(value, asm);
            asm.push("OP_NEG64".to_string());
        },
        Expression::Le64ToScriptNum { value } => {
            generate_expression_asm(value, asm);
            asm.push("OP_LE64TOSCRIPTNUM".to_string());
        },
        Expression::Le32ToLe64 { value } => {
            generate_expression_asm(value, asm);
            asm.push("OP_LE32TOLE64".to_string());
        },
        // Crypto Opcodes
        Expression::EcMulScalarVerify { scalar, point_p, point_q } => {
            generate_expression_asm(point_q, asm);
            generate_expression_asm(point_p, asm);
            generate_expression_asm(scalar, asm);
            asm.push("OP_ECMULSCALARVERIFY".to_string());
        },
        Expression::TweakVerify { point_p, tweak, point_q } => {
            generate_expression_asm(point_q, asm);
            generate_expression_asm(tweak, asm);
            generate_expression_asm(point_p, asm);
            asm.push("OP_TWEAKVERIFY".to_string());
        },
        Expression::CheckSigFromStackVerify { signature, pubkey, message } => {
            asm.push(format!("<{}>", message));
            asm.push(format!("<{}>", pubkey));
            asm.push(format!("<{}>", signature));
            asm.push("OP_CHECKSIGFROMSTACKVERIFY".to_string());
        },
        Expression::AssetLookup { source, index, asset_id } => {
            emit_asset_lookup_asm(source, index, asset_id, asm);
        },
        Expression::AssetCount { source, index } => {
            emit_asset_count_asm(source, index, asm);
        },
        Expression::AssetAt { source, io_index, asset_index, property } => {
            emit_asset_at_asm(source, io_index, asset_index, property, asm);
        },
        Expression::TxIntrospection { property } => {
            emit_tx_introspection_asm(property, asm);
        },
        Expression::InputIntrospection { index, property } => {
            emit_input_introspection_asm(index, property, asm);
        },
        Expression::OutputIntrospection { index, property } => {
            emit_output_introspection_asm(index, property, asm);
        },
        Expression::GroupFind { asset_id } => {
            asm.push(format!("<{}_txid>", asset_id));
            asm.push(format!("<{}_gidx>", asset_id));
            asm.push("OP_FINDASSETGROUPBYASSETID".to_string());
        },
        Expression::GroupProperty { group, property } => {
            emit_group_property_asm(group, property, asm);
        },
        Expression::AssetGroupsLength => {
            asm.push("OP_INSPECTNUMASSETGROUPS".to_string());
        },
        Expression::GroupSum { index, source } => {
            generate_expression_asm(index, asm);
            match source {
                GroupSumSource::Inputs => asm.push("OP_0".to_string()),
                GroupSumSource::Outputs => asm.push("OP_1".to_string()),
            }
            asm.push("OP_INSPECTASSETGROUPSUM".to_string());
        },
    }
}

/// Generate assembly for comparison expressions
fn generate_comparison_asm(left: &Expression, op: &str, right: &Expression, asm: &mut Vec<String>) {
    match (left, op, right) {
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
                if let Some(prop) = property {
                    match prop.as_str() {
                        "scriptPubKey" => asm.push("OP_INPUTBYTECODE".to_string()),
                        "value" => asm.push("OP_INPUTVALUE".to_string()),
                        "sequence" => asm.push("OP_INPUTSEQUENCE".to_string()),
                        "outpoint" => asm.push("OP_INPUTOUTPOINT".to_string()),
                        _ => asm.push("OP_INPUTBYTECODE".to_string()),
                    }
                } else {
                    asm.push("OP_INPUTBYTECODE".to_string());
                }
            }
        },
        _ => {
            // For all other expression types, delegate to emit_comparison_asm
            emit_comparison_asm(left, op, right, asm);
        }
    }
}

/// Generate assembly instructions for a requirement (legacy function)
#[allow(dead_code)]
fn generate_base_asm_instructions(requirements: &[Requirement]) -> Vec<String> {
    let mut asm = Vec::new();

    for req in requirements {
        match req {
            Requirement::CheckSig { signature, pubkey } => {
                asm.push(format!("<{}>", pubkey));
                asm.push(format!("<{}>", signature));
                asm.push("OP_CHECKSIG".to_string());
            }
            Requirement::CheckMultisig {
                signatures,
                pubkeys,
            } => {
                asm.push(format!("OP_{}", pubkeys.len()));
                for pubkey in pubkeys {
                    asm.push(format!("<{}>", pubkey));
                }
                asm.push(format!("OP_{}", signatures.len()));
                for signature in signatures {
                    asm.push(format!("<{}>", signature));
                }
                asm.push("OP_CHECKMULTISIG".to_string());
            }
            Requirement::After {
                blocks,
                timelock_var,
            } => {
                if let Some(var) = timelock_var {
                    asm.push(format!("<{}>", var));
                } else {
                    asm.push(format!("{}", blocks));
                }
                asm.push("OP_CHECKLOCKTIMEVERIFY".to_string());
                asm.push("OP_DROP".to_string());
            }
            Requirement::HashEqual { preimage, hash } => {
                asm.push(format!("<{}>", preimage));
                asm.push("OP_SHA256".to_string());
                asm.push(format!("<{}>", hash));
                asm.push("OP_EQUAL".to_string());
            }
            Requirement::Comparison { left, op, right } => {
                emit_comparison_asm(left, op, right, &mut asm);
            }
        }
    }

    asm
}

/// Emit assembly for a comparison requirement.
///
/// Handles both simple comparisons (variable/literal/property) and complex
/// expressions involving asset lookups and 64-bit arithmetic.
fn emit_comparison_asm(left: &Expression, op: &str, right: &Expression, asm: &mut Vec<String>) {
    // Special case: CurrentInput introspection (dummy comparison from parser)
    if let Expression::CurrentInput(property) = left {
        emit_current_input_asm(property.as_deref(), asm);
        return;
    }

    // Special case: standalone property/function call introspection (dummy comparison)
    if op == "==" {
        if let Expression::Literal(val) = right {
            if val == "true" {
                // This is a dummy comparison wrapping an introspection expression
                emit_expression_asm(left, asm);
                return;
            }
        }
    }

    // Determine if this comparison involves 64-bit values (asset lookups, group sums)
    let is_64bit = is_64bit_expression(left) || is_64bit_expression(right);

    // Emit left operand
    emit_expression_asm(left, asm);

    // Emit right operand
    emit_expression_asm(right, asm);

    // Emit comparison operator (correct Bitcoin Script order: left, right, op)
    if is_64bit {
        emit_comparison_op_64(op, asm);
    } else {
        emit_comparison_op(op, asm);
    }
}

/// Check if an expression produces a 64-bit (u64le) value
fn is_64bit_expression(expr: &Expression) -> bool {
    match expr {
        Expression::AssetLookup { .. } => true,
        Expression::GroupSum { .. } => true,
        // AssetAt with "amount" property returns u64
        Expression::AssetAt { property, .. } => property == "amount",
        // Input/Output "value" property returns u64
        Expression::InputIntrospection { property, .. } => property == "value",
        Expression::OutputIntrospection { property, .. } => property == "value",
        Expression::BinaryOp { left, right, .. } => {
            is_64bit_expression(left) || is_64bit_expression(right)
        }
        _ => false,
    }
}

/// Emit assembly for an expression (push its value onto the stack)
fn emit_expression_asm(expr: &Expression, asm: &mut Vec<String>) {
    match expr {
        Expression::Variable(var) => {
            asm.push(format!("<{}>", var));
        }
        Expression::Literal(lit) => {
            asm.push(lit.clone());
        }
        Expression::Property(prop) => {
            asm.push(format!("<{}>", prop));
        }
        Expression::CurrentInput(property) => {
            emit_current_input_asm(property.as_deref(), asm);
        }
        Expression::AssetLookup {
            source,
            index,
            asset_id,
        } => {
            emit_asset_lookup_asm(source, index, asset_id, asm);
        }
        Expression::AssetCount { source, index } => {
            emit_asset_count_asm(source, index, asm);
        }
        Expression::AssetAt { source, io_index, asset_index, property } => {
            emit_asset_at_asm(source, io_index, asset_index, property, asm);
        }
        Expression::TxIntrospection { property } => {
            emit_tx_introspection_asm(property, asm);
        }
        Expression::InputIntrospection { index, property } => {
            emit_input_introspection_asm(index, property, asm);
        }
        Expression::OutputIntrospection { index, property } => {
            emit_output_introspection_asm(index, property, asm);
        }
        Expression::BinaryOp { left, op, right } => {
            emit_binary_op_asm(left, op, right, asm);
        }
        Expression::GroupFind { asset_id } => {
            // tx.assetGroups.find(assetId) → OP_FINDASSETGROUPBYASSETID
            asm.push(format!("<{}_txid>", asset_id));
            asm.push(format!("<{}_gidx>", asset_id));
            asm.push("OP_FINDASSETGROUPBYASSETID".to_string());
        }
        Expression::GroupProperty { group, property } => {
            emit_group_property_asm(group, property, asm);
        }
        Expression::AssetGroupsLength => {
            asm.push("OP_INSPECTNUMASSETGROUPS".to_string());
        }
        Expression::GroupSum { index, source } => {
            emit_expression_asm(index, asm);
            match source {
                GroupSumSource::Inputs => asm.push("OP_0".to_string()),
                GroupSumSource::Outputs => asm.push("OP_1".to_string()),
            }
            asm.push("OP_INSPECTASSETGROUPSUM".to_string());
        }
        Expression::ArrayIndex { array, index } => {
            // TODO: Implement array indexing in Commit 6
            emit_expression_asm(array, asm);
            emit_expression_asm(index, asm);
        }
        Expression::ArrayLength(_) => {
            // TODO: Implement array length in Commit 6
        }
        Expression::CheckSigExpr { signature, pubkey } => {
            asm.push(format!("<{}>", pubkey));
            asm.push(format!("<{}>", signature));
            asm.push("OP_CHECKSIG".to_string());
        }
        Expression::CheckSigFromStackExpr { signature, pubkey, message } => {
            asm.push(format!("<{}>", message));
            asm.push(format!("<{}>", pubkey));
            asm.push(format!("<{}>", signature));
            asm.push("OP_CHECKSIGFROMSTACK".to_string());
        }
        // Streaming SHA256
        Expression::Sha256Initialize { data } => {
            emit_expression_asm(data, asm);
            asm.push("OP_SHA256INITIALIZE".to_string());
        }
        Expression::Sha256Update { context, chunk } => {
            emit_expression_asm(context, asm);
            emit_expression_asm(chunk, asm);
            asm.push("OP_SHA256UPDATE".to_string());
        }
        Expression::Sha256Finalize { context, last_chunk } => {
            emit_expression_asm(context, asm);
            emit_expression_asm(last_chunk, asm);
            asm.push("OP_SHA256FINALIZE".to_string());
        }
        // Conversion & Arithmetic
        Expression::Neg64 { value } => {
            emit_expression_asm(value, asm);
            asm.push("OP_NEG64".to_string());
        }
        Expression::Le64ToScriptNum { value } => {
            emit_expression_asm(value, asm);
            asm.push("OP_LE64TOSCRIPTNUM".to_string());
        }
        Expression::Le32ToLe64 { value } => {
            emit_expression_asm(value, asm);
            asm.push("OP_LE32TOLE64".to_string());
        }
        // Crypto Opcodes
        Expression::EcMulScalarVerify { scalar, point_p, point_q } => {
            emit_expression_asm(point_q, asm);
            emit_expression_asm(point_p, asm);
            emit_expression_asm(scalar, asm);
            asm.push("OP_ECMULSCALARVERIFY".to_string());
        }
        Expression::TweakVerify { point_p, tweak, point_q } => {
            emit_expression_asm(point_q, asm);
            emit_expression_asm(tweak, asm);
            emit_expression_asm(point_p, asm);
            asm.push("OP_TWEAKVERIFY".to_string());
        }
        Expression::CheckSigFromStackVerify { signature, pubkey, message } => {
            asm.push(format!("<{}>", message));
            asm.push(format!("<{}>", pubkey));
            asm.push(format!("<{}>", signature));
            asm.push("OP_CHECKSIGFROMSTACKVERIFY".to_string());
        }
    }
}

/// Emit assembly for tx.input.current property access
fn emit_current_input_asm(property: Option<&str>, asm: &mut Vec<String>) {
    match property {
        Some("scriptPubKey") => {
            asm.push("OP_PUSHCURRENTINPUTINDEX".to_string());
            asm.push("OP_INSPECTINPUTSCRIPTPUBKEY".to_string());
        }
        Some("value") => {
            asm.push("OP_PUSHCURRENTINPUTINDEX".to_string());
            asm.push("OP_INSPECTINPUTVALUE".to_string());
        }
        Some("sequence") => {
            asm.push("OP_PUSHCURRENTINPUTINDEX".to_string());
            asm.push("OP_INSPECTINPUTSEQUENCE".to_string());
        }
        Some("outpoint") => {
            asm.push("OP_PUSHCURRENTINPUTINDEX".to_string());
            asm.push("OP_INSPECTINPUTOUTPOINT".to_string());
        }
        _ => {
            asm.push("OP_PUSHCURRENTINPUTINDEX".to_string());
            asm.push("OP_INSPECTINPUTSCRIPTPUBKEY".to_string());
        }
    }
}

/// Emit assembly for an asset lookup: tx.inputs[i].assets.lookup(assetId)
///
/// Emits the lookup opcode followed by sentinel guard pattern.
/// The sentinel guard verifies the result is not -1 (asset not found).
fn emit_asset_lookup_asm(
    source: &AssetLookupSource,
    index: &Expression,
    asset_id: &str,
    asm: &mut Vec<String>,
) {
    // Push the index
    emit_expression_asm(index, asm);

    // Push decomposed asset ID (txid + gidx)
    asm.push(format!("<{}_txid>", asset_id));
    asm.push(format!("<{}_gidx>", asset_id));

    // Emit the appropriate lookup opcode
    match source {
        AssetLookupSource::Input => {
            asm.push("OP_INSPECTINASSETLOOKUP".to_string());
        }
        AssetLookupSource::Output => {
            asm.push("OP_INSPECTOUTASSETLOOKUP".to_string());
        }
    }

    // Sentinel guard: verify result is not -1 (asset not found)
    asm.push("OP_DUP".to_string());
    asm.push("OP_1NEGATE".to_string());
    asm.push("OP_EQUAL".to_string());
    asm.push("OP_NOT".to_string());
    asm.push("OP_VERIFY".to_string());
}

/// Emit assembly for asset count: tx.inputs[i].assets.length or tx.outputs[o].assets.length
///
/// Pushes the count of assets at the given input/output index.
fn emit_asset_count_asm(
    source: &AssetLookupSource,
    index: &Expression,
    asm: &mut Vec<String>,
) {
    // Push the index
    emit_expression_asm(index, asm);

    // Emit the appropriate count opcode
    match source {
        AssetLookupSource::Input => {
            asm.push("OP_INSPECTINASSETCOUNT".to_string());
        }
        AssetLookupSource::Output => {
            asm.push("OP_INSPECTOUTASSETCOUNT".to_string());
        }
    }
}

/// Emit assembly for indexed asset access: tx.inputs[i].assets[t].property
///
/// OP_INSPECTINASSETAT / OP_INSPECTOUTASSETAT returns: txid32, gidx_u16, amount_u64
/// We extract based on the property requested.
fn emit_asset_at_asm(
    source: &AssetLookupSource,
    io_index: &Expression,
    asset_index: &Expression,
    property: &str,
    asm: &mut Vec<String>,
) {
    // Push io_index
    emit_expression_asm(io_index, asm);

    // Push asset_index
    emit_expression_asm(asset_index, asm);

    // Emit the appropriate opcode
    match source {
        AssetLookupSource::Input => {
            asm.push("OP_INSPECTINASSETAT".to_string());
        }
        AssetLookupSource::Output => {
            asm.push("OP_INSPECTOUTASSETAT".to_string());
        }
    }

    // Stack after opcode: txid32, gidx_u16, amount_u64 (top)
    // Extract based on property
    match property {
        "assetId" => {
            // Drop the amount, keep txid32 and gidx_u16
            asm.push("OP_DROP".to_string());
        }
        "amount" => {
            // Keep only the amount (top of stack)
            // NIP removes the second item from the top
            asm.push("OP_NIP".to_string()); // Remove gidx_u16
            asm.push("OP_NIP".to_string()); // Remove txid32
        }
        _ => {
            // Unknown property, leave stack as-is
        }
    }
}

/// Emit assembly for transaction introspection: tx.version, tx.locktime, etc.
fn emit_tx_introspection_asm(property: &str, asm: &mut Vec<String>) {
    match property {
        "version" => asm.push("OP_INSPECTVERSION".to_string()),
        "locktime" => asm.push("OP_INSPECTLOCKTIME".to_string()),
        "numInputs" => asm.push("OP_INSPECTNUMINPUTS".to_string()),
        "numOutputs" => asm.push("OP_INSPECTNUMOUTPUTS".to_string()),
        "weight" => asm.push("OP_TXWEIGHT".to_string()),
        _ => {
            // Unknown property, emit as placeholder
            asm.push(format!("<tx.{}>", property));
        }
    }
}

/// Emit assembly for input introspection: tx.inputs[i].property
fn emit_input_introspection_asm(index: &Expression, property: &str, asm: &mut Vec<String>) {
    // Push the index
    emit_expression_asm(index, asm);

    // Emit the appropriate opcode
    match property {
        "value" => asm.push("OP_INSPECTINPUTVALUE".to_string()),
        "scriptPubKey" => asm.push("OP_INSPECTINPUTSCRIPTPUBKEY".to_string()),
        "sequence" => asm.push("OP_INSPECTINPUTSEQUENCE".to_string()),
        "outpoint" => asm.push("OP_INSPECTINPUTOUTPOINT".to_string()),
        "issuance" => asm.push("OP_INSPECTINPUTISSUANCE".to_string()),
        _ => {
            // Unknown property, emit as placeholder
            asm.push(format!("<tx.inputs[?].{}>", property));
        }
    }
}

/// Emit assembly for output introspection: tx.outputs[o].property
fn emit_output_introspection_asm(index: &Expression, property: &str, asm: &mut Vec<String>) {
    // Push the index
    emit_expression_asm(index, asm);

    // Emit the appropriate opcode
    match property {
        "value" => asm.push("OP_INSPECTOUTPUTVALUE".to_string()),
        "scriptPubKey" => asm.push("OP_INSPECTOUTPUTSCRIPTPUBKEY".to_string()),
        "nonce" => asm.push("OP_INSPECTOUTPUTNONCE".to_string()),
        _ => {
            // Unknown property, emit as placeholder
            asm.push(format!("<tx.outputs[?].{}>", property));
        }
    }
}

/// Emit assembly for a binary arithmetic operation (64-bit)
fn emit_binary_op_asm(left: &Expression, op: &str, right: &Expression, asm: &mut Vec<String>) {
    // Emit left operand
    emit_expression_asm(left, asm);

    // Convert to u64le if needed (witness inputs arrive as csn)
    if needs_u64_conversion(left) {
        asm.push("OP_SCRIPTNUMTOLE64".to_string());
    }

    // Emit right operand
    emit_expression_asm(right, asm);

    // Convert to u64le if needed
    if needs_u64_conversion(right) {
        asm.push("OP_SCRIPTNUMTOLE64".to_string());
    }

    // Emit 64-bit arithmetic opcode + overflow verify
    match op {
        "+" => {
            asm.push("OP_ADD64".to_string());
            asm.push("OP_VERIFY".to_string());
        }
        "-" => {
            asm.push("OP_SUB64".to_string());
            asm.push("OP_VERIFY".to_string());
        }
        "*" => {
            asm.push("OP_MUL64".to_string());
            asm.push("OP_VERIFY".to_string());
        }
        "/" => {
            asm.push("OP_DIV64".to_string());
            asm.push("OP_VERIFY".to_string());
        }
        _ => {
            asm.push(format!("OP_{}", op.to_uppercase()));
        }
    }
}

/// Check if an expression needs csn→u64le conversion for 64-bit arithmetic
fn needs_u64_conversion(expr: &Expression) -> bool {
    match expr {
        // Variables (witness inputs) arrive as CScriptNum
        Expression::Variable(_) => true,
        // Literals are emitted as-is (caller should provide 8-byte LE)
        Expression::Literal(_) => false,
        // Asset lookups already produce u64le
        Expression::AssetLookup { .. } => false,
        // Asset count produces CScriptNum
        Expression::AssetCount { .. } => false,
        // AssetAt "amount" produces u64le, "assetId" produces (txid32, gidx_u16)
        Expression::AssetAt { property, .. } => property != "amount",
        // Group sums already produce u64le
        Expression::GroupSum { .. } => false,
        // Binary ops produce u64le
        Expression::BinaryOp { .. } => false,
        // Properties depend on context
        Expression::Property(_) => false,
        _ => false,
    }
}

/// Emit assembly for group property access
fn emit_group_property_asm(group: &str, property: &str, asm: &mut Vec<String>) {
    match property {
        "sumInputs" => {
            asm.push(format!("<{}>", group));
            asm.push("OP_0".to_string()); // source=inputs
            asm.push("OP_INSPECTASSETGROUPSUM".to_string());
        }
        "sumOutputs" => {
            asm.push(format!("<{}>", group));
            asm.push("OP_1".to_string()); // source=outputs
            asm.push("OP_INSPECTASSETGROUPSUM".to_string());
        }
        "delta" => {
            // delta = sumOutputs - sumInputs
            asm.push(format!("<{}>", group));
            asm.push("OP_1".to_string());
            asm.push("OP_INSPECTASSETGROUPSUM".to_string());
            asm.push(format!("<{}>", group));
            asm.push("OP_0".to_string());
            asm.push("OP_INSPECTASSETGROUPSUM".to_string());
            asm.push("OP_SUB64".to_string());
            asm.push("OP_VERIFY".to_string());
        }
        "control" => {
            asm.push(format!("<{}>", group));
            asm.push("OP_INSPECTASSETGROUPCTRL".to_string());
        }
        "metadataHash" => {
            asm.push(format!("<{}>", group));
            asm.push("OP_INSPECTASSETGROUPMETADATAHASH".to_string());
        }
        "assetId" => {
            // Returns (txid32, gidx_u16) tuple on stack
            asm.push(format!("<{}>", group));
            asm.push("OP_INSPECTASSETGROUPASSETID".to_string());
        }
        "isFresh" => {
            // isFresh: compares assetId.txid with current transaction's txid
            // 1. Get group's assetId (returns txid32, gidx_u16)
            asm.push(format!("<{}>", group));
            asm.push("OP_INSPECTASSETGROUPASSETID".to_string());
            // 2. Drop gidx_u16, keep txid32
            asm.push("OP_DROP".to_string());
            // 3. Get current transaction hash
            asm.push("OP_TXHASH".to_string());
            // 4. Compare txids - result is bool
            asm.push("OP_EQUAL".to_string());
        }
        _ => {
            // Unknown group property
            asm.push(format!("<{}.{}>", group, property));
        }
    }
}

/// Emit standard comparison operator (CScriptNum / non-64-bit)
fn emit_comparison_op(op: &str, asm: &mut Vec<String>) {
    match op {
        "==" => asm.push("OP_EQUAL".to_string()),
        "!=" => {
            asm.push("OP_EQUAL".to_string());
            asm.push("OP_NOT".to_string());
        }
        ">=" => asm.push("OP_GREATERTHANOREQUAL".to_string()),
        ">" => asm.push("OP_GREATERTHAN".to_string()),
        "<=" => asm.push("OP_LESSTHANOREQUAL".to_string()),
        "<" => asm.push("OP_LESSTHAN".to_string()),
        _ => asm.push(format!("OP_{}", op)),
    }
}

/// Emit 64-bit comparison operator (u64le operands)
fn emit_comparison_op_64(op: &str, asm: &mut Vec<String>) {
    match op {
        "==" => {
            asm.push("OP_EQUAL".to_string());
            asm.push("OP_VERIFY".to_string());
        }
        "!=" => {
            asm.push("OP_EQUAL".to_string());
            asm.push("OP_NOT".to_string());
            asm.push("OP_VERIFY".to_string());
        }
        ">=" => {
            asm.push("OP_GREATERTHANOREQUAL64".to_string());
            asm.push("OP_VERIFY".to_string());
        }
        ">" => {
            asm.push("OP_GREATERTHAN64".to_string());
            asm.push("OP_VERIFY".to_string());
        }
        "<=" => {
            asm.push("OP_LESSTHANOREQUAL64".to_string());
            asm.push("OP_VERIFY".to_string());
        }
        "<" => {
            asm.push("OP_LESSTHAN64".to_string());
            asm.push("OP_VERIFY".to_string());
        }
        _ => {
            asm.push(format!("OP_{}", op));
            asm.push("OP_VERIFY".to_string());
        }
    }
}

// ─── Loop Unrolling (Commit 5 & 6) ──────────────────────────────────────────────

/// Substitute loop variables in the body for a specific iteration index k.
///
/// Transforms:
/// - `GroupProperty { group: value_var, property: "sumOutputs" }` → `GroupSum { index: k, source: Outputs }`
/// - `GroupProperty { group: value_var, property: "sumInputs" }` → `GroupSum { index: k, source: Inputs }`
/// - `Variable(index_var)` → `Literal(k)`
/// - `Variable(value_var)` when array_name is Some → `Variable("array_name_{k}")`
/// - Array indexing `arr[index_var]` → `Variable("arr_{k}")`
fn substitute_loop_body(body: &[Statement], index_var: &str, value_var: &str, k: usize, array_name: Option<&String>) -> Vec<Statement> {
    body.iter()
        .map(|stmt| substitute_statement(stmt, index_var, value_var, k, array_name))
        .collect()
}

fn substitute_statement(stmt: &Statement, index_var: &str, value_var: &str, k: usize, array_name: Option<&String>) -> Statement {
    match stmt {
        Statement::Require(req) => {
            Statement::Require(substitute_requirement(req, index_var, value_var, k, array_name))
        }
        Statement::LetBinding { name, value } => {
            Statement::LetBinding {
                name: name.clone(),
                value: substitute_expression(value, index_var, value_var, k, array_name),
            }
        }
        Statement::VarAssign { name, value } => {
            Statement::VarAssign {
                name: name.clone(),
                value: substitute_expression(value, index_var, value_var, k, array_name),
            }
        }
        Statement::IfElse { condition, then_body, else_body } => {
            Statement::IfElse {
                condition: substitute_expression(condition, index_var, value_var, k, array_name),
                then_body: substitute_loop_body(then_body, index_var, value_var, k, array_name),
                else_body: else_body.as_ref().map(|b| substitute_loop_body(b, index_var, value_var, k, array_name)),
            }
        }
        Statement::ForIn { index_var: inner_idx, value_var: inner_val, iterable, body } => {
            // Nested loops: substitute in iterable, leave inner variables alone
            Statement::ForIn {
                index_var: inner_idx.clone(),
                value_var: inner_val.clone(),
                iterable: substitute_expression(iterable, index_var, value_var, k, array_name),
                body: body.clone(), // Inner loop body keeps its own variables
            }
        }
    }
}

fn substitute_requirement(req: &Requirement, index_var: &str, value_var: &str, k: usize, array_name: Option<&String>) -> Requirement {
    match req {
        Requirement::Comparison { left, op, right } => {
            Requirement::Comparison {
                left: substitute_expression(left, index_var, value_var, k, array_name),
                op: op.clone(),
                right: substitute_expression(right, index_var, value_var, k, array_name),
            }
        }
        Requirement::CheckSig { signature, pubkey } => {
            // Substitute signature and pubkey if they match loop variables
            let new_sig = if signature == value_var {
                if let Some(arr) = array_name {
                    format!("{}_{}", arr, k)
                } else {
                    signature.clone()
                }
            } else {
                signature.clone()
            };
            let new_pk = pubkey.clone();
            Requirement::CheckSig { signature: new_sig, pubkey: new_pk }
        }
        // Other requirement types don't need substitution
        _ => req.clone(),
    }
}

fn substitute_expression(expr: &Expression, index_var: &str, value_var: &str, k: usize, array_name: Option<&String>) -> Expression {
    match expr {
        // Replace index variable with literal k
        Expression::Variable(var) if var == index_var => {
            Expression::Literal(k.to_string())
        }
        // Replace value_var with array_name_{k} when iterating over arrays
        Expression::Variable(var) if var == value_var && array_name.is_some() => {
            Expression::Variable(format!("{}_{}", array_name.unwrap(), k))
        }
        // Replace value_var.property with appropriate indexed expression
        Expression::GroupProperty { group, property } if group == value_var => {
            match property.as_str() {
                "sumInputs" => Expression::GroupSum {
                    index: Box::new(Expression::Literal(k.to_string())),
                    source: GroupSumSource::Inputs,
                },
                "sumOutputs" => Expression::GroupSum {
                    index: Box::new(Expression::Literal(k.to_string())),
                    source: GroupSumSource::Outputs,
                },
                // For delta, control, isFresh, assetId, metadataHash - replace group name with index literal
                _ => Expression::GroupProperty {
                    group: k.to_string(),
                    property: property.clone(),
                },
            }
        }
        // Handle array indexing: arr[index_var] → Variable("arr_{k}")
        Expression::ArrayIndex { array, index } => {
            // Check if the index is the loop index variable
            if let Expression::Variable(idx_name) = index.as_ref() {
                if idx_name == index_var {
                    // Get the array name
                    if let Expression::Variable(arr_name) = array.as_ref() {
                        return Expression::Variable(format!("{}_{}", arr_name, k));
                    }
                }
            }
            // Recursively substitute in array and index
            Expression::ArrayIndex {
                array: Box::new(substitute_expression(array, index_var, value_var, k, array_name)),
                index: Box::new(substitute_expression(index, index_var, value_var, k, array_name)),
            }
        }
        // Handle Property expressions that look like array indexing (e.g., "oracles[i]")
        Expression::Property(prop) => {
            // Check if this looks like array indexing
            if let Some(bracket_start) = prop.find('[') {
                if let Some(bracket_end) = prop.find(']') {
                    let arr_name = &prop[..bracket_start];
                    let idx = &prop[bracket_start + 1..bracket_end];
                    if idx == index_var {
                        return Expression::Variable(format!("{}_{}", arr_name, k));
                    }
                }
            }
            expr.clone()
        }
        // Recursively substitute in binary operations
        Expression::BinaryOp { left, op, right } => {
            Expression::BinaryOp {
                left: Box::new(substitute_expression(left, index_var, value_var, k, array_name)),
                op: op.clone(),
                right: Box::new(substitute_expression(right, index_var, value_var, k, array_name)),
            }
        }
        // Handle CheckSigFromStackExpr
        Expression::CheckSigFromStackExpr { signature, pubkey, message } => {
            let new_sig = if signature == value_var {
                if let Some(arr) = array_name {
                    format!("{}_{}", arr, k)
                } else {
                    signature.clone()
                }
            } else {
                signature.clone()
            };
            // Check if pubkey is an array indexed expression (string form)
            let new_pk = if pubkey.contains('[') && pubkey.contains(']') {
                if let Some(bracket_start) = pubkey.find('[') {
                    if let Some(bracket_end) = pubkey.find(']') {
                        let arr_name = &pubkey[..bracket_start];
                        let idx = &pubkey[bracket_start + 1..bracket_end];
                        if idx == index_var {
                            format!("{}_{}", arr_name, k)
                        } else {
                            pubkey.clone()
                        }
                    } else {
                        pubkey.clone()
                    }
                } else {
                    pubkey.clone()
                }
            } else {
                pubkey.clone()
            };
            Expression::CheckSigFromStackExpr {
                signature: new_sig,
                pubkey: new_pk,
                message: message.clone()
            }
        }
        // Handle CheckSigExpr
        Expression::CheckSigExpr { signature, pubkey } => {
            let new_sig = if signature == value_var {
                if let Some(arr) = array_name {
                    format!("{}_{}", arr, k)
                } else {
                    signature.clone()
                }
            } else {
                signature.clone()
            };
            Expression::CheckSigExpr {
                signature: new_sig,
                pubkey: pubkey.clone()
            }
        }
        // Handle InputIntrospection - substitute index if it matches loop variable
        Expression::InputIntrospection { index, property } => {
            Expression::InputIntrospection {
                index: Box::new(substitute_expression(index, index_var, value_var, k, array_name)),
                property: property.clone(),
            }
        }
        // Handle OutputIntrospection - substitute index if it matches loop variable
        Expression::OutputIntrospection { index, property } => {
            Expression::OutputIntrospection {
                index: Box::new(substitute_expression(index, index_var, value_var, k, array_name)),
                property: property.clone(),
            }
        }
        // All other expressions are returned as-is
        _ => expr.clone(),
    }
}
