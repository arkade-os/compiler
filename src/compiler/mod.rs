use crate::models::{
    Requirement, Expression, Statement, ContractJson, AbiFunction, FunctionInput,
    RequireStatement, CompilerInfo, AssetLookupSource, GroupSumSource,
};
use crate::parser;
use chrono::Utc;

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

    // Validate server key parameter exists in contract parameters
    if let Some(ref server_key) = contract.server_key_param {
        if !contract.parameters.iter().any(|p| p.name == *server_key) {
            return Err(format!(
                "Server key parameter '{}' not found in contract parameters",
                server_key
            ));
        }
    }

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

/// Decompose constructor params: bytes32 params used in asset lookups become _txid + _gidx pairs
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
        } else {
            result.push(param.clone());
        }
    }
    result
}

/// Generate a function ABI with server variant flag
fn generate_function(
    function: &crate::models::Function,
    contract: &crate::models::Contract,
    server_variant: bool,
) -> AbiFunction {
    let function_inputs = function
        .parameters
        .iter()
        .map(|param| FunctionInput {
            name: param.name.clone(),
            param_type: param.param_type.clone(),
        })
        .collect();

    let mut require = generate_requirements(function);

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

    // Generate assembly instructions from statements
    let mut asm = generate_asm_from_statements(&function.statements);

    // Add server signature or exit timelock check
    if server_variant {
        if contract.server_key_param.is_some() {
            asm.push("<SERVER_KEY>".to_string());
            asm.push("<serverSig>".to_string());
            asm.push("OP_CHECKSIG".to_string());
        }
    } else if let Some(exit_timelock) = contract.exit_timelock {
        asm.push(format!("{}", exit_timelock));
        asm.push("OP_CHECKLOCKTIMEVERIFY".to_string());
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
            Statement::ForIn { index_var: _, value_var: _, iterable: _, body: _ } => {
                // TODO: Implement loop unrolling in Commit 5
                // For now, just process the body as if it were inline
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
        Expression::AssetLookup { source, index, asset_id } => {
            emit_asset_lookup_asm(source, index, asset_id, asm);
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
            asm.push(format!("<{}>", group));
            asm.push("OP_INSPECTASSETGROUPASSETID".to_string());
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
