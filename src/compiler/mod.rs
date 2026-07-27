use crate::models::{
    ArkadeCovenant, CompilerInfo, ContractJson, Expression, Function, FunctionInput, Parameter,
    Requirement, Statement, DEFAULT_ARRAY_LENGTH,
};
use crate::opcodes::{
    OP_0, OP_1, OP_8, OP_ADD, OP_BIN2NUM, OP_BOOLAND, OP_CAT, OP_CHECKLOCKTIMEVERIFY, OP_CHECKSIG,
    OP_CHECKSIGADD, OP_CHECKSIGFROMSTACK, OP_DIV, OP_DROP, OP_ECMULSCALARVERIFY, OP_ELSE, OP_ENDIF,
    OP_EQUAL, OP_EQUALVERIFY, OP_FINDASSETGROUPBYASSETID, OP_GREATERTHAN, OP_GREATERTHANOREQUAL,
    OP_IF, OP_INSPECTASSETGROUP, OP_INSPECTASSETGROUPASSETID, OP_INSPECTASSETGROUPCTRL,
    OP_INSPECTASSETGROUPMETADATAHASH, OP_INSPECTASSETGROUPNUM, OP_INSPECTASSETGROUPSUM,
    OP_INSPECTINASSETAT, OP_INSPECTINASSETCOUNT, OP_INSPECTINASSETLOOKUP,
    OP_INSPECTINPUTARKADESCRIPTHASH, OP_INSPECTINPUTARKADEWITNESSHASH, OP_INSPECTINPUTOUTPOINT,
    OP_INSPECTINPUTPACKET, OP_INSPECTINPUTSCRIPTPUBKEY, OP_INSPECTINPUTSEQUENCE,
    OP_INSPECTINPUTVALUE, OP_INSPECTLOCKTIME, OP_INSPECTNUMASSETGROUPS, OP_INSPECTNUMINPUTS,
    OP_INSPECTNUMOUTPUTS, OP_INSPECTOUTASSETAT, OP_INSPECTOUTASSETCOUNT, OP_INSPECTOUTASSETLOOKUP,
    OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_INSPECTOUTPUTVALUE, OP_INSPECTPACKET, OP_INSPECTVERSION,
    OP_LESSTHAN, OP_LESSTHANOREQUAL, OP_MODEXP, OP_MUL, OP_NEGATE, OP_NIP, OP_NOT, OP_NUM2BIN,
    OP_NUMEQUAL, OP_PUSHCURRENTINPUTINDEX, OP_REVERSEBYTES, OP_SHA256, OP_SHA256FINALIZE,
    OP_SHA256INITIALIZE, OP_SHA256UPDATE, OP_SIZE, OP_SUB, OP_SUBSTR, OP_SWAP, OP_TWEAKVERIFY,
    OP_TXID, OP_TXWEIGHT, OP_VERIFY,
};
use crate::parser;
use crate::typechecker::{self};
use crate::validator::{self, Severity};
use chrono::Utc;

pub mod tapscript;

// ASM codegen and rewrite passes split into submodules;
// siblings reach each other via `use super::*`.
mod asset;
mod comparison;
mod concat;
mod expr;
mod introspection;
mod loops;

pub(crate) use asset::*;
pub(crate) use comparison::*;
pub(crate) use concat::*;
pub(crate) use expr::*;
pub(crate) use introspection::*;
pub(crate) use loops::*;

fn strip_comments(source: &str) -> String {
    source
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with("//") {
                None
            } else if let Some(idx) = line.find("//") {
                let without_comment = line[..idx].trim_end();
                Some(without_comment.to_string())
            } else {
                Some(line.to_string())
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Compiles an Arkade Script contract into a JSON-serializable structure.
///
/// Takes source code, parses it into an AST, and transforms it into a ContractJson
/// structure. The output includes contract name, constructor inputs (with asset ID
/// decomposition for lookup parameters), spend groups, optional arkade covenants,
/// and L1 tapleaf assemblies.
///
/// # Arguments
///
/// * `source_code` - The Arkade Script source code
///
/// # Returns
///
/// A Result containing a ContractJson or an error message
pub fn compile(source_code: &str) -> Result<ContractJson, String> {
    let mut contract = match parser::parse(source_code) {
        Ok(contract) => contract,
        Err(e) => return Err(format!("Parse error: {}", e)),
    };

    // ── Semantic validation ────────────────────────────────────────────────
    // Catch errors the PEG grammar cannot express (duplicate names, missing
    // timelocks, etc.) before we attempt code generation.
    let ast_issues = validator::validate_ast(&contract);
    if validator::has_errors(&ast_issues) {
        let errors: Vec<String> = ast_issues
            .iter()
            .filter(|i| matches!(i.severity, Severity::Error))
            .map(|i| format!("validation error: {}", i.message))
            .collect();
        return Err(errors.join("; "));
    }

    // ── Rewrite pass: route `+` to OP_CAT when operands are bytes-like ─────
    rewrite_concat_ops(&mut contract);

    // ── Type checking ──────────────────────────────────────────────────────
    // Run the type checker. Errors are non-fatal and returned as warnings on
    // ContractJson so callers (CLI, WASM, tests) can surface them as they see fit.
    let type_errors = typechecker::check_contract(&contract);
    let mut warnings: Vec<String> = type_errors
        .iter()
        .map(|e| format!("warning[type]: {}", e.message))
        .collect();

    // Append any non-fatal validation warnings (e.g. renew=0)
    for issue in &ast_issues {
        if matches!(issue.severity, Severity::Warning) {
            warnings.push(format!("warning[validation]: {}", issue.message));
        }
    }

    // Build constructor inputs (array params expand to indexed scalars).
    let parameters = expand_abi_params(&contract.parameters);

    let mut json = ContractJson {
        name: contract.name.clone(),
        parameters,
        functions: Vec::new(),
        source: Some(strip_comments(source_code)),
        compiler: Some(CompilerInfo {
            name: "arkade-compiler".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }),
        updated_at: Some(Utc::now().to_rfc3339()),
        warnings,
    };

    // Build covenant objects for non-internal functions.
    let mut covenants: std::collections::HashMap<String, ArkadeCovenant> =
        std::collections::HashMap::new();
    for function in contract.functions.iter().filter(|f| !f.is_internal) {
        covenants.insert(function.name.clone(), covenant_for(function)?);
    }

    json.functions = tapscript::build_function_groups(&contract, covenants)?;

    // ── Output invariant check ─────────────────────────────────────────────
    // Self-check the emitted JSON for structural invariants. Issues here
    // indicate compiler bugs; surface them as warnings so callers can report
    // them rather than silently producing malformed output.
    let output_issues = validator::validate_output(&json);
    for issue in &output_issues {
        let tag = match issue.severity {
            Severity::Error => "warning[output-invariant-error]",
            Severity::Warning => "warning[output-invariant]",
        };
        json.warnings.push(format!("{}: {}", tag, issue.message));
    }

    Ok(json)
}

/// Expand ABI params for emission. Array types (e.g., `pubkey[]`) are flattened
/// to `name_0`, `name_1`, `name_2`, …; every other param passes through unchanged.
pub(crate) fn expand_abi_params(params: &[Parameter]) -> Vec<Parameter> {
    let mut result = Vec::new();
    for param in params {
        for_each_expanded_param(param, |name, param_type| {
            result.push(Parameter { name, param_type });
        });
    }
    result
}

/// Build an `ArkadeCovenant` for a non-internal function: array-expand inputs,
/// emit ASM from statements (no server cosig, no exit timelock).
fn covenant_for(function: &Function) -> Result<ArkadeCovenant, String> {
    let inputs = expand_function_inputs(&function.parameters);
    let mut asm = generate_asm_from_statements(&function.statements)?;
    // Every require() above fails fast via OP_VERIFY, so terminate the covenant
    // with an explicit truthy value as its top-of-stack result. Intermediate
    // stack items left by let/assignments sit harmlessly below it.
    // FOLLOW-UP: once symbolic stack management lands, drop the last require's
    // OP_VERIFY and leave its boolean instead.
    asm.push(OP_1.to_string());
    Ok(ArkadeCovenant { inputs, asm })
}

fn expand_function_inputs(params: &[Parameter]) -> Vec<FunctionInput> {
    let mut inputs = Vec::new();
    for param in params {
        for_each_expanded_param(param, |name, param_type| {
            inputs.push(FunctionInput { name, param_type });
        });
    }
    inputs
}

fn for_each_expanded_param(param: &Parameter, mut f: impl FnMut(String, String)) {
    if let Some(base_type) = param.param_type.strip_suffix("[]") {
        for i in 0..DEFAULT_ARRAY_LENGTH {
            f(format!("{}_{}", param.name, i), base_type.to_string());
        }
    } else {
        f(param.name.clone(), param.param_type.clone());
    }
}

/// Generate assembly instructions from statements
fn generate_asm_from_statements(statements: &[Statement]) -> Result<Vec<String>, String> {
    let mut asm = Vec::new();
    generate_asm_from_statements_recursive(statements, &mut asm)?;
    Ok(asm)
}

/// Recursively generate assembly from statements
fn generate_asm_from_statements_recursive(
    statements: &[Statement],
    asm: &mut Vec<String>,
) -> Result<(), String> {
    for stmt in statements {
        match stmt {
            Statement::Require(req) => {
                generate_requirement_asm(req, asm)?;
            }
            Statement::IfElse {
                condition,
                then_body,
                else_body,
            } => {
                // Generate condition expression
                emit_expression_asm(condition, asm);
                asm.push(OP_IF.to_string());

                // Generate then branch
                generate_asm_from_statements_recursive(then_body, asm)?;

                // Generate else branch if present
                if let Some(else_stmts) = else_body {
                    asm.push(OP_ELSE.to_string());
                    generate_asm_from_statements_recursive(else_stmts, asm)?;
                }

                asm.push(OP_ENDIF.to_string());
            }
            Statement::ForIn {
                index_var,
                value_var,
                iterable,
                body,
            } => {
                match iterable {
                    Expression::Property(prop) if prop == "tx.assetGroups" => {
                        unroll_loop_body(body, index_var, value_var, None, asm)?;
                    }
                    Expression::Variable(array_name) => {
                        unroll_loop_body(body, index_var, value_var, Some(array_name), asm)?;
                    }
                    _ => {
                        // Unsupported iterables keep the historical fallback behavior.
                        generate_asm_from_statements_recursive(body, asm)?;
                    }
                }
            }
            Statement::LetBinding { name: _, value } => {
                // Emit the expression value onto the stack
                // TODO: Implement proper variable binding with stack tracking
                emit_expression_asm(value, asm);
            }
            Statement::VarAssign { name: _, value } => {
                // Push the new value onto the stack.
                // Full variable reassignment (dropping the old stack value) requires
                // stack-position tracking, which is deferred to a later phase.
                // For the common pattern of `typed_var = expr; require(typed_var == ...)`,
                // emitting the expression is sufficient because the old value has already
                // been consumed by the time the re-assignment is reached.
                emit_expression_asm(value, asm);
            }
        }
    }
    Ok(())
}

/// Generate assembly for a single requirement
fn generate_requirement_asm(req: &Requirement, asm: &mut Vec<String>) -> Result<(), String> {
    match req {
        Requirement::Expression(expr) => {
            if let Expression::GroupFind {
                asset_txid,
                asset_gidx,
            } = expr
            {
                emit_group_find_asm(asset_txid, asset_gidx, asm);
                asm.push(OP_DROP.to_string());
                asm.push(OP_1.to_string());
            } else {
                emit_expression_asm(expr, asm);
            }
            // require() fails fast: abort the script immediately if the
            // condition is false, matching CashScript's per-require OP_VERIFY.
            asm.push(OP_VERIFY.to_string());
            Ok(())
        }
        Requirement::CheckSig { signature, pubkey } => {
            asm.push(format!("<{}>", pubkey));
            asm.push(format!("<{}>", signature));
            asm.push(OP_CHECKSIG.to_string());
            asm.push(OP_VERIFY.to_string());
            Ok(())
        }
        Requirement::CheckSigFromStack {
            signature,
            pubkey,
            message,
        } => {
            asm.push(format!("<{}>", message));
            asm.push(format!("<{}>", pubkey));
            asm.push(format!("<{}>", signature));
            asm.push(OP_CHECKSIGFROMSTACK.to_string());
            asm.push(OP_VERIFY.to_string());
            Ok(())
        }
        Requirement::CheckMultisig { pubkeys, threshold } => {
            let pubkeys_size = pubkeys.len();
            let pubkeys_size = if pubkeys_size <= 999 {
                pubkeys_size as u16
            } else {
                return Err("Number of pubkeys should be less than 999.".to_string());
            };

            if threshold < &1u16 {
                return Err(format!(
                    "m-of-n multisig cannot succeed with threshold(m) of {}",
                    threshold
                ));
            }
            if threshold > &pubkeys_size {
                return Err(
                    "m-of-n multisig threshold(m) exceeds acceptable number of signers(n)"
                        .to_string(),
                );
            }

            for (i, pubkey) in pubkeys.iter().enumerate() {
                if i == 0 {
                    asm.push(format!("<{}>", pubkey));
                    asm.push(OP_CHECKSIG.to_string());
                    continue;
                }
                asm.push(format!("<{}>", pubkey));
                asm.push(OP_CHECKSIGADD.to_string());
            }
            if threshold <= &16u16 {
                asm.push(format!("OP_{}", threshold));
            } else {
                asm.push(format!("{}", threshold));
            }
            asm.push(OP_NUMEQUAL.to_string());
            asm.push(OP_VERIFY.to_string());
            Ok(())
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
            asm.push(OP_CHECKLOCKTIMEVERIFY.to_string());
            asm.push(OP_DROP.to_string());
            Ok(())
        }
        Requirement::HashEqual {
            hash_fn,
            preimage,
            hash,
        } => {
            asm.push(format!("<{}>", preimage));
            asm.push(hash_fn.opcode().to_string());
            asm.push(format!("<{}>", hash));
            asm.push(OP_EQUAL.to_string());
            asm.push(OP_VERIFY.to_string());
            Ok(())
        }
        Requirement::Comparison { left, op, right } => {
            emit_comparison_asm(left, op, right, asm);
            asm.push(OP_VERIFY.to_string());
            Ok(())
        }
    }
}
