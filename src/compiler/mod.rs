use crate::models::{
    ArkadeCovenant, CompilerInfo, ContractJson, Expression, Function, FunctionInput, Parameter,
    Requirement, Statement,
};
use crate::opcodes::{
    OP_0, OP_1, OP_ADD, OP_BIN2NUM, OP_BOOLAND, OP_CAT, OP_CHECKLOCKTIMEVERIFY, OP_CHECKSIG,
    OP_CHECKSIGADD, OP_CHECKSIGFROMSTACK, OP_DIGEST, OP_DIV, OP_DROP, OP_ECADD, OP_ECMUL,
    OP_ECMULSCALARVERIFY, OP_ECPAIRING, OP_ELSE, OP_ENDIF, OP_EQUAL, OP_EQUALVERIFY,
    OP_FINDASSETGROUPBYASSETID, OP_FROMALTSTACK, OP_GREATERTHAN, OP_GREATERTHANOREQUAL, OP_IF,
    OP_INSPECTASSETGROUP, OP_INSPECTASSETGROUPASSETID, OP_INSPECTASSETGROUPCTRL,
    OP_INSPECTASSETGROUPMETADATAHASH, OP_INSPECTASSETGROUPNUM, OP_INSPECTASSETGROUPSUM,
    OP_INSPECTINASSETAT, OP_INSPECTINASSETCOUNT, OP_INSPECTINASSETLOOKUP,
    OP_INSPECTINPUTARKADESCRIPTHASH, OP_INSPECTINPUTARKADEWITNESSHASH, OP_INSPECTINPUTOUTPOINT,
    OP_INSPECTINPUTPACKET, OP_INSPECTINPUTSCRIPTPUBKEY, OP_INSPECTINPUTSEQUENCE,
    OP_INSPECTINPUTVALUE, OP_INSPECTLOCKTIME, OP_INSPECTNUMASSETGROUPS, OP_INSPECTNUMINPUTS,
    OP_INSPECTNUMOUTPUTS, OP_INSPECTOUTASSETAT, OP_INSPECTOUTASSETCOUNT, OP_INSPECTOUTASSETLOOKUP,
    OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_INSPECTOUTPUTVALUE, OP_INSPECTPACKET, OP_INSPECTVERSION,
    OP_LESSTHAN, OP_LESSTHANOREQUAL, OP_MODEXP, OP_MUL, OP_NEGATE, OP_NIP, OP_NOT, OP_NUM2BIN,
    OP_NUMEQUAL, OP_PICK, OP_PUSHCURRENTINPUTINDEX, OP_REVERSEBYTES, OP_ROLL, OP_SHA256,
    OP_SHA256FINALIZE, OP_SHA256INITIALIZE, OP_SHA256UPDATE, OP_SIGHASH, OP_SIZE, OP_SUB,
    OP_SUBSTR, OP_SWAP, OP_TOALTSTACK, OP_TWEAKVERIFY, OP_TXID, OP_TXWEIGHT, OP_VERIFY,
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

#[derive(Clone, Debug, PartialEq, Eq)]
enum BindingKind {
    Constructor,
    FunctionInput,
    Local,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum StackItem {
    Binding { name: String, kind: BindingKind },
    Temporary,
}

// `$` is outside the source identifier grammar, so this namespace cannot collide with user bindings.
const INTERNAL_ARRAY_BINDING_PREFIX: &str = "$array:";
const INTERNAL_ARRAY_INDEX_PREFIX: &str = "$array-index:";

fn internal_array_binding_name(array: &str, index: &str) -> String {
    format!("{INTERNAL_ARRAY_BINDING_PREFIX}{array}:{index}")
}

struct Generator {
    asm: Vec<String>,
    stack: Vec<StackItem>,
    scopes: Vec<usize>,
    alt_depth: usize,
    constructor_array_expansions: Vec<(String, String)>,
}

impl Generator {
    fn new(function_parameters: &[Parameter], constructor_parameters: &[Parameter]) -> Self {
        let mut function_bindings = Vec::new();
        for parameter in function_parameters {
            for_each_expanded_param(parameter, |_, binding_name, _| {
                function_bindings.push(binding_name);
            });
        }
        let mut stack = function_bindings
            .into_iter()
            .rev()
            .map(|name| StackItem::Binding {
                name,
                kind: BindingKind::FunctionInput,
            })
            .collect::<Vec<_>>();

        let mut constructor_bindings = Vec::new();
        let mut constructor_array_expansions = Vec::new();
        for parameter in constructor_parameters {
            let mut expanded_placeholders = Vec::new();
            for_each_expanded_param(parameter, |placeholder, binding_name, _| {
                expanded_placeholders.push(format!("<{placeholder}>"));
                constructor_bindings.push((placeholder, binding_name));
            });
            if crate::models::array_type_parts(&parameter.param_type).is_some() {
                constructor_array_expansions.push((
                    format!("<{}>", parameter.name),
                    expanded_placeholders.join(","),
                ));
            }
        }
        let mut asm = Vec::new();
        for (placeholder, binding_name) in constructor_bindings.into_iter().rev() {
            asm.push(format!("<{placeholder}>"));
            stack.push(StackItem::Binding {
                name: binding_name,
                kind: BindingKind::Constructor,
            });
        }
        Self {
            asm,
            stack,
            scopes: Vec::new(),
            alt_depth: 0,
            constructor_array_expansions,
        }
    }

    fn push_depth(&mut self, depth: usize) {
        self.asm.push(if depth <= 16 {
            format!("OP_{depth}")
        } else {
            depth.to_string()
        });
    }

    fn push_temporary(&mut self, token: impl Into<String>) {
        self.asm.push(token.into());
        self.stack.push(StackItem::Temporary);
    }

    fn binding_index(&self, name: &str) -> Option<usize> {
        self.stack.iter().position(
            |item| matches!(item, StackItem::Binding { name: binding, .. } if binding == name),
        )
    }

    /// Element count of an array binding, read off the symbolic stack: its
    /// elements are bound as `$array:name:0 … $array:name:N-1`.
    fn array_length(&self, array: &str) -> usize {
        (0..)
            .take_while(|i| {
                self.binding_index(&internal_array_binding_name(array, &i.to_string()))
                    .is_some()
            })
            .count()
    }

    fn internal_binding_name(name: &str) -> String {
        let name = name.trim();
        if name.starts_with(INTERNAL_ARRAY_BINDING_PREFIX) {
            return name.to_string();
        }
        if let Some((array, index)) = name.strip_suffix(']').and_then(|name| name.split_once('[')) {
            if index.parse::<usize>().is_ok() {
                return internal_array_binding_name(array, index);
            }
        }
        name.to_string()
    }

    fn read_binding(&mut self, name: &str) -> Result<(), String> {
        if let Some(array) = name.trim().strip_suffix(".length") {
            let length = self.array_length(array);
            if length == 0 {
                return Err(format!("'{array}' is not an array; '.length' is undefined"));
            }
            self.push_integer_temporary(length);
            return Ok(());
        }
        if let Some((array, index)) = name
            .trim()
            .strip_suffix(']')
            .and_then(|name| name.split_once('['))
        {
            if index.parse::<usize>().is_err() {
                return self.read_indexed_binding(array, index);
            }
        }
        let name = Self::internal_binding_name(name);
        self.read_static_binding(&name)
    }

    fn read_static_binding(&mut self, name: &str) -> Result<(), String> {
        let index = self
            .binding_index(name)
            .ok_or_else(|| format!("undefined binding '{name}'"))?;
        let depth = self.stack.len() - 1 - index;
        self.push_depth(depth);
        self.asm.push(OP_PICK.to_string());
        self.stack.push(StackItem::Temporary);
        Ok(())
    }

    fn push_integer_temporary(&mut self, value: usize) {
        self.push_temporary(if value <= 16 {
            format!("OP_{value}")
        } else {
            value.to_string()
        });
    }

    fn read_indexed_binding(&mut self, array: &str, index: &str) -> Result<(), String> {
        self.read_binding(index)?;
        self.select_indexed_value(array)
    }

    fn select_indexed_value(&mut self, array: &str) -> Result<(), String> {
        let first_element = internal_array_binding_name(array, "0");
        let first_index = self
            .binding_index(&first_element)
            .ok_or_else(|| format!("undefined array binding '{array}'"))?;
        let first_depth = self.stack.len() - 1 - first_index;
        let first_depth_without_index = first_depth.checked_sub(1).ok_or_else(|| {
            format!("internal compiler error: array index for '{array}' is not on the stack")
        })?;

        self.push_integer_temporary(0);
        self.apply(OP_PICK, 1, 1)?;
        self.push_integer_temporary(0);
        self.apply(OP_GREATERTHANOREQUAL, 2, 1)?;
        self.apply(OP_VERIFY, 1, 0)?;

        self.push_integer_temporary(0);
        self.apply(OP_PICK, 1, 1)?;
        self.push_integer_temporary(self.array_length(array));
        self.apply(OP_LESSTHAN, 2, 1)?;
        self.apply(OP_VERIFY, 1, 0)?;

        self.push_integer_temporary(first_depth_without_index);
        self.apply(OP_ADD, 2, 1)?;
        self.apply(OP_PICK, 1, 1)
    }

    fn read_binding_or_integer(&mut self, value: &str) -> Result<(), String> {
        if value.parse::<i64>().is_ok() {
            self.push_temporary(value);
            Ok(())
        } else {
            self.read_binding(value)
        }
    }

    fn pop_temporaries(&mut self, count: usize, opcode: &str) -> Result<(), String> {
        if count > self.stack.len()
            || self.stack[self.stack.len() - count..]
                .iter()
                .any(|item| !matches!(item, StackItem::Temporary))
        {
            return Err(format!(
                "internal compiler error: {opcode} expected {count} temporary stack operands"
            ));
        }
        self.stack.truncate(self.stack.len() - count);
        Ok(())
    }

    fn apply(&mut self, opcode: &str, inputs: usize, outputs: usize) -> Result<(), String> {
        self.pop_temporaries(inputs, opcode)?;
        self.asm.push(opcode.to_string());
        self.stack
            .extend(std::iter::repeat_n(StackItem::Temporary, outputs));
        Ok(())
    }

    fn nip(&mut self) -> Result<(), String> {
        if self.stack.len() < 2 {
            return Err("internal compiler error: OP_NIP stack underflow".to_string());
        }
        let index = self.stack.len() - 2;
        self.stack.remove(index);
        self.asm.push(OP_NIP.to_string());
        Ok(())
    }

    fn swap(&mut self) -> Result<(), String> {
        if self.stack.len() < 2 {
            return Err("internal compiler error: OP_SWAP stack underflow".to_string());
        }
        let len = self.stack.len();
        self.stack.swap(len - 2, len - 1);
        self.asm.push(OP_SWAP.to_string());
        Ok(())
    }

    fn lower_raw_opcode(&mut self, opcode: &str) -> Result<(), String> {
        match opcode {
            OP_0 | OP_1 | "OP_2" | "OP_3" | "OP_4" | "OP_5" | "OP_6" | "OP_7" | "OP_8" | "OP_9"
            | "OP_10" | "OP_11" | "OP_12" | "OP_13" | "OP_14" | "OP_15" | "OP_16" => {
                self.push_temporary(opcode);
                Ok(())
            }
            OP_DROP => self.apply(opcode, 1, 0),
            OP_NIP => self.nip(),
            OP_SWAP => self.swap(),
            OP_VERIFY => self.apply(opcode, 1, 0),
            OP_EQUALVERIFY => self.apply(opcode, 2, 0),
            OP_PUSHCURRENTINPUTINDEX
            | OP_INSPECTVERSION
            | OP_INSPECTLOCKTIME
            | OP_INSPECTNUMINPUTS
            | OP_INSPECTNUMOUTPUTS
            | OP_INSPECTNUMASSETGROUPS
            | OP_TXID
            | OP_TXWEIGHT => {
                self.push_temporary(opcode);
                Ok(())
            }
            OP_NEGATE
            | OP_NOT
            | OP_SHA256
            | "OP_HASH160"
            | "OP_HASH256"
            | "OP_RIPEMD160"
            | OP_SHA256INITIALIZE
            | OP_SIGHASH
            | OP_BIN2NUM
            | OP_REVERSEBYTES
            | OP_INSPECTINPUTVALUE
            | OP_INSPECTINPUTSEQUENCE
            | OP_INSPECTINPUTARKADESCRIPTHASH
            | OP_INSPECTINPUTARKADEWITNESSHASH
            | OP_INSPECTOUTPUTVALUE
            | OP_INSPECTINASSETCOUNT
            | OP_INSPECTOUTASSETCOUNT
            | OP_INSPECTASSETGROUPMETADATAHASH => self.apply(opcode, 1, 1),
            OP_ADD
            | OP_SUB
            | OP_MUL
            | OP_DIV
            | OP_EQUAL
            | OP_GREATERTHAN
            | OP_GREATERTHANOREQUAL
            | OP_LESSTHAN
            | OP_LESSTHANOREQUAL
            | OP_NUMEQUAL
            | OP_BOOLAND
            | OP_CAT
            | OP_SHA256UPDATE
            | OP_SHA256FINALIZE
            | OP_DIGEST
            | OP_NUM2BIN
            | OP_CHECKSIG
            | OP_INSPECTASSETGROUPSUM
            | OP_INSPECTASSETGROUPNUM => self.apply(opcode, 2, 1),
            OP_MODEXP | OP_SUBSTR | OP_CHECKSIGADD | OP_CHECKSIGFROMSTACK => {
                self.apply(opcode, 3, 1)
            }
            OP_INSPECTINPUTSCRIPTPUBKEY | OP_INSPECTOUTPUTSCRIPTPUBKEY => self.apply(opcode, 1, 2),
            OP_INSPECTINPUTOUTPOINT => self.apply(opcode, 1, 2),
            OP_INSPECTINASSETLOOKUP | OP_INSPECTOUTASSETLOOKUP => self.apply(opcode, 3, 2),
            OP_FINDASSETGROUPBYASSETID => self.apply(opcode, 2, 2),
            OP_INSPECTINASSETAT | OP_INSPECTOUTASSETAT => self.apply(opcode, 2, 3),
            OP_INSPECTASSETGROUPCTRL => self.apply(opcode, 1, 3),
            OP_INSPECTASSETGROUPASSETID => self.apply(opcode, 1, 2),
            OP_INSPECTPACKET => self.apply(opcode, 1, 2),
            OP_INSPECTINPUTPACKET => self.apply(opcode, 2, 2),
            OP_SIZE => self.apply(opcode, 1, 2),
            OP_ECADD => self.apply(opcode, 5, 2),
            OP_ECMUL => self.apply(opcode, 4, 2),
            OP_ECPAIRING => self.apply(opcode, 8, 1),
            OP_ECMULSCALARVERIFY | OP_TWEAKVERIFY => self.apply(opcode, 3, 0),
            OP_INSPECTASSETGROUP => self.apply(opcode, 3, 3),
            _ => Err(format!(
                "internal compiler error: unknown expression opcode {opcode}"
            )),
        }
    }

    fn lower_raw_token(&mut self, token: &str) -> Result<(), String> {
        if let Some(array) = token.strip_prefix(INTERNAL_ARRAY_INDEX_PREFIX) {
            return self.select_indexed_value(array);
        }
        if token.starts_with("<VTXO:") {
            let mut token = token.to_string();
            for (array, elements) in &self.constructor_array_expansions {
                token = token.replace(array, elements);
            }
            self.push_temporary(token);
            return Ok(());
        }
        if token.starts_with('<') && token.ends_with('>') {
            let value = &token[1..token.len() - 1];
            if value.parse::<i64>().is_ok() {
                self.push_temporary(value);
                return Ok(());
            }
            return self.read_binding(value);
        }
        if token.starts_with("OP_") {
            return self.lower_raw_opcode(token);
        }
        self.push_temporary(token);
        Ok(())
    }

    fn emit_expression(&mut self, expression: &Expression) -> Result<(), String> {
        if matches!(
            expression,
            Expression::CurrentInput(Some(property)) if property == "outpoint"
        ) || matches!(
            expression,
            Expression::InputIntrospection { property, .. } if property == "outpoint"
        ) {
            return Err(
                "outpoint inspection produces 2 stack items; composite values are not supported"
                    .to_string(),
            );
        }
        if matches!(expression, Expression::ArrayLiteral(_)) {
            return Err(
                "array literals may only initialize an array declaration; composite values are not supported"
                    .to_string(),
            );
        }
        if matches!(
            expression,
            Expression::GroupIOAccess {
                source: crate::models::GroupIOSource::Inputs,
                ..
            }
        ) {
            return Err(
                "asset-group input inspection has a variable-width result and cannot be used as a value"
                    .to_string(),
            );
        }
        let before = self.stack.len();
        let mut raw = Vec::new();
        emit_expression_asm(expression, &mut raw);
        for token in raw {
            self.lower_raw_token(&token)?;
        }
        if self.stack.len() != before + 1
            || !matches!(self.stack.last(), Some(StackItem::Temporary))
        {
            return Err(format!(
                "expression produces {} stack items; exactly one is required",
                self.stack.len().saturating_sub(before)
            ));
        }
        Ok(())
    }

    fn bind_local(&mut self, name: &str) -> Result<(), String> {
        let top = self.stack.last_mut().ok_or_else(|| {
            "internal compiler error: local initializer produced no value".to_string()
        })?;
        if !matches!(top, StackItem::Temporary) {
            return Err(
                "internal compiler error: local initializer did not leave a temporary".to_string(),
            );
        }
        *top = StackItem::Binding {
            name: name.to_string(),
            kind: BindingKind::Local,
        };
        Ok(())
    }

    fn assign(&mut self, name: &str) -> Result<(), String> {
        if let Some((array, element)) = name.strip_suffix(']').and_then(|n| n.split_once('[')) {
            if element.parse::<usize>().is_err() {
                // Writing at a runtime depth needs a write-at-depth opcode
                // (see docs: OP_PUT); emulating it costs one guarded write per
                // element. Lift this once the VM provides that primitive.
                return Err(format!(
                    "assignment to '{array}' at a runtime index is not supported; use a literal index"
                ));
            }
        }
        let name = &Self::internal_binding_name(name);
        let index = self
            .binding_index(name)
            .ok_or_else(|| format!("assignment to undeclared binding '{name}'"))?;
        if matches!(
            self.stack[index],
            StackItem::Binding {
                kind: BindingKind::Constructor,
                ..
            }
        ) {
            return Err(format!(
                "cannot assign to constructor parameter '{name}'; constructor parameters are immutable"
            ));
        }
        if !matches!(self.stack.last(), Some(StackItem::Temporary)) {
            return Err("internal compiler error: assignment has no result value".to_string());
        }
        let depth = self.stack.len() - 1 - index;
        self.push_depth(depth);
        self.asm.push(OP_ROLL.to_string());
        self.asm.push(OP_DROP.to_string());
        for step in 0..depth.saturating_sub(1) {
            self.asm.push(OP_SWAP.to_string());
            if step + 1 < depth - 1 {
                self.asm.push(OP_TOALTSTACK.to_string());
                self.alt_depth += 1;
            }
        }
        for _ in 0..depth.saturating_sub(2) {
            self.asm.push(OP_FROMALTSTACK.to_string());
            self.alt_depth = self.alt_depth.checked_sub(1).ok_or_else(|| {
                "internal compiler error: assignment alternate-stack underflow".to_string()
            })?;
        }
        self.stack.pop();
        if self.alt_depth != 0 {
            return Err(
                "internal compiler error: assignment left values on the alternate stack"
                    .to_string(),
            );
        }
        Ok(())
    }

    fn enter_scope(&mut self) {
        self.scopes.push(self.stack.len());
    }

    fn exit_scope(&mut self) -> Result<(), String> {
        let baseline = self
            .scopes
            .pop()
            .ok_or_else(|| "internal compiler error: scope stack underflow".to_string())?;
        while self.stack.len() > baseline {
            match self.stack.last() {
                Some(StackItem::Binding {
                    kind: BindingKind::Local,
                    ..
                }) => {
                    self.asm.push(OP_DROP.to_string());
                    self.stack.pop();
                }
                _ => {
                    return Err(
                        "internal compiler error: scope ended with a temporary or outer binding above its locals"
                            .to_string(),
                    )
                }
            }
        }
        Ok(())
    }

    fn assert_statement_boundary(&self) -> Result<(), String> {
        if self.alt_depth != 0
            || self
                .stack
                .iter()
                .any(|item| matches!(item, StackItem::Temporary))
        {
            return Err(
                "internal compiler error: statement left a temporary stack value".to_string(),
            );
        }
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<String>, String> {
        if !self.scopes.is_empty() || self.alt_depth != 0 {
            return Err("internal compiler error: unbalanced generator scope".to_string());
        }
        self.push_temporary(OP_1);
        while self.stack.len() > 1 {
            self.nip()?;
        }
        if self.stack != vec![StackItem::Temporary] {
            return Err("internal compiler error: covenant did not finish cleanly".to_string());
        }
        Ok(self.asm)
    }
}

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
    rewrite_concat_ops(&mut contract)?;

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
        covenants.insert(
            function.name.clone(),
            covenant_for(function, &contract.parameters)?,
        );
    }

    json.functions = tapscript::build_function_groups(&contract, covenants)?;

    // ── Output invariant check ─────────────────────────────────────────────
    // Self-check the emitted JSON for structural invariants.
    let output_issues = validator::validate_output(&json);
    if validator::has_errors(&output_issues) {
        return Err(output_issues
            .iter()
            .filter(|issue| matches!(issue.severity, Severity::Error))
            .map(|issue| format!("output validation error: {}", issue.message))
            .collect::<Vec<_>>()
            .join("; "));
    }
    for issue in &output_issues {
        json.warnings
            .push(format!("warning[output-invariant]: {}", issue.message));
    }

    Ok(json)
}

/// Expand ABI params for emission. Array types (e.g., `pubkey[]`) are flattened
/// to `name_0`, `name_1`, `name_2`, …; every other param passes through unchanged.
pub(crate) fn expand_abi_params(params: &[Parameter]) -> Vec<Parameter> {
    let mut result = Vec::new();
    for param in params {
        for_each_expanded_param(param, |name, _, param_type| {
            result.push(Parameter { name, param_type });
        });
    }
    result
}

/// Build an `ArkadeCovenant` for a non-internal function.
fn covenant_for(
    function: &Function,
    constructor_parameters: &[Parameter],
) -> Result<ArkadeCovenant, String> {
    let inputs = expand_function_inputs(&function.parameters);
    let mut generator = Generator::new(&function.parameters, constructor_parameters);
    generate_asm_from_statements_recursive(&function.statements, &mut generator)?;
    let asm = generator.finish()?;
    Ok(ArkadeCovenant { inputs, asm })
}

fn expand_function_inputs(params: &[Parameter]) -> Vec<FunctionInput> {
    let mut inputs = Vec::new();
    for param in params {
        for_each_expanded_param(param, |name, _, param_type| {
            inputs.push(FunctionInput { name, param_type });
        });
    }
    inputs
}

fn for_each_expanded_param(param: &Parameter, mut f: impl FnMut(String, String, String)) {
    if let Some((base_type, length)) = crate::models::array_type_parts(&param.param_type) {
        for i in 0..length {
            f(
                format!("{}_{}", param.name, i),
                internal_array_binding_name(&param.name, &i.to_string()),
                base_type.to_string(),
            );
        }
    } else {
        f(
            param.name.clone(),
            param.name.clone(),
            param.param_type.clone(),
        );
    }
}

/// Recursively generate assembly from statements
fn generate_asm_from_statements_recursive(
    statements: &[Statement],
    generator: &mut Generator,
) -> Result<(), String> {
    for stmt in statements {
        match stmt {
            Statement::Require(req) => {
                generate_requirement_asm(req, generator)?;
            }
            Statement::IfElse {
                condition,
                then_body,
                else_body,
            } => {
                generator.emit_expression(condition)?;
                generator.apply(OP_IF, 1, 0)?;
                let baseline = generator.stack.clone();
                generator.enter_scope();
                generate_asm_from_statements_recursive(then_body, generator)?;
                generator.exit_scope()?;
                if generator.stack != baseline {
                    return Err(
                        "internal compiler error: then branch changed outer stack layout"
                            .to_string(),
                    );
                }
                if let Some(else_stmts) = else_body {
                    generator.asm.push(OP_ELSE.to_string());
                    generator.enter_scope();
                    generate_asm_from_statements_recursive(else_stmts, generator)?;
                    generator.exit_scope()?;
                    if generator.stack != baseline {
                        return Err(
                            "internal compiler error: else branch changed outer stack layout"
                                .to_string(),
                        );
                    }
                }
                generator.asm.push(OP_ENDIF.to_string());
            }
            Statement::ForIn {
                index_var,
                value_var,
                iterable,
                body,
            } => {
                let Expression::Variable(array_name) = iterable else {
                    return Err("unsupported loop iterable".to_string());
                };
                let array_name = array_name.as_str();
                for k in 0..generator.array_length(array_name) {
                    let substituted =
                        substitute_loop_body(body, index_var, value_var, k, array_name);
                    let baseline = generator.stack.clone();
                    generator.enter_scope();
                    generate_asm_from_statements_recursive(&substituted, generator)?;
                    generator.exit_scope()?;
                    if generator.stack != baseline {
                        return Err(format!(
                            "internal compiler error: loop iteration {k} changed outer stack layout"
                        ));
                    }
                }
            }
            Statement::LetBinding {
                name,
                declared_type,
                value,
            } => match (
                declared_type
                    .as_deref()
                    .and_then(crate::models::array_type_parts),
                value,
            ) {
                (Some((_, length)), Expression::ArrayLiteral(elements)) => {
                    if elements.len() != length {
                        return Err(format!(
                            "array '{name}' declares {length} elements but its initializer has {}",
                            elements.len()
                        ));
                    }
                    // Deepest element last, so element 0 sits closest to the top —
                    // the layout parameter arrays already have.
                    for (index, element) in elements.iter().enumerate().rev() {
                        generator.emit_expression(element)?;
                        generator
                            .bind_local(&internal_array_binding_name(name, &index.to_string()))?;
                    }
                }
                _ => {
                    generator.emit_expression(value)?;
                    generator.bind_local(name)?;
                }
            },
            Statement::VarAssign { name, value } => {
                generator.emit_expression(value)?;
                generator.assign(name)?;
            }
        }
        generator.assert_statement_boundary()?;
    }
    Ok(())
}

/// Generate assembly for a single requirement
fn generate_requirement_asm(req: &Requirement, generator: &mut Generator) -> Result<(), String> {
    match req {
        Requirement::Expression(expr) => {
            match expr {
                Expression::GroupFind { .. } => {
                    generator.emit_expression(expr)?;
                    generator.apply(OP_DROP, 1, 0)?;
                    generator.push_temporary(OP_1);
                    generator.apply(OP_VERIFY, 1, 0)?;
                }
                Expression::CheckSigFromStackVerify {
                    signature,
                    pubkey,
                    message,
                } => {
                    generator.read_binding(signature)?;
                    generator.read_binding(message)?;
                    generator.read_binding(pubkey)?;
                    generator.apply(OP_CHECKSIGFROMSTACK, 3, 1)?;
                    generator.apply(OP_VERIFY, 1, 0)?;
                }
                Expression::EcMulScalarVerify {
                    scalar,
                    point_p,
                    point_q,
                } => {
                    generator.emit_expression(scalar)?;
                    generator.emit_expression(point_p)?;
                    generator.emit_expression(point_q)?;
                    generator.apply(OP_ECMULSCALARVERIFY, 3, 0)?;
                }
                Expression::TweakVerify {
                    point_p,
                    tweak,
                    point_q,
                } => {
                    generator.emit_expression(point_p)?;
                    generator.emit_expression(tweak)?;
                    generator.emit_expression(point_q)?;
                    generator.apply(OP_TWEAKVERIFY, 3, 0)?;
                }
                _ => {
                    generator.emit_expression(expr)?;
                    generator.apply(OP_VERIFY, 1, 0)?;
                }
            }
            Ok(())
        }
        Requirement::CheckSig { signature, pubkey } => {
            generator.read_binding(signature)?;
            generator.read_binding(pubkey)?;
            generator.apply(OP_CHECKSIG, 2, 1)?;
            generator.apply(OP_VERIFY, 1, 0)?;
            Ok(())
        }
        Requirement::CheckSigFromStack {
            signature,
            pubkey,
            message,
        } => {
            generator.read_binding(signature)?;
            generator.read_binding(message)?;
            generator.read_binding(pubkey)?;
            generator.apply(OP_CHECKSIGFROMSTACK, 3, 1)?;
            generator.apply(OP_VERIFY, 1, 0)?;
            Ok(())
        }
        Requirement::CheckMultisig {
            pubkeys,
            signatures,
            threshold,
        } => {
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
            if pubkeys.len() != signatures.len() {
                return Err("checkMultisig key and signature counts must match".to_string());
            }
            for signature in signatures.iter().rev() {
                generator.read_binding(signature)?;
            }
            generator.read_binding(&pubkeys[0])?;
            generator.apply(OP_CHECKSIG, 2, 1)?;
            for pubkey in pubkeys.iter().skip(1) {
                generator.read_binding(pubkey)?;
                generator.apply(OP_CHECKSIGADD, 3, 1)?;
            }
            if threshold <= &16 {
                generator.push_temporary(format!("OP_{threshold}"));
            } else {
                generator.push_temporary(threshold.to_string());
            }
            generator.apply(OP_NUMEQUAL, 2, 1)?;
            generator.apply(OP_VERIFY, 1, 0)?;
            Ok(())
        }
        Requirement::After {
            blocks,
            timelock_var,
        } => {
            if let Some(var) = timelock_var {
                generator.read_binding_or_integer(var)?;
            } else {
                generator.push_temporary(blocks.to_string());
            }
            generator.apply(OP_CHECKLOCKTIMEVERIFY, 1, 1)?;
            generator.apply(OP_DROP, 1, 0)?;
            Ok(())
        }
        Requirement::HashEqual {
            hash_fn,
            preimage,
            hash,
        } => {
            generator.read_binding_or_integer(preimage)?;
            generator.lower_raw_opcode(hash_fn.opcode())?;
            generator.read_binding_or_integer(hash)?;
            generator.apply(OP_EQUAL, 2, 1)?;
            generator.apply(OP_VERIFY, 1, 0)?;
            Ok(())
        }
        Requirement::Comparison { left, op, right } => {
            generator.emit_expression(left)?;
            generator.emit_expression(right)?;
            let mut raw = Vec::new();
            emit_comparison_op(op, &mut raw);
            for token in raw {
                generator.lower_raw_opcode(&token)?;
            }
            generator.apply(OP_VERIFY, 1, 0)?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod symbolic_stack_tests {
    use super::*;

    #[test]
    fn deep_assignment_replaces_the_original_slot_and_restores_the_alt_stack() {
        let inputs = ["a", "b", "c", "d"]
            .into_iter()
            .map(|name| Parameter {
                name: name.to_string(),
                param_type: "int".to_string(),
            })
            .collect::<Vec<_>>();
        let mut generator = Generator::new(&inputs, &[]);

        generator.push_temporary("9");
        generator.assign("d").expect("deep assignment");

        assert_eq!(
            generator.asm,
            [
                "9",
                "OP_4",
                "OP_ROLL",
                "OP_DROP",
                "OP_SWAP",
                "OP_TOALTSTACK",
                "OP_SWAP",
                "OP_TOALTSTACK",
                "OP_SWAP",
                "OP_FROMALTSTACK",
                "OP_FROMALTSTACK",
            ]
        );
        assert_eq!(generator.alt_depth, 0);
        assert_eq!(
            generator.stack,
            ["d", "c", "b", "a"]
                .into_iter()
                .map(|name| StackItem::Binding {
                    name: name.to_string(),
                    kind: BindingKind::FunctionInput,
                })
                .collect::<Vec<_>>()
        );
    }
}
