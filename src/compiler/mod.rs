use crate::diagnostics::Diagnostic;
use crate::models::{
    ArkadeCovenant, AssignmentTarget, CompilerInfo, Contract, ContractJson, ExprKind, Expression,
    Function, FunctionInput, LocatedStatement, Parameter, Path, Requirement, Segment, Statement,
};
use crate::opcodes::Opcode::{
    self, Add, Bin2Num, BoolAnd, Cat, CheckSig, CheckSigAdd, Drop, Dup, EcPairing, Else, EndIf,
    Equal, EqualVerify, FindAssetGroupByAssetId, GreaterThanOrEqual, If, InspectAssetGroup,
    InspectAssetGroupAssetId, InspectAssetGroupCtrl, InspectAssetGroupMetadataHash,
    InspectAssetGroupNum, InspectAssetGroupSum, InspectInAssetAt, InspectInAssetCount,
    InspectInAssetLookup, InspectInputArkadeScriptHash, InspectInputArkadeWitnessHash,
    InspectInputOutpoint, InspectInputPacket, InspectInputScriptPubKey, InspectInputSequence,
    InspectInputValue, InspectIntentMessage, InspectLockTime, InspectNumAssetGroups,
    InspectNumInputs, InspectNumOutputs, InspectOutAssetAt, InspectOutAssetCount,
    InspectOutAssetLookup, InspectOutputScriptPubKey, InspectOutputValue, InspectPacket,
    InspectVersion, Int0, Int1, LessThan, LessThanOrEqual, Mul, Nip, Not, NotEqual0, NumEqual,
    Pick, PushCurrentInputIndex, PushExpiry, Put, Roll, Size, Sub, Swap, Tunnel, TxWeight, Txid,
    Verify,
};
use crate::types::{self};
use crate::validator::{self, Severity};
use chrono::Utc;
use sha2::{Digest, Sha256};

pub mod tapscript;

// ASM codegen and rewrite passes split into submodules;
// siblings reach each other via `use super::*`.
mod access;
mod asset;
mod comparison;
pub(crate) mod constants;
pub(crate) use constants::{fold as fold_constants, resolve as resolve_constants};
mod expr;
mod functions;
mod ir;
pub(crate) use ir::Op;
mod introspection;
mod loops;
mod optimization;
mod stack;
mod statements;
use statements::generate_asm_from_statements_recursive;

pub(crate) use asset::*;
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
    Binding { name: Path, kind: BindingKind },
    Temporary,
}

/// Data and alt stack items the VM allows at once (`txscript.MaxStackSize`).
const MAX_STACK_ITEMS: usize = 1000;
/// Bytes the VM allows in a script (`txscript.MaxScriptSize`).
const MAX_SCRIPT_SIZE: usize = 10_000;

fn integer_op(value: usize) -> Op {
    use crate::opcodes::Opcode::*;
    const SMALL: [Opcode; 17] = [
        Int0, Int1, Int2, Int3, Int4, Int5, Int6, Int7, Int8, Int9, Int10, Int11, Int12, Int13,
        Int14, Int15, Int16,
    ];
    match SMALL.get(value) {
        Some(&opcode) => Op::Opcode(opcode),
        None => Op::Push(value.to_string()),
    }
}

struct Generator {
    optimize: bool,
    asm: Vec<Op>,
    stack: Vec<StackItem>,
    /// The most items the stacks hold at once, data and alt together.
    max_depth: usize,
    scopes: Vec<(usize, types::Scope)>,
    deferred: std::collections::HashSet<String>,
    /// Placeholders of constructor parameters that flatten to other leaves.
    constructor_expansions: Vec<(String, Vec<String>)>,
    structs: Vec<crate::models::StructDefinition>,
    scope: types::Scope,
    constructor_scope: types::Scope,
    functions: Vec<Function>,
    // Constructor leaves pushed at their single read instead of in the prologue.
    inlined: std::collections::HashMap<Path, String>,
    // Emitted reads per constructor slot; runtime-indexed slots count as two.
    constructor_reads: std::collections::HashMap<Path, usize>,
    // Read-only scalar parameters can name slots in the pinned caller frame.
    aliases: std::collections::HashMap<Path, usize>,
    // None outside a helper; Some(None) inside a void helper.
    return_type: Option<Option<String>>,
    direct_return: bool,
    // Record reads once, then replay final uses at their new stack depths.
    final_reads: Vec<bool>,
    last_reads: std::collections::HashMap<(Path, usize), usize>,
    read_cursor: Option<usize>,
    preserve_bindings: bool,
    pinned_stack_len: usize,
    // Rebinding the top slot can consume its old value without changing a branch join.
    replacement: Option<(Path, BindingKind, usize)>,
}

impl Generator {
    fn new(
        function_parameters: &[Parameter],
        constructor_parameters: &[Parameter],
        structs: &[crate::models::StructDefinition],
        inlined_bindings: &std::collections::HashSet<Path>,
    ) -> Result<Self, String> {
        let mut function_bindings = Vec::new();
        for parameter in function_parameters {
            for_each_expanded_param(parameter, structs, |_, binding_name, leaf_type| {
                function_bindings.push((binding_name, leaf_type));
            })?;
        }
        let mut stack = function_bindings
            .iter()
            .rev()
            .map(|(name, _)| StackItem::Binding {
                name: name.clone(),
                kind: BindingKind::FunctionInput,
            })
            .collect::<Vec<_>>();

        let mut constructor_bindings = Vec::new();
        let mut constructor_expansions = Vec::new();
        for parameter in constructor_parameters {
            let mut placeholders = Vec::new();
            for_each_expanded_param(parameter, structs, |placeholder, binding_name, _| {
                placeholders.push(placeholder.clone());
                constructor_bindings.push((placeholder, binding_name));
            })?;
            if placeholders != [parameter.name.as_str()] {
                constructor_expansions.push((parameter.name.clone(), placeholders));
            }
        }
        let mut asm = Vec::new();
        let mut inlined = std::collections::HashMap::new();
        for (placeholder, binding_name) in constructor_bindings.into_iter().rev() {
            if inlined_bindings.contains(&binding_name) {
                inlined.insert(binding_name, placeholder);
                continue;
            }
            asm.push(Op::Param(placeholder));
            stack.push(StackItem::Binding {
                name: binding_name,
                kind: BindingKind::Constructor,
            });
        }
        // Witness inputs carry any length; pin fixed-width ones before the body reads them.
        let prologue = asm.len();
        for (index, (_, leaf_type)) in function_bindings.iter().enumerate() {
            let width = match types::ArkType::parse(leaf_type) {
                types::ArkType::Bytes20 => "20",
                types::ArkType::Bytes32 => "32",
                _ => continue,
            };
            let depth = prologue + index;
            if depth > 0 {
                asm.extend([integer_op(depth), Op::Opcode(Pick)]);
            }
            asm.extend([
                Op::Opcode(Size),
                Op::Push(width.into()),
                Op::Opcode(EqualVerify),
            ]);
            if depth > 0 {
                asm.push(Op::Opcode(Drop));
            }
        }
        let constructor_scope = types::build_scope_with_structs(constructor_parameters, structs);
        let mut scope = constructor_scope.clone();
        scope.extend(types::build_scope_with_structs(
            function_parameters,
            structs,
        ));
        Ok(Self {
            optimize: false,
            asm,
            max_depth: stack.len(),
            stack,
            scopes: Vec::new(),
            deferred: std::collections::HashSet::new(),
            constructor_expansions,
            structs: structs.to_vec(),
            scope,
            constructor_scope,
            functions: Vec::new(),
            inlined,
            constructor_reads: std::collections::HashMap::new(),
            aliases: std::collections::HashMap::new(),
            return_type: None,
            direct_return: false,
            final_reads: Vec::new(),
            last_reads: std::collections::HashMap::new(),
            read_cursor: None,
            preserve_bindings: false,
            pinned_stack_len: 0,
            replacement: None,
        })
    }

    fn lower_raw_opcode(&mut self, opcode: Opcode) -> Result<(), String> {
        match opcode {
            // These move bindings as well as temporaries.
            Nip => self.nip(),
            Swap => self.swap(),
            Tunnel => {
                // Fixed exception counts are emitted immediately before the opcode.
                let inputs = self
                    .asm
                    .last()
                    .and_then(|count| match count {
                        Op::Push(count) => count.parse::<usize>().ok(),
                        _ => None,
                    })
                    .and_then(|count| count.checked_mul(2)?.checked_add(3))
                    .ok_or("invalid tunnel exception count")?;
                self.apply(opcode, inputs, 1)
            }
            _ => {
                let (inputs, outputs) = opcode.stack_effect().ok_or_else(|| {
                    format!("internal compiler error: unknown expression opcode {opcode}")
                })?;
                self.apply(opcode, inputs, outputs)
            }
        }
    }

    fn lower_op(&mut self, op: Op) -> Result<(), String> {
        match op {
            Op::Opcode(opcode) => self.lower_raw_opcode(opcode),
            Op::Push(value) => {
                self.push_temporary(Op::Push(value));
                Ok(())
            }
            Op::Read(path) => self.read_binding(&path),
            Op::ArrayElement(array) => self.select_indexed_value(&array),
            Op::Contract { name, args } => {
                let args = args
                    .into_iter()
                    .flat_map(|arg| {
                        let expansion = match arg.as_slice() {
                            [Op::Param(param)] => self
                                .constructor_expansions
                                .iter()
                                .find(|(name, _)| name == param),
                            _ => None,
                        };
                        match expansion {
                            Some((_, placeholders)) => placeholders
                                .iter()
                                .map(|placeholder| vec![Op::Param(placeholder.clone())])
                                .collect(),
                            None => vec![arg],
                        }
                    })
                    .collect();
                self.push_temporary(Op::Contract { name, args });
                Ok(())
            }
            Op::Value(_) => {
                Err("internal compiler error: extracted value outside an expression".to_string())
            }
            Op::Param(_) => Err(
                "internal compiler error: constructor parameter inside an expression".to_string(),
            ),
        }
    }

    fn emit_expression(&mut self, expression: &Expression) -> Result<(), String> {
        if matches!(&expression.kind, ExprKind::ArrayLiteral(_)) {
            return Err(
                "array literals may only initialize an array declaration; composite values are not supported"
                    .to_string(),
            );
        }
        if matches!(&expression.kind, ExprKind::StructLiteral(_)) {
            return Err(
                "struct literals may only initialize a typed struct declaration; composite values are not supported"
                    .to_string(),
            );
        }
        self.emit_expression_items(expression, 1)
    }

    fn emit_expression_items(
        &mut self,
        expression: &Expression,
        expected: usize,
    ) -> Result<(), String> {
        // Counts temporaries instead of a stack watermark: a consuming read can
        // remove a binding below the watermark, so only the top `expected` items
        // are checked for being temporaries.
        let before = self
            .stack
            .iter()
            .filter(|item| matches!(item, StackItem::Temporary))
            .count();
        let mut raw = Vec::new();
        let mut expression = expression.clone();
        let mut values = Vec::new();
        functions::extract_values(&mut expression, &mut values);
        emit_expression_asm(&expression, &mut raw);
        // ponytail: short-circuit joins need identical layouts, so reads inside an open branch stay
        // copies and leave their slots to the final cleanup; moving them needs path-sensitive liveness.
        let preserved = self.preserve_bindings;
        let mut branches = Vec::new();
        for op in raw {
            self.preserve_bindings = preserved || !branches.is_empty();
            match op {
                Op::Opcode(If) => {
                    self.apply(If, 1, 0)?;
                    branches.push(self.stack.clone());
                }
                Op::Opcode(token @ (Else | EndIf)) => {
                    self.pop_temporaries(1, token)?;
                    if branches.last() != Some(&self.stack) {
                        return Err(
                            "logical branch must produce exactly one stack item".to_string()
                        );
                    }
                    if token == EndIf {
                        branches.pop();
                        self.stack.push(StackItem::Temporary);
                    }
                    self.asm.push(Op::Opcode(token));
                }
                Op::Value(index) => {
                    let value = values.get(index).ok_or("invalid call marker")?;
                    if matches!(&value.kind, ExprKind::Call { .. }) {
                        self.emit_call(value)?;
                    } else if matches!(&value.kind, ExprKind::Builtin { builtin, .. } if matches!(builtin.lowering, crate::builtins::Lowering::Pairing))
                    {
                        self.emit_pairing(value)?;
                    } else if matches!(&value.kind, ExprKind::Builtin { builtin, .. } if matches!(builtin.lowering, crate::builtins::Lowering::Multisig))
                    {
                        self.emit_multisig(value)?;
                    } else if matches!(
                        &value.kind,
                        ExprKind::GroupIOAccess {
                            source: crate::models::GroupIOSource::Inputs,
                            ..
                        }
                    ) {
                        self.emit_group_input(value)?;
                    } else {
                        let ty = value.ty.as_str();
                        self.emit_access_value(value, &ty)?;
                    }
                }
                op => self.lower_op(op)?,
            }
        }
        self.preserve_bindings = preserved;
        if !branches.is_empty() {
            return Err("unclosed logical branch".to_string());
        }
        let after = self
            .stack
            .iter()
            .filter(|item| matches!(item, StackItem::Temporary))
            .count();
        if after != before + expected
            || self
                .stack
                .iter()
                .rev()
                .take(expected)
                .any(|item| !matches!(item, StackItem::Temporary))
        {
            return Err(format!(
                "expression produces {} stack items; exactly {expected} required",
                after.saturating_sub(before),
            ));
        }
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<Op>, String> {
        if !self.scopes.is_empty() {
            return Err("internal compiler error: unbalanced generator scope".to_string());
        }
        self.push_temporary(Op::Opcode(Int1));
        while self.stack.len() > 1 {
            self.nip()?;
        }
        if self.stack != vec![StackItem::Temporary] {
            return Err("internal compiler error: covenant did not finish cleanly".to_string());
        }
        Ok(self.asm)
    }
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
    crate::imports::compile_sources(
        "main.ark",
        &std::collections::BTreeMap::from([("main.ark".to_string(), source_code.to_string())]),
        crate::CompileOptions::default(),
    )
}

/// Runs semantic validation, including type checking, on `contract`. Returns every
/// warning on success, every error (each its own diagnostic, not joined into
/// one message) on failure. Diagnostic messages carry no location prefix —
/// `Diagnostic::span` is the byte range; `diagnostics::render_errors` adds a
/// `"line N, column M: "` prefix only when rendering the legacy joined string.
pub(crate) fn prepare(
    contract: &mut Contract,
    require_entrypoint: bool,
    file: &str,
) -> Result<Vec<Diagnostic>, Vec<Diagnostic>> {
    types::annotate(contract);

    // ── Semantic validation ────────────────────────────────────────────────
    // Catch errors the PEG grammar cannot express (duplicate names, missing
    // timelocks, etc.) before we attempt code generation.
    let ast_issues = validator::validate_ast(contract, require_entrypoint);
    if validator::has_errors(&ast_issues) {
        return Err(ast_issues
            .iter()
            .filter(|i| matches!(i.severity, Severity::Error))
            .map(|i| {
                Diagnostic::error(file, i.message.clone())
                    .with_code(i.code)
                    .with_span(i.span)
            })
            .collect());
    }
    let leaf_errors: Vec<_> = contract
        .tapscripts
        .iter()
        .filter_map(|ts| tapscript::check_tapscript(contract, ts).err())
        .map(|message| Diagnostic::error(file, message).with_code("validation"))
        .collect();
    if !leaf_errors.is_empty() {
        return Err(leaf_errors);
    }
    let mut warnings = Vec::new();

    // Append any non-fatal validation warnings (e.g. renew=0)
    for issue in &ast_issues {
        if matches!(issue.severity, Severity::Warning) {
            warnings.push(
                Diagnostic::warning(file, issue.message.clone())
                    .with_code(issue.code)
                    .with_span(issue.span),
            );
        }
    }

    Ok(warnings)
}

pub(crate) fn emit(
    contract: &Contract,
    source: crate::models::SourceBundle,
    warnings: Vec<String>,
    options: crate::CompileOptions,
) -> Result<ContractJson, String> {
    let parameters = contract.parameters.clone();

    let mut json = ContractJson {
        format_version: Some(crate::models::ARTIFACT_FORMAT_VERSION),
        name: contract.name.clone(),
        structs: contract.structs.clone(),
        parameters,
        functions: Vec::new(),
        source: Some(source),
        compiler: Some(CompilerInfo {
            name: "arkadec".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            options: Some(options),
        }),
        updated_at: None,
        fingerprint: None,
        warnings,
    };

    // Build covenant objects for public functions.
    let mut covenants: std::collections::HashMap<String, ArkadeCovenant> =
        std::collections::HashMap::new();
    for function in contract.functions.iter().filter(|f| !f.is_private) {
        covenants.insert(
            function.name.clone(),
            covenant_for(
                function,
                &contract.parameters,
                &contract.structs,
                &contract.functions,
                options.optimize,
            )?,
        );
    }

    json.functions = tapscript::build_function_groups(contract, covenants)?;

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

    // Serialized field order is part of the fingerprint; reordering artifact fields changes it.
    let bytes = serde_json::to_vec(&json).map_err(|error| error.to_string())?;
    json.fingerprint = Some(format!("sha256:{:x}", Sha256::digest(bytes)));
    json.updated_at = Some(Utc::now().to_rfc3339());

    Ok(json)
}

/// The placeholder namespace a parameter list emits: array types (e.g.
/// `pubkey[3]`) flatten to `name.0`, `name.1`, `name.2`; every other param
/// passes through unchanged. This is the `<name>` namespace in `asm`, not the
/// artifact ABI, which keeps one entry per source parameter.
pub(crate) fn expanded_placeholder_params(
    params: &[Parameter],
    structs: &[crate::models::StructDefinition],
) -> Result<Vec<Parameter>, String> {
    let mut result = Vec::new();
    for param in params {
        for_each_expanded_param(param, structs, |name, _, param_type| {
            result.push(Parameter { name, param_type });
        })?;
    }
    Ok(result)
}

/// Build an `ArkadeCovenant` for a public function.
fn covenant_for(
    function: &Function,
    constructor_parameters: &[Parameter],
    structs: &[crate::models::StructDefinition],
    functions: &[Function],
    optimize: bool,
) -> Result<ArkadeCovenant, String> {
    let inputs = function_inputs(&function.parameters);
    let references =
        crate::validator::references::referenced_parameters(&function.statements, functions);
    let retained_parameters = constructor_parameters
        .iter()
        .filter(|parameter| references.contains(parameter.name.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !optimize {
        // ponytail: validate folded lowering with an extra emission pass; use a dedicated
        // validation walk if this becomes costly for large unoptimized contracts.
        let mut validation = Generator::new(
            &function.parameters,
            &retained_parameters,
            structs,
            &Default::default(),
        )?;
        validation.optimize = true;
        validation.functions = functions.to_vec();
        generate_asm_from_statements_recursive(&function.statements, &mut validation)?;
    }
    let mut counting = Generator::new(
        &function.parameters,
        &retained_parameters,
        structs,
        &Default::default(),
    )?;
    counting.optimize = optimize;
    counting.functions = functions.to_vec();
    generate_asm_from_statements_recursive(&function.statements, &mut counting)?;
    // A leaf read once costs no more as an inline push than as a prologue slot; an unread leaf is never pushed.
    let mut inlined = std::collections::HashSet::new();
    for parameter in &retained_parameters {
        for_each_expanded_param(parameter, structs, |_, binding_name, _| {
            if counting
                .constructor_reads
                .get(&binding_name)
                .copied()
                .unwrap_or(0)
                <= 1
            {
                inlined.insert(binding_name);
            }
        })?;
    }
    // Without inlined leaves the counting pass already has the emission layout.
    let analysis = if inlined.is_empty() {
        counting
    } else {
        let mut analysis = Generator::new(
            &function.parameters,
            &retained_parameters,
            structs,
            &inlined,
        )?;
        analysis.optimize = optimize;
        analysis.functions = functions.to_vec();
        generate_asm_from_statements_recursive(&function.statements, &mut analysis)?;
        analysis
    };
    let mut generator = Generator::new(
        &function.parameters,
        &retained_parameters,
        structs,
        &inlined,
    )?;
    generator.optimize = optimize;
    generator.functions = functions.to_vec();
    generator.final_reads = analysis.final_reads;
    generator.read_cursor = Some(0);
    generate_asm_from_statements_recursive(&function.statements, &mut generator)?;
    if generator.read_cursor != Some(generator.final_reads.len()) {
        return Err(
            "internal compiler error: final-use analysis diverged from emission".to_string(),
        );
    }
    if generator.max_depth > MAX_STACK_ITEMS {
        return Err(format!(
            "function '{}' can hold {} stack items, above the VM limit of {MAX_STACK_ITEMS}",
            function.name, generator.max_depth
        ));
    }
    let mut ops = generator.finish()?;
    if optimize {
        ops = optimization::optimize(ops);
    }
    let mut widths = std::collections::HashMap::new();
    for parameter in &retained_parameters {
        for leaf in crate::models::flatten_parameter(parameter, structs)? {
            let width = match types::ArkType::parse(&leaf.leaf_type) {
                types::ArkType::Signature => 64,
                types::ArkType::Bytes32 | types::ArkType::Asset => 32,
                types::ArkType::Bytes20 => 20,
                _ => 0,
            };
            widths.insert(leaf.emitted_name, width);
        }
    }
    let width = |name: &str| widths.get(name).copied().unwrap_or(0);
    let size: usize = ops.iter().map(|op| op.min_size(&width)).sum();
    if size > MAX_SCRIPT_SIZE {
        return Err(format!(
            "function '{}' assembles to at least {size} bytes, above the VM limit of {MAX_SCRIPT_SIZE}",
            function.name
        ));
    }
    let asm = ops.iter().map(Op::spell).collect();
    Ok(ArkadeCovenant { inputs, asm })
}

fn function_inputs(params: &[Parameter]) -> Vec<FunctionInput> {
    params
        .iter()
        .map(|param| FunctionInput {
            name: param.name.clone(),
            param_type: param.param_type.clone(),
        })
        .collect()
}

fn for_each_expanded_param(
    param: &Parameter,
    structs: &[crate::models::StructDefinition],
    mut f: impl FnMut(String, Path, String),
) -> Result<(), String> {
    for leaf in crate::models::flatten_parameter(param, structs)? {
        f(leaf.emitted_name, leaf.access, leaf.leaf_type);
    }
    Ok(())
}
