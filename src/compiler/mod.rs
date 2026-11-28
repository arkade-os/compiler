//! Code generation: turns a validated, typed contract into one Arkade Script per public function
//! and the artifact JSON. Each script ends with a single true item on its stack.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::result;

use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::builtins::Lowering;
use crate::diagnostics::{self, CompileError, Diagnostic, Span, Suggestion};
use crate::lint::{self, Lints};
use crate::models::{
    self, ArkadeScript, CompilerInfo, Contract, ContractJson, Cost, ExprKind, Expression, Function,
    FunctionInput, GroupIOSource, LocatedStatement, Parameter, Path, SourceBundle, SourceRange,
    Statement, StructDefinition, TypeName, ARTIFACT_FORMAT_VERSION,
};
use crate::opcodes::Opcode;
use crate::validator::{self, references};
use crate::{imports, types};
use error::{CompileErrorKind, InternalError};

pub mod tapscript;

type Result<T, E = CompileError> = result::Result<T, E>;

mod access;
mod asset;
mod comparison;
pub(crate) mod constants;
pub(crate) mod error;
pub(crate) use constants::{fold as fold_constants, resolve as resolve_constants};
mod expr;
mod functions;
mod ir;
pub(crate) use ir::{Op, Spanned};
mod introspection;
mod loops;
mod lowering;
mod optimization;
mod stack;
mod statements;
use statements::{emit_body, emit_function};

#[derive(Clone, Debug, PartialEq, Eq)]
enum BindingKind {
    Constructor,
    FunctionInput,
    Local,
    /// A wide literal bound once and read wherever the function would push it, static helpers
    /// included. It is bound under the literal's own text, which no source name can collide with.
    Constant,
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
/// Iterations a loop and the loops nested in it may unroll, checked before unrolling. An
/// iteration can emit no bytes, so `MAX_SCRIPT_SIZE` alone does not bound the work.
pub(crate) const MAX_LOOP_ITERATIONS: usize = 10_000;
/// Bytes the VM allows in one stack element (`txscript.MaxScriptElementSize`).
const MAX_ELEMENT_SIZE: usize = 520;

/// A binding on the top slot that the assignment being emitted rebinds in place.
#[derive(Clone)]
struct Replacement {
    target: Path,
    kind: BindingKind,
    start: usize,
}

struct Generator {
    optimize: bool,
    asm: ir::Assembly,
    stack: Vec<StackItem>,
    /// The most items the stacks hold at once, data and alt together.
    max_depth: usize,
    scopes: Vec<(usize, types::Scope)>,
    deferred: HashSet<String>,
    /// Composite constructor parameters and their leaf placeholders, so `new` can pass one whole.
    constructor_expansions: Vec<(String, Vec<String>)>,
    structs: Vec<StructDefinition>,
    scope: types::Scope,
    constructor_scope: types::Scope,
    functions: Vec<Function>,
    // Constructor leaves pushed at their single read instead of in the prologue.
    inlined: HashMap<Path, String>,
    // Emitted reads per constructor slot; runtime-indexed slots count as two.
    constructor_reads: HashMap<Path, usize>,
    // Read-only scalar parameters can name slots in the pinned caller frame.
    aliases: HashMap<Path, usize>,
    // None outside a helper; Some(None) inside a void helper.
    return_type: Option<Option<TypeName>>,
    direct_return: bool,
    // Record reads once, then replay final uses at their new stack depths.
    final_reads: Vec<bool>,
    last_reads: HashMap<(Path, usize), usize>,
    read_cursor: Option<usize>,
    preserve_bindings: bool,
    pinned_stack_len: usize,
    replacement: Option<Replacement>,
    /// How often each literal that takes 4 or more bytes is pushed.
    wide_pushes: BTreeMap<String, usize>,
}

impl Generator {
    fn new(
        function_parameters: &[Parameter],
        constructor_parameters: &[Parameter],
        structs: &[StructDefinition],
        inlined_bindings: &HashSet<Path>,
    ) -> Result<Self> {
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
        let mut asm = ir::Assembly::default();
        let mut inlined = HashMap::new();
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
        // Witness inputs carry any bytes; pin fixed-width and bool ones before the body reads them.
        let prologue = asm.len();
        let mut prologue_peak = 0;
        for (index, (_, leaf_type)) in function_bindings.iter().enumerate() {
            let depth = prologue + index;
            let width = match leaf_type.ark_type() {
                types::ArkType::Bytes20 => "20",
                types::ArkType::Bytes32 => "32",
                types::ArkType::Bool => {
                    // Only empty and 0x01 equal their own 0NOTEQUAL, so `require`, `if` and `==` agree.
                    prologue_peak = prologue_peak.max(2);
                    asm.extend(match depth {
                        0 => vec![Opcode::Dup.into()],
                        _ => vec![Op::push_int(depth), Opcode::Pick.into()],
                    });
                    asm.extend([
                        Opcode::Dup.into(),
                        Opcode::NotEqual0.into(),
                        Opcode::EqualVerify.into(),
                    ]);
                    continue;
                }
                _ => continue,
            };
            // Extra items at the peak: the picked copy (only when depth > 0), its size and the
            // expected width.
            prologue_peak = prologue_peak.max(2 + usize::from(depth > 0));
            if depth > 0 {
                asm.extend([Op::push_int(depth), Opcode::Pick.into()]);
            }
            asm.extend([
                Opcode::Size.into(),
                Op::Push(width.into()),
                Opcode::EqualVerify.into(),
            ]);
            if depth > 0 {
                asm.push(Opcode::Drop.into());
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
            max_depth: stack.len() + prologue_peak,
            stack,
            scopes: Vec::new(),
            deferred: HashSet::new(),
            constructor_expansions,
            structs: structs.to_vec(),
            scope,
            constructor_scope,
            functions: Vec::new(),
            inlined,
            constructor_reads: HashMap::new(),
            aliases: HashMap::new(),
            return_type: None,
            direct_return: false,
            final_reads: Vec::new(),
            last_reads: HashMap::new(),
            read_cursor: None,
            preserve_bindings: false,
            pinned_stack_len: 0,
            replacement: None,
            wide_pushes: Default::default(),
        })
    }

    fn lower_raw_opcode(&mut self, opcode: Opcode) -> Result<()> {
        match opcode {
            // NIP and SWAP can move bindings, not only temporaries, so they keep their own stack
            // bookkeeping.
            Opcode::Nip => self.nip(),
            Opcode::Swap => self.swap(),
            Opcode::Tunnel => {
                // Fixed exception counts are emitted immediately before the opcode.
                let inputs = self
                    .asm
                    .last()
                    .and_then(|count| match count {
                        Op::Push(count) => count.parse::<usize>().ok(),
                        _ => None,
                    })
                    .and_then(|count| count.checked_mul(2)?.checked_add(3))
                    .ok_or(CompileErrorKind::InvalidTunnelExceptionCount)?;
                self.apply(opcode, inputs, 1)
            }
            _ => {
                let (inputs, outputs) = opcode
                    .stack_effect()
                    .ok_or(InternalError::UnknownExpressionOpcode { opcode })?;
                self.apply(opcode, inputs, outputs)
            }
        }
    }

    fn lower_op(&mut self, op: Op) -> Result<()> {
        match op {
            Op::Opcode(opcode) => self.lower_raw_opcode(opcode),
            Op::Push(value) => {
                let op = Op::Push(value.clone());
                if op.pushes_more_than(3) {
                    let hoisted = Path::new(value.as_str());
                    if self.binding_index(&hoisted).is_some() {
                        return self.read_static_binding(&hoisted, false);
                    }
                    *self.wide_pushes.entry(value).or_default() += 1;
                }
                self.push_temporary(op);
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
            Op::Value(_) => Err(InternalError::ValueOutsideExpression.into()),
            Op::Param(_) => Err(InternalError::ParameterInsideExpression.into()),
        }
    }

    fn emit_expression(&mut self, expression: &Expression) -> Result<()> {
        if matches!(&expression.kind, ExprKind::ArrayLiteral(_)) {
            return Err(CompileErrorKind::CompositeArrayLiteral.into());
        }
        if matches!(&expression.kind, ExprKind::StructLiteral { .. }) {
            return Err(CompileErrorKind::CompositeStructLiteral.into());
        }
        self.emit_expression_items(expression, 1)
    }

    fn emit_expression_items(&mut self, expression: &Expression, expected: usize) -> Result<()> {
        // Counts temporaries instead of a stack watermark: a consuming read can remove a
        // binding below the watermark.
        let before = self
            .stack
            .iter()
            .filter(|item| matches!(item, StackItem::Temporary))
            .count();
        let mut raw = Vec::new();
        let mut expression = expression.clone();
        let mut values = Vec::new();
        functions::extract_values(&mut expression, &mut values);
        expr::emit_expression_asm(&expression, &mut raw);
        // LIMITATION: short-circuit joins need identical layouts, so reads inside an open branch stay
        // copies and leave their slots to the final cleanup; moving them needs path-sensitive liveness.
        let preserved = self.preserve_bindings;
        let mut branches = Vec::new();
        for op in raw {
            self.preserve_bindings = preserved || !branches.is_empty();
            match op {
                Op::Opcode(Opcode::If) => {
                    self.apply(Opcode::If, 1, 0)?;
                    branches.push(self.stack.clone());
                }
                Op::Opcode(token @ (Opcode::Else | Opcode::EndIf)) => {
                    self.pop_temporaries(1, token)?;
                    if branches.last() != Some(&self.stack) {
                        return Err(CompileErrorKind::LogicalBranchItems.into());
                    }
                    if token == Opcode::EndIf {
                        branches.pop();
                        self.stack.push(StackItem::Temporary);
                    }
                    self.asm.push(token.into());
                }
                Op::Value(index) => {
                    let value = values
                        .get(index)
                        .ok_or(CompileErrorKind::InvalidCallMarker)?;
                    if let ExprKind::BinaryOp { left, op, right } = &value.kind {
                        let ty = self
                            .composite_type(left)
                            .or_else(|| self.composite_type(right))
                            .ok_or(CompileErrorKind::InvalidComparisonMarker)?;
                        self.emit_composite_comparison(left, *op, right, &ty, false)?;
                    } else if matches!(&value.kind, ExprKind::Call { .. }) {
                        self.emit_call(value)?;
                    } else if matches!(&value.kind, ExprKind::Builtin { builtin, .. } if matches!(builtin.lowering, Lowering::Pairing))
                    {
                        self.emit_pairing(value)?;
                    } else if matches!(&value.kind, ExprKind::Builtin { builtin, .. } if matches!(builtin.lowering, Lowering::Multisig))
                    {
                        self.emit_multisig(value)?;
                    } else if matches!(
                        &value.kind,
                        ExprKind::GroupIOAccess {
                            source: GroupIOSource::Inputs,
                            ..
                        }
                    ) {
                        self.emit_group_input(value)?;
                    } else {
                        self.emit_access_value(value, &TypeName::from(&value.ty))?;
                    }
                }
                op => self.lower_op(op)?,
            }
        }
        self.preserve_bindings = preserved;
        if !branches.is_empty() {
            return Err(CompileErrorKind::UnclosedLogicalBranch.into());
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
            return Err(CompileErrorKind::ExpressionItems {
                produced: after.saturating_sub(before),
                expected,
            }
            .into());
        }
        Ok(())
    }

    /// The Arkade Script's instructions, each with its statement's span, and its stack peak.
    fn finish(mut self) -> Result<(Vec<Spanned>, usize)> {
        if !self.scopes.is_empty() {
            return Err(InternalError::UnbalancedScope.into());
        }
        self.asm.set_span(None);
        self.push_temporary(Opcode::Int1);
        while self.stack.len() > 1 {
            self.nip()?;
        }
        if self.stack != vec![StackItem::Temporary] {
            return Err(InternalError::UnfinishedScript.into());
        }
        Ok((self.asm.into_spanned(), self.max_depth))
    }
}

pub fn compile(source_code: &str) -> Result<ContractJson, String> {
    imports::compile_sources(
        "main.ark",
        &BTreeMap::from([("main.ark".to_string(), source_code.to_string())]),
        crate::CompileOptions::default(),
    )
}

/// A validated contract's warnings and its checked tapscript leaves, in declaration order.
pub(crate) struct Prepared {
    pub lints: Lints,
    pub leaves: Vec<tapscript::CheckedLeaf>,
}

/// Every error is its own diagnostic, with no location prefix in its message;
/// `diagnostics::render_errors` adds `line N, column M: ` when it joins them.
pub(crate) fn prepare(
    contract: &mut Contract,
    require_entrypoint: bool,
    file: &str,
) -> Result<Prepared, Vec<Diagnostic>> {
    types::annotate(contract);
    let ast_issues = validator::validate_ast(contract, require_entrypoint);
    if !ast_issues.is_empty() {
        return Err(ast_issues
            .iter()
            .map(|i| {
                let suggestions = i.suggestion.iter().filter_map(|suggestion| {
                    Some(Suggestion {
                        message: format!("replace with '{}'", suggestion.replacement),
                        span: suggestion.span.or(i.span)?,
                        replacement: suggestion.replacement.clone(),
                    })
                });
                Diagnostic::error(file, i.to_string())
                    .with_code(i.kind.code())
                    .with_span(i.span)
                    .with_suggestions(suggestions.collect())
            })
            .collect());
    }
    let mut leaves = Vec::new();
    let mut leaf_errors = Vec::new();
    for ts in &contract.tapscripts {
        match tapscript::check_tapscript(contract, ts) {
            Ok(leaf) => leaves.push(leaf),
            Err(error) => leaf_errors.push(
                Diagnostic::error(file, error.to_string())
                    .with_code("validation")
                    .with_span(ts.span),
            ),
        }
    }
    if !leaf_errors.is_empty() {
        return Err(leaf_errors);
    }
    Ok(Prepared {
        lints: lint::check(contract),
        leaves,
    })
}

pub(crate) fn emit(
    contract: &Contract,
    leaves: &[tapscript::CheckedLeaf],
    source: SourceBundle,
    warnings: Vec<String>,
    options: crate::CompileOptions,
    code_hash: &mut dyn FnMut(&str) -> Result<String>,
) -> Result<ContractJson> {
    let parameters = contract.parameters.clone();
    let entry_source = source.files.get(&source.entry).cloned().unwrap_or_default();
    let mut messages = HashMap::new();
    for function in contract.functions.iter().filter(|f| !f.is_imported()) {
        require_messages(&function.statements, &mut messages);
    }

    let mut json = ContractJson {
        format_version: ARTIFACT_FORMAT_VERSION,
        name: contract.name.clone(),
        structs: contract.structs.clone(),
        parameters,
        functions: Vec::new(),
        contracts: Default::default(),
        code_hash: None,
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

    let mut scripts: HashMap<String, ArkadeScript> = HashMap::new();
    for function in contract.functions.iter().filter(|f| !f.is_private) {
        scripts.insert(
            function.name.clone(),
            arkade_script_for(
                function,
                &contract.parameters,
                &contract.structs,
                &contract.functions,
                options.optimize,
            )
            .map(|(inputs, ops, costs)| ArkadeScript {
                inputs,
                asm: ops.iter().map(|(op, _)| op.spell()).collect(),
                source_map: source_map(&ops, &entry_source, &messages),
                costs,
            })
            .map_err(|error| error.at(function.span))?,
        );
    }

    json.functions = tapscript::build_function_groups(contract, leaves, scripts)?;

    let output_issues = validator::validate_output(&json);
    if !output_issues.is_empty() {
        return Err(CompileErrorKind::OutputValidation {
            errors: output_issues,
        }
        .into());
    }
    let instantiated: BTreeSet<String> = json
        .functions
        .iter()
        .filter_map(|group| group.arkade.as_ref())
        .flat_map(|arkade| &arkade.asm)
        .filter_map(|token| Some(token.strip_prefix("<CONTRACT:")?.split_once('(')?.0.into()))
        .collect();
    for name in instantiated {
        let hash = code_hash(&name)?;
        json.contracts.insert(name, hash);
    }
    // Serialized field order is part of both hashes; reordering artifact fields changes them.
    let sha256 = |json: &ContractJson| -> Result<String> {
        let bytes = serde_json::to_vec(json).map_err(|error| CompileErrorKind::Serialize {
            message: error.to_string(),
        })?;
        let digest = Sha256::digest(bytes);
        Ok(format!(
            "sha256:{}",
            digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ))
    };
    let (source, compiler) = (json.source.take(), json.compiler.take());
    json.code_hash = Some(sha256(&json)?);
    (json.source, json.compiler) = (source, compiler);
    json.fingerprint = Some(sha256(&json)?);
    json.updated_at = Some(Utc::now().to_rfc3339());

    Ok(json)
}

/// The `<name>` placeholders `asm` uses, where a composite parameter flattens (`pubkey[3]` to
/// `name.0`, `name.1`, `name.2`); the artifact ABI keeps one entry per source parameter.
pub(crate) fn expanded_placeholder_params(
    params: &[Parameter],
    structs: &[StructDefinition],
) -> Result<Vec<Parameter>> {
    let mut result = Vec::new();
    for param in params {
        for_each_expanded_param(param, structs, |name, _, param_type| {
            result.push(Parameter {
                span: Default::default(),
                name,
                param_type,
            });
        })?;
    }
    Ok(result)
}

/// Compute budgets are deployment-configurable; compare the reported counts with the target
/// emulator's limits rather than enforcing defaults here.
fn arkade_script_for(
    function: &Function,
    constructor_parameters: &[Parameter],
    structs: &[StructDefinition],
    functions: &[Function],
    optimize: bool,
) -> Result<(Vec<FunctionInput>, Vec<Spanned>, Vec<Cost>)> {
    let inputs = function_inputs(&function.parameters);
    let references = references::referenced_parameters(&function.statements, functions);
    let retained_parameters = constructor_parameters
        .iter()
        .filter(|parameter| references.contains(parameter.name.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let new = |inlined: &HashSet<Path>| -> Result<Generator> {
        let mut generator =
            Generator::new(&function.parameters, &retained_parameters, structs, inlined)?;
        generator.optimize = optimize;
        generator.functions = functions.to_vec();
        Ok(generator)
    };
    let mut counting = new(&Default::default())?;
    if !optimize {
        let mut checked = HashSet::new();
        lowering::check_folded(
            &function.statements,
            &counting.scope,
            &counting.constructor_scope,
            structs,
            functions,
            &mut checked,
        )?;
    }
    let body = counting.lower(&function.statements)?;
    emit_body(&body, &mut counting)?;
    // A leaf read once costs no more as an inline push than as a prologue slot; an unread leaf is never pushed.
    let mut inlined = HashSet::new();
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
    // A wide literal is bound once when its pushes cost more than one push, a 3-byte read per
    // use and a final drop.
    let hoisted: Vec<_> = counting
        .wide_pushes
        .iter()
        .filter(|&(literal, &uses)| {
            let width = Op::Push(literal.to_string()).min_size(&|_| 0);
            optimize && uses * width > width + 3 * uses + 1
        })
        .map(|(literal, _)| literal.clone())
        .collect();
    let emit = |analysis: Generator, hoisted: &[String]| -> Result<(Vec<Spanned>, usize)> {
        let mut generator = new(&inlined)?;
        generator.final_reads = analysis.final_reads;
        generator.read_cursor = Some(0);
        emit_function(&body, &mut generator, hoisted)?;
        if generator.read_cursor != Some(generator.final_reads.len()) {
            return Err(InternalError::FinalUseDiverged.into());
        }
        let (mut ops, mut peak) = generator.finish()?;
        if optimize {
            let (optimized, raise) = optimization::optimize(ops);
            ops = optimized;
            peak += raise;
        }
        Ok((ops, peak))
    };
    // Without inlined leaves the counting pass already has the emission layout.
    let analysis = if inlined.is_empty() {
        counting
    } else {
        let mut analysis = new(&inlined)?;
        emit_body(&body, &mut analysis)?;
        analysis
    };
    let (mut ops, mut peak) = emit(analysis, &[])?;
    let mut widths = HashMap::new();
    for parameter in &retained_parameters {
        for leaf in
            models::flatten_value(&Path::new(&parameter.name), &parameter.param_type, structs)?
        {
            let width = match leaf.leaf_type.ark_type() {
                types::ArkType::Signature => 64,
                types::ArkType::Bytes32 => 32,
                types::ArkType::Bytes20 => 20,
                _ => 0,
            };
            widths.insert(leaf.emitted_name, width);
        }
    }
    let width = |name: &str| widths.get(name).copied().unwrap_or(0);
    // A lower bound: a variable-width parameter counts as its shortest push, so an instance
    // with long values can still exceed the limit.
    let size_of =
        |ops: &[Spanned]| -> usize { ops.iter().map(|(op, _)| op.min_size(&width)).sum() };
    // Bound at the start, the literals sit below every local, so assigning the top local still
    // replaces it in place. They deepen reads of the inputs below them, so they are kept only
    // when the script gets smaller.
    if !hoisted.is_empty() {
        let mut analysis = new(&inlined)?;
        emit_function(&body, &mut analysis, &hoisted)?;
        let (hoisted_ops, hoisted_peak) = emit(analysis, &hoisted)?;
        if size_of(&hoisted_ops) < size_of(&ops) && hoisted_peak <= MAX_STACK_ITEMS {
            (ops, peak) = (hoisted_ops, hoisted_peak);
        }
    }
    if peak > MAX_STACK_ITEMS {
        return Err(CompileErrorKind::StackLimit {
            function: function.name.clone(),
            peak,
        }
        .into());
    }
    let size = size_of(&ops);
    if size > MAX_SCRIPT_SIZE {
        return Err(CompileErrorKind::ScriptSizeLimit {
            function: function.name.clone(),
            size,
        }
        .into());
    }
    if ops
        .iter()
        .any(|(op, _)| op.pushes_more_than(MAX_ELEMENT_SIZE))
    {
        return Err(CompileErrorKind::ElementSizeLimit {
            function: function.name.clone(),
        }
        .into());
    }
    let mut executions = most_executions(&ops, &mut 0);
    // Conditional opcodes execute even inside skipped branches.
    for (op, _) in &ops {
        if let Op::Opcode(opcode @ (Opcode::If | Opcode::Else | Opcode::EndIf)) = op {
            *executions.entry(*opcode).or_default() += 1;
        }
    }
    let cost = |name: &str, used| Cost {
        name: name.to_string(),
        used,
    };
    let mut costs = vec![
        cost("script bytes (min)", size),
        cost("stack items (peak)", peak),
    ];
    let mut executions: Vec<_> = executions.into_iter().collect();
    executions.sort_unstable_by_key(|(opcode, _)| opcode.name());
    for (opcode, count) in executions {
        costs.push(cost(opcode.name(), count));
    }
    Ok((inputs, ops, costs))
}

/// Runs of `ops` from one statement, located in `source`.
fn source_map(ops: &[Spanned], source: &str, messages: &HashMap<Span, String>) -> Vec<SourceRange> {
    let mut ranges: Vec<(Span, SourceRange)> = Vec::new();
    for (index, (_, span)) in ops.iter().enumerate() {
        let Some(span) = *span else {
            continue;
        };
        if let Some((last, range)) = ranges.last_mut() {
            if *last == span && range.asm[1] == index {
                range.asm[1] += 1;
                continue;
            }
        }
        let position = |offset| diagnostics::position(source, offset).map(<[usize; 2]>::from);
        let (Some(start), Some(end)) = (position(span.start), position(span.end)) else {
            continue;
        };
        let message = messages.get(&span).cloned();
        let range = SourceRange {
            asm: [index, index + 1],
            start,
            end,
            message,
        };
        ranges.push((span, range));
    }
    ranges.into_iter().map(|(_, range)| range).collect()
}

fn require_messages(statements: &[LocatedStatement], messages: &mut HashMap<Span, String>) {
    for statement in statements {
        if let Some(message) = &statement.message {
            messages.insert(statement.span, message.clone());
        }
        match &statement.statement {
            Statement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                require_messages(then_body, messages);
                require_messages(else_body.as_deref().unwrap_or_default(), messages);
            }
            Statement::ForIn { body, .. }
            | Statement::ForCount { body, .. }
            | Statement::ForRange { body, .. } => require_messages(body, messages),
            _ => {}
        }
    }
}

/// An upper bound on executions of each non-conditional opcode from `position` to the
/// enclosing `Else` or `EndIf`. Correlated branch conditions are counted independently.
fn most_executions(ops: &[Spanned], position: &mut usize) -> HashMap<Opcode, usize> {
    let mut counts = HashMap::new();
    while let Some((op, _)) = ops.get(*position) {
        match op {
            Op::Opcode(Opcode::Else | Opcode::EndIf) => break,
            Op::Opcode(Opcode::If) => {
                *position += 1;
                let mut branch = most_executions(ops, position);
                if matches!(ops.get(*position), Some((Op::Opcode(Opcode::Else), _))) {
                    *position += 1;
                    for (opcode, count) in most_executions(ops, position) {
                        let longest = branch.entry(opcode).or_default();
                        *longest = (*longest).max(count);
                    }
                }
                for (opcode, count) in branch {
                    *counts.entry(opcode).or_default() += count;
                }
            }
            Op::Opcode(opcode) => *counts.entry(*opcode).or_default() += 1,
            _ => {}
        }
        *position += 1;
    }
    counts
}

fn function_inputs(params: &[Parameter]) -> Vec<FunctionInput> {
    params
        .iter()
        .map(|param| FunctionInput {
            name: param.name.clone(),
            param_type: param.param_type.to_string(),
        })
        .collect()
}

fn for_each_expanded_param(
    param: &Parameter,
    structs: &[StructDefinition],
    mut f: impl FnMut(String, Path, TypeName),
) -> Result<()> {
    for leaf in models::flatten_value(&Path::new(&param.name), &param.param_type, structs)? {
        f(leaf.emitted_name, leaf.access, leaf.leaf_type);
    }
    Ok(())
}
