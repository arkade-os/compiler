//! Emits lowered statements onto the generator's stack model, joining both arms of a branch to
//! one stack layout.

use std::collections::HashSet;
use std::slice;

use super::ir::Op;
use super::lowering::{self, Lowered};
use super::{BindingKind, Generator, Result, StackItem};
use crate::builtins::Builtin;
use crate::builtins::Lowering::Check;
use crate::diagnostics::CompileError;
use crate::models::{
    self, AssignmentTarget, ExprKind, Expression, LocatedStatement, Path, Statement, TypeName,
};
use crate::opcodes::Opcode;
use crate::types;

impl Generator {
    pub(super) fn emit_branches(
        &mut self,
        then_body: &[Lowered],
        else_body: Option<&[Lowered]>,
        implicit_else_continues: bool,
    ) -> Result<bool> {
        let baseline = self.stack.clone();
        let deferred = self.deferred.clone();
        let start = self.asm.len();
        self.enter_scope();
        let left_continues = emit_body(then_body, self)?;
        self.exit_scope()?;
        let left = self.stack.clone();
        let left_deferred = self.deferred.clone();
        let left_asm = self.asm.split_off(start);
        self.stack = baseline.clone();
        self.deferred = deferred.clone();
        self.last_reads
            .retain(|(_, slot), _| *slot < baseline.len());
        // A return guard's absent branch has already returned and cannot continue.
        let right_continues = if let Some(body) = else_body {
            self.enter_scope();
            let continues = emit_body(body, self)?;
            self.exit_scope()?;
            continues
        } else {
            implicit_else_continues
        };
        let right = self.stack.clone();
        let right_deferred = self.deferred.clone();
        let right_asm = self.asm.split_off(start);
        let initialized: HashSet<_> = deferred
            .iter()
            .filter(|name| {
                (left_continues || right_continues)
                    && (!left_continues || !left_deferred.contains(*name))
                    && (!right_continues || !right_deferred.contains(*name))
            })
            .cloned()
            .collect();
        let mut initialized_leaves = HashSet::new();
        for name in &initialized {
            let ty = self
                .scope
                .get(name)
                .ok_or_else(|| CompileError::internal("missing declaration type"))?;
            for leaf in self.value_leaves(&Path::new(name), &TypeName::from(ty))? {
                initialized_leaves.insert(leaf.access);
            }
        }
        let mut target = baseline.clone();
        let preferred = if left_continues { &left } else { &right };
        target.extend(preferred.iter().skip(baseline.len()).filter(|item| {
            matches!(item, StackItem::Binding { name, .. } if initialized_leaves.contains(name))
        }).cloned());
        if !left.starts_with(&baseline) || !right.starts_with(&baseline) {
            return Err(CompileError::internal("branch changed outer stack layout"));
        }
        self.stack = left;
        self.asm.append(left_asm);
        self.join_stack(&target)?;
        let left_joined = self.asm.split_off(start);
        self.stack = right;
        self.asm.append(right_asm);
        self.join_stack(&target)?;
        let right_joined = self.asm.split_off(start);
        self.asm.append(left_joined);
        if else_body.is_some() || !right_joined.is_empty() {
            self.asm.push(Opcode::Else.into());
            self.asm.append(right_joined);
        }
        self.asm.push(Opcode::EndIf.into());
        self.deferred = deferred.difference(&initialized).cloned().collect();
        self.last_reads
            .retain(|(_, slot), _| *slot < baseline.len());
        Ok(left_continues || right_continues)
    }
}

/// Every push of a `hoisted` literal reads its binding instead. A binding serves several
/// statements, so, like the prologue, it maps to no statement.
// LIMITATION: only Arkade Scripts hoist; tapscript leaves are assembled elsewhere in the fixed
// closure shapes arkd matches, and could hoist only if arkd stopped matching those shapes.
pub(super) fn emit_function(
    body: &[Lowered],
    generator: &mut Generator,
    hoisted: &[String],
) -> Result<()> {
    for literal in hoisted {
        generator.push_temporary(Op::Push(literal.clone()));
        generator.stack.pop();
        generator.stack.push(StackItem::Binding {
            name: Path::new(literal.as_str()),
            kind: BindingKind::Constant,
        });
    }
    emit_body(body, generator)?;
    Ok(())
}

/// Whether an emitted path falls through.
pub(super) fn emit_body(body: &[Lowered], generator: &mut Generator) -> Result<bool> {
    let outer = generator.asm.span();
    let continues = emit_items(body, generator);
    generator.asm.set_span(outer);
    continues
}

fn emit_items(body: &[Lowered], generator: &mut Generator) -> Result<bool> {
    for (index, item) in body.iter().enumerate() {
        generator.asm.set_span(Some(item.span()));
        let continues = emit_lowered(item, generator).map_err(|error| error.at(item.span()))?;
        // A return leaves its value for the caller.
        if item.is_return() {
            return Ok(false);
        }
        generator.assert_statement_boundary()?;
        if !continues {
            return Ok(false);
        }
        if lowering::contains_return(slice::from_ref(item)) && index + 1 < body.len() {
            return generator.emit_unless_returned(&body[index + 1..]);
        }
    }
    Ok(true)
}

fn emit_lowered(item: &Lowered, generator: &mut Generator) -> Result<bool> {
    match item {
        Lowered::Simple(statement) => emit_statement(statement, generator),
        Lowered::If {
            condition,
            then_body,
            else_body,
            ..
        } => {
            // The branch opcodes map to the condition, not the whole statement.
            generator.asm.set_span(Some(condition.span));
            generator.emit_expression(condition)?;
            generator.apply(Opcode::If, 1, 0)?;
            generator.emit_branches(then_body, else_body.as_deref(), true)
        }
        Lowered::Unrolled {
            iterations,
            guarded,
            ..
        } => {
            let mut continues = true;
            for (k, iteration) in iterations.iter().enumerate() {
                let baseline = generator.stack.clone();
                generator.enter_scope();
                continues = if k > 0 && *guarded {
                    generator.emit_unless_returned(iteration)?
                } else {
                    emit_body(iteration, generator)?
                };
                generator.exit_scope()?;
                if !generator.stack.starts_with(&baseline) {
                    return Err(CompileError::internal(format!(
                        "loop iteration {k} changed outer stack layout"
                    )));
                }
            }
            Ok(continues)
        }
        Lowered::Bound {
            span,
            name,
            value,
            body,
        } => {
            let ty = TypeName::from(&value.ty);
            generator.enter_scope();
            // The value's opcodes map to the value, not the whole statement.
            generator.asm.set_span(Some(value.span));
            generator.emit_let(name, value, &ty)?;
            generator.asm.set_span(Some(*span));
            let continues = emit_body(body, generator)?;
            generator.exit_scope()?;
            Ok(continues)
        }
    }
}

fn emit_statement(stmt: &LocatedStatement, generator: &mut Generator) -> Result<bool> {
    match &stmt.statement {
        Statement::Call(expression) => generator.emit_call(expression)?,
        Statement::Return(value) => {
            generator.emit_return(value.as_ref())?;
            return Ok(false);
        }
        Statement::Require(condition) => generate_requirement_asm(condition, generator)?,
        Statement::IfElse { .. }
        | Statement::ForIn { .. }
        | Statement::ForCount { .. }
        | Statement::ForRange { .. } => {
            return Err(CompileError::internal(
                "control flow reached emission unlowered",
            ));
        }
        Statement::Declaration {
            name,
            declared_type,
        } => {
            generator.bind_type(name, declared_type);
            generator.deferred.insert(name.clone());
        }
        Statement::LetBinding {
            name,
            declared_type,
            value,
        } => {
            let result_type = declared_type
                .clone()
                .or_else(|| match &value.kind {
                    ExprKind::Call { return_type, .. } => return_type.clone(),
                    _ => models::expression_result_struct(value).map(TypeName::from),
                })
                .or_else(|| generator.composite_type(value));
            if let Some(ty) = &result_type {
                generator.emit_let(name, value, ty)?;
            } else {
                generator.emit_expression(value)?;
                generator.bind_local(Path::new(name))?;
                let ty = value.ty.clone();
                generator.scope.insert(name.clone(), ty);
            }
        }
        Statement::VarAssign { target, value } => {
            let previous_replacement = generator.replacement.take();
            // Deeper targets use OP_PUT; moving them needs scope and branch layout repair.
            generator.replacement = match (target, generator.stack.last()) {
                (AssignmentTarget::Binding(name), Some(StackItem::Binding { name: top, kind }))
                    if name == top
                        && *kind != BindingKind::Constructor
                        && !generator.preserve_bindings =>
                {
                    Some((
                        name.clone(),
                        kind.clone(),
                        generator.read_cursor.unwrap_or(generator.final_reads.len()),
                    ))
                }
                _ => None,
            };
            let mut access = value.with_kind(match target {
                AssignmentTarget::Binding(name) => ExprKind::Name(name.clone()),
                AssignmentTarget::ArrayIndex { array, index } => ExprKind::ArrayIndex {
                    array: array.clone(),
                    index: index.clone(),
                },
                AssignmentTarget::Access(access) => access.kind.clone(),
            });
            types::annotate_expression(&mut access, &generator.scope, &generator.structs);
            // Only a bare name can be declared without a value.
            if let AssignmentTarget::Binding(name) = target {
                if name.segments.is_empty() && generator.deferred.remove(&name.root) {
                    generator.emit_typed_value(value, &TypeName::from(&access.ty))?;
                    generator.bind_value(&name.key(), &TypeName::from(&access.ty))?;
                    generator.replacement = previous_replacement;
                    return Ok(true);
                }
            }
            if matches!(
                access.ty,
                types::ArkType::Struct(_) | types::ArkType::Array(..)
            ) {
                generator.emit_typed_value(value, &TypeName::from(&access.ty))?;
                generator.assign_access(&access)?;
            } else {
                generator.emit_expression(value)?;
                generator.assign(target)?;
            }
            generator.replacement = previous_replacement;
        }
    }
    Ok(true)
}

fn generate_requirement_asm(condition: &Expression, generator: &mut Generator) -> Result<()> {
    if let ExprKind::BinaryOp { left, op, right } = &condition.kind {
        let composite = generator
            .composite_type(left)
            .or_else(|| generator.composite_type(right));
        if let Some(ty) = composite.filter(|_| op.compares()) {
            return generator.emit_composite_comparison(left, *op, right, &ty, true);
        }
    }
    match &condition.kind {
        ExprKind::GroupLookup { .. } => {
            generator.emit_expression(condition)?;
            generator.apply(Opcode::Drop, 1, 0)?;
            generator.push_temporary(Opcode::Int1);
            generator.apply(Opcode::Verify, 1, 0)?;
        }
        // The check fails the spend itself, so `require` leaves out its `true`.
        ExprKind::Builtin {
            builtin:
                Builtin {
                    lowering: Check(opcodes),
                    ..
                },
            args,
        } => {
            for arg in args {
                generator.emit_expression(arg)?;
            }
            for &opcode in opcodes.iter() {
                generator.lower_raw_opcode(opcode)?;
            }
        }
        _ => {
            generator.emit_expression(condition)?;
            generator.apply(Opcode::Verify, 1, 0)?;
        }
    }
    Ok(())
}
