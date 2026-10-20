use super::*;
use crate::models::{child_exprs_mut, TypeLeaf, TypeName};

pub(super) fn extract_values(expression: &mut Expression, values: &mut Vec<Expression>) {
    if matches!(
        &expression.kind,
        ExprKind::Call { .. } | ExprKind::FieldAccess { .. } | ExprKind::IndexAccess { .. }
    ) || matches!(&expression.kind, ExprKind::Builtin { builtin, .. } if matches!(builtin.lowering, crate::builtins::Lowering::Pairing | crate::builtins::Lowering::Multisig))
        || matches!(
            &expression.kind,
            ExprKind::GroupIOAccess {
                source: crate::models::GroupIOSource::Inputs,
                ..
            }
        )
        || (matches!(&expression.kind, ExprKind::ArrayIndex { .. })
            && matches!(
                expression.ty,
                types::ArkType::Array(..) | types::ArkType::Struct(_)
            ))
    {
        let mut replacement = expression.with_kind(ExprKind::Extracted(values.len()));
        // The placeholder stands for the extracted value, so it keeps its type.
        replacement.ty = expression.ty.clone();
        values.push(std::mem::replace(expression, replacement));
    } else {
        for child in child_exprs_mut(expression) {
            extract_values(child, values);
        }
    }
}

pub(super) fn contains_return(statements: &[LocatedStatement]) -> bool {
    statements
        .iter()
        .any(|statement| match &statement.statement {
            Statement::Return(_) => true,
            Statement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                contains_return(then_body)
                    || else_body.as_ref().is_some_and(|body| contains_return(body))
            }
            Statement::ForIn { body, .. } | Statement::ForCount { body, .. } => {
                contains_return(body)
            }
            _ => false,
        })
}

// This scans each helper body per argument; cache assigned names if call counts grow.
fn assigns_parameter(statements: &[LocatedStatement], name: &str) -> bool {
    statements
        .iter()
        .any(|statement| match &statement.statement {
            Statement::VarAssign {
                target: AssignmentTarget::Binding(target),
                ..
            } => target.root == name && target.segments.is_empty(),
            Statement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                assigns_parameter(then_body, name)
                    || else_body
                        .as_ref()
                        .is_some_and(|body| assigns_parameter(body, name))
            }
            Statement::ForIn { body, .. } | Statement::ForCount { body, .. } => {
                assigns_parameter(body, name)
            }
            _ => false,
        })
}

impl Generator {
    pub(super) fn value_leaves(&self, path: &Path, ty: &TypeName) -> Result<Vec<TypeLeaf>> {
        Ok(crate::models::flatten_value(path, ty, &self.structs)?)
    }

    /// Stack slots a value of `ty` occupies.
    pub(super) fn width(&self, ty: &TypeName) -> Result<usize> {
        Ok(self.value_leaves(&Path::new(""), ty)?.len())
    }

    pub(super) fn bind_value(&mut self, name: &str, ty: &TypeName) -> Result<()> {
        let leaves = self.value_leaves(&Path::new(name), ty)?;
        if self.stack.len() < leaves.len() {
            return Err("missing function result".into());
        }
        let start = self.stack.len() - leaves.len();
        for (item, leaf) in self.stack[start..].iter_mut().zip(leaves.iter().rev()) {
            if *item != StackItem::Temporary {
                return Err("function result is not a temporary".into());
            }
            *item = StackItem::Binding {
                name: leaf.access.clone(),
                kind: BindingKind::Local,
            };
        }
        Ok(())
    }

    pub(super) fn emit_typed_value(
        &mut self,
        expression: &Expression,
        ty: &TypeName,
    ) -> Result<()> {
        if matches!(&expression.kind, ExprKind::Call { .. }) {
            return self.emit_call(expression);
        }
        if ty.is_builtin() {
            return self.emit_expression(expression);
        }
        if matches!(
            &expression.kind,
            ExprKind::ArrayIndex { .. }
                | ExprKind::FieldAccess { .. }
                | ExprKind::IndexAccess { .. }
        ) {
            return self.emit_access_value(expression, ty);
        }
        if let ExprKind::Name(path) = &expression.kind {
            for leaf in self.value_leaves(path, ty)?.iter().rev() {
                self.read_binding(&leaf.access)?;
            }
            return Ok(());
        }
        if let Some((element, length)) = ty.array_parts() {
            let ExprKind::ArrayLiteral(elements) = &expression.kind else {
                return Err(format!("expected array value of type '{ty}'").into());
            };
            if elements.len() != length {
                return Err(format!("expected {length} array elements").into());
            }
            for element_value in elements.iter().rev() {
                self.emit_typed_value(element_value, element)?;
            }
            return Ok(());
        }
        if crate::models::expression_result_struct(expression) == ty.name() {
            let width = self.width(ty)?;
            self.emit_expression_items(expression, width)?;
            // Native results are first deepest; reverse them so the first leaf is on top.
            for depth in 1..width {
                if depth == 1 {
                    self.swap()?;
                } else {
                    self.push_integer_temporary(depth);
                    self.apply(Roll, depth + 2, depth + 1)?;
                }
            }
            return Ok(());
        }
        let ExprKind::StructLiteral(values) = &expression.kind else {
            return Err(format!("expected struct value of type '{ty}'").into());
        };
        let fields = if let Some(fields) = ty.name().and_then(crate::models::builtin_struct_fields)
        {
            fields
                .iter()
                .map(|(name, ty)| Parameter {
                    span: Default::default(),
                    name: name.to_string(),
                    param_type: TypeName::parse(ty),
                })
                .collect()
        } else {
            self.structs
                .iter()
                .find(|s| ty.name() == Some(&s.name))
                .ok_or_else(|| format!("unknown struct '{ty}'"))?
                .fields
                .clone()
        };
        for field in fields.iter().rev() {
            let value = values
                .iter()
                .find(|(name, _)| *name == field.name)
                .ok_or_else(|| format!("missing field '{}'", field.name))?;
            self.emit_typed_value(&value.1, &field.param_type)?;
        }
        Ok(())
    }

    pub(super) fn emit_call(&mut self, expression: &Expression) -> Result<()> {
        let ExprKind::Call { name, args, .. } = &expression.kind else {
            return Err("expected private function call".into());
        };
        let function = self
            .functions
            .iter()
            .find(|f| f.name == *name && f.is_private)
            .cloned()
            .ok_or_else(|| format!("unknown private function '{name}'"))?;
        if args.len() != function.parameters.len() {
            return Err(format!("wrong argument count for '{name}'").into());
        }
        let caller = self.stack.clone();
        let caller_scope = self.scope.clone();
        let caller_deferred = std::mem::take(&mut self.deferred);
        let baseline = caller.len();
        let pinned = std::mem::replace(&mut self.pinned_stack_len, baseline);
        // A caller's top-slot rebinding must not match helper bindings with the same name.
        let replacement = self.replacement.take();
        let mut arguments = Vec::new();
        let mut aliases = std::collections::HashMap::new();
        for (index, (argument, parameter)) in args.iter().zip(&function.parameters).enumerate() {
            if parameter.param_type.is_builtin()
                && !assigns_parameter(&function.statements, &parameter.name)
            {
                let source = match &argument.kind {
                    ExprKind::Name(path) if path.segments.is_empty() => Some(path.clone()),
                    ExprKind::ArrayIndex { array, index } => index
                        .literal_index()
                        .map(|index| array.clone().index(index)),
                    _ => None,
                };
                if let Some(source) = source {
                    if let Some(source_index) =
                        self.binding_index(&source).filter(|&i| i < baseline)
                    {
                        self.count_constructor_reads(source_index, 1);
                        if self.read_cursor.is_none() {
                            if let Some(previous) = self.last_reads.get(&(source, source_index)) {
                                self.final_reads[*previous] = false;
                            }
                        }
                        aliases.insert(Path::new(&parameter.name), source_index);
                        continue;
                    }
                }
            }
            let start = self.stack.len();
            self.emit_typed_value(argument, &parameter.param_type)?;
            self.bind_value(&format!("$argument:{index}"), &parameter.param_type)?;
            arguments.push((
                start,
                self.value_leaves(&Path::new(&parameter.name), &parameter.param_type)?,
            ));
        }
        // Static calls hide all caller bindings; instance helpers retain constructor state.
        let caller_inlined = function
            .is_static
            .then(|| std::mem::take(&mut self.inlined));
        for (index, item) in self.stack[..baseline].iter_mut().enumerate() {
            if function.is_static
                || !matches!(
                    item,
                    StackItem::Binding {
                        kind: BindingKind::Constructor,
                        ..
                    }
                )
            {
                *item = StackItem::Binding {
                    name: Path::new(format!("$caller:{index}")),
                    kind: BindingKind::Local,
                };
            }
        }
        for (start, leaves) in arguments {
            for (item, leaf) in self.stack[start..start + leaves.len()]
                .iter_mut()
                .zip(leaves.iter().rev())
            {
                *item = StackItem::Binding {
                    name: leaf.access.clone(),
                    kind: BindingKind::Local,
                };
            }
        }
        let caller_scopes = std::mem::take(&mut self.scopes);
        self.scope = if function.is_static {
            types::Scope::new()
        } else {
            self.constructor_scope.clone()
        };
        let previous_aliases = std::mem::replace(&mut self.aliases, aliases);
        for parameter in &function.parameters {
            self.bind_type(&parameter.name, &parameter.param_type);
        }
        let previous_return = self.return_type.replace(function.return_type.clone());
        // Nested returns need shared slots until their control flow can be lowered directly.
        let direct_return = !function.statements.iter().any(|statement| {
            !matches!(statement.statement, Statement::Return(_))
                && contains_return(std::slice::from_ref(statement))
        });
        let previous_direct_return = std::mem::replace(&mut self.direct_return, direct_return);
        let results = function
            .return_type
            .as_ref()
            .map(|ty| self.value_leaves(&Path::new("$result"), ty))
            .transpose()?
            .unwrap_or_default();
        if !direct_return {
            self.push_temporary(Int0);
            self.bind_local(Path::new("$returned"))?;
            for leaf in results.iter().rev() {
                self.push_temporary(Int0);
                self.bind_local(leaf.access.clone())?;
            }
        }
        if function.is_imported() {
            self.asm.pin();
        }
        let emitted = self
            .lower(&function.statements)
            .and_then(|body| emit_body(&body, self));
        if function.is_imported() {
            self.asm.unpin();
        }
        emitted.map_err(|mut error| {
            // An imported helper's spans index its own file; the call locates the error instead.
            if function.is_imported() {
                error.span = None;
            }
            error
        })?;
        if !direct_return {
            for leaf in results.iter().rev() {
                self.read_static_binding(&leaf.access, true)?;
            }
        }
        self.discard_call_frame(baseline, results.len())?;
        self.last_reads.retain(|(_, index), _| *index < baseline);
        self.stack[..baseline].clone_from_slice(&caller);
        self.scope = caller_scope;
        self.scopes = caller_scopes;
        self.deferred = caller_deferred;
        self.aliases = previous_aliases;
        if let Some(inlined) = caller_inlined {
            self.inlined = inlined;
        }
        self.return_type = previous_return;
        self.direct_return = previous_direct_return;
        self.pinned_stack_len = pinned;
        self.replacement = replacement;
        Ok(())
    }

    pub(super) fn discard_call_frame(&mut self, baseline: usize, results: usize) -> Result<()> {
        while self.stack.len() > baseline + results {
            match results {
                0 => {
                    self.asm.push(Drop.into());
                    self.stack.pop();
                }
                1 => self.nip()?,
                _ => {
                    self.push_integer_temporary(results);
                    self.pop_temporaries(1, Roll)?;
                    self.asm.push(Roll.into());
                    self.asm.push(Drop.into());
                    self.stack.remove(self.stack.len() - results - 1);
                }
            }
        }
        Ok(())
    }

    pub(super) fn emit_return(&mut self, value: Option<&Expression>) -> Result<()> {
        let ty = self
            .return_type
            .clone()
            .ok_or("return outside private function")?;
        match (ty.as_ref(), value) {
            (Some(ty), Some(value)) => {
                self.emit_typed_value(value, ty)?;
                if !self.direct_return {
                    for leaf in self.value_leaves(&Path::new("$result"), ty)? {
                        self.assign_static_binding(leaf.access)?;
                    }
                }
            }
            (None, None) => {}
            _ => return Err("return value does not match function signature".into()),
        }
        if self.direct_return {
            Ok(())
        } else {
            self.push_temporary(Int1);
            self.assign_static_binding(Path::new("$returned"))
        }
    }

    /// Lowers a body in the current scope, folded when optimizing.
    pub(super) fn lower(&self, statements: &[LocatedStatement]) -> Result<Vec<Lowered>> {
        lowering::lower(
            statements,
            &mut self.scope.clone(),
            &self.structs,
            self.optimize,
        )
    }

    pub(super) fn emit_unless_returned(&mut self, statements: &[Lowered]) -> Result<bool> {
        self.read_binding(&Path::new("$returned"))?;
        self.apply(Not, 1, 1)?;
        self.apply(If, 1, 0)?;
        self.emit_branches(statements, None, false)
    }
}
