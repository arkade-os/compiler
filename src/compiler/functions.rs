use super::*;
use crate::models::{child_exprs_mut, flatten_parameter, is_builtin_type, TypeLeaf};
use crate::opcodes::OP_ROLL;

pub(super) fn extract_calls(expression: &mut Expression, calls: &mut Vec<Expression>) {
    if matches!(expression, Expression::Call { .. }) {
        let replacement = Expression::Variable(format!("$call:{}", calls.len()));
        calls.push(std::mem::replace(expression, replacement));
    } else {
        for child in child_exprs_mut(expression) {
            extract_calls(child, calls);
        }
    }
}

pub(super) fn contains_return(statements: &[Statement]) -> bool {
    statements.iter().any(|statement| match statement {
        Statement::Return(_) => true,
        Statement::IfElse {
            then_body,
            else_body,
            ..
        } => {
            contains_return(then_body)
                || else_body.as_ref().is_some_and(|body| contains_return(body))
        }
        Statement::ForIn { body, .. } => contains_return(body),
        _ => false,
    })
}

impl Generator {
    pub(super) fn value_leaves(&self, name: &str, ty: &str) -> Result<Vec<TypeLeaf>, String> {
        flatten_parameter(
            &Parameter {
                name: name.to_string(),
                param_type: ty.to_string(),
            },
            &self.structs,
        )
    }

    pub(super) fn bind_value(&mut self, name: &str, ty: &str) -> Result<(), String> {
        let leaves = self.value_leaves(name, ty)?;
        if self.stack.len() < leaves.len() {
            return Err("missing function result".to_string());
        }
        let start = self.stack.len() - leaves.len();
        for (item, leaf) in self.stack[start..].iter_mut().zip(leaves.iter().rev()) {
            if *item != StackItem::Temporary {
                return Err("function result is not a temporary".to_string());
            }
            *item = StackItem::Binding {
                name: Self::internal_binding_name(&leaf.access_name),
                kind: BindingKind::Local,
            };
        }
        Ok(())
    }

    pub(super) fn emit_typed_value(
        &mut self,
        expression: &Expression,
        ty: &str,
    ) -> Result<(), String> {
        if matches!(expression, Expression::Call { .. }) {
            return self.emit_call(expression);
        }
        if is_builtin_type(ty) {
            return self.emit_expression(expression);
        }
        if let Expression::Variable(name) | Expression::Property(name) = expression {
            for leaf in self.value_leaves(name, ty)?.iter().rev() {
                self.read_binding(&leaf.access_name)?;
            }
            return Ok(());
        }
        if let Some((element, length)) = crate::models::array_type_parts(ty) {
            let Expression::ArrayLiteral(elements) = expression else {
                return Err(format!("expected array value of type '{ty}'"));
            };
            if elements.len() != length {
                return Err(format!("expected {length} array elements"));
            }
            for element_value in elements.iter().rev() {
                self.emit_typed_value(element_value, element)?;
            }
            return Ok(());
        }
        if crate::models::expression_result_struct(expression) == Some(ty) {
            let width = self.value_leaves("", ty)?.len();
            if width != 2 {
                return Err(format!(
                    "native struct '{ty}' has unsupported width {width}"
                ));
            }
            self.emit_expression_items(expression, width)?;
            // Native results are first deepest; wider native structs need a general reversal.
            return self.swap();
        }
        let Expression::StructLiteral(values) = expression else {
            return Err(format!("expected struct value of type '{ty}'"));
        };
        let fields = if let Some(fields) = crate::models::builtin_struct_fields(ty) {
            fields
                .iter()
                .map(|(name, ty)| Parameter {
                    name: name.to_string(),
                    param_type: ty.to_string(),
                })
                .collect()
        } else {
            self.structs
                .iter()
                .find(|s| s.name == ty)
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

    pub(super) fn emit_call(&mut self, expression: &Expression) -> Result<(), String> {
        let Expression::Call { name, args, .. } = expression else {
            return Err("expected private function call".to_string());
        };
        let function = self
            .functions
            .iter()
            .find(|f| f.name == *name && f.is_private)
            .cloned()
            .ok_or_else(|| format!("unknown private function '{name}'"))?;
        if args.len() != function.parameters.len() {
            return Err(format!("wrong argument count for '{name}'"));
        }
        let caller = self.stack.clone();
        let caller_scope = self.scope.clone();
        let baseline = caller.len();
        let mut arguments = Vec::new();
        for (index, (argument, parameter)) in args.iter().zip(&function.parameters).enumerate() {
            let start = self.stack.len();
            self.emit_typed_value(argument, &parameter.param_type)?;
            self.bind_value(&format!("$argument:{index}"), &parameter.param_type)?;
            arguments.push((
                start,
                self.value_leaves(&parameter.name, &parameter.param_type)?,
            ));
        }
        // Only constructor bindings cross the call boundary; caller temporaries are hidden too.
        for (index, item) in self.stack[..baseline].iter_mut().enumerate() {
            if !matches!(
                item,
                StackItem::Binding {
                    kind: BindingKind::Constructor,
                    ..
                }
            ) {
                *item = StackItem::Binding {
                    name: format!("$caller:{index}"),
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
                    name: Self::internal_binding_name(&leaf.access_name),
                    kind: BindingKind::Local,
                };
            }
        }
        for parameter in &function.parameters {
            self.bind_type(&parameter.name, &parameter.param_type);
        }
        let previous_return = self.return_type.replace(function.return_type.clone());
        self.push_temporary(OP_0);
        self.bind_local("$returned")?;
        let results = function
            .return_type
            .as_deref()
            .map(|ty| self.value_leaves("$result", ty))
            .transpose()?
            .unwrap_or_default();
        for leaf in results.iter().rev() {
            self.push_temporary(OP_0);
            self.bind_local(&Self::internal_binding_name(&leaf.access_name))?;
        }
        generate_asm_from_statements_recursive(&function.statements, self)?;
        for leaf in results.iter().rev() {
            self.read_binding(&leaf.access_name)?;
        }
        self.discard_call_frame(baseline, results.len())?;
        self.stack[..baseline].clone_from_slice(&caller);
        self.scope = caller_scope;
        self.return_type = previous_return;
        Ok(())
    }

    fn discard_call_frame(&mut self, baseline: usize, results: usize) -> Result<(), String> {
        while self.stack.len() > baseline + results {
            match results {
                0 => {
                    self.asm.push(OP_DROP.to_string());
                    self.stack.pop();
                }
                1 => self.nip()?,
                _ => {
                    self.push_integer_temporary(results);
                    self.pop_temporaries(1, OP_ROLL)?;
                    self.asm.push(OP_ROLL.to_string());
                    self.asm.push(OP_DROP.to_string());
                    self.stack.remove(self.stack.len() - results - 1);
                }
            }
        }
        Ok(())
    }

    pub(super) fn emit_return(&mut self, value: Option<&Expression>) -> Result<(), String> {
        let ty = self
            .return_type
            .clone()
            .ok_or("return outside private function")?;
        match (ty.as_deref(), value) {
            (Some(ty), Some(value)) => {
                self.emit_typed_value(value, ty)?;
                for leaf in self.value_leaves("$result", ty)? {
                    self.assign_static_binding(&leaf.access_name, &leaf.access_name)?;
                }
            }
            (None, None) => {}
            _ => return Err("return value does not match function signature".to_string()),
        }
        self.push_temporary(OP_1);
        self.assign_static_binding("$returned", "$returned")
    }

    pub(super) fn emit_unless_returned(&mut self, statements: &[Statement]) -> Result<(), String> {
        self.read_binding("$returned")?;
        self.apply(OP_NOT, 1, 1)?;
        self.apply(OP_IF, 1, 0)?;
        let baseline = self.stack.clone();
        self.enter_scope();
        generate_asm_from_statements_recursive(statements, self)?;
        self.exit_scope()?;
        if self.stack != baseline {
            return Err("private return changed outer stack layout".to_string());
        }
        self.asm.push(OP_ENDIF.to_string());
        Ok(())
    }
}
