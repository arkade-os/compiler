use super::*;
use crate::typechecker::{infer_type, ArkType};

impl Generator {
    fn access_layout<'a>(
        &self,
        value: &'a Expression,
        indices: &mut Vec<(&'a Expression, usize, usize)>,
    ) -> Result<String, String> {
        match value {
            Expression::Variable(name) | Expression::Property(name) => Ok(name.clone()),
            Expression::FieldAccess { value, field } => {
                Ok(format!("{}.{field}", self.access_layout(value, indices)?))
            }
            Expression::ArrayIndex { array, index } => {
                self.index_layout(array.clone(), index, indices)
            }
            Expression::IndexAccess { value, index } => {
                let array = self.access_layout(value, indices)?;
                self.index_layout(array, index, indices)
            }
            _ => Err("expected a binding access".to_string()),
        }
    }

    fn index_layout<'a>(
        &self,
        array: String,
        index: &'a Expression,
        indices: &mut Vec<(&'a Expression, usize, usize)>,
    ) -> Result<String, String> {
        let Some(ArkType::Array(element, length)) = self.scope.get(&array) else {
            return Err(format!("'{array}' is not an array"));
        };
        if let Expression::Literal(index) = index {
            if let Ok(index) = index.parse::<usize>() {
                if index >= *length {
                    return Err(format!(
                        "array index '{index}' is out of range for '{array}'"
                    ));
                }
                return Ok(format!("{array}[{index}]"));
            }
        }
        indices.push((
            index,
            *length,
            self.value_leaves("", &element.as_str())?.len(),
        ));
        Ok(format!("{array}[0]"))
    }

    fn emit_access_offset(
        &mut self,
        indices: &[(&Expression, usize, usize)],
    ) -> Result<(), String> {
        for (position, (index, length, stride)) in indices.iter().enumerate() {
            self.emit_expression(index)?;
            self.check_array_index_length(*length)?;
            if *stride != 1 {
                self.push_integer_temporary(*stride);
                self.apply(OP_MUL, 2, 1)?;
            }
            if position > 0 {
                self.apply(OP_ADD, 2, 1)?;
            }
        }
        Ok(())
    }

    pub(super) fn emit_access_value(&mut self, value: &Expression, ty: &str) -> Result<(), String> {
        let mut indices = Vec::new();
        let name = self.access_layout(value, &mut indices)?;
        let length = name
            .strip_suffix(".length")
            .filter(|_| !self.scope.contains_key(&name))
            .and_then(|array| match self.scope.get(array) {
                Some(ArkType::Array(_, length)) => Some(*length),
                _ => None,
            });
        if indices.is_empty() {
            if let Some(length) = length {
                self.push_integer_temporary(length);
            } else {
                for leaf in self.value_leaves(&name, ty)?.iter().rev() {
                    self.read_static_binding(
                        &Self::internal_binding_name(&leaf.access_name),
                        false,
                    )?;
                }
            }
            return Ok(());
        }
        self.emit_access_offset(&indices)?;
        if let Some(length) = length {
            self.apply(OP_DROP, 1, 0)?;
            self.push_integer_temporary(length);
            return Ok(());
        }
        let leaves = self.value_leaves(&name, ty)?;
        for (copied, leaf) in leaves.iter().rev().enumerate() {
            // Copy the offset until the last leaf consumes it; each index is evaluated once.
            if copied + 1 < leaves.len() {
                self.push_integer_temporary(copied);
                self.apply(OP_PICK, 1, 1)?;
            } else if copied > 0 {
                self.push_integer_temporary(copied);
                self.apply(OP_ROLL, 1, 0)?;
            }
            let slot = self
                .binding_index(&Self::internal_binding_name(&leaf.access_name))
                .ok_or_else(|| format!("undefined binding '{}'", leaf.access_name))?;
            self.push_integer_temporary(self.stack.len() - slot - 2);
            self.apply(OP_ADD, 2, 1)?;
            self.apply(OP_PICK, 1, 1)?;
        }
        Ok(())
    }

    pub(super) fn assign_access(&mut self, value: &Expression) -> Result<(), String> {
        if matches!(
            infer_type(value, &self.scope),
            ArkType::Array(..) | ArkType::Struct(_)
        ) {
            return Err("assignment requires a scalar field".to_string());
        }
        let mut indices = Vec::new();
        let name = self.access_layout(value, &mut indices)?;
        if indices.is_empty() {
            return self.assign_static_binding(&name, &name);
        }
        self.emit_access_offset(&indices)?;
        let slot = self
            .binding_index(&Self::internal_binding_name(&name))
            .ok_or_else(|| format!("undefined binding '{name}'"))?;
        if matches!(
            self.stack[slot],
            StackItem::Binding {
                kind: BindingKind::Constructor,
                ..
            }
        ) {
            return Err(format!("cannot assign to constructor parameter '{name}'"));
        }
        self.push_integer_temporary(self.stack.len() - slot - 3);
        self.apply(OP_ADD, 2, 1)?;
        self.apply(OP_PUT, 2, 0)
    }
}
