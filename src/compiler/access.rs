use super::*;
use crate::typechecker::{infer_type, ArkType};

impl Generator {
    /// Resolve an access to its layout path, collecting runtime indexes.
    fn access_indices<'a>(
        &self,
        value: &'a Expression,
        indices: &mut Vec<(&'a Expression, usize, usize)>,
    ) -> Result<String, String> {
        let path = value.binding_path().ok_or("expected a binding access")?;
        let (array, index) = match value {
            Expression::FieldAccess { value, .. } => {
                self.access_indices(value, indices)?;
                return Ok(path);
            }
            Expression::ArrayIndex { array, index } => (array.clone(), index),
            Expression::IndexAccess { value, index } => {
                (self.access_indices(value, indices)?, index)
            }
            _ => return Ok(path),
        };
        let Some(ArkType::Array(element, length)) = self.scope.get(&array) else {
            return Err(format!("'{array}' is not an array"));
        };
        let literal = match index.as_ref() {
            Expression::Literal(literal) => literal.parse::<usize>().ok(),
            _ => None,
        };
        match literal {
            Some(literal) if literal >= *length => {
                return Err(format!(
                    "array index '{literal}' is out of range for '{array}'"
                ));
            }
            Some(_) => {}
            None => indices.push((
                index,
                *length,
                self.value_leaves("", &element.as_str())?.len(),
            )),
        }
        Ok(path)
    }

    fn emit_access_offset(
        &mut self,
        indices: &[(&Expression, usize, usize)],
    ) -> Result<(), String> {
        for (position, (index, length, stride)) in indices.iter().enumerate() {
            self.emit_expression(index)?;
            self.check_array_index(*length)?;
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
        let name = self.access_indices(value, &mut indices)?;
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
        let name = self.access_indices(value, &mut indices)?;
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

    /// Push each (G1, G2) pair with fields first-deepest, as OP_ECPAIRING reads them.
    pub(super) fn emit_pairing(&mut self, pairing: &Expression) -> Result<(), String> {
        let Expression::EcPairing { g1, g2, curve_id } = pairing else {
            return Err("expected ecPairing".to_string());
        };
        let ArkType::Array(_, pairs) = infer_type(g1, &self.scope) else {
            return Err("ecPairing G1 points must be an ECPoint array".to_string());
        };
        for index in 0..pairs {
            for (points, ty) in [(g1, "ECPoint"), (g2, "G2Point")] {
                if points.binding_path().is_none() {
                    return Err(
                        "ecPairing points must be array bindings; bind computed arrays with `let` first"
                            .to_string(),
                    );
                }
                let index = Box::new(Expression::Literal(index.to_string()));
                let element = match points.as_ref() {
                    Expression::Variable(array) | Expression::Property(array) => {
                        Expression::ArrayIndex {
                            array: array.clone(),
                            index,
                        }
                    }
                    value => Expression::IndexAccess {
                        value: Box::new(value.clone()),
                        index,
                    },
                };
                for (field, field_type) in crate::models::builtin_struct_fields(ty)
                    .ok_or("internal compiler error: missing native point layout")?
                {
                    let leaf = Expression::FieldAccess {
                        value: Box::new(element.clone()),
                        field: field.to_string(),
                    };
                    self.emit_access_value(&leaf, field_type)?;
                }
            }
        }
        self.push_integer_temporary(pairs);
        self.emit_expression(curve_id)?;
        self.apply(OP_ECPAIRING, 6 * pairs + 2, 1)
    }
}
