use super::*;
use crate::opcodes::{OP_FROMALTSTACK, OP_TOALTSTACK};
use crate::properties::GroupIoProperty;
use crate::types::ArkType;

impl Generator {
    /// Resolve an access to its layout path, collecting runtime indexes.
    fn access_indices<'a>(
        &self,
        value: &'a Expression,
        indices: &mut Vec<(&'a Expression, usize, usize)>,
    ) -> Result<String, String> {
        let path = value.binding_path().ok_or("expected a binding access")?;
        let (array, index) = match &value.kind {
            ExprKind::FieldAccess { value, .. } => {
                self.access_indices(value, indices)?;
                return Ok(path);
            }
            ExprKind::ArrayIndex { array, index } => (array.clone(), index),
            ExprKind::IndexAccess { value, index } => (self.access_indices(value, indices)?, index),
            _ => return Ok(path),
        };
        let Some(ArkType::Array(element, length)) = self.scope.get(&array) else {
            return Err(format!("'{array}' is not an array"));
        };
        let literal = match &index.as_ref().kind {
            ExprKind::Literal(literal) => literal.parse::<usize>().ok(),
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
        if matches!(value.ty, ArkType::Array(..) | ArkType::Struct(_)) {
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

    pub(super) fn emit_multisig(&mut self, expression: &Expression) -> Result<(), String> {
        let ExprKind::Builtin { args, .. } = &expression.kind else {
            return Err("expected checkMultisig".to_string());
        };
        let keys = &args[0];
        let signatures = &args[1];
        let ArkType::Array(element, count) = keys.ty.clone() else {
            return Err("checkMultisig public keys must be an array".to_string());
        };
        if count == 0 || count > 999 {
            return Err("checkMultisig needs between 1 and 999 public keys".to_string());
        }
        if !matches!(signatures.ty, ArkType::Array(_, length) if length == count) {
            return Err("checkMultisig key and signature counts must match".to_string());
        }
        let threshold = args.get(2);
        let literal_threshold = match threshold {
            None => Some(count),
            Some(Expression {
                kind: ExprKind::Literal(value),
                ..
            }) => Some(
                value
                    .parse::<usize>()
                    .map_err(|_| "invalid multisig threshold")?,
            ),
            _ => None,
        };
        if literal_threshold.is_some_and(|threshold| threshold == 0 || threshold > count) {
            return Err(
                "checkMultisig threshold must be between 1 and the number of public keys"
                    .to_string(),
            );
        }
        // Keys need indexed reads, so computed arrays are bound once.
        if !matches!(&keys.kind, ExprKind::ArrayLiteral(_)) && keys.binding_path().is_none() {
            let baseline = self.stack.len();
            let scope = self.scope.clone();
            let pinned = std::mem::replace(&mut self.pinned_stack_len, baseline);
            let ty = keys.ty.as_str();
            let name = format!("$multisig:{baseline}");
            self.emit_typed_value(keys, &ty)?;
            self.bind_value(&name, &ty)?;
            self.bind_type(&name, &ty);
            let mut normalized = expression.clone();
            let ExprKind::Builtin { args, .. } = &mut normalized.kind else {
                unreachable!()
            };
            args[0] = keys.with_kind(ExprKind::Variable(name));
            args[0].ty = keys.ty.clone();
            self.emit_multisig(&normalized)?;
            self.discard_call_frame(baseline, 1)?;
            self.last_reads.retain(|(_, index), _| *index < baseline);
            self.scope = scope;
            self.pinned_stack_len = pinned;
            return Ok(());
        }
        // Signatures need no binding: array emission leaves sig[0] on top for the checks.
        self.emit_typed_value(signatures, &format!("signature[{count}]"))?;
        for index in 0..count {
            let mut key = match &keys.kind {
                ExprKind::ArrayLiteral(elements) => elements[index].clone(),
                _ => keys.with_kind(ExprKind::IndexAccess {
                    value: Box::new(keys.clone()),
                    index: Box::new(keys.with_kind(ExprKind::Literal(index.to_string()))),
                }),
            };
            key.ty = (*element).clone();
            self.emit_expression(&key)?;
            self.apply(
                if index == 0 {
                    OP_CHECKSIG
                } else {
                    OP_CHECKSIGADD
                },
                if index == 0 { 2 } else { 3 },
                1,
            )?;
        }
        if let Some(threshold) = literal_threshold {
            self.push_integer_temporary(threshold);
        } else {
            self.emit_expression(threshold.expect("runtime threshold"))?;
            self.apply(OP_DUP, 1, 2)?;
            self.push_integer_temporary(1);
            self.apply(OP_GREATERTHANOREQUAL, 2, 1)?;
            self.apply(OP_VERIFY, 1, 0)?;
            self.apply(OP_DUP, 1, 2)?;
            self.push_integer_temporary(count);
            self.apply(OP_LESSTHANOREQUAL, 2, 1)?;
            self.apply(OP_VERIFY, 1, 0)?;
        }
        self.apply(OP_NUMEQUAL, 2, 1)
    }

    /// Push each (G1, G2) pair with fields first-deepest, as OP_ECPAIRING reads them.
    /// One field of a group input record, which is `[type, txid, vin, amount]` for an
    /// intent input and `[type, vin, amount]` for a local one.
    pub(super) fn emit_group_input(&mut self, record: &Expression) -> Result<(), String> {
        let ExprKind::GroupIOAccess {
            group,
            io_index,
            property: Some(property),
            ..
        } = &record.kind
        else {
            return Err("asset group input records need a field".to_string());
        };
        self.emit_expression(group)?;
        self.emit_expression(io_index)?;
        self.push_temporary(OP_0);
        self.apply(OP_INSPECTASSETGROUP, 3, 1)?;
        // Only an intent input's txid is 32 bytes; the type below it is 1 or 2.
        const DROP_TXID: &[&str] = &[OP_SIZE, "32", OP_EQUAL, OP_IF, OP_DROP, OP_ENDIF];
        let restore: &[&str] = &[OP_DROP, OP_FROMALTSTACK];
        let ops = match property {
            GroupIoProperty::Amount => [&[OP_TOALTSTACK, OP_DROP], DROP_TXID, restore].concat(),
            GroupIoProperty::Index => [&[OP_DROP, OP_TOALTSTACK], DROP_TXID, restore].concat(),
            GroupIoProperty::Type => [&[OP_DROP, OP_DROP], DROP_TXID].concat(),
            // A local input has no txid, so the size check fails the spend.
            GroupIoProperty::Txid => vec![OP_DROP, OP_DROP, OP_SIZE, "32", OP_EQUALVERIFY, OP_NIP],
        };
        self.asm.extend(ops.iter().map(|op| op.to_string()));
        Ok(())
    }

    pub(super) fn emit_pairing(&mut self, pairing: &Expression) -> Result<(), String> {
        let ExprKind::Builtin { args, .. } = &pairing.kind else {
            return Err("expected ecPairing".to_string());
        };
        let [g1, g2, curve_id] = args.as_slice() else {
            return Err("ecPairing takes three arguments".to_string());
        };
        let ArkType::Array(_, pairs) = g1.ty else {
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
                let index = Box::new(points.with_kind(ExprKind::Literal(index.to_string())));
                let element = points.with_kind(match &points.kind {
                    ExprKind::Variable(array) | ExprKind::Property(array) => ExprKind::ArrayIndex {
                        array: array.clone(),
                        index,
                    },
                    _ => ExprKind::IndexAccess {
                        value: Box::new(points.clone()),
                        index,
                    },
                });
                for (field, field_type) in crate::models::builtin_struct_fields(ty)
                    .ok_or("internal compiler error: missing native point layout")?
                {
                    let leaf = points.with_kind(ExprKind::FieldAccess {
                        value: Box::new(element.clone()),
                        field: field.to_string(),
                    });
                    self.emit_access_value(&leaf, field_type)?;
                }
            }
        }
        self.push_integer_temporary(pairs);
        self.emit_expression(curve_id)?;
        self.apply(OP_ECPAIRING, 6 * pairs + 2, 1)
    }
}
