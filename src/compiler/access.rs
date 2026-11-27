use super::Result;
use crate::compiler::ir::Op;
use crate::compiler::BindingKind;
use crate::compiler::Generator;
use crate::compiler::StackItem;
use crate::diagnostics::CompileError;
use crate::models::ExprKind;
use crate::models::Expression;
use crate::models::Path;
use crate::models::TypeName;
use crate::opcodes::Opcode;
use crate::properties::GroupIoProperty;
use crate::types::ArkType;

/// A `checkMultisig` threshold known at compile time: the key count when omitted, or a literal
/// that must lie between 1 and `count`.
pub(super) fn multisig_threshold(
    threshold: Option<&Expression>,
    count: usize,
) -> std::result::Result<Option<usize>, String> {
    let threshold = match threshold.map(|threshold| &threshold.kind) {
        None => count,
        Some(ExprKind::Literal(value)) => value
            .parse::<usize>()
            .map_err(|_| "invalid multisig threshold")?,
        Some(_) => return Ok(None),
    };
    if threshold == 0 || threshold > count {
        return Err(
            "checkMultisig threshold must be between 1 and the number of public keys".into(),
        );
    }
    Ok(Some(threshold))
}

impl Generator {
    /// Resolve an access to its layout path, collecting runtime indexes.
    fn access_indices<'a>(
        &self,
        value: &'a Expression,
        indices: &mut Vec<(&'a Expression, usize, usize)>,
    ) -> Result<Path> {
        let (array, index) = match &value.kind {
            ExprKind::Name(path) => return Ok(path.clone()),
            ExprKind::FieldAccess { value, field } => {
                return Ok(self.access_indices(value, indices)?.field(field));
            }
            ExprKind::ArrayIndex { array, index } => (array.clone(), index),
            ExprKind::IndexAccess { value, index } => (self.access_indices(value, indices)?, index),
            _ => return Err("expected a binding access".into()),
        };
        let Some(ArkType::Array(element, length)) = self.scope.get(&array.key()) else {
            return Err(format!("'{array}' is not an array").into());
        };
        // Validation and folding reject an out-of-range constant on a reachable path; one left
        // here is in code that folding removes, so it is checked at runtime.
        if let Some(literal) = index.literal_index().filter(|literal| literal < length) {
            return Ok(array.index(literal));
        }
        indices.push((index, *length, self.width(&(&**element).into())?));
        Ok(array.index(0))
    }

    fn emit_access_offset(&mut self, indices: &[(&Expression, usize, usize)]) -> Result<()> {
        for (position, (index, length, stride)) in indices.iter().enumerate() {
            self.emit_expression(index)?;
            self.check_array_index(*length)?;
            if *stride != 1 {
                self.push_integer_temporary(*stride);
                self.apply(Opcode::Mul, 2, 1)?;
            }
            if position > 0 {
                self.apply(Opcode::Add, 2, 1)?;
            }
        }
        Ok(())
    }

    pub(super) fn emit_access_value(&mut self, value: &Expression, ty: &TypeName) -> Result<()> {
        if value.binding_path().is_none() {
            return self.emit_computed_access(value, ty);
        }
        let mut indices = Vec::new();
        let name = self.access_indices(value, &mut indices)?;
        let length = name
            .split_last()
            .filter(|&(_, field)| field == "length" && !self.scope.contains_key(&name.key()))
            .and_then(|(array, _)| match self.scope.get(&array.key()) {
                Some(ArkType::Array(_, length)) => Some(*length),
                _ => None,
            });
        if indices.is_empty() {
            if let Some(length) = length {
                self.push_integer_temporary(length);
            } else {
                for leaf in self.value_leaves(&name, ty)?.iter().rev() {
                    self.read_static_binding(&leaf.access, false)?;
                }
            }
            return Ok(());
        }
        self.emit_access_offset(&indices)?;
        if let Some(length) = length {
            self.apply(Opcode::Drop, 1, 0)?;
            self.push_integer_temporary(length);
            return Ok(());
        }
        self.pin_constructor_slots(&name);
        let leaves = self.value_leaves(&name, ty)?;
        for (copied, leaf) in leaves.iter().rev().enumerate() {
            // Copy the offset until the last leaf consumes it; each index is evaluated once.
            if copied + 1 < leaves.len() {
                self.push_integer_temporary(copied);
                self.apply(Opcode::Pick, 1, 1)?;
            } else if copied > 0 {
                self.push_integer_temporary(copied);
                self.apply(Opcode::Roll, 1, 0)?;
            }
            let slot = self
                .binding_index(&leaf.access)
                .ok_or_else(|| format!("undefined binding '{}'", leaf.access))?;
            self.push_integer_temporary(self.stack.len() - slot - 2);
            self.apply(Opcode::Add, 2, 1)?;
            self.apply(Opcode::Pick, 1, 1)?;
        }
        Ok(())
    }

    /// Bind an access's computed root once, then read the access from that binding.
    // ponytail: the read leaves are copied and the whole root dropped after, one copy and drop
    // more than a move; consume the final reads if script size matters.
    fn emit_computed_access(&mut self, value: &Expression, ty: &TypeName) -> Result<()> {
        fn root(access: &mut Expression) -> &mut Expression {
            match access.kind {
                ExprKind::FieldAccess { ref mut value, .. }
                | ExprKind::IndexAccess { ref mut value, .. } => root(value),
                _ => access,
            }
        }
        let mut access = value.clone();
        let computed = root(&mut access).clone();
        let width = self.width(ty)?;
        self.with_bound_value(&computed, width, |generator, bound| {
            *root(&mut access) = bound;
            generator.emit_access_value(&access, ty)
        })
    }

    pub(super) fn assign_access(&mut self, value: &Expression) -> Result<()> {
        let mut indices = Vec::new();
        let name = self.access_indices(value, &mut indices)?;
        let leaves = self.value_leaves(&name, &TypeName::from(&value.ty))?;
        if indices.is_empty() {
            for leaf in leaves {
                self.assign_static_binding(leaf.access)?;
            }
            return Ok(());
        }
        self.emit_access_offset(&indices)?;
        for (assigned, leaf) in leaves.iter().enumerate() {
            if assigned + 1 < leaves.len() {
                // Keep the offset below the next value; runtime indexes are evaluated once.
                self.swap()?;
                self.push_integer_temporary(1);
                self.apply(Opcode::Pick, 1, 1)?;
            }
            let slot = self
                .binding_index(&leaf.access)
                .ok_or_else(|| format!("undefined binding '{}'", leaf.access))?;
            if matches!(
                self.stack[slot],
                StackItem::Binding {
                    kind: BindingKind::Constructor,
                    ..
                }
            ) {
                return Err(format!("cannot assign to constructor parameter '{name}'").into());
            }
            self.push_integer_temporary(self.stack.len() - slot - 3);
            self.apply(Opcode::Add, 2, 1)?;
            self.apply(Opcode::Put, 2, 0)?;
        }
        Ok(())
    }

    /// Evaluate `value` as `ty` into the local binding `name`.
    pub(super) fn emit_let(&mut self, name: &str, value: &Expression, ty: &TypeName) -> Result<()> {
        self.emit_typed_value(value, ty)?;
        self.bind_value(name, ty)?;
        self.bind_type(name, ty);
        Ok(())
    }

    /// Evaluate `value` once into a stack binding, then let `read` emit through an expression
    /// naming it. `width` is the size of what `read` leaves, not of `value`: those items are
    /// kept and the binding dropped.
    // TODO(ir): emission reads composite values only by binding path, so computed ones get a
    // made-up name here. Remove once operands are IR values instead of paths.
    pub(super) fn with_bound_value(
        &mut self,
        value: &Expression,
        width: usize,
        read: impl FnOnce(&mut Self, Expression) -> Result<()>,
    ) -> Result<()> {
        let baseline = self.stack.len();
        let scope = self.scope.clone();
        let pinned = std::mem::replace(&mut self.pinned_stack_len, baseline);
        let ty = TypeName::from(&value.ty);
        // A later call at this depth reuses the name only after this binding is dropped.
        let name = format!("$bound:{baseline}");
        self.emit_let(&name, value, &ty)?;
        let mut bound = value.with_kind(ExprKind::Name(Path::new(name)));
        bound.ty = value.ty.clone();
        read(self, bound)?;
        self.discard_call_frame(baseline, width)?;
        self.last_reads.retain(|(_, index), _| *index < baseline);
        self.scope = scope;
        self.pinned_stack_len = pinned;
        Ok(())
    }

    /// Emit a builtin call with argument `position` evaluated once.
    fn emit_with_bound_arg(
        &mut self,
        call: &Expression,
        position: usize,
        emit: fn(&mut Self, &Expression) -> Result<()>,
    ) -> Result<()> {
        let ExprKind::Builtin { args, .. } = &call.kind else {
            return Err("expected a builtin call".into());
        };
        self.with_bound_value(&args[position], 1, |generator, bound| {
            let mut call = call.clone();
            if let ExprKind::Builtin { args, .. } = &mut call.kind {
                args[position] = bound;
            }
            emit(generator, &call)
        })
    }

    pub(super) fn emit_multisig(&mut self, expression: &Expression) -> Result<()> {
        let ExprKind::Builtin { args, .. } = &expression.kind else {
            return Err("expected checkMultisig".into());
        };
        let keys = &args[0];
        let signatures = &args[1];
        let ArkType::Array(element, count) = keys.ty.clone() else {
            return Err("checkMultisig public keys must be an array".into());
        };
        if count == 0 || count > 999 {
            return Err("checkMultisig needs between 1 and 999 public keys".into());
        }
        if !matches!(signatures.ty, ArkType::Array(_, length) if length == count) {
            return Err("checkMultisig key and signature counts must match".into());
        }
        let threshold = args.get(2);
        // Validation and folding reject an out-of-range constant on a reachable path; one left
        // here is in a branch that folding removes, so it keeps the runtime check.
        let literal_threshold = multisig_threshold(threshold, count).ok().flatten();
        // Keys need indexed reads, so arrays without a static path are bound once.
        if !matches!(&keys.kind, ExprKind::ArrayLiteral(_)) && keys.static_path().is_none() {
            return self.emit_with_bound_arg(expression, 0, Self::emit_multisig);
        }
        // Signatures need no binding: array emission leaves sig[0] on top for the checks.
        let signatures_type = TypeName::array(TypeName::Named("signature".into()), count);
        self.emit_typed_value(signatures, &signatures_type)?;
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
                    Opcode::CheckSig
                } else {
                    Opcode::CheckSigAdd
                },
                if index == 0 { 2 } else { 3 },
                1,
            )?;
        }
        if let Some(threshold) = literal_threshold {
            self.push_integer_temporary(threshold);
        } else {
            self.emit_expression(threshold.expect("runtime threshold"))?;
            self.check_within(1, count + 1)?;
        }
        // At least the threshold must sign; for N-of-N that is all, which NUMEQUAL checks and
        // a following VERIFY fuses with.
        let compare = if literal_threshold == Some(count) {
            Opcode::NumEqual
        } else {
            Opcode::GreaterThanOrEqual
        };
        self.apply(compare, 2, 1)
    }

    /// One field of a group input record, or the whole record without its txid as
    /// `[type, vin, amount]`. The record is `[type, txid, vin, amount]` for a proof
    /// input and `[type, vin, amount]` for a local one.
    pub(super) fn emit_group_input(&mut self, record: &Expression) -> Result<()> {
        let ExprKind::GroupIOAccess {
            group,
            io_index,
            property,
            ..
        } = &record.kind
        else {
            return Err("expected an asset group input record".into());
        };
        self.emit_expression(group)?;
        self.emit_expression(io_index)?;
        self.push_temporary(Opcode::Int0);
        // A proof input record is four items, and normalizing sizes its txid with the items above
        // it dropped or parked on the alt stack: counting both stacks, at most five items for
        // a field and six for the whole record.
        let (items, peak) = if property.is_some() { (1, 5) } else { (3, 6) };
        self.apply(Opcode::InspectAssetGroup, 3, items)?;
        self.max_depth = self.max_depth.max(self.stack.len() - items + peak);
        // Only a proof input's txid is 32 bytes; the type below it is 1 or 2. Each
        // sequence takes back what it puts on the alt stack and leaves the items the
        // model holds, so the stack model needs no update.
        let size_32 = [Opcode::Size.into(), Op::Push("32".into())];
        let drop_txid = [
            Opcode::Equal.into(),
            Opcode::If.into(),
            Opcode::Drop.into(),
            Opcode::EndIf.into(),
        ];
        let restore = [Opcode::Drop.into(), Opcode::FromAltStack.into()];
        let ops: Vec<Op> = match property {
            None => [
                vec![Opcode::ToAltStack.into(), Opcode::ToAltStack.into()],
                size_32.to_vec(),
                drop_txid.to_vec(),
                vec![Opcode::FromAltStack.into(), Opcode::FromAltStack.into()],
            ]
            .concat(),
            Some(GroupIoProperty::Amount) => [
                vec![Opcode::ToAltStack.into(), Opcode::Drop.into()],
                size_32.to_vec(),
                drop_txid.to_vec(),
                restore.to_vec(),
            ]
            .concat(),
            Some(GroupIoProperty::Index) => [
                vec![Opcode::Drop.into(), Opcode::ToAltStack.into()],
                size_32.to_vec(),
                drop_txid.to_vec(),
                restore.to_vec(),
            ]
            .concat(),
            Some(GroupIoProperty::Type) => [
                vec![Opcode::Drop.into(), Opcode::Drop.into()],
                size_32.to_vec(),
                drop_txid.to_vec(),
            ]
            .concat(),
            // A local input has no txid, so the size check fails the spend.
            Some(GroupIoProperty::Txid) => [
                vec![Opcode::Drop.into(), Opcode::Drop.into()],
                size_32.to_vec(),
                vec![Opcode::EqualVerify.into(), Opcode::Nip.into()],
            ]
            .concat(),
        };
        self.asm.extend(ops);
        Ok(())
    }

    /// Push each (G1, G2) pair with fields first-deepest, as OP_ECPAIRING reads them.
    pub(super) fn emit_pairing(&mut self, pairing: &Expression) -> Result<()> {
        let ExprKind::Builtin { args, .. } = &pairing.kind else {
            return Err("expected ecPairing".into());
        };
        let [g1, g2, curve_id] = args.as_slice() else {
            return Err("ecPairing takes three arguments".into());
        };
        let ArkType::Array(_, pairs) = g1.ty else {
            return Err("ecPairing G1 points must be an ECPoint array".into());
        };
        // Pairs need indexed reads, so arrays without a static path are bound once, G1 first.
        if let Some(position) = [g1, g2]
            .iter()
            .position(|points| points.static_path().is_none())
        {
            if matches!(&args[position].kind, ExprKind::ArrayLiteral(points)
                if points.iter().any(|point| matches!(point.kind, ExprKind::StructLiteral { name: None, .. })))
            {
                return Err("struct literals may only initialize a typed struct declaration; composite values are not supported".into());
            }
            return self.emit_with_bound_arg(pairing, position, Self::emit_pairing);
        }
        for index in 0..pairs {
            for (points, ty) in [(g1, "ECPoint"), (g2, "G2Point")] {
                let index = Box::new(points.with_kind(ExprKind::Literal(index.to_string())));
                let element = points.with_kind(match &points.kind {
                    ExprKind::Name(path) => ExprKind::ArrayIndex {
                        array: path.clone(),
                        index,
                    },
                    _ => ExprKind::IndexAccess {
                        value: Box::new(points.clone()),
                        index,
                    },
                });
                for (field, field_type) in crate::models::builtin_struct_fields(ty)
                    .ok_or_else(|| CompileError::internal("missing native point layout"))?
                {
                    let leaf = points.with_kind(ExprKind::FieldAccess {
                        value: Box::new(element.clone()),
                        field: field.to_string(),
                    });
                    self.emit_access_value(&leaf, &TypeName::parse(field_type))?;
                }
            }
        }
        self.push_integer_temporary(pairs);
        self.emit_expression(curve_id)?;
        self.apply(Opcode::EcPairing, 6 * pairs + 2, 1)
    }
}
