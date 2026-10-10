//! The generator's model of the stack: which binding each slot holds, and the
//! reads, assignments, scopes and joins that move them.

use super::*;

impl Generator {
    pub(super) fn push_temporary(&mut self, op: Op) {
        self.asm.push(op);
        self.stack.push(StackItem::Temporary);
        self.max_depth = self.max_depth.max(self.stack.len());
    }

    pub(super) fn binding_index(&self, name: &Path) -> Option<usize> {
        self.aliases.get(name).copied().or_else(|| {
            self.stack.iter().position(
                |item| matches!(item, StackItem::Binding { name: binding, .. } if binding == name),
            )
        })
    }

    /// Declared element count, independent of the flattened element width.
    pub(super) fn array_length(&self, array: &Path) -> usize {
        match self.scope.get(&array.key()) {
            Some(types::ArkType::Array(_, length)) => *length,
            _ => 0,
        }
    }

    pub(super) fn read_binding(&mut self, name: &Path) -> Result<(), String> {
        // A field named `length` outranks synthetic array length.
        let is_binding = self.binding_index(name).is_some() || self.inlined.contains_key(name);
        if let Some((array, "length")) = name.split_last().filter(|_| !is_binding) {
            let length = self.array_length(&array);
            if length == 0 {
                return Err(format!("'{array}' is not an array; '.length' is undefined"));
            }
            self.push_integer_temporary(length);
            return Ok(());
        }
        self.read_static_binding(name, false)
    }

    pub(super) fn read_static_binding(&mut self, name: &Path, take: bool) -> Result<(), String> {
        let Some(index) = self.binding_index(name) else {
            let placeholder = self
                .inlined
                .get(name)
                .ok_or_else(|| format!("undefined binding '{name}'"))?;
            self.push_temporary(Op::Param(placeholder.clone()));
            return Ok(());
        };
        // An inlined alias source is copied once at the call, however often the helper reads it.
        if !self.aliases.contains_key(name) {
            self.count_constructor_reads(index, 1);
        }
        let depth = self.stack.len() - 1 - index;
        let consume = if let Some(cursor) = self.read_cursor.as_mut() {
            let consume = *self
                .final_reads
                .get(*cursor)
                .ok_or("internal compiler error: final-use analysis diverged from emission")?;
            *cursor += 1;
            consume
        } else {
            if let Some(previous) = self
                .last_reads
                .insert((name.clone(), index), self.final_reads.len())
            {
                self.final_reads[previous] = false;
            }
            // Arrays and outer scope slots stay pinned unless reassignment restores the slot.
            self.final_reads.push(
                take || (!self.preserve_bindings
                    && index >= self.pinned_stack_len
                    && !name.root.starts_with('$')
                    && !name
                        .segments
                        .iter()
                        .any(|segment| matches!(segment, Segment::Index(_)))
                    && (self.scopes.last().is_none_or(|(baseline, scope)| {
                        index >= *baseline && !scope.contains_key(&name.key())
                    }) || self
                        .replacement
                        .as_ref()
                        .is_some_and(|(target, _, _)| target == name))),
            );
            false
        };
        self.push_integer_temporary(depth);
        if consume {
            self.stack.remove(index);
        }
        self.apply(if consume { Roll } else { Pick }, 1, 1)
    }

    pub(super) fn count_constructor_reads(&mut self, index: usize, reads: usize) {
        if let StackItem::Binding {
            name,
            kind: BindingKind::Constructor,
        } = &self.stack[index]
        {
            *self.constructor_reads.entry(name.clone()).or_default() += reads;
        }
    }

    /// Runtime indexes address leaves by their prologue slots.
    // ponytail: pins every leaf of the indexed parameter, so unread siblings keep slots;
    // pin only the indexed array's leaves if wide runtime-indexed structs become common.
    pub(super) fn pin_constructor_slots(&mut self, path: &Path) {
        for index in 0..self.stack.len() {
            if matches!(&self.stack[index], StackItem::Binding { name, .. } if name.root == path.root)
            {
                self.count_constructor_reads(index, 2);
            }
        }
    }

    pub(super) fn push_integer_temporary(&mut self, value: usize) {
        self.push_temporary(integer_op(value));
    }

    pub(super) fn check_array_index(&mut self, length: usize) -> Result<(), String> {
        self.apply(Dup, 1, 2)?;
        self.push_integer_temporary(0);
        self.apply(GreaterThanOrEqual, 2, 1)?;
        self.apply(Verify, 1, 0)?;

        self.apply(Dup, 1, 2)?;
        self.push_integer_temporary(length);
        self.apply(LessThan, 2, 1)?;
        self.apply(Verify, 1, 0)
    }

    pub(super) fn select_indexed_value(&mut self, array: &Path) -> Result<(), String> {
        let first_element = array.clone().index(0);
        let first_index = self
            .binding_index(&first_element)
            .ok_or_else(|| format!("undefined array binding '{array}'"))?;
        self.pin_constructor_slots(array);
        let first_depth_without_index =
            self.stack
                .len()
                .checked_sub(first_index + 2)
                .ok_or_else(|| {
                    format!(
                        "internal compiler error: array index for '{array}' is not on the stack"
                    )
                })?;

        self.check_array_index(self.array_length(array))?;
        if first_depth_without_index != 0 {
            self.push_integer_temporary(first_depth_without_index);
            self.apply(Add, 2, 1)?;
        }
        self.apply(Pick, 1, 1)
    }

    pub(super) fn pop_temporaries(&mut self, count: usize, opcode: Opcode) -> Result<(), String> {
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

    pub(super) fn apply(
        &mut self,
        opcode: Opcode,
        inputs: usize,
        outputs: usize,
    ) -> Result<(), String> {
        self.pop_temporaries(inputs, opcode)?;
        self.asm.push(Op::Opcode(opcode));
        self.stack
            .extend(std::iter::repeat_n(StackItem::Temporary, outputs));
        self.max_depth = self.max_depth.max(self.stack.len());
        Ok(())
    }

    pub(super) fn nip(&mut self) -> Result<(), String> {
        if self.stack.len() < 2 {
            return Err("internal compiler error: OP_NIP stack underflow".to_string());
        }
        let index = self.stack.len() - 2;
        self.stack.remove(index);
        self.asm.push(Op::Opcode(Nip));
        Ok(())
    }

    pub(super) fn swap(&mut self) -> Result<(), String> {
        if self.stack.len() < 2 {
            return Err("internal compiler error: OP_SWAP stack underflow".to_string());
        }
        let len = self.stack.len();
        self.stack.swap(len - 2, len - 1);
        self.asm.push(Op::Opcode(Swap));
        Ok(())
    }

    pub(super) fn bind_local(&mut self, name: Path) -> Result<(), String> {
        let top = self.stack.last_mut().ok_or_else(|| {
            "internal compiler error: local initializer produced no value".to_string()
        })?;
        if !matches!(top, StackItem::Temporary) {
            return Err(
                "internal compiler error: local initializer did not leave a temporary".to_string(),
            );
        }
        *top = StackItem::Binding {
            name,
            kind: BindingKind::Local,
        };
        Ok(())
    }

    pub(super) fn assign(&mut self, target: &AssignmentTarget) -> Result<(), String> {
        match target {
            AssignmentTarget::Access(value) => self.assign_access(value),
            AssignmentTarget::Binding(name) => self.assign_static_binding(name.clone()),
            AssignmentTarget::ArrayIndex { array, index } => match &index.kind {
                ExprKind::Literal(literal) => match literal.parse() {
                    Ok(index) => self.assign_static_binding(array.clone().index(index)),
                    Err(_) => Err(format!(
                        "assignment to undeclared binding '{array}[{literal}]'"
                    )),
                },
                _ => self.assign_indexed_binding(array, index),
            },
        }
    }

    pub(super) fn assign_static_binding(&mut self, name: Path) -> Result<(), String> {
        if self.aliases.contains_key(&name) {
            return Err(format!(
                "internal compiler error: aliased parameter '{name}' is assigned"
            ));
        }
        if let Some((target, kind, start)) = self.replacement.clone() {
            if target == name && !self.preserve_bindings {
                if !matches!(self.stack.last(), Some(StackItem::Temporary)) {
                    return Err(
                        "internal compiler error: assignment has no result value".to_string()
                    );
                }
                if let Some(index) = self.stack.len().checked_sub(2) {
                    if let Some(previous) = self.last_reads.remove(&(name.clone(), index)) {
                        if previous < start {
                            self.final_reads[previous] = false;
                        }
                    }
                }
                if let Some(index) = self.binding_index(&name) {
                    if index + 2 != self.stack.len() {
                        return Err(
                            "internal compiler error: assignment target moved below the top slot"
                                .to_string(),
                        );
                    }
                    self.nip()?;
                }
                *self
                    .stack
                    .last_mut()
                    .ok_or("internal compiler error: assignment has no result value")? =
                    StackItem::Binding { name, kind };
                return Ok(());
            }
        }
        let index = self
            .binding_index(&name)
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
        if let Some(previous) = self.last_reads.remove(&(name.clone(), index)) {
            self.final_reads[previous] = false;
        }
        let depth = self.stack.len().checked_sub(index + 2).ok_or_else(|| {
            format!("internal compiler error: invalid assignment target '{name}'")
        })?;
        self.push_integer_temporary(depth);
        self.apply(Put, 2, 0)
    }

    pub(super) fn assign_indexed_binding(
        &mut self,
        array: &Path,
        index: &Expression,
    ) -> Result<(), String> {
        if !matches!(self.stack.last(), Some(StackItem::Temporary)) {
            return Err("internal compiler error: assignment has no result value".to_string());
        }
        // The index expression may consume a binding, so resolve the array slot after it.
        self.emit_expression(index)?;
        let first_index = self
            .binding_index(&array.clone().index(0))
            .ok_or_else(|| format!("undefined array binding '{array}'"))?;
        if matches!(
            self.stack[first_index],
            StackItem::Binding {
                kind: BindingKind::Constructor,
                ..
            }
        ) {
            return Err(format!(
                "cannot assign to constructor parameter '{array}'; constructor parameters are immutable"
            ));
        }
        let first_depth_without_operands =
            self.stack
                .len()
                .checked_sub(first_index + 3)
                .ok_or_else(|| {
                    format!(
                        "internal compiler error: array assignment operands for '{array}' are not on the stack"
                    )
                })?;
        self.check_array_index(self.array_length(array))?;
        if first_depth_without_operands != 0 {
            self.push_integer_temporary(first_depth_without_operands);
            self.apply(Add, 2, 1)?;
        }
        self.apply(Put, 2, 0)
    }

    pub(super) fn enter_scope(&mut self) {
        self.scopes.push((self.stack.len(), self.scope.clone()));
    }

    pub(super) fn exit_scope(&mut self) -> Result<(), String> {
        let (baseline, scope) = self
            .scopes
            .pop()
            .ok_or("internal compiler error: scope stack underflow")?;
        for index in (baseline..self.stack.len()).rev() {
            match &self.stack[index] {
                StackItem::Binding {
                    name,
                    kind: BindingKind::Local,
                } if !scope.contains_key(&name.key()) => self.drop_binding(index)?,
                StackItem::Binding { .. } => {}
                StackItem::Temporary => {
                    return Err("internal compiler error: scope ended with a temporary".into())
                }
            }
        }
        self.deferred.retain(|name| scope.contains_key(name));
        self.scope = scope;
        Ok(())
    }

    pub(super) fn drop_binding(&mut self, index: usize) -> Result<(), String> {
        let depth = self.stack.len() - index - 1;
        match depth {
            0 => self.asm.push(Op::Opcode(Drop)),
            1 => self.asm.push(Op::Opcode(Nip)),
            _ => {
                self.push_integer_temporary(depth);
                self.pop_temporaries(1, Roll)?;
                self.asm.extend([Op::Opcode(Roll), Op::Opcode(Drop)]);
            }
        }
        self.stack.remove(index);
        self.last_reads.retain(|(_, slot), _| *slot < index);
        Ok(())
    }

    // Joins scan local frames quadratically; index permutations if large frames become common.
    pub(super) fn join_stack(&mut self, target: &[StackItem]) -> Result<(), String> {
        if self.stack == target {
            return Ok(());
        }
        for index in (0..self.stack.len()).rev() {
            if !target.contains(&self.stack[index]) {
                self.drop_binding(index)?;
            }
        }
        for item in target {
            if !self.stack.contains(item) {
                let StackItem::Binding { name, .. } = item else {
                    return Err("internal compiler error: temporary at branch join".into());
                };
                // Returning paths share the join frame; direct return lowering could remove this padding.
                self.push_temporary(Op::Opcode(Int0));
                self.bind_local(name.clone())?;
            }
        }
        if self.stack != target {
            let start = self
                .stack
                .iter()
                .zip(target)
                .take_while(|(left, right)| left == right)
                .count();
            for item in &target[start..] {
                let index = self
                    .stack
                    .iter()
                    .position(|slot| slot == item)
                    .ok_or("internal compiler error: missing branch binding")?;
                let depth = self.stack.len() - index - 1;
                if depth != 0 {
                    if depth == 1 {
                        self.swap()?;
                    } else {
                        self.push_integer_temporary(depth);
                        self.pop_temporaries(1, Roll)?;
                        self.asm.push(Op::Opcode(Roll));
                        let item = self.stack.remove(index);
                        self.stack.push(item);
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn assert_statement_boundary(&self) -> Result<(), String> {
        if self
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
}

#[cfg(test)]
mod symbolic_stack_tests {
    use super::*;

    #[test]
    fn deep_assignment_uses_put_at_the_remaining_stack_depth() {
        let inputs = ["a", "b", "c", "d"]
            .into_iter()
            .map(|name| Parameter {
                name: name.to_string(),
                param_type: "int".to_string(),
            })
            .collect::<Vec<_>>();
        let mut generator =
            Generator::new(&inputs, &[], &[], &Default::default()).expect("scalar test inputs");

        generator.push_temporary(Op::Push("9".into()));
        generator
            .assign(&AssignmentTarget::Binding(Path::new("d")))
            .expect("deep assignment");

        assert_eq!(
            generator.asm.iter().map(Op::spell).collect::<Vec<_>>(),
            ["9", "OP_3", "OP_PUT"]
        );
        assert_eq!(
            generator.stack,
            ["d", "c", "b", "a"]
                .into_iter()
                .map(|name| StackItem::Binding {
                    name: Path::new(name),
                    kind: BindingKind::FunctionInput,
                })
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn shallow_assignment_uses_zero_depth_put() {
        let inputs = ["a", "b"]
            .into_iter()
            .map(|name| Parameter {
                name: name.to_string(),
                param_type: "int".to_string(),
            })
            .collect::<Vec<_>>();
        let mut generator =
            Generator::new(&inputs, &[], &[], &Default::default()).expect("scalar test inputs");

        generator.push_temporary(Op::Push("9".into()));
        generator
            .assign(&AssignmentTarget::Binding(Path::new("a")))
            .expect("shallow assignment");

        assert_eq!(
            generator.asm.iter().map(Op::spell).collect::<Vec<_>>(),
            ["9", "OP_0", "OP_PUT"]
        );
        assert_eq!(
            generator.stack,
            ["b", "a"]
                .into_iter()
                .map(|name| StackItem::Binding {
                    name: Path::new(name),
                    kind: BindingKind::FunctionInput,
                })
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn indexed_assignment_without_offset_preserves_bindings() {
        let inputs = [
            Parameter {
                name: "values".into(),
                param_type: "int[3]".into(),
            },
            Parameter {
                name: "i".into(),
                param_type: "int".into(),
            },
        ];
        let mut generator =
            Generator::new(&inputs, &[], &[], &Default::default()).expect("array test inputs");
        let bindings = generator.stack.clone();
        generator.push_temporary(Op::Push("9".into()));
        generator
            .assign(&AssignmentTarget::ArrayIndex {
                array: Path::new("values"),
                index: Box::new(ExprKind::Name(crate::models::Path::from_key("i")).into()),
            })
            .expect("indexed assignment");
        assert_eq!(
            generator.asm.iter().map(Op::spell).collect::<Vec<_>>(),
            [
                "9",
                "OP_4",
                "OP_PICK",
                "OP_DUP",
                "OP_0",
                "OP_GREATERTHANOREQUAL",
                "OP_VERIFY",
                "OP_DUP",
                "OP_3",
                "OP_LESSTHAN",
                "OP_VERIFY",
                "OP_PUT",
            ]
        );
        assert_eq!(generator.stack, bindings);
    }

    #[test]
    fn expression_index_assignment_checks_bounds_and_uses_put() {
        let inputs = [
            Parameter {
                name: "values".to_string(),
                param_type: "int[3]".to_string(),
            },
            Parameter {
                name: "i".to_string(),
                param_type: "int".to_string(),
            },
        ];
        let mut generator =
            Generator::new(&inputs, &[], &[], &Default::default()).expect("array test inputs");
        generator.push_temporary(Op::Push("7".into()));
        generator
            .bind_local(Path::new("above"))
            .expect("local above array");

        generator.push_temporary(Op::Push("9".into()));
        generator
            .assign(&AssignmentTarget::ArrayIndex {
                array: Path::new("values"),
                index: Box::new(
                    ExprKind::BinaryOp {
                        left: Box::new(ExprKind::Name(crate::models::Path::from_key("i")).into()),
                        op: crate::operators::BinaryOperator::Add,
                        right: Box::new(ExprKind::Literal("1".to_string()).into()),
                    }
                    .into(),
                ),
            })
            .expect("expression index assignment");

        assert_eq!(
            generator.asm.iter().map(Op::spell).collect::<Vec<_>>(),
            [
                "7",
                "9",
                "OP_5",
                "OP_PICK",
                "1",
                "OP_ADD",
                "OP_DUP",
                "OP_0",
                "OP_GREATERTHANOREQUAL",
                "OP_VERIFY",
                "OP_DUP",
                "OP_3",
                "OP_LESSTHAN",
                "OP_VERIFY",
                "OP_1",
                "OP_ADD",
                "OP_PUT",
            ]
        );
        assert!(generator
            .stack
            .iter()
            .all(|item| !matches!(item, StackItem::Temporary)));
        assert_eq!(
            generator.stack.last(),
            Some(&StackItem::Binding {
                name: Path::new("above"),
                kind: BindingKind::Local,
            })
        );
    }
}
