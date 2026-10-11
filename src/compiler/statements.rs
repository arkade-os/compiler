//! Statement lowering onto the generator.

use super::*;

impl Generator {
    pub(super) fn emit_branches(
        &mut self,
        then_body: &[LocatedStatement],
        else_body: Option<&[LocatedStatement]>,
        implicit_else_continues: bool,
    ) -> Result<bool, String> {
        let baseline = self.stack.clone();
        let deferred = self.deferred.clone();
        let start = self.asm.len();
        self.enter_scope();
        let left_continues = generate_asm_from_statements_recursive(then_body, self)?;
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
            let continues = generate_asm_from_statements_recursive(body, self)?;
            self.exit_scope()?;
            continues
        } else {
            implicit_else_continues
        };
        let right = self.stack.clone();
        let right_deferred = self.deferred.clone();
        let right_asm = self.asm.split_off(start);
        let initialized: std::collections::HashSet<_> = deferred
            .iter()
            .filter(|name| {
                (left_continues || right_continues)
                    && (!left_continues || !left_deferred.contains(*name))
                    && (!right_continues || !right_deferred.contains(*name))
            })
            .cloned()
            .collect();
        let mut initialized_leaves = std::collections::HashSet::new();
        for name in &initialized {
            let ty = self
                .scope
                .get(name)
                .ok_or("internal compiler error: missing declaration type")?;
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
            return Err("internal compiler error: branch changed outer stack layout".into());
        }
        self.stack = left;
        self.asm.extend(left_asm);
        self.join_stack(&target)?;
        let left_joined = self.asm.split_off(start);
        self.stack = right;
        self.asm.extend(right_asm);
        self.join_stack(&target)?;
        let right_joined = self.asm.split_off(start);
        self.asm.extend(left_joined);
        if else_body.is_some() || !right_joined.is_empty() {
            self.asm.push(Else.into());
            self.asm.extend(right_joined);
        }
        self.asm.push(EndIf.into());
        self.deferred = deferred.difference(&initialized).cloned().collect();
        self.last_reads
            .retain(|(_, slot), _| *slot < baseline.len());
        Ok(left_continues || right_continues)
    }
}

/// Generate assembly and report whether an emitted path falls through.
pub(super) fn generate_asm_from_statements_recursive(
    statements: &[LocatedStatement],
    generator: &mut Generator,
) -> Result<bool, String> {
    for (index, stmt) in statements.iter().enumerate() {
        let mut folded;
        let stmt = if generator.optimize {
            folded = stmt.clone();
            optimization::fold_statement(&mut folded.statement, &generator.scope)?;
            &folded
        } else {
            stmt
        };
        let mut continues = true;
        match &stmt.statement {
            Statement::Call(expression) => generator.emit_call(expression)?,
            Statement::Return(value) => {
                generator.emit_return(value.as_ref())?;
                return Ok(false);
            }
            Statement::Require(req) => {
                generate_requirement_asm(req, generator)?;
            }
            Statement::IfElse {
                condition,
                then_body,
                else_body,
            } => {
                if generator.optimize
                    && matches!(&condition.kind, ExprKind::Literal(value) if value == "true" || value == "false")
                {
                    let body = if matches!(&condition.kind, ExprKind::Literal(value) if value == "true")
                    {
                        then_body.as_slice()
                    } else {
                        else_body.as_deref().unwrap_or_default()
                    };
                    generator.enter_scope();
                    continues = generate_asm_from_statements_recursive(body, generator)?;
                    generator.exit_scope()?;
                } else {
                    generator.emit_expression(condition)?;
                    generator.apply(If, 1, 0)?;
                    continues = generator.emit_branches(then_body, else_body.as_deref(), true)?;
                }
            }
            Statement::ForIn {
                index_var,
                value_var,
                iterable,
                body,
            } => {
                let types::ArkType::Array(_, length) = iterable.ty else {
                    return Err("unsupported loop iterable".to_string());
                };
                for k in 0..length {
                    let mut substituted =
                        substitute_loop_body(body, index_var, value_var, k, iterable);
                    // Substitution builds untyped nodes; return types and group members
                    // were resolved on the original body and survive the copy.
                    types::annotate_statements(
                        &mut substituted,
                        &mut generator.scope.clone(),
                        &generator.structs,
                    );
                    let baseline = generator.stack.clone();
                    generator.enter_scope();
                    continues = if k > 0 && functions::contains_return(body) {
                        generator.emit_unless_returned(&substituted)?
                    } else {
                        generate_asm_from_statements_recursive(&substituted, generator)?
                    };
                    generator.exit_scope()?;
                    if !generator.stack.starts_with(&baseline) {
                        return Err(format!("internal compiler error: loop iteration {k} changed outer stack layout"));
                    }
                    if !continues && generator.optimize {
                        break;
                    }
                }
            }
            Statement::ForCount { count, body } => {
                let ExprKind::Literal(count) = &count.kind else {
                    return Err(
                        "loop count must be a non-negative integer compile-time constant"
                            .to_string(),
                    );
                };
                let count = count.parse::<usize>().map_err(|_| {
                    "loop count must be a non-negative integer compile-time constant".to_string()
                })?;
                for k in 0..count {
                    let baseline = generator.stack.clone();
                    generator.enter_scope();
                    continues = if k > 0 && functions::contains_return(body) {
                        generator.emit_unless_returned(body)?
                    } else {
                        generate_asm_from_statements_recursive(body, generator)?
                    };
                    generator.exit_scope()?;
                    if !generator.stack.starts_with(&baseline) {
                        return Err(format!("internal compiler error: loop iteration {k} changed outer stack layout"));
                    }
                    if !continues && generator.optimize {
                        break;
                    }
                }
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
                        _ => crate::models::expression_result_struct(value).map(TypeName::from),
                    })
                    .or_else(|| generator.composite_type(value));
                if let Some(ty) = &result_type {
                    generator.emit_typed_value(value, ty)?;
                    generator.bind_value(name, ty)?;
                    generator.bind_type(name, ty);
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
                    (
                        AssignmentTarget::Binding(name),
                        Some(StackItem::Binding { name: top, kind }),
                    ) if name == top
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
                types::annotate_expression(&mut access, &generator.scope);
                if let AssignmentTarget::Binding(name) = target {
                    if generator.deferred.remove(&name.key()) {
                        generator.emit_typed_value(value, &TypeName::from(&access.ty))?;
                        generator.bind_value(&name.key(), &TypeName::from(&access.ty))?;
                        generator.replacement = previous_replacement;
                        generator.assert_statement_boundary()?;
                        continue;
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
        generator.assert_statement_boundary()?;
        if !continues {
            return Ok(false);
        }
        if functions::contains_return(std::slice::from_ref(stmt)) && index + 1 < statements.len() {
            return generator.emit_unless_returned(&statements[index + 1..]);
        }
    }
    Ok(true)
}

/// Generate assembly for a single requirement
fn generate_requirement_asm(req: &Requirement, generator: &mut Generator) -> Result<(), String> {
    if generator.optimize
        && matches!(req, Requirement::Expression(Expression { kind: ExprKind::Literal(value), .. }) if value == "true")
    {
        return Ok(());
    }
    match req {
        Requirement::Expression(expr) => {
            match &expr.kind {
                ExprKind::GroupFind { .. } => {
                    generator.emit_expression(expr)?;
                    generator.apply(Drop, 1, 0)?;
                    generator.push_temporary(Int1);
                    generator.apply(Verify, 1, 0)?;
                }
                ExprKind::Builtin { builtin, .. } if builtin.result.is_none() => {
                    generator.emit_expression_items(expr, 0)?;
                }
                _ => {
                    generator.emit_expression(expr)?;
                    generator.apply(Verify, 1, 0)?;
                }
            }
            Ok(())
        }
        Requirement::Comparison { left, op, right } => {
            if let Some(ty) = generator
                .composite_type(left)
                .or_else(|| generator.composite_type(right))
            {
                return generator.emit_composite_requirement(left, *op, right, &ty);
            }
            generator.emit_expression(left)?;
            generator.emit_expression(right)?;
            for &opcode in op.opcodes() {
                generator.lower_raw_opcode(opcode)?;
            }
            generator.apply(Verify, 1, 0)?;
            Ok(())
        }
    }
}
