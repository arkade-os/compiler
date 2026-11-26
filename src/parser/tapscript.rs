use super::Rule;
#[allow(unused_imports)]
use super::*;
use pest::iterators::Pair;

/// True if a `function` pair carries a `tapscript_block` body.
pub(crate) fn function_pair_is_tapscript(pair: &Pair<Rule>) -> bool {
    pair.clone()
        .into_inner()
        .any(|p| p.as_rule() == Rule::tapscript_block)
}

/// Parse a `function <name>(<params>) tapscript { … }` declaration.
pub(crate) fn parse_named_tapscript(
    pair: Pair<Rule>,
    constants: &[Constant],
) -> Result<crate::models::NamedTapscript, CompileError> {
    let declaration = pair.as_span().into();
    let mut inner = pair.into_inner().peekable();
    if let Some(visibility) = inner.next_if(|p| p.as_rule() == Rule::function_visibility) {
        return Err(format!("tapscript functions cannot be {}", visibility.as_str()).into());
    }
    let name = inner.next().ok_or("Missing tapscript name")?;
    let span = name.as_span().into();
    let name = name.as_str().to_string();
    let params = inner.next().ok_or("Missing tapscript parameter list")?;
    let inputs = parse_parameters(params)?;
    let block = inner.next().ok_or("Missing tapscript body")?;
    let mut items = Vec::new();
    let mut consumed = std::collections::HashSet::new();
    for stmt in block.into_inner() {
        if stmt.as_rule() == Rule::tap_require_stmt {
            let mut inner = stmt.into_inner();
            let expr = inner.next().ok_or("Empty require() in tapscript")?;
            // Start and text of the older/after argument a blocks/seconds unit may fill.
            let mut units = Vec::new();
            for part in std::iter::once(expr.clone()).chain(expr.clone().into_inner().flatten()) {
                let name = match part.as_rule() {
                    Rule::function_call => {
                        let mut call = part.clone().into_inner();
                        let callee = call.next().ok_or("Missing call name")?.as_str();
                        let args: Vec<_> = call.collect();
                        if crate::models::HashFn::parse(callee).is_some() {
                            let message = format!(
                                "a tapscript function can use `{callee}` only as \
                                 `require({callee}(preimage) == hash)`"
                            );
                            return Err(CompileError::from(message).at(part.as_span().into()));
                        }
                        if let Some(params) = crate::builtins::tapscript_params(callee) {
                            let whole = matches!(callee, "older" | "after")
                                && part.as_str() == trim_trivia_end(expr.as_str());
                            if whole {
                                units.extend(args.first().map(|arg| {
                                    (arg.as_span().start(), trim_trivia_end(arg.as_str()))
                                }));
                            }
                            let unit = matches!(callee, "blocks" | "seconds")
                                && units.contains(&(part.as_span().start(), part.as_str()));
                            if whole || unit || params.len() != args.len() {
                                continue;
                            }
                            let signature = format!("{callee}({})", params.join(", "));
                            let place = match callee {
                                "older" | "after" => format!("`require({signature})`"),
                                "tweak" => "a key inside checkSig or checkMultisig".to_string(),
                                _ => format!("`older({signature})` or `after({signature})`"),
                            };
                            let message =
                                format!("a tapscript function can use `{callee}` only as {place}");
                            return Err(CompileError::from(message).at(part.as_span().into()));
                        }
                        let tapscript_call = crate::builtins::find(callee)
                            .is_none_or(|b| matches!(b.name, "checkSig" | "checkMultisig"));
                        if tapscript_call {
                            continue;
                        }
                        format!("{callee}(...)")
                    }
                    Rule::primary_expr => match arkade_script_member(&part) {
                        Some(name) => name,
                        None => continue,
                    },
                    _ => continue,
                };
                let message = format!("`{name}` is only available in Arkade Script functions");
                return Err(CompileError::from(message).at(part.as_span().into()));
            }
            let at = expr.as_span().into();
            let item = parse_tap_item(expr.clone(), constants)
                .map_err(|e| CompileError::from(e).at(at))?;
            let operands = match &item {
                crate::models::TapItem::Hash { preimage, .. } => std::slice::from_ref(preimage),
                crate::models::TapItem::Sig { sigs, .. } => sigs.as_slice(),
                _ => &[],
            };
            for (path, operand) in operands.iter().zip(witness_operands(&expr)) {
                let input = path.key();
                if inputs.iter().any(|p| p.name == input) && !consumed.insert(input.clone()) {
                    let message = format!(
                        "tapscript `{name}`: input `{input}` is used more than once, but the \
                         witness carries each input once; declare a separate input for each use"
                    );
                    return Err(CompileError::from(message).at(operand.as_span().into()));
                }
            }
            items.push(item);
            if let Some(message) = inner.next() {
                parse_string_literal(message.as_str())?;
            }
        }
    }
    Ok(crate::models::NamedTapscript {
        name,
        span,
        declaration,
        attributes: Vec::new(),
        inputs,
        items,
    })
}

/// The operands a tapscript require consumes from the witness, in source order: a hash's
/// preimage or a signature check's signatures.
fn witness_operands<'a>(expr: &Pair<'a, Rule>) -> Vec<Pair<'a, Rule>> {
    let mut inner = expr.clone().into_inner();
    match expr.as_rule() {
        Rule::hash_comparison => inner
            .next()
            .and_then(|f| f.into_inner().nth(1))
            .into_iter()
            .collect(),
        Rule::check_sig => inner.take(1).collect(),
        Rule::check_multisig => inner
            .nth(1)
            .into_iter()
            .flat_map(|sigs| sigs.into_inner())
            .collect(),
        _ => Vec::new(),
    }
}

/// The Arkade-Script-only member a `primary_expr` starts with: `this.expiry`, `this.tunnel(...)`,
/// `this.renew(...)`, `tx.proof.output`, `tx.proof.field(...)` or `tx.proof.has(...)`, or either
/// of the last two under the deprecated `tx.intent`.
fn arkade_script_member(pair: &Pair<Rule>) -> Option<String> {
    let mut inner = pair.clone().into_inner();
    let mut name = inner
        .next()
        .filter(|head| head.as_rule() == Rule::identifier)?
        .as_str()
        .to_string();
    for postfix in inner {
        let mut parts = postfix.into_inner();
        let member = parts.next().filter(|p| p.as_rule() == Rule::identifier)?;
        name = format!("{name}.{}", member.as_str());
        match (name.as_str(), parts.next().is_some()) {
            ("tx.proof" | "tx.intent", false) => continue,
            ("this.expiry" | "tx.proof.output", false) => return Some(name),
            (
                "this.tunnel" | "this.renew" | "tx.proof.field" | "tx.proof.has"
                | "tx.intent.field" | "tx.intent.has",
                true,
            ) => return Some(format!("{name}(...)")),
            _ => return None,
        }
    }
    None
}

/// Interpret one `require(...)` inner expression as a tapscript item.
pub(crate) fn parse_tap_item(
    pair: Pair<Rule>,
    constants: &[Constant],
) -> Result<crate::models::TapItem, String> {
    use crate::models::{HashFn, TapItem, TapOperand};
    match pair.as_rule() {
        Rule::primary_expr if pair.clone().into_inner().nth(1).is_some() => Err(format!(
            "a tapscript require can check only signatures, hashes and timelocks, not `{}`",
            trim_trivia_end(pair.as_str())
        )),
        rule if is_operator_level(rule)
            || matches!(rule, Rule::unary_expr | Rule::primary_expr) =>
        {
            let mut inner = pair.into_inner();
            let item = inner
                .next()
                .ok_or("Empty expression in tapscript require()")?;
            if inner.next().is_some() {
                return Err("unsupported compound expression in tapscript require()".to_string());
            }
            parse_tap_item(item, constants)
        }
        Rule::hash_comparison => {
            let mut inner = pair.into_inner();
            let func = inner.next().ok_or("Missing hash function")?; // hash_func
            let mut f_inner = func.into_inner();
            let fn_name = f_inner.next().ok_or("Missing hash fn name")?.as_str();
            let hash_fn =
                HashFn::parse(fn_name).ok_or_else(|| format!("unknown hash function {fn_name}"))?;
            let preimage = parse_general_expression(f_inner.next().ok_or("Missing hash preimage")?)?;
            let preimage = operand_path(&preimage, constants).ok_or_else(|| {
                format!(
                    "hash preimage `{}` is not a tapscript input",
                    preimage.source_text()
                )
            })?;
            let hash = inner.next().ok_or("Missing hash value")?;
            let hash = if hash.as_rule() == Rule::named_binding {
                let path = parse_binding(hash, constants)?;
                match constant_value(&path, constants) {
                    Ok(value) if value.starts_with("0x") => TapOperand::Literal(value),
                    _ => TapOperand::Name(path),
                }
            } else {
                TapOperand::Literal(parse_named_operand(hash)?)
            };
            Ok(TapItem::Hash {
                hash_fn,
                preimage,
                hash,
            })
        }
        Rule::time_comparison => Err(
            "`tx.locktime` is only available in Arkade Script functions; use `after(...)` in tapscript functions"
                .to_string(),
        ),
        Rule::check_sig => {
            let mut inner = pair.into_inner();
            let sig = parse_binding(inner.next().ok_or("Missing signature")?, constants)?;
            let key = parse_key_expr(inner.next().ok_or("Missing key")?, constants)?;
            Ok(TapItem::Sig {
                keys: vec![key],
                sigs: vec![sig],
            })
        }
        Rule::check_multisig => parse_tap_multisig(pair, constants),
        Rule::function_call => {
            // older(n) / after(n)
            let mut inner = pair.into_inner();
            let name = inner
                .next()
                .ok_or("Missing call name")?
                .as_str()
                .to_string();
            if !matches!(name.as_str(), "older" | "after") {
                return Err(format!("unsupported tapscript call `{name}(...)`"));
            }
            let arg = inner
                .next()
                .ok_or_else(|| format!("{name}() requires one argument"))?;
            if inner.next().is_some() {
                return Err(format!("{name}() requires one argument"));
            }
            let (value, unit) = parse_time_operand(&name, arg, constants)?;
            if name == "older" {
                Ok(TapItem::Older { value, unit })
            } else {
                Ok(TapItem::After { value, unit })
            }
        }
        other => Err(format!(
            "a tapscript require can check only signatures, hashes and timelocks, not {}",
            super::rule_term(&other).unwrap_or_else(|| "this expression".to_string())
        )),
    }
}

/// Split a timelock operand into its value and the unit of a `blocks(n)` or
/// `seconds(n)` wrapper.
fn parse_time_operand(
    call: &str,
    arg: Pair<Rule>,
    constants: &[Constant],
) -> Result<(crate::models::TapOperand, Option<crate::models::TimeUnit>), String> {
    use crate::models::TimeUnit;
    let text = trim_trivia_end(arg.as_str());
    let Some(wrapper) = arg
        .clone()
        .into_inner()
        .flatten()
        .find(|p| p.as_rule() == Rule::function_call && p.as_str() == text)
    else {
        return Ok((parse_time_value(arg, constants)?, None));
    };
    let mut parts = wrapper.into_inner();
    let unit_name = parts.next().ok_or("Missing call name")?.as_str();
    let unit = match unit_name {
        "blocks" => TimeUnit::Blocks,
        "seconds" => TimeUnit::Seconds,
        other => {
            return Err(format!(
                "{call}() takes blocks(n), seconds(n), or a value, not `{other}(...)`"
            ))
        }
    };
    let value = parts
        .next()
        .ok_or_else(|| format!("{unit_name}() requires one argument"))?;
    if parts.next().is_some() {
        return Err(format!("{unit_name}() requires one argument"));
    }
    Ok((parse_time_value(value, constants)?, Some(unit)))
}

/// A timelock value: a literal, with constants folded in, or the binding it reads.
fn parse_time_value(
    pair: Pair<Rule>,
    constants: &[Constant],
) -> Result<crate::models::TapOperand, String> {
    use crate::models::TapOperand;
    let value = parse_general_expression(pair)?;
    let mut constant = |path: &crate::models::Path| constant_value(path, constants);
    if let Ok(literal) = crate::compiler::constants::evaluate(&value, &mut constant) {
        return Ok(TapOperand::Literal(literal));
    }
    operand_path(&value, constants)
        .map(TapOperand::Name)
        .ok_or_else(|| {
            format!(
                "timelock `{}` is not a literal or scalar constructor parameter",
                value.source_text()
            )
        })
}

/// The binding `operand` reads, with each index evaluated from the constants, or `None` for
/// any other expression or an index that is not constant.
fn operand_path(operand: &Expression, constants: &[Constant]) -> Option<crate::models::Path> {
    let index = |index: &Expression| {
        let mut constant = |path: &crate::models::Path| constant_value(path, constants);
        crate::compiler::constants::evaluate(index, &mut constant)
            .ok()?
            .parse()
            .ok()
    };
    match &operand.kind {
        ExprKind::Name(path) => Some(path.clone()),
        ExprKind::ArrayIndex { array, index: at } => Some(array.clone().index(index(at)?)),
        ExprKind::IndexAccess { value, index: at } => {
            Some(operand_path(value, constants)?.index(index(at)?))
        }
        ExprKind::FieldAccess { value, field } => {
            Some(operand_path(value, constants)?.field(field))
        }
        _ => None,
    }
}

/// The literal value of the constant `path` names.
pub(crate) fn constant_value(
    path: &crate::models::Path,
    constants: &[Constant],
) -> Result<String, String> {
    let key = path.key();
    match constants
        .iter()
        .find(|c| c.name == key)
        .map(|c| &c.value.kind)
    {
        Some(ExprKind::Literal(value)) => Ok(value.clone()),
        _ => Err(format!("unknown constant '{path}'")),
    }
}

/// The binding a `named_binding` operand reads.
fn parse_binding(pair: Pair<Rule>, constants: &[Constant]) -> Result<crate::models::Path, String> {
    let binding = parse_property_access(pair)?;
    operand_path(&binding, constants).ok_or_else(|| {
        format!(
            "`{}` must be indexed by an integer literal or constant",
            binding.source_text()
        )
    })
}

/// Parse `check_multisig` inner pairs into a Sig item.
pub(crate) fn parse_tap_multisig(
    pair: Pair<Rule>,
    constants: &[Constant],
) -> Result<crate::models::TapItem, String> {
    use crate::models::TapItem;
    let mut keys = Vec::new();
    let mut sigs = Vec::new();
    for child in pair.into_inner() {
        match child.as_rule() {
            Rule::key_array => {
                for k in child.into_inner() {
                    keys.push(parse_key_expr(k, constants)?);
                }
            }
            Rule::array => {
                for s in child.into_inner() {
                    sigs.push(parse_binding(s, constants)?);
                }
            }
            _ => {}
        }
    }
    Ok(TapItem::Sig { keys, sigs })
}

/// Parse a `key_expr` (a pubkey binding, a pubkey constant or `tweak(base, func)`).
pub(crate) fn parse_key_expr(
    pair: Pair<Rule>,
    constants: &[Constant],
) -> Result<crate::models::KeyExpr, String> {
    use crate::models::KeyExpr;
    match pair.as_rule() {
        Rule::named_binding => {
            let path = parse_binding(pair, constants)?;
            let pubkey = constants.iter().any(|c| {
                c.name == path.key() && c.const_type.ark_type() == crate::types::ArkType::Bytes
            });
            if !pubkey {
                return Ok(KeyExpr::Ident(path));
            }
            // BIP-342 checks accept any signature for a key of another non-zero length.
            let value = constant_value(&path, constants)?;
            match (value.len() - 2) / 2 {
                32 => Ok(KeyExpr::Literal(value)),
                width => Err(format!(
                    "tapscript key '{path}' is {width} bytes; tapscript keys are 32-byte x-only public keys"
                )),
            }
        }
        Rule::key_expr => {
            let inner = pair.into_inner().next().ok_or("Empty key expression")?;
            parse_key_expr(inner, constants)
        }
        Rule::tweak_key => {
            let mut inner = pair.into_inner();
            let base = inner
                .next()
                .ok_or("Missing tweak base")?
                .as_str()
                .to_string();
            let func = inner
                .next()
                .ok_or("Missing tweak func name")?
                .as_str()
                .to_string();
            Ok(KeyExpr::Tweak { base, func })
        }
        other => Err(format!("unexpected key expression: {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    //! Parser-level tests for the `tapscript` modifier: assert AST routing,
    //! not ABI output.
    use crate::models::{Contract, HashFn, KeyExpr, Path, TapItem, TapOperand};

    fn parse(src: &str) -> Contract {
        super::super::parse(src).expect("parse should succeed")
    }

    #[test]
    fn routes_tapscript_into_tapscripts_not_functions() {
        let src = r#"
contract Demo(pubkey owner) {
    function claim() {
        require(tx.outputs[0].value >= 1);
    }
    function claim(bytes preimage, signature operatorSig, signature ownerSig) tapscript {
        require(hash160(preimage) == preimageHash);
        require(checkMultisig([operator, owner], [operatorSig, ownerSig]));
    }
}
"#;
        let c = parse(src);
        assert_eq!(
            c.functions.len(),
            1,
            "Arkade Script function stays in functions"
        );
        assert_eq!(c.functions[0].name, "claim");
        assert_eq!(c.tapscripts.len(), 1, "tapscript routed into tapscripts");
        let ts = &c.tapscripts[0];
        assert_eq!(ts.name, "claim");
        assert_eq!(ts.inputs.len(), 3);
        assert_eq!(ts.inputs[0].name, "preimage");
        // First item: HASH160 condition.
        match &ts.items[0] {
            TapItem::Hash {
                hash_fn,
                preimage,
                hash,
            } => {
                assert_eq!(*hash_fn, HashFn::Hash160);
                assert_eq!(preimage, "preimage");
                assert_eq!(hash, &TapOperand::Name("preimageHash".into()));
            }
            other => panic!("expected Hash item, got {other:?}"),
        }
        // Second item: multisig with two keys and two sigs.
        match &ts.items[1] {
            TapItem::Sig { keys, sigs } => {
                assert_eq!(
                    keys,
                    &vec![
                        KeyExpr::Ident("operator".into()),
                        KeyExpr::Ident("owner".into())
                    ]
                );
                assert_eq!(sigs, &vec![Path::new("operatorSig"), Path::new("ownerSig")]);
            }
            other => panic!("expected Sig item, got {other:?}"),
        }
    }

    #[test]
    fn parses_older_after_and_tweak_key() {
        let src = r#"
contract Demo(pubkey owner) {
    function exit(signature ownerSig) tapscript {
        require(older(exitDelay));
        require(checkSig(ownerSig, owner));
    }
    function direct(signature operatorSig) tapscript {
        require(checkSig(operatorSig, tweak(operator, exit)));
    }
    function cancel(signature backupSig, signature operatorSig) tapscript {
        require(after(cancelTime));
        require(checkMultisig([backup, operator], [backupSig, operatorSig]));
    }
}
"#;
        let c = parse(src);
        assert_eq!(c.tapscripts.len(), 3);
        let exit = c.tapscripts.iter().find(|t| t.name == "exit").unwrap();
        assert!(
            matches!(&exit.items[0], TapItem::Older { value: TapOperand::Name(value), unit: None } if value == "exitDelay")
        );
        let direct = c.tapscripts.iter().find(|t| t.name == "direct").unwrap();
        match &direct.items[0] {
            TapItem::Sig { keys, .. } => assert_eq!(
                keys,
                &vec![KeyExpr::Tweak {
                    base: "operator".into(),
                    func: "exit".into()
                }]
            ),
            other => panic!("expected Sig with tweak key, got {other:?}"),
        }
        let cancel = c.tapscripts.iter().find(|t| t.name == "cancel").unwrap();
        assert!(
            matches!(&cancel.items[0], TapItem::After { value: TapOperand::Name(value), unit: None } if value == "cancelTime")
        );
    }

    #[test]
    fn parses_operands_into_paths_with_constant_indexes_and_no_whitespace() {
        let src = r#"
struct Policy { pubkey owner; bytes32 h; int delay; }
contract Demo(pubkey[2] keys, Policy[2] ps) {
    const int SECOND = 1;
    function exit(bytes32 pre , signature s1 , signature s2 ) tapscript {
        require(sha256(pre ) == ps[ 0 ].h );
        require(older(ps[SECOND].delay ));
        require(checkMultisig([keys[ SECOND ] , ps[0].owner ], [s1 , s2 ]));
    }
}
"#;
        let c = parse(src);
        let ps = |at| Path::new("ps").index(at);
        let items = &c.tapscripts[0].items;
        assert!(matches!(
            &items[0],
            TapItem::Hash { preimage, hash: TapOperand::Name(hash), .. }
                if preimage == "pre" && *hash == ps(0).field("h")
        ));
        assert!(matches!(
            &items[1],
            TapItem::Older { value: TapOperand::Name(value), unit: None } if *value == ps(1).field("delay")
        ));
        match &items[2] {
            TapItem::Sig { keys, sigs, .. } => {
                assert_eq!(
                    keys,
                    &vec![
                        KeyExpr::Ident(Path::new("keys").index(1)),
                        KeyExpr::Ident(ps(0).field("owner"))
                    ]
                );
                assert_eq!(sigs, &vec![Path::new("s1"), Path::new("s2")]);
            }
            other => panic!("expected Sig item, got {other:?}"),
        }
    }

    #[test]
    fn rejects_a_runtime_index_in_a_tapscript_operand() {
        let src = "contract Demo(pubkey[2] keys) { function exit(signature s, int i) tapscript { require(checkSig(s, keys[i])); } }";
        let err = super::super::parse(src).unwrap_err();
        assert!(
            err.contains("`keys[i]` must be indexed by an integer literal or constant"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_extra_arguments_to_tapscript_time_locks_and_multisig() {
        for call in [
            "older(exitDelay, extra)",
            "after(cancelTime, extra)",
            "checkMultisig([owner], [ownerSig], 1)",
        ] {
            let src = format!(
                r#"
contract Demo(pubkey owner) {{
    function exit(signature ownerSig) tapscript {{
        require({call});
    }}
}}
"#
            );

            assert!(
                super::super::parse(&src).is_err(),
                "{call} should reject extra arguments"
            );
        }
    }

    #[test]
    fn rejects_tx_locktime_in_tapscript() {
        let src = r#"
contract Demo(pubkey owner, int deadline) {
    function exit(signature ownerSig) tapscript {
        require(tx.locktime >= deadline);
        require(checkSig(ownerSig, owner));
    }
}
"#;

        let err = super::super::parse(src).unwrap_err();
        assert!(err.contains("use `after(...)`"));
    }

    #[test]
    fn keeps_unsupported_tapscript_calls_on_unsupported_error_path() {
        let src = r#"
contract Demo(pubkey owner) {
    function exit(signature ownerSig) tapscript {
        require(foo(exitDelay, extra));
    }
}
"#;

        let err = super::super::parse(src).expect_err("unsupported tapscript call should fail");
        assert!(
            err.to_string()
                .contains("unsupported tapscript call `foo(...)`"),
            "unexpected error: {err}"
        );
    }
}
