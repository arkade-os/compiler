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
) -> Result<crate::models::NamedTapscript, String> {
    let declaration = pair.as_span().into();
    let mut inner = pair.into_inner().peekable();
    if inner
        .peek()
        .is_some_and(|p| p.as_rule() == Rule::function_visibility)
    {
        let visibility = inner.next().expect("visibility").as_str();
        if visibility != "public" {
            return Err(format!("tapscript functions cannot be {visibility}"));
        }
    }
    let name = inner.next().ok_or("Missing tapscript name")?;
    let span = name.as_span().into();
    let name = name.as_str().to_string();
    let params = inner.next().ok_or("Missing tapscript parameter list")?;
    let inputs = parse_parameters(params)?;
    let block = inner.next().ok_or("Missing tapscript body")?;
    let mut items = Vec::new();
    for stmt in block.into_inner() {
        if stmt.as_rule() == Rule::tap_require_stmt {
            let mut inner = stmt.into_inner();
            let expr = inner.next().ok_or("Empty require() in tapscript")?;
            for part in std::iter::once(expr.clone()).chain(expr.clone().into_inner().flatten()) {
                let callee = part.clone().into_inner().next();
                let name = match part.as_rule() {
                    Rule::function_call
                        if callee.is_some_and(|name| name.as_str() == "checkTime") =>
                    {
                        "checkTime(...)"
                    }
                    Rule::tunnel => "this.tunnel(...)",
                    Rule::intent_field => "tx.intent.field(...)",
                    Rule::intent_has => "tx.intent.has(...)",
                    Rule::this_property if part.as_str() == "expiry" => "this.expiry",
                    _ => continue,
                };
                return Err(format!("`{name}` is only available in covenant functions"));
            }
            items.push(parse_tap_item(expr, constants)?);
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

/// Interpret one `require(...)` inner expression as a tapscript item.
pub(crate) fn parse_tap_item(
    pair: Pair<Rule>,
    constants: &[Constant],
) -> Result<crate::models::TapItem, String> {
    use crate::models::{HashFn, TapItem, TapOperand};
    match pair.as_rule() {
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
            "`tx.locktime` is only available in covenant functions; use `after(...)` in tapscript functions"
                .to_string(),
        ),
        Rule::check_sig => {
            let mut inner = pair.into_inner();
            let sig = parse_binding(inner.next().ok_or("Missing signature")?, constants)?;
            let key = parse_key_expr(inner.next().ok_or("Missing key")?, constants)?;
            Ok(TapItem::Sig {
                keys: vec![key],
                sigs: vec![sig],
                threshold: Some(1),
            })
        }
        Rule::check_multisig => {
            // check_multisig wraps check_threshold_multisig.
            let inner = pair
                .into_inner()
                .next()
                .ok_or("Missing checkMultisig body")?;
            parse_tap_multisig(inner, constants)
        }
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
            "unsupported expression in tapscript require(): {other:?}"
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
    let text = arg.as_str().trim_end();
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
fn constant_value(path: &crate::models::Path, constants: &[Constant]) -> Result<String, String> {
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

/// Parse `check_threshold_multisig` inner pairs into a Sig item.
pub(crate) fn parse_tap_multisig(
    pair: Pair<Rule>,
    constants: &[Constant],
) -> Result<crate::models::TapItem, String> {
    use crate::models::TapItem;
    let mut keys = Vec::new();
    let mut sigs = Vec::new();
    let mut threshold = None;
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
            Rule::number_literal | Rule::qualified_name => {
                threshold = Some(parse_multisig_threshold(child, constants)?);
            }
            _ => {}
        }
    }
    Ok(TapItem::Sig {
        keys,
        sigs,
        threshold,
    })
}

/// Parse a `key_expr` (a pubkey binding or `tweak(emulator, func)`).
pub(crate) fn parse_key_expr(
    pair: Pair<Rule>,
    constants: &[Constant],
) -> Result<crate::models::KeyExpr, String> {
    use crate::models::KeyExpr;
    match pair.as_rule() {
        Rule::named_binding => parse_binding(pair, constants).map(KeyExpr::Ident),
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
    function claim(bytes preimage, signature serverSig, signature emulatorSig) tapscript {
        require(hash160(preimage) == preimageHash);
        require(checkMultisig([server, emulator], [serverSig, emulatorSig], 2));
    }
}
"#;
        let c = parse(src);
        assert_eq!(c.functions.len(), 1, "covenant function stays in functions");
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
        // Second item: multisig with two keys, two sigs, threshold 2.
        match &ts.items[1] {
            TapItem::Sig {
                keys,
                sigs,
                threshold,
            } => {
                assert_eq!(
                    keys,
                    &vec![
                        KeyExpr::Ident("server".into()),
                        KeyExpr::Ident("emulator".into())
                    ]
                );
                assert_eq!(
                    sigs,
                    &vec![Path::new("serverSig"), Path::new("emulatorSig")]
                );
                assert_eq!(*threshold, Some(2));
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
    function direct(signature emulatorSig) tapscript {
        require(checkSig(emulatorSig, tweak(emulator, exit)));
    }
    function cancel(signature backupSig, signature serverSig) tapscript {
        require(after(cancelTime));
        require(checkMultisig([backup, server], [backupSig, serverSig]));
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
                    base: "emulator".into(),
                    func: "exit".into()
                }]
            ),
            other => panic!("expected Sig with tweak key, got {other:?}"),
        }
        let cancel = c.tapscripts.iter().find(|t| t.name == "cancel").unwrap();
        assert!(
            matches!(&cancel.items[0], TapItem::After { value: TapOperand::Name(value), unit: None } if value == "cancelTime")
        );
        // Omitted threshold → N-of-N (None).
        match &cancel.items[1] {
            TapItem::Sig { threshold, .. } => assert_eq!(*threshold, None),
            other => panic!("expected Sig, got {other:?}"),
        }
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
        require(checkMultisig([keys[ SECOND ] , ps[0].owner ], [s1 , s2 ], 2));
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
    fn rejects_extra_arguments_to_tapscript_time_locks() {
        for call in ["older(exitDelay, extra)", "after(cancelTime, extra)"] {
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
