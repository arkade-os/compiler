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
) -> Result<crate::models::NamedTapscript, String> {
    let mut inner = pair.into_inner();
    let name = inner
        .next()
        .ok_or("Missing tapscript name")?
        .as_str()
        .to_string();
    let params = inner.next().ok_or("Missing tapscript parameter list")?;
    let inputs = parse_parameters(params)?;
    let block = inner.next().ok_or("Missing tapscript body")?;
    let mut items = Vec::new();
    for stmt in block.into_inner() {
        if stmt.as_rule() == Rule::require_stmt {
            let expr = stmt
                .into_inner()
                .next()
                .ok_or("Empty require() in tapscript")?;
            items.push(parse_tap_item(expr)?);
        }
    }
    Ok(crate::models::NamedTapscript {
        name,
        inputs,
        items,
    })
}

/// Interpret one `require(...)` inner expression as a tapscript item.
pub(crate) fn parse_tap_item(pair: Pair<Rule>) -> Result<crate::models::TapItem, String> {
    use crate::models::{HashFn, TapItem};
    match pair.as_rule() {
        Rule::general_expression
        | Rule::comparison_expr
        | Rule::additive_expr
        | Rule::multiplicative_expr
        | Rule::unary_expr
        | Rule::primary_expr => {
            let mut inner = pair.into_inner();
            let item = inner
                .next()
                .ok_or("Empty expression in tapscript require()")?;
            if inner.next().is_some() {
                return Err("unsupported compound expression in tapscript require()".to_string());
            }
            parse_tap_item(item)
        }
        Rule::hash_comparison => {
            let mut inner = pair.into_inner();
            let func = inner.next().ok_or("Missing hash function")?; // hash_func
            let mut f_inner = func.into_inner();
            let fn_name = f_inner.next().ok_or("Missing hash fn name")?.as_str();
            let hash_fn =
                HashFn::parse(fn_name).ok_or_else(|| format!("unknown hash function {fn_name}"))?;
            let preimage = f_inner
                .next()
                .ok_or("Missing hash preimage")?
                .as_str()
                .to_string();
            let hash = inner
                .next()
                .ok_or("Missing hash value")?
                .as_str()
                .to_string();
            Ok(TapItem::Hash {
                hash_fn,
                preimage,
                hash,
            })
        }
        Rule::time_comparison => {
            // tx.time >= ident  → absolute (CLTV)
            let mut inner = pair.into_inner();
            let value = inner
                .next()
                .ok_or("Missing tx.time bound")?
                .as_str()
                .to_string();
            Ok(TapItem::After { value })
        }
        Rule::check_sig => {
            let mut inner = pair.into_inner();
            let sig = inner
                .next()
                .ok_or("Missing signature")?
                .as_str()
                .to_string();
            let key = parse_key_expr(inner.next().ok_or("Missing key")?)?;
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
            parse_tap_multisig(inner)
        }
        Rule::function_call => {
            // older(n) / after(n)
            let mut inner = pair.into_inner();
            let name = inner
                .next()
                .ok_or("Missing call name")?
                .as_str()
                .to_string();
            let arg = inner
                .next()
                .ok_or_else(|| format!("{name}() requires one argument"))?
                .as_str()
                .to_string();
            match name.as_str() {
                "older" => {
                    if inner.next().is_some() {
                        return Err(format!("{name}() requires one argument"));
                    }
                    Ok(TapItem::Older { value: arg })
                }
                "after" => {
                    if inner.next().is_some() {
                        return Err(format!("{name}() requires one argument"));
                    }
                    Ok(TapItem::After { value: arg })
                }
                other => Err(format!("unsupported tapscript call `{other}(...)`")),
            }
        }
        other => Err(format!(
            "unsupported expression in tapscript require(): {other:?}"
        )),
    }
}

/// Parse `check_threshold_multisig` inner pairs into a Sig item.
pub(crate) fn parse_tap_multisig(pair: Pair<Rule>) -> Result<crate::models::TapItem, String> {
    use crate::models::TapItem;
    let mut keys = Vec::new();
    let mut sigs = Vec::new();
    let mut threshold = None;
    for child in pair.into_inner() {
        match child.as_rule() {
            Rule::key_array => {
                for k in child.into_inner() {
                    keys.push(parse_key_expr(k)?);
                }
            }
            Rule::array => {
                for s in child.into_inner() {
                    sigs.push(s.as_str().to_string());
                }
            }
            Rule::number_literal => {
                threshold = Some(
                    child
                        .as_str()
                        .parse::<u16>()
                        .map_err(|e| format!("invalid threshold: {e}"))?,
                );
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

/// Parse a `key_expr` (bare identifier or `tweak(emulator, func)`).
pub(crate) fn parse_key_expr(pair: Pair<Rule>) -> Result<crate::models::KeyExpr, String> {
    use crate::models::KeyExpr;
    match pair.as_rule() {
        Rule::identifier | Rule::named_binding => Ok(KeyExpr::Ident(pair.as_str().to_string())),
        Rule::key_expr => {
            let inner = pair.into_inner().next().ok_or("Empty key expression")?;
            parse_key_expr(inner)
        }
        Rule::tweak_key => {
            let mut inner = pair.into_inner();
            let base = inner
                .next()
                .ok_or("Missing tweak base")?
                .as_str()
                .to_string();
            if base != "emulator" {
                return Err(format!("tweak() base must be `emulator`, got `{base}`"));
            }
            let func = inner
                .next()
                .ok_or("Missing tweak func name")?
                .as_str()
                .to_string();
            Ok(KeyExpr::Tweak { func })
        }
        other => Err(format!("unexpected key expression: {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    //! Parser-level tests for the `tapscript` modifier: assert AST routing,
    //! not ABI output.
    use crate::models::{Contract, HashFn, KeyExpr, TapItem};

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
                assert_eq!(hash, "preimageHash");
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
                    &vec!["serverSig".to_string(), "emulatorSig".to_string()]
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
        assert!(matches!(&exit.items[0], TapItem::Older { value } if value == "exitDelay"));
        let direct = c.tapscripts.iter().find(|t| t.name == "direct").unwrap();
        match &direct.items[0] {
            TapItem::Sig { keys, .. } => assert_eq!(
                keys,
                &vec![KeyExpr::Tweak {
                    func: "exit".into()
                }]
            ),
            other => panic!("expected Sig with tweak key, got {other:?}"),
        }
        let cancel = c.tapscripts.iter().find(|t| t.name == "cancel").unwrap();
        assert!(matches!(&cancel.items[0], TapItem::After { value } if value == "cancelTime"));
        // Omitted threshold → N-of-N (None).
        match &cancel.items[1] {
            TapItem::Sig { threshold, .. } => assert_eq!(*threshold, None),
            other => panic!("expected Sig, got {other:?}"),
        }
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
