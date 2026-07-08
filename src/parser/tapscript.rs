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
        Rule::identifier => Ok(KeyExpr::Ident(pair.as_str().to_string())),
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
