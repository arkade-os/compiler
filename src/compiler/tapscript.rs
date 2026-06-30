//! Tapscript (L1 leaf) compilation: closure assembly, validation, and ASM
//! emission. Pure functions over `NamedTapscript`; ABI wiring lives in mod.rs.

use crate::models::{HashFn, KeyExpr, NamedTapscript, TapItem};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Context {
    Covenant,
    Tapscript,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClosureClass {
    Multisig,
    CltvMultisig,
    CsvMultisig,
    ConditionMultisig,
    ConditionCsvMultisig,
}

impl ClosureClass {
    pub fn is_forfeit(&self) -> bool {
        matches!(
            self,
            ClosureClass::Multisig | ClosureClass::CltvMultisig | ClosureClass::ConditionMultisig
        )
    }
    pub fn is_exit(&self) -> bool {
        matches!(
            self,
            ClosureClass::CsvMultisig | ClosureClass::ConditionCsvMultisig
        )
    }
}

#[derive(Debug, Clone)]
pub struct Closure {
    pub class: ClosureClass,
    pub condition: Option<(HashFn, String)>, // (hashFn, hash value name)
    pub timelock: Option<String>,            // CSV or CLTV bound (literal or param)
    pub keys: Vec<KeyExpr>,
    pub sigs: Vec<String>,
    pub threshold: Option<u16>,
}

/// Assemble a tapscript body into exactly one closure, enforcing the
/// `condition? · timelock? · multisig` template in source order. The compiler
/// does not reorder; any out-of-order, duplicate, or unrepresentable
/// combination is an error (§4.4, §5.2).
pub fn assemble_closure(ts: &NamedTapscript) -> Result<Closure, String> {
    let mut condition: Option<(HashFn, String)> = None;
    let mut timelock: Option<String> = None;
    let mut is_csv = false; // older() → CSV; after()/tx.time → CLTV
    let mut multisig: Option<(Vec<KeyExpr>, Vec<String>, Option<u16>)> = None;

    for item in &ts.items {
        match item {
            TapItem::Hash {
                hash_fn,
                preimage,
                hash,
            } => {
                if multisig.is_some() {
                    return Err(format!(
                        "tapscript `{}`: condition must come before the multisig (out of order)",
                        ts.name
                    ));
                }
                if timelock.is_some() {
                    return Err(format!(
                        "tapscript `{}`: condition must come before the timelock (out of order)",
                        ts.name
                    ));
                }
                if condition.is_some() {
                    return Err(format!(
                        "tapscript `{}`: at most one condition (single hashlock) is allowed",
                        ts.name
                    ));
                }
                condition = Some((hash_fn.clone(), format!("{}|{}", preimage, hash)));
            }
            TapItem::Older { value } | TapItem::After { value } => {
                if multisig.is_some() {
                    return Err(format!(
                        "tapscript `{}`: timelock must come before the multisig (out of order)",
                        ts.name
                    ));
                }
                if timelock.is_some() {
                    return Err(format!(
                        "tapscript `{}`: only one timelock (CSV or CLTV) per leaf",
                        ts.name
                    ));
                }
                timelock = Some(value.clone());
                is_csv = matches!(item, TapItem::Older { .. });
            }
            TapItem::Sig {
                keys,
                sigs,
                threshold,
            } => {
                if multisig.is_some() {
                    return Err(format!(
                        "tapscript `{}`: only one checkSig/checkMultisig suffix per leaf",
                        ts.name
                    ));
                }
                multisig = Some((keys.clone(), sigs.clone(), *threshold));
            }
        }
    }

    let (keys, sigs, threshold) = multisig.ok_or_else(|| {
        format!(
            "tapscript `{}`: missing checkSig/checkMultisig suffix (no multisig)",
            ts.name
        )
    })?;

    // Re-decompose the encoded condition (preimage|hash) back into fields.
    let condition = match condition {
        Some((hash_fn, joined)) => {
            let (preimage, hash) = joined
                .split_once('|')
                .ok_or("internal: malformed condition encoding")?;
            Some((hash_fn, preimage.to_string(), hash.to_string()))
        }
        None => None,
    };

    let class = match (&condition, &timelock, is_csv) {
        (None, None, _) => ClosureClass::Multisig,
        (None, Some(_), false) => ClosureClass::CltvMultisig,
        (None, Some(_), true) => ClosureClass::CsvMultisig,
        (Some(_), None, _) => ClosureClass::ConditionMultisig,
        (Some(_), Some(_), true) => ClosureClass::ConditionCsvMultisig,
        (Some(_), Some(_), false) => {
            return Err(format!(
                "tapscript `{}`: condition + CLTV is not a recognized closure shape; \
                 split into two tapscripts (one ConditionMultisig forfeit, one CLTV forfeit)",
                ts.name
            ))
        }
    };

    Ok(Closure {
        class,
        condition: condition.map(|(f, _p, h)| (f, h)), // keep (hashFn, hash) for emission
        timelock,
        keys,
        sigs,
        threshold,
    })
}

/// L1/arkd opcode-safety (§5.1). Tapscript items can only ever lower to stock
/// BIP-342 opcodes, so the prerequisite reduces to confirming each item is a
/// recognized leaf component. Covenant-only constructs have no TapItem and were
/// rejected at parse time. The condition prefix is restricted to a single hash
/// function (no signature/timelock op can appear there).
pub fn validate_opcode_safety(ts: &NamedTapscript) -> Result<(), String> {
    let mut conditions = 0;
    for item in &ts.items {
        match item {
            TapItem::Hash { .. } => conditions += 1,
            TapItem::Older { .. } | TapItem::After { .. } | TapItem::Sig { .. } => {}
        }
    }
    if conditions > 1 {
        return Err(format!(
            "tapscript `{}`: condition prefix is limited to a single hashlock",
            ts.name
        ));
    }
    Ok(())
}

/// Closure-shape acceptance beyond `assemble_closure`'s template check:
/// arkd's MultisigClosure is **always N-of-N** (the decoder requires the pushed
/// integer to equal the key count, `closure.go:172`). So a declared threshold
/// must equal the key count; anything less cannot decode (§ Global Constraints).
pub fn validate_closure_shape(c: &Closure, ts_name: &str) -> Result<(), String> {
    if c.keys.is_empty() {
        return Err(format!("tapscript `{ts_name}`: empty key set (F1)"));
    }
    if let Some(t) = c.threshold {
        if t as usize != c.keys.len() {
            return Err(format!(
                "tapscript `{ts_name}`: arkd recognizes only N-of-N multisig closures; \
                 threshold {t} must equal the {} key(s) in the set",
                c.keys.len()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(items: Vec<TapItem>) -> NamedTapscript {
        NamedTapscript {
            name: "t".into(),
            inputs: vec![],
            items,
        }
    }
    fn ident(s: &str) -> KeyExpr {
        KeyExpr::Ident(s.into())
    }

    #[test]
    fn plain_multisig_is_forfeit() {
        let c = assemble_closure(&ts(vec![TapItem::Sig {
            keys: vec![ident("server"), ident("emulator")],
            sigs: vec!["serverSig".into(), "emulatorSig".into()],
            threshold: Some(2),
        }]))
        .unwrap();
        assert_eq!(c.class, ClosureClass::Multisig);
        assert!(c.class.is_forfeit());
    }

    #[test]
    fn condition_then_multisig_is_condition_multisig() {
        let c = assemble_closure(&ts(vec![
            TapItem::Hash {
                hash_fn: HashFn::Hash160,
                preimage: "preimage".into(),
                hash: "preimageHash".into(),
            },
            TapItem::Sig {
                keys: vec![ident("server"), ident("emulator")],
                sigs: vec!["serverSig".into(), "emulatorSig".into()],
                threshold: Some(2),
            },
        ]))
        .unwrap();
        assert_eq!(c.class, ClosureClass::ConditionMultisig);
    }

    #[test]
    fn older_then_multisig_is_csv_exit() {
        let c = assemble_closure(&ts(vec![
            TapItem::Older {
                value: "exitDelay".into(),
            },
            TapItem::Sig {
                keys: vec![ident("owner")],
                sigs: vec!["ownerSig".into()],
                threshold: Some(1),
            },
        ]))
        .unwrap();
        assert_eq!(c.class, ClosureClass::CsvMultisig);
        assert!(c.class.is_exit());
    }

    #[test]
    fn after_then_multisig_is_cltv_forfeit() {
        let c = assemble_closure(&ts(vec![
            TapItem::After {
                value: "cancelTime".into(),
            },
            TapItem::Sig {
                keys: vec![ident("backup"), ident("server")],
                sigs: vec!["backupSig".into(), "serverSig".into()],
                threshold: Some(2),
            },
        ]))
        .unwrap();
        assert_eq!(c.class, ClosureClass::CltvMultisig);
    }

    #[test]
    fn condition_plus_cltv_is_rejected() {
        let err = assemble_closure(&ts(vec![
            TapItem::Hash {
                hash_fn: HashFn::Hash160,
                preimage: "p".into(),
                hash: "h".into(),
            },
            TapItem::After { value: "t".into() },
            TapItem::Sig {
                keys: vec![ident("server")],
                sigs: vec!["serverSig".into()],
                threshold: Some(1),
            },
        ]))
        .unwrap_err();
        assert!(
            err.contains("condition") && err.contains("CLTV"),
            "got: {err}"
        );
    }

    #[test]
    fn missing_multisig_is_rejected() {
        let err = assemble_closure(&ts(vec![TapItem::Older { value: "x".into() }])).unwrap_err();
        assert!(err.contains("multisig"), "got: {err}");
    }

    #[test]
    fn out_of_order_condition_after_multisig_is_rejected() {
        let err = assemble_closure(&ts(vec![
            TapItem::Sig {
                keys: vec![ident("server")],
                sigs: vec!["serverSig".into()],
                threshold: Some(1),
            },
            TapItem::Hash {
                hash_fn: HashFn::Hash160,
                preimage: "p".into(),
                hash: "h".into(),
            },
        ]))
        .unwrap_err();
        assert!(err.contains("order"), "got: {err}");
    }

    #[test]
    fn condition_must_use_a_hash_function_only() {
        // HashFn variants are the only condition ops; this is a structural
        // guarantee. Assert the allowlist function accepts a hashlock leaf and
        // that a Sig-only leaf (no condition) is also fine.
        let ok = validate_opcode_safety(&ts(vec![
            TapItem::Hash {
                hash_fn: HashFn::Sha256,
                preimage: "p".into(),
                hash: "h".into(),
            },
            TapItem::Sig {
                keys: vec![ident("server")],
                sigs: vec!["serverSig".into()],
                threshold: Some(1),
            },
        ]));
        assert!(ok.is_ok(), "hashlock condition is allowed: {ok:?}");
    }

    #[test]
    fn threshold_below_keycount_is_shape_error() {
        let c = assemble_closure(&ts(vec![TapItem::Sig {
            keys: vec![ident("a"), ident("b"), ident("server")],
            sigs: vec!["aSig".into(), "bSig".into(), "serverSig".into()],
            threshold: Some(2),
        }]))
        .unwrap();
        let err = validate_closure_shape(&c, "t").unwrap_err();
        assert!(err.contains("N-of-N"), "got: {err}");
    }

    #[test]
    fn nofn_threshold_is_accepted() {
        let c = assemble_closure(&ts(vec![TapItem::Sig {
            keys: vec![ident("server"), ident("emulator")],
            sigs: vec!["serverSig".into(), "emulatorSig".into()],
            threshold: Some(2),
        }]))
        .unwrap();
        assert!(validate_closure_shape(&c, "t").is_ok());
    }

    #[test]
    fn empty_key_set_is_rejected() {
        let c = assemble_closure(&ts(vec![TapItem::Sig {
            keys: vec![],
            sigs: vec![],
            threshold: None,
        }]))
        .unwrap();
        assert!(validate_closure_shape(&c, "t").is_err());
    }
}
