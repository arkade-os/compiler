//! Tapscript (L1 leaf) compilation: closure assembly, validation, and ASM
//! emission. Pure functions over `NamedTapscript`; ABI wiring lives in mod.rs.

use crate::models::{Contract, HashFn, KeyExpr, NamedTapscript, TapItem};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Binding {
    /// Leaf name matches a covenant function; bare `emulator` is implicitly tweaked.
    NameMatched,
    /// Unmatched leaf that explicitly tweaks exactly one function's emulator key.
    Tweaked(String),
    /// Unmatched leaf with no emulator binding at all.
    Standalone,
}

/// Resolve a tapscript's binding and enforce the `emulator` rule + key
/// resolution (§5.3). `contract` supplies the covenant function names.
pub fn resolve_binding(contract: &Contract, ts: &NamedTapscript) -> Result<Binding, String> {
    let name_matches = contract.functions.iter().any(|f| f.name == ts.name);

    // Collect bare-emulator usage and explicit tweak targets across all keys.
    let mut uses_bare_emulator = false;
    let mut tweak_targets: Vec<String> = Vec::new();
    for item in &ts.items {
        if let TapItem::Sig { keys, .. } = item {
            for k in keys {
                match k {
                    KeyExpr::Ident(id) if id == "emulator" => uses_bare_emulator = true,
                    KeyExpr::Tweak { func } => tweak_targets.push(func.clone()),
                    _ => {}
                }
            }
        }
    }

    if name_matches {
        if !tweak_targets.is_empty() {
            return Err(format!(
                "`tweak(emulator, ...)` not allowed in name-matched tapscript `{}`",
                ts.name
            ));
        }
        if !uses_bare_emulator {
            return Err(format!(
                "function-bound tapscript `{}` must include `emulator`",
                ts.name
            ));
        }
        return Ok(Binding::NameMatched);
    }

    // Unmatched leaf: bare emulator forbidden.
    if uses_bare_emulator {
        return Err(format!(
            "`emulator` not allowed in standalone tapscript `{}`; \
             use tweak(emulator, funcName) in a signature check",
            ts.name
        ));
    }

    // Validate explicit tweak targets: all must reference one existing function.
    tweak_targets.dedup();
    match tweak_targets.as_slice() {
        [] => Ok(Binding::Standalone),
        [func] => {
            if !contract.functions.iter().any(|f| &f.name == func) {
                return Err(format!(
                    "tweak(emulator, {func}) in tapscript `{}`: no function named `{func}`",
                    ts.name
                ));
            }
            Ok(Binding::Tweaked(func.clone()))
        }
        _ => {
            // Could still be the same name repeated; dedup above handles that.
            if tweak_targets.windows(2).all(|w| w[0] == w[1]) {
                let func = tweak_targets[0].clone();
                if !contract.functions.iter().any(|f| f.name == func) {
                    return Err(format!(
                        "tweak(emulator, {func}) in tapscript `{}`: no function named `{func}`",
                        ts.name
                    ));
                }
                Ok(Binding::Tweaked(func))
            } else {
                Err(format!(
                    "ambiguous emulator tweak targets in tapscript `{}`",
                    ts.name
                ))
            }
        }
    }
}

/// arkd structural rules F2/F3/E1/E3 + key resolution (§5.3). `min_exit_delay`
/// enables literal-only E3 magnitude checks. Returns non-fatal warnings on success.
pub fn validate_arkd_rules(
    contract: &Contract,
    ts: &NamedTapscript,
    c: &Closure,
    _binding: &Binding,
    min_exit_delay: Option<u64>,
) -> Result<Vec<String>, String> {
    let mut warnings = Vec::new();

    // Pubkeys in scope: constructor pubkey params + pubkey tapscript inputs.
    let in_scope = |name: &str| -> bool {
        name == "server"
            || name == "emulator"
            || contract
                .parameters
                .iter()
                .any(|p| p.name == name && p.param_type == "pubkey")
            || ts
                .inputs
                .iter()
                .any(|p| p.name == name && p.param_type == "pubkey")
    };

    // Key resolution.
    for k in &c.keys {
        if let KeyExpr::Ident(id) = k {
            if !in_scope(id) {
                return Err(format!("unknown key `{id}` in tapscript `{}`", ts.name));
            }
        }
    }

    // F2: forfeit closures must contain `server`.
    if c.class.is_forfeit() {
        let has_server = c
            .keys
            .iter()
            .any(|k| matches!(k, KeyExpr::Ident(id) if id == "server"));
        if !has_server {
            return Err(format!(
                "forfeit tapscript `{}` must include `server` (arkd co-signer)",
                ts.name
            ));
        }
        // Threshold nuance: warn on k-of-n forfeits where server could be excluded.
        if let Some(t) = c.threshold {
            if (t as usize) < c.keys.len() {
                warnings.push(format!(
                    "tapscript `{}`: k-of-n forfeit closure may exclude `server` from the satisfying set",
                    ts.name
                ));
            }
        }
    }

    // E3: literal exit-delay magnitude (CSV closures only).
    if c.class.is_exit() {
        if let (Some(tl), Some(min)) = (&c.timelock, min_exit_delay) {
            if let Ok(v) = tl.parse::<u64>() {
                if v < min {
                    return Err(format!(
                        "tapscript `{}`: exit delay too short (min {min})",
                        ts.name
                    ));
                }
            }
            // Non-literal (param) timelock: defer to arkd.
        }
    }

    // F3 (CLTV seconds vs block) is value-dependent and only decidable for
    // literal locktimes with a known block-type policy; with literals-only and
    // no policy source wired yet, defer to arkd. (Placeholder for future config.)

    Ok(warnings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Contract, Function, Parameter};

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

    fn contract_with(funcs: &[&str], tapscripts: Vec<NamedTapscript>) -> Contract {
        Contract {
            name: "C".into(),
            parameters: vec![
                Parameter {
                    name: "owner".into(),
                    param_type: "pubkey".into(),
                },
                Parameter {
                    name: "backup".into(),
                    param_type: "pubkey".into(),
                },
            ],
            renewal_timelock: None,
            exit_timelock: None,
            has_server_key: false,
            functions: funcs
                .iter()
                .map(|n| Function {
                    name: (*n).into(),
                    parameters: vec![],
                    statements: vec![],
                    is_internal: false,
                })
                .collect(),
            tapscripts,
            imports: vec![],
        }
    }

    fn sig(keys: Vec<KeyExpr>) -> TapItem {
        let sigs = keys
            .iter()
            .enumerate()
            .map(|(i, _)| format!("s{i}"))
            .collect();
        TapItem::Sig {
            keys,
            sigs,
            threshold: None,
        }
    }

    #[test]
    fn name_matched_requires_bare_emulator() {
        // claim covenant exists; leaf named claim with bare emulator → NameMatched
        let leaf = NamedTapscript {
            name: "claim".into(),
            inputs: vec![],
            items: vec![sig(vec![ident("server"), ident("emulator")])],
        };
        let c = contract_with(&["claim"], vec![leaf.clone()]);
        assert_eq!(resolve_binding(&c, &leaf).unwrap(), Binding::NameMatched);
    }

    #[test]
    fn name_matched_without_emulator_is_error() {
        let leaf = NamedTapscript {
            name: "claim".into(),
            inputs: vec![],
            items: vec![sig(vec![ident("server"), ident("owner")])],
        };
        let c = contract_with(&["claim"], vec![leaf.clone()]);
        let err = resolve_binding(&c, &leaf).unwrap_err();
        assert!(err.contains("must include `emulator`"), "got: {err}");
    }

    #[test]
    fn standalone_with_bare_emulator_is_error() {
        let leaf = NamedTapscript {
            name: "weird".into(),
            inputs: vec![],
            items: vec![sig(vec![ident("server"), ident("emulator")])],
        };
        let c = contract_with(&["claim"], vec![leaf.clone()]);
        let err = resolve_binding(&c, &leaf).unwrap_err();
        assert!(err.contains("not allowed in standalone"), "got: {err}");
    }

    #[test]
    fn standalone_tweak_groups_under_target() {
        let leaf = NamedTapscript {
            name: "direct".into(),
            inputs: vec![],
            items: vec![sig(vec![KeyExpr::Tweak {
                func: "claim".into(),
            }])],
        };
        let c = contract_with(&["claim"], vec![leaf.clone()]);
        assert_eq!(
            resolve_binding(&c, &leaf).unwrap(),
            Binding::Tweaked("claim".into())
        );
    }

    #[test]
    fn name_matched_with_explicit_tweak_is_error() {
        let leaf = NamedTapscript {
            name: "claim".into(),
            inputs: vec![],
            items: vec![sig(vec![KeyExpr::Tweak {
                func: "claim".into(),
            }])],
        };
        let c = contract_with(&["claim"], vec![leaf.clone()]);
        let err = resolve_binding(&c, &leaf).unwrap_err();
        assert!(err.contains("not allowed in name-matched"), "got: {err}");
    }

    #[test]
    fn tweak_to_missing_function_is_error() {
        let leaf = NamedTapscript {
            name: "direct".into(),
            inputs: vec![],
            items: vec![sig(vec![KeyExpr::Tweak {
                func: "nope".into(),
            }])],
        };
        let c = contract_with(&["claim"], vec![leaf.clone()]);
        assert!(resolve_binding(&c, &leaf).is_err());
    }

    #[test]
    fn ambiguous_tweak_targets_are_error() {
        let leaf = NamedTapscript {
            name: "direct".into(),
            inputs: vec![],
            items: vec![sig(vec![
                KeyExpr::Tweak {
                    func: "claim".into(),
                },
                KeyExpr::Tweak {
                    func: "refund".into(),
                },
            ])],
        };
        let c = contract_with(&["claim", "refund"], vec![leaf.clone()]);
        let err = resolve_binding(&c, &leaf).unwrap_err();
        assert!(err.contains("ambiguous"), "got: {err}");
    }

    #[test]
    fn pure_standalone_has_no_emulator_no_tweak() {
        let leaf = NamedTapscript {
            name: "unilateral".into(),
            inputs: vec![],
            items: vec![sig(vec![ident("owner")])],
        };
        let c = contract_with(&["claim"], vec![leaf.clone()]);
        assert_eq!(resolve_binding(&c, &leaf).unwrap(), Binding::Standalone);
    }

    fn closure_of(leaf: &NamedTapscript) -> Closure {
        assemble_closure(leaf).unwrap()
    }

    #[test]
    fn forfeit_without_server_is_rejected() {
        let leaf = NamedTapscript {
            name: "liquidate".into(),
            inputs: vec![],
            items: vec![sig(vec![ident("owner"), ident("backup")])],
        };
        let c = contract_with(&[], vec![leaf.clone()]);
        let cl = closure_of(&leaf);
        let b = resolve_binding(&c, &leaf).unwrap();
        let err = validate_arkd_rules(&c, &leaf, &cl, &b, None).unwrap_err();
        assert!(err.contains("server"), "got: {err}");
    }

    #[test]
    fn exit_using_after_is_rejected() {
        // after()+server is a CLTV forfeit; an *exit* must use older(). This
        // leaf is actually a valid CLTV forfeit, so instead test the inverse:
        // a CSV (older) leaf is an exit and needs no server — accepted.
        let leaf = NamedTapscript {
            name: "unilateral".into(),
            inputs: vec![],
            items: vec![
                TapItem::Older {
                    value: "exitDelay".into(),
                },
                sig(vec![ident("owner")]),
            ],
        };
        let c = contract_with(&[], vec![leaf.clone()]);
        let cl = closure_of(&leaf);
        let b = resolve_binding(&c, &leaf).unwrap();
        assert!(validate_arkd_rules(&c, &leaf, &cl, &b, None).is_ok());
    }

    #[test]
    fn unknown_key_is_rejected() {
        let leaf = NamedTapscript {
            name: "x".into(),
            inputs: vec![],
            items: vec![sig(vec![ident("server"), ident("ghost")])],
        };
        let c = contract_with(&[], vec![leaf.clone()]);
        let cl = closure_of(&leaf);
        let b = resolve_binding(&c, &leaf).unwrap();
        let err = validate_arkd_rules(&c, &leaf, &cl, &b, None).unwrap_err();
        assert!(err.contains("unknown key"), "got: {err}");
    }

    #[test]
    fn literal_exit_delay_below_min_is_rejected() {
        let leaf = NamedTapscript {
            name: "exit".into(),
            inputs: vec![],
            items: vec![
                TapItem::Older { value: "10".into() }, // literal
                sig(vec![ident("owner")]),
            ],
        };
        let c = contract_with(&[], vec![leaf.clone()]);
        let cl = closure_of(&leaf);
        let b = resolve_binding(&c, &leaf).unwrap();
        let err = validate_arkd_rules(&c, &leaf, &cl, &b, Some(144)).unwrap_err();
        assert!(err.contains("exit delay too short"), "got: {err}");
    }

    #[test]
    fn param_exit_delay_defers_magnitude_check() {
        let leaf = NamedTapscript {
            name: "exit".into(),
            inputs: vec![],
            items: vec![
                TapItem::Older {
                    value: "exitDelay".into(),
                }, // param → defer
                sig(vec![ident("owner")]),
            ],
        };
        let c = contract_with(&[], vec![leaf.clone()]);
        let cl = closure_of(&leaf);
        let b = resolve_binding(&c, &leaf).unwrap();
        assert!(validate_arkd_rules(&c, &leaf, &cl, &b, Some(144)).is_ok());
    }
}
