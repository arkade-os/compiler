//! Tapscript (L1 leaf) compilation: closure assembly, validation, and ASM
//! emission. Pure functions over `NamedTapscript`; ABI wiring lives in mod.rs.

use crate::models::{
    AbiFunctionGroup, AbiLeaf, ArkadeCovenant, Contract, HashFn, KeyExpr, NamedTapscript,
    Parameter, TapItem, WitnessElement,
};
use crate::opcodes::{
    OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_DROP,
    OP_EQUAL, OP_VERIFY,
};
use crate::typechecker::ArkType;

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
    let mut multisig: Option<(Vec<KeyExpr>, Option<u16>)> = None;

    for item in &ts.items {
        match item {
            TapItem::Hash {
                hash_fn,
                preimage: _,
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
                condition = Some((hash_fn.clone(), hash.clone()));
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
                sigs: _,
                threshold,
            } => {
                if multisig.is_some() {
                    return Err(format!(
                        "tapscript `{}`: only one checkSig/checkMultisig suffix per leaf",
                        ts.name
                    ));
                }
                multisig = Some((keys.clone(), *threshold));
            }
        }
    }

    let (keys, threshold) = multisig.ok_or_else(|| {
        format!(
            "tapscript `{}`: missing checkSig/checkMultisig suffix (no multisig)",
            ts.name
        )
    })?;

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
        condition,
        timelock,
        keys,
        threshold,
    })
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
    let unique_targets: std::collections::BTreeSet<String> = tweak_targets.into_iter().collect();
    match unique_targets.len() {
        0 => Ok(Binding::Standalone),
        1 => {
            let func = unique_targets.iter().next().expect("one target");
            if !contract.functions.iter().any(|f| &f.name == func) {
                return Err(format!(
                    "tweak(emulator, {func}) in tapscript `{}`: no function named `{func}`",
                    ts.name
                ));
            }
            Ok(Binding::Tweaked(func.clone()))
        }
        _ => Err(format!(
            "ambiguous emulator tweak targets in tapscript `{}`",
            ts.name
        )),
    }
}

/// arkd structural rules F2/F3/E1/E3 + key resolution (§5.3). `min_exit_delay`
/// enables literal-only E3 magnitude checks.
pub fn validate_arkd_rules(
    contract: &Contract,
    ts: &NamedTapscript,
    c: &Closure,
    min_exit_delay: Option<u64>,
) -> Result<(), String> {
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

    // Any declared name (constructor param or tapscript input), any type.
    let name_declared = |name: &str| -> bool {
        contract.parameters.iter().any(|p| p.name == name)
            || ts.inputs.iter().any(|p| p.name == name)
    };
    // A declared `signature` input.
    let sig_input = |name: &str| -> bool {
        ts.inputs
            .iter()
            .any(|p| p.name == name && p.param_type == "signature")
    };

    // Signature-operand validation (§4.3, §8): every signature operand in a
    // checkSig/checkMultisig must be a declared `signature` input, and the
    // signature array must align 1:1 with the key set (the leaf's witness is
    // unspendable otherwise — a missing or misaligned sig yields a witness ABI
    // that cannot satisfy the closure).
    for item in &ts.items {
        if let TapItem::Sig { keys, sigs, .. } = item {
            if sigs.len() != keys.len() {
                return Err(format!(
                    "tapscript `{}`: checkSig/checkMultisig has {} key(s) but {} signature(s); \
                     signatures must align 1:1 with keys",
                    ts.name,
                    keys.len(),
                    sigs.len()
                ));
            }
            for s in sigs {
                if !sig_input(s) {
                    return Err(format!(
                        "tapscript `{}`: signature operand `{s}` is not a declared `signature` input",
                        ts.name
                    ));
                }
            }
        }
    }

    // Operand scope: condition preimage/hash and timelock values are emitted as
    // `<name>` placeholders, so each must resolve to a declared input or
    // constructor parameter (timelocks may also be numeric literals).
    for item in &ts.items {
        match item {
            TapItem::Hash { preimage, hash, .. } => {
                if !name_declared(preimage) {
                    return Err(format!(
                        "tapscript `{}`: hash preimage `{preimage}` is not a declared input or constructor parameter",
                        ts.name
                    ));
                }
                if !name_declared(hash) {
                    return Err(format!(
                        "tapscript `{}`: hash value `{hash}` is not a declared input or constructor parameter",
                        ts.name
                    ));
                }
            }
            TapItem::Older { value } | TapItem::After { value } => {
                if value.parse::<u64>().is_err() && !name_declared(value) {
                    return Err(format!(
                        "tapscript `{}`: timelock `{value}` is not a literal, declared input, or constructor parameter",
                        ts.name
                    ));
                }
            }
            TapItem::Sig { .. } => {}
        }
    }

    // F2: forfeit closures must contain `server`.
    if c.class.is_forfeit() && !c.keys.iter().any(KeyExpr::is_server) {
        return Err(format!(
            "forfeit tapscript `{}` must include `server` (arkd co-signer)",
            ts.name
        ));
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

    Ok(())
}

/// Lower a key operand to its ASM placeholder. `leaf_func` is the function name
/// used for a name-matched leaf's bare `emulator`.
pub fn key_placeholder(k: &KeyExpr, leaf_func: &str) -> String {
    match k {
        KeyExpr::Ident(id) if id == "server" => "<SERVER_KEY>".to_string(),
        KeyExpr::Ident(id) if id == "emulator" => format!("<EMULATOR_KEY:{leaf_func}>"),
        KeyExpr::Ident(id) => format!("<{id}>"),
        KeyExpr::Tweak { func } => format!("<EMULATOR_KEY:{func}>"),
    }
}

/// Emit a timelock operand: literal as-is, else a `<param>` placeholder.
fn timelock_operand(value: &str) -> String {
    if value.parse::<u64>().is_ok() {
        value.to_string()
    } else {
        format!("<{value}>")
    }
}

/// Emit the multisig suffix (N-of-N CHECKSIG chain).
fn emit_multisig(keys: &[KeyExpr], leaf_func: &str, asm: &mut Vec<String>) {
    for (i, k) in keys.iter().enumerate() {
        asm.push(key_placeholder(k, leaf_func));
        if i == keys.len() - 1 {
            asm.push(OP_CHECKSIG.to_string());
        } else {
            asm.push(OP_CHECKSIGVERIFY.to_string());
        }
    }
}

/// Assemble the full leaf ASM in arkd's closure byte order: condition? · timelock? · multisig.
pub fn emit_leaf_asm(c: &Closure, ts_name: &str, binding: &Binding) -> Vec<String> {
    let mut asm = Vec::new();
    // The function name used for a bare `emulator` placeholder.
    let leaf_func = match binding {
        Binding::Tweaked(f) => f.as_str(),
        _ => ts_name,
    };

    // Condition prefix.
    if let Some((hash_fn, hash)) = &c.condition {
        asm.push(hash_fn.opcode().to_string());
        asm.push(format!("<{hash}>"));
        asm.push(OP_EQUAL.to_string());
        asm.push(OP_VERIFY.to_string());
    }

    // Timelock prefix.
    if let Some(tl) = &c.timelock {
        asm.push(timelock_operand(tl));
        match c.class {
            ClosureClass::CsvMultisig | ClosureClass::ConditionCsvMultisig => {
                asm.push(OP_CHECKSEQUENCEVERIFY.to_string());
            }
            _ => asm.push(OP_CHECKLOCKTIMEVERIFY.to_string()),
        }
        asm.push(OP_DROP.to_string());
    }

    emit_multisig(&c.keys, leaf_func, &mut asm);
    asm
}

/// Derive the leaf witness from the tapscript inputs, one entry per input.
/// Tapscript inputs are scalars; the validator rejects array types here.
pub fn leaf_witness(ts: &NamedTapscript) -> Vec<WitnessElement> {
    let mut out = Vec::new();
    let injected = injected_signature_names(ts);
    for p in &ts.inputs {
        push_witness_param(p, injected.contains(&p.name), &mut out);
    }
    out
}

fn injected_signature_names(ts: &NamedTapscript) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();
    for item in &ts.items {
        if let TapItem::Sig { keys, sigs, .. } = item {
            for (key, sig) in keys.iter().zip(sigs) {
                if key.is_cosigner() {
                    names.insert(sig.clone());
                }
            }
        }
    }
    names
}

fn push_witness_param(p: &Parameter, injected: bool, out: &mut Vec<WitnessElement>) {
    out.push(WitnessElement {
        name: p.name.clone(),
        elem_type: p.param_type.clone(),
        encoding: ArkType::parse(&p.param_type).encoding().to_string(),
        injected,
    });
}

/// Build the unified `functions[]` ABI: one group per covenant function plus
/// one group per pure-standalone leaf. Runs validation per leaf. `covenants`
/// holds each function's emulator covenant (built by mod.rs to avoid a cycle);
/// it is consumed as groups are assembled.
pub fn build_function_groups(
    contract: &Contract,
    mut covenants: std::collections::HashMap<String, ArkadeCovenant>,
) -> Result<Vec<AbiFunctionGroup>, String> {
    // Resolve + validate every author-written tapscript; bucket by group key.
    // group key = function name for NameMatched / Tweaked(func); leaf's own name for Standalone.
    use std::collections::BTreeMap;
    let mut grouped: BTreeMap<String, Vec<AbiLeaf>> = BTreeMap::new();

    for ts in &contract.tapscripts {
        let closure = assemble_closure(ts)?;
        validate_closure_shape(&closure, &ts.name)?;
        let binding = resolve_binding(contract, ts)?;
        validate_arkd_rules(contract, ts, &closure, None)?;

        let group_key = match &binding {
            Binding::NameMatched => ts.name.clone(),
            Binding::Tweaked(func) => func.clone(),
            Binding::Standalone => ts.name.clone(),
        };

        grouped.entry(group_key).or_default().push(AbiLeaf {
            name: ts.name.clone(),
            witness: leaf_witness(ts),
            asm: emit_leaf_asm(&closure, &ts.name, &binding),
        });
    }

    let mut groups = Vec::new();

    // One group per covenant function, in declaration order.
    for f in contract.functions.iter().filter(|f| !f.is_internal) {
        let arkade = covenants.remove(&f.name);
        let mut leaves = grouped.remove(&f.name).unwrap_or_default();
        if leaves.is_empty() {
            leaves.push(synthesize_default_leaf(&f.name));
        }
        groups.push(AbiFunctionGroup {
            name: f.name.clone(),
            arkade,
            leaves,
        });
    }

    // Remaining groups are pure-standalone leaves (no covenant). Stable order.
    for (name, leaves) in grouped {
        groups.push(AbiFunctionGroup {
            name,
            arkade: None,
            leaves,
        });
    }

    Ok(groups)
}

/// The §5.4 default collaborative leaf: checkMultisig([server, tweak(emulator, fn)], …, 2).
fn synthesize_default_leaf(func: &str) -> AbiLeaf {
    let closure = Closure {
        class: ClosureClass::Multisig,
        condition: None,
        timelock: None,
        keys: vec![
            KeyExpr::Ident("server".into()),
            KeyExpr::Tweak { func: func.into() },
        ],
        threshold: Some(2),
    };
    let sig_encoding = ArkType::Signature.encoding().to_string();
    AbiLeaf {
        name: func.to_string(),
        witness: vec![
            WitnessElement {
                name: "serverSig".into(),
                elem_type: "signature".into(),
                encoding: sig_encoding.clone(),
                injected: true,
            },
            WitnessElement {
                name: "emulatorSig".into(),
                elem_type: "signature".into(),
                encoding: sig_encoding,
                injected: true,
            },
        ],
        asm: emit_leaf_asm(&closure, func, &Binding::NameMatched),
    }
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
            structs: vec![],
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

    /// `signature` inputs `s0..sn` matching the names `sig()` generates.
    fn sig_params(n: usize) -> Vec<Parameter> {
        (0..n)
            .map(|i| Parameter {
                name: format!("s{i}"),
                param_type: "signature".into(),
            })
            .collect()
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
            inputs: sig_params(2),
            items: vec![sig(vec![ident("owner"), ident("backup")])],
        };
        let c = contract_with(&[], vec![leaf.clone()]);
        let cl = closure_of(&leaf);
        let _binding = resolve_binding(&c, &leaf).unwrap();
        let err = validate_arkd_rules(&c, &leaf, &cl, None).unwrap_err();
        assert!(err.contains("server"), "got: {err}");
    }

    #[test]
    fn csv_exit_without_server_is_accepted() {
        let mut inputs = sig_params(1);
        inputs.push(Parameter {
            name: "exitDelay".into(),
            param_type: "int".into(),
        });
        let leaf = NamedTapscript {
            name: "unilateral".into(),
            inputs,
            items: vec![
                TapItem::Older {
                    value: "exitDelay".into(),
                },
                sig(vec![ident("owner")]),
            ],
        };
        let c = contract_with(&[], vec![leaf.clone()]);
        let cl = closure_of(&leaf);
        let _binding = resolve_binding(&c, &leaf).unwrap();
        assert!(validate_arkd_rules(&c, &leaf, &cl, None).is_ok());
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
        let _binding = resolve_binding(&c, &leaf).unwrap();
        let err = validate_arkd_rules(&c, &leaf, &cl, None).unwrap_err();
        assert!(err.contains("unknown key"), "got: {err}");
    }

    #[test]
    fn literal_exit_delay_below_min_is_rejected() {
        let leaf = NamedTapscript {
            name: "exit".into(),
            inputs: sig_params(1),
            items: vec![
                TapItem::Older { value: "10".into() }, // literal
                sig(vec![ident("owner")]),
            ],
        };
        let c = contract_with(&[], vec![leaf.clone()]);
        let cl = closure_of(&leaf);
        let _binding = resolve_binding(&c, &leaf).unwrap();
        let err = validate_arkd_rules(&c, &leaf, &cl, Some(144)).unwrap_err();
        assert!(err.contains("exit delay too short"), "got: {err}");
    }

    #[test]
    fn param_exit_delay_defers_magnitude_check() {
        let mut inputs = sig_params(1);
        inputs.push(Parameter {
            name: "exitDelay".into(),
            param_type: "int".into(),
        });
        let leaf = NamedTapscript {
            name: "exit".into(),
            inputs,
            items: vec![
                TapItem::Older {
                    value: "exitDelay".into(),
                }, // param → defer
                sig(vec![ident("owner")]),
            ],
        };
        let c = contract_with(&[], vec![leaf.clone()]);
        let cl = closure_of(&leaf);
        let _binding = resolve_binding(&c, &leaf).unwrap();
        assert!(validate_arkd_rules(&c, &leaf, &cl, Some(144)).is_ok());
    }

    #[test]
    fn misaligned_sig_and_key_count_is_rejected() {
        // 2 keys but 1 declared signature → witness cannot satisfy the closure.
        let leaf = NamedTapscript {
            name: "x".into(),
            inputs: vec![Parameter {
                name: "serverSig".into(),
                param_type: "signature".into(),
            }],
            items: vec![TapItem::Sig {
                keys: vec![ident("server"), ident("emulator")],
                sigs: vec!["serverSig".into()],
                threshold: Some(2),
            }],
        };
        let c = contract_with(&["x"], vec![leaf.clone()]);
        let cl = closure_of(&leaf);
        let _binding = resolve_binding(&c, &leaf).unwrap();
        let err = validate_arkd_rules(&c, &leaf, &cl, None).unwrap_err();
        assert!(err.contains("align 1:1"), "got: {err}");
    }

    #[test]
    fn undeclared_signature_operand_is_rejected() {
        // sig operand `ghostSig` is not declared as a `signature` input.
        let leaf = NamedTapscript {
            name: "x".into(),
            inputs: vec![],
            items: vec![TapItem::Sig {
                keys: vec![ident("server")],
                sigs: vec!["ghostSig".into()],
                threshold: Some(1),
            }],
        };
        let c = contract_with(&[], vec![leaf.clone()]);
        let cl = closure_of(&leaf);
        let _binding = resolve_binding(&c, &leaf).unwrap();
        let err = validate_arkd_rules(&c, &leaf, &cl, None).unwrap_err();
        assert!(
            err.contains("not a declared `signature` input"),
            "got: {err}"
        );
    }

    #[test]
    fn undeclared_timelock_operand_is_rejected() {
        // older(typo) where `typo` is neither a literal nor a declared name.
        let leaf = NamedTapscript {
            name: "exit".into(),
            inputs: sig_params(1),
            items: vec![
                TapItem::Older {
                    value: "typoDelay".into(),
                },
                sig(vec![ident("owner")]),
            ],
        };
        let c = contract_with(&[], vec![leaf.clone()]);
        let cl = closure_of(&leaf);
        let _binding = resolve_binding(&c, &leaf).unwrap();
        let err = validate_arkd_rules(&c, &leaf, &cl, None).unwrap_err();
        assert!(err.contains("timelock `typoDelay`"), "got: {err}");
    }

    #[test]
    fn undeclared_hash_value_is_rejected() {
        // hash160(preimage) == typoHash where typoHash is not declared.
        let leaf = NamedTapscript {
            name: "claim".into(),
            inputs: vec![
                Parameter {
                    name: "preimage".into(),
                    param_type: "bytes".into(),
                },
                Parameter {
                    name: "serverSig".into(),
                    param_type: "signature".into(),
                },
            ],
            items: vec![
                TapItem::Hash {
                    hash_fn: HashFn::Hash160,
                    preimage: "preimage".into(),
                    hash: "typoHash".into(),
                },
                TapItem::Sig {
                    keys: vec![ident("server")],
                    sigs: vec!["serverSig".into()],
                    threshold: Some(1),
                },
            ],
        };
        let c = contract_with(&[], vec![leaf.clone()]);
        let cl = closure_of(&leaf);
        let _binding = resolve_binding(&c, &leaf).unwrap();
        let err = validate_arkd_rules(&c, &leaf, &cl, None).unwrap_err();
        assert!(err.contains("hash value `typoHash`"), "got: {err}");
    }

    use crate::opcodes::{
        OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_DROP,
        OP_EQUAL, OP_HASH160, OP_VERIFY,
    };

    #[test]
    fn emits_condition_multisig_like_golden_htlc_claim() {
        // ConditionMultisigClosure { HASH160 <preimageHash> EQUAL, [server, emulator(claim)] }
        let leaf = NamedTapscript {
            name: "claim".into(),
            inputs: vec![
                Parameter {
                    name: "preimage".into(),
                    param_type: "bytes".into(),
                },
                Parameter {
                    name: "serverSig".into(),
                    param_type: "signature".into(),
                },
                Parameter {
                    name: "emulatorSig".into(),
                    param_type: "signature".into(),
                },
            ],
            items: vec![
                TapItem::Hash {
                    hash_fn: HashFn::Hash160,
                    preimage: "preimage".into(),
                    hash: "preimageHash".into(),
                },
                sig(vec![ident("server"), ident("emulator")]),
            ],
        };
        let c = assemble_closure(&leaf).unwrap();
        let asm = emit_leaf_asm(&c, "claim", &Binding::NameMatched);
        assert_eq!(
            asm,
            vec![
                OP_HASH160.to_string(),
                "<preimageHash>".to_string(),
                OP_EQUAL.to_string(),
                OP_VERIFY.to_string(),
                "<SERVER_KEY>".to_string(),
                OP_CHECKSIGVERIFY.to_string(),
                "<EMULATOR_KEY:claim>".to_string(),
                OP_CHECKSIG.to_string(),
            ]
        );
        // Signatures are witness, not script.
        assert!(!asm.iter().any(|t| t.contains("Sig")));
        let w = leaf_witness(&leaf);
        let names: Vec<_> = w.iter().map(|e| e.name.clone()).collect();
        assert_eq!(names, vec!["preimage", "serverSig", "emulatorSig"]);
    }

    #[test]
    fn emits_cltv_multisig_like_golden_htlc_refund() {
        let leaf = NamedTapscript {
            name: "refund".into(),
            inputs: vec![],
            items: vec![
                TapItem::After {
                    value: "refundTime".into(),
                },
                sig(vec![ident("server"), ident("emulator")]),
            ],
        };
        let c = assemble_closure(&leaf).unwrap();
        let asm = emit_leaf_asm(&c, "refund", &Binding::NameMatched);
        assert_eq!(
            asm,
            vec![
                "<refundTime>".to_string(),
                OP_CHECKLOCKTIMEVERIFY.to_string(),
                OP_DROP.to_string(),
                "<SERVER_KEY>".to_string(),
                OP_CHECKSIGVERIFY.to_string(),
                "<EMULATOR_KEY:refund>".to_string(),
                OP_CHECKSIG.to_string(),
            ]
        );
    }

    #[test]
    fn emits_csv_single_sig_exit() {
        let leaf = NamedTapscript {
            name: "unilateral".into(),
            inputs: vec![Parameter {
                name: "senderSig".into(),
                param_type: "signature".into(),
            }],
            items: vec![
                TapItem::Older {
                    value: "exit".into(),
                },
                TapItem::Sig {
                    keys: vec![ident("sender")],
                    sigs: vec!["senderSig".into()],
                    threshold: Some(1),
                },
            ],
        };
        let c = assemble_closure(&leaf).unwrap();
        let asm = emit_leaf_asm(&c, "unilateral", &Binding::Standalone);
        assert_eq!(
            asm,
            vec![
                "<exit>".to_string(),
                OP_CHECKSEQUENCEVERIFY.to_string(),
                OP_DROP.to_string(),
                "<sender>".to_string(),
                OP_CHECKSIG.to_string(),
            ]
        );
    }
}
