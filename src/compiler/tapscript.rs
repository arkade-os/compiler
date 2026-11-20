//! Tapscript (L1 leaf) compilation: closure assembly, validation, and ASM
//! emission. Pure functions over `NamedTapscript`; ABI wiring lives in mod.rs.

use crate::models::{
    AbiFunctionGroup, AbiLeaf, ArkadeScript, Contract, HashFn, KeyExpr, NamedTapscript, Parameter,
    TapItem, TapOperand, TimeUnit, WitnessElement,
};
use crate::models::{OPERATOR, OPERATOR_EXIT_DELAY};
use crate::opcodes::{
    OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_DROP,
    OP_EQUAL, OP_EQUALVERIFY, OP_SIZE, OP_VERIFY,
};
use crate::types::{bytes_of_width, digest_accepts, ArkType};

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
}

#[derive(Debug, Clone)]
pub struct Closure {
    pub class: ClosureClass,
    pub preimage_width: Option<usize>,
    pub keys: Vec<KeyExpr>,
}

/// An operand the leaf script pushes. The script is fixed when the address is
/// made, so no tapscript input can be one; inputs reach the leaf only as witness
/// elements it consumes: the preimage and the signatures. `Constructor` takes
/// any name; `LeafScript` is what keeps inputs out.
#[derive(Debug, Clone, PartialEq)]
pub enum Pushed {
    /// Assembled as written: a number or a hex string.
    Literal(String),
    Constructor(String),
    /// A constructor pubkey tweaked by `func`'s Arkade Script hash.
    TweakedConstructor {
        base: String,
        func: String,
    },
    /// The operator key tweaked by `func`'s Arkade Script hash.
    TweakedOperator(String),
    /// A value the operator supplies, by its placeholder.
    Operator(&'static str),
}

impl Pushed {
    fn asm(&self) -> String {
        match self {
            Pushed::Literal(token) => token.clone(),
            Pushed::Constructor(name) => format!("<{name}>"),
            Pushed::TweakedConstructor { base, func } => format!("<TWEAK:{base}:{func}>"),
            Pushed::TweakedOperator(func) => format!("<OPERATOR_KEY:{func}>"),
            Pushed::Operator(placeholder) => format!("<{placeholder}>"),
        }
    }
}

/// A closure whose pushed operands are resolved; what leaf emission reads. Its
/// fields are private, so only this module builds one: `validate_arkd_rules`,
/// once it has refused every tapscript input in a pushed slot, and the
/// synthesized default leaf.
#[derive(Debug, Clone)]
pub struct LeafScript {
    /// The digest, the preimage width it pins, and the hash the preimage must match.
    condition: Option<(HashFn, Option<usize>, Pushed)>,
    /// The bound, and whether it is a CSV rather than a CLTV.
    timelock: Option<(Pushed, bool)>,
    keys: Vec<Pushed>,
}

/// Assemble a tapscript body into exactly one closure, enforcing the
/// `condition? · timelock? · multisig` template in source order. The compiler
/// does not reorder; any out-of-order, duplicate, or unrepresentable
/// combination is an error (§4.4, §5.2).
pub fn assemble_closure(ts: &NamedTapscript) -> Result<Closure, String> {
    let mut condition: Option<(HashFn, String)> = None;
    let mut preimage_width = None;
    let mut timelock: Option<(String, Option<TimeUnit>)> = None;
    let mut is_csv = false; // older() → CSV; after() → CLTV
    let mut multisig: Option<Vec<KeyExpr>> = None;

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
                condition = Some((hash_fn.clone(), hash.to_string()));
                preimage_width = ts
                    .inputs
                    .iter()
                    .find(|p| *preimage == *p.name)
                    .and_then(|p| match p.param_type.ark_type() {
                        ArkType::Bytes20 => Some(20),
                        ArkType::Bytes32 => Some(32),
                        _ => None,
                    });
            }
            TapItem::Older { value, unit } | TapItem::After { value, unit } => {
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
                timelock = Some((value.to_string(), *unit));
                is_csv = matches!(item, TapItem::Older { .. });
            }
            TapItem::Sig { keys, sigs: _ } => {
                if multisig.is_some() {
                    return Err(format!(
                        "tapscript `{}`: only one checkSig/checkMultisig suffix per leaf",
                        ts.name
                    ));
                }
                multisig = Some(keys.clone());
            }
        }
    }

    let keys = multisig.ok_or_else(|| {
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
        preimage_width,
        keys,
    })
}

/// Closure-shape acceptance beyond `assemble_closure`'s template check.
pub fn validate_closure_shape(c: &Closure, ts_name: &str) -> Result<(), String> {
    if c.keys.is_empty() {
        return Err(format!("tapscript `{ts_name}`: empty key set (F1)"));
    }
    Ok(())
}

/// Enforce the binding rule (§5.3): a leaf named after an Arkade Script function tweaks a key
/// to that function, so the leaf binds its Arkade Script, and has no CSV delay, since a CSV
/// leaf sits beside the function's default leaf, which carries that name. `contract` supplies
/// the Arkade Script function names.
pub fn resolve_binding(contract: &Contract, ts: &NamedTapscript) -> Result<(), String> {
    if contract
        .functions
        .iter()
        .any(|f| f.is_private && f.name == ts.name)
    {
        return Err(format!(
            "tapscript '{}' cannot bind to a private function",
            ts.name
        ));
    }
    if !contract
        .functions
        .iter()
        .any(|f| !f.is_private && f.name == ts.name)
    {
        return Ok(());
    }
    let keys = ts
        .items
        .iter()
        .find_map(|item| match item {
            TapItem::Sig { keys, .. } => Some(keys.as_slice()),
            _ => None,
        })
        .unwrap_or_default();
    match shared_tweak_func(&ts.name, keys)? {
        Some(func) if func != ts.name => Err(format!(
            "function-bound tapscript `{}` may tweak keys only to `{}`, not `{func}`",
            ts.name, ts.name
        )),
        Some(_)
            if ts
                .items
                .iter()
                .any(|item| matches!(item, TapItem::Older { .. })) =>
        {
            Err(format!(
                "tapscript `{0}` has a CSV delay, so it sits beside `{0}`'s default leaf, which \
                 is named `{0}`; give the tapscript another name, and it still joins `{0}`'s \
                 spend group through its tweak",
                ts.name
            ))
        }
        Some(_) => Ok(()),
        None => Err(format!(
            "function-bound tapscript `{0}` must tweak a key to `{0}`, e.g. tweak(operator, {0})",
            ts.name
        )),
    }
}

/// The one Arkade Script function this leaf tweaks a key to.
///
/// `tweak(base, func)` names `func`. A leaf can name only one function, so it has one `leaves`
/// array to join.
pub(crate) fn shared_tweak_func(ts_name: &str, keys: &[KeyExpr]) -> Result<Option<String>, String> {
    let mut target: Option<String> = None;
    for key in keys {
        let KeyExpr::Tweak { func, .. } = key else {
            continue;
        };
        if let Some(prev) = &target {
            if prev != func {
                return Err(format!(
                    "tapscript `{ts_name}`: keys may be tweaked to only one Arkade Script function"
                ));
            }
        } else {
            target = Some(func.clone());
        }
    }
    Ok(target)
}

/// Whether `func` keeps its synthesized default leaf: no author-written non-CSV leaf joins its
/// spend group. An offchain spend sets nSequence final, so a CSV leaf is never an offchain path;
/// the default stays beside it and keeps the Arkade Script reachable offchain.
pub(crate) fn keeps_default_leaf(contract: &Contract, func: &str) -> bool {
    !contract.tapscripts.iter().any(|ts| {
        assemble_closure(ts).is_ok_and(|c| {
            c.class.is_forfeit()
                && shared_tweak_func(&ts.name, &c.keys)
                    .ok()
                    .flatten()
                    .as_deref()
                    == Some(func)
        })
    })
}

/// arkd structural rules F2/F3/E1, and resolution of every operand the leaf
/// script pushes (§5.3).
pub fn validate_arkd_rules(
    contract: &Contract,
    ts: &NamedTapscript,
    c: &Closure,
) -> Result<LeafScript, String> {
    let constructor_scope =
        crate::types::build_scope_with_structs(&contract.parameters, &contract.structs);
    let is_input = |name: &str| ts.inputs.iter().any(|p| p.name == name);
    // The type of a scalar constructor binding the script pushes as `role`.
    let fixed = |name: &str, role: &str| -> Result<Option<ArkType>, String> {
        if is_input(name) {
            return Err(format!(
                "tapscript `{}`: `{name}` is a tapscript input, but a {role} is part of the \
                 leaf script, which is fixed when the address is made; take it from a \
                 constructor parameter",
                ts.name
            ));
        }
        Ok(constructor_scope
            .get(name)
            .filter(|t| !matches!(t, ArkType::Struct(_) | ArkType::Array(..)))
            .cloned())
    };

    let mut constructor_tweak_funcs: std::collections::BTreeMap<
        String,
        std::collections::BTreeSet<String>,
    > = std::collections::BTreeMap::new();
    let mut keys = Vec::with_capacity(c.keys.len());
    for k in &c.keys {
        keys.push(match k {
            KeyExpr::Ident(id) if id == OPERATOR => Pushed::Operator("OPERATOR_KEY"),
            KeyExpr::Literal(key) => Pushed::Literal(key.clone()),
            KeyExpr::Ident(id) => {
                if fixed(&id.key(), "key")? != Some(ArkType::Bytes) {
                    return Err(format!("unknown key `{id}` in tapscript `{}`", ts.name));
                }
                Pushed::Constructor(id.key())
            }
            KeyExpr::Tweak { base, func } => {
                if base != OPERATOR && fixed(base, "key")? != Some(ArkType::Bytes) {
                    return Err(format!(
                        "tweak({base}, {func}) in tapscript `{}`: `{base}` is not `operator` or a \
                         constructor pubkey",
                        ts.name
                    ));
                }
                if !contract
                    .functions
                    .iter()
                    .any(|f| !f.is_private && &f.name == func)
                {
                    return Err(format!(
                        "tweak({base}, {func}) in tapscript `{}`: no function named `{func}`",
                        ts.name
                    ));
                }
                if base == OPERATOR {
                    Pushed::TweakedOperator(func.clone())
                } else {
                    constructor_tweak_funcs
                        .entry(base.clone())
                        .or_default()
                        .insert(func.clone());
                    Pushed::TweakedConstructor {
                        base: base.clone(),
                        func: func.clone(),
                    }
                }
            }
        });
    }
    for (base, funcs) in &constructor_tweak_funcs {
        if funcs.len() > 1 {
            return Err(format!(
                "ambiguous constructor tweak targets for `{base}` in tapscript `{}`",
                ts.name
            ));
        }
    }
    // Every tweak must name the same function.
    shared_tweak_func(&ts.name, &c.keys)?;

    // A declared `signature` input.
    let sig_input = |name: &str| -> bool {
        ts.inputs
            .iter()
            .any(|p| p.name == name && p.param_type.name() == Some("signature"))
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
                if !sig_input(&s.key()) {
                    return Err(format!(
                        "tapscript `{}`: signature operand `{s}` is not a declared `signature` input",
                        ts.name
                    ));
                }
            }
        }
    }

    // The preimage comes from the witness. The hash and the timelock are pushed,
    // and may also be literals.
    let mut condition = None;
    let mut timelock = None;
    for item in &ts.items {
        match item {
            TapItem::Hash {
                hash_fn,
                preimage,
                hash,
            } => {
                let preimage = preimage.key();
                if !is_input(&preimage) {
                    let why = if constructor_scope.contains_key(&preimage) {
                        "a constructor parameter, but the leaf consumes its preimage from the \
                         witness; declare it as a tapscript input"
                    } else {
                        "not a tapscript input"
                    };
                    return Err(format!(
                        "tapscript `{}`: hash preimage `{preimage}` is {why}",
                        ts.name
                    ));
                }
                let (t, hash_operand) = match hash {
                    TapOperand::Literal(bytes) => (
                        bytes_of_width(Some((bytes.len() - 2) / 2)),
                        Pushed::Literal(bytes.clone()),
                    ),
                    TapOperand::Name(path) => {
                        let Some(t) = fixed(&path.key(), "hash value")? else {
                            return Err(format!(
                                "tapscript `{}`: hash value `{hash}` is not a scalar constructor parameter",
                                ts.name
                            ));
                        };
                        (t, Pushed::Constructor(path.key()))
                    }
                };
                // A literal types as `bytes` only when it is neither 20 nor 32 bytes, so it
                // never equals a digest.
                let unsized_literal = matches!(hash, TapOperand::Literal(_)) && t == ArkType::Bytes;
                if unsized_literal || !digest_accepts(hash_fn, &t) {
                    return Err(format!(
                        "tapscript `{}`: {} value `{hash}` has type '{}', expected {}",
                        ts.name,
                        hash_fn.name(),
                        t.as_str(),
                        hash_fn.digest_type()
                    ));
                }
                condition = Some((hash_fn.clone(), c.preimage_width, hash_operand));
            }
            TapItem::Older { value, unit } | TapItem::After { value, unit } => {
                let csv = matches!(item, TapItem::Older { .. });
                let call = if csv { "older" } else { "after" };
                let value = value.to_string();
                let operand = match unit {
                    Some(TimeUnit::Blocks) => format!("blocks({value})"),
                    Some(TimeUnit::Seconds) => format!("seconds({value})"),
                    None => value.clone(),
                };
                timelock = Some((timelock_operand(&value, *unit, csv), csv));
                if csv && value == OPERATOR_EXIT_DELAY {
                    if unit.is_some() {
                        return Err(format!(
                            "tapscript `{}`: operatorExitDelay has its own unit; write older(operatorExitDelay)",
                            ts.name
                        ));
                    }
                    continue;
                }
                let Some(n) = timelock_number(&value) else {
                    let declared = fixed(&value, "timelock")?;
                    if unit.is_some() {
                        let hint = if declared.is_some() {
                            format!("; pass `{value}` without a unit to push it raw")
                        } else {
                            String::new()
                        };
                        return Err(format!(
                            "tapscript `{}`: {call}({operand}) takes an integer literal or constant{hint}",
                            ts.name
                        ));
                    }
                    match declared {
                        None => {
                            return Err(format!(
                                "tapscript `{}`: timelock `{value}` is not a literal or scalar constructor parameter",
                                ts.name
                            ))
                        }
                        Some(t) if t != ArkType::Int => {
                            return Err(format!(
                                "tapscript `{}`: timelock `{value}` has type '{}', expected 'int'",
                                ts.name,
                                t.as_str()
                            ))
                        }
                        Some(_) => continue,
                    }
                };
                const MAX: i128 = u32::MAX as i128;
                let (valid, expected) = match (csv, unit) {
                    // BIP68 ignores bits 16-21 and 23-30, and bit 31 disables the lock.
                    (true, None) => (
                        n & !(0xffff | 1 << 22) == 0,
                        "a BIP68 sequence that sets only the 16 value bits and the type flag \
                         (bit 22); write blocks(n) or seconds(n)",
                    ),
                    (true, Some(TimeUnit::Blocks)) => {
                        ((1..=0xffff).contains(&n), "1..=65535 blocks")
                    }
                    (true, Some(TimeUnit::Seconds)) => (
                        (1..=0xffff * 512).contains(&n) && n % 512 == 0,
                        "a multiple of 512 in 512..=33553920 seconds",
                    ),
                    (false, None) => ((0..=MAX).contains(&n), "a locktime in 0..=4294967295"),
                    (false, Some(TimeUnit::Blocks)) => (
                        (1..500_000_000).contains(&n),
                        "a block height in 1..=499999999",
                    ),
                    (false, Some(TimeUnit::Seconds)) => (
                        (500_000_000..=MAX).contains(&n),
                        "a Unix timestamp in 500000000..=4294967295",
                    ),
                };
                if !valid {
                    return Err(format!(
                        "tapscript `{}`: {call}({operand}) must be {expected}",
                        ts.name
                    ));
                }
            }
            TapItem::Sig { .. } => {}
        }
    }

    // F2: forfeit closures must contain the operator key.
    if c.class.is_forfeit() && !c.keys.iter().any(KeyExpr::is_operator) {
        return Err(format!(
            "forfeit tapscript `{}` must include `operator` or `tweak(operator, fn)` (the operator \
             co-signs every offchain spend)",
            ts.name
        ));
    }

    // F3 (CLTV seconds vs block) is value-dependent and only decidable for
    // literal locktimes with a known block-type policy; with literals-only and
    // no policy source wired yet, defer to arkd. (Placeholder for future config.)

    Ok(LeafScript {
        condition,
        timelock,
        keys,
    })
}

/// The value of a numeric timelock operand, or `None` for a name. Out-of-range
/// digit strings saturate so range checks reject them.
fn timelock_number(value: &str) -> Option<i128> {
    let digits = value.strip_prefix('-').unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(value.parse().unwrap_or(if digits == value {
        i128::MAX
    } else {
        i128::MIN
    }))
}

/// A timelock operand: `operatorExitDelay` as the operator's unilateral exit delay,
/// `seconds(n)` in a CSV as its BIP68 time-based sequence, any other number
/// as-is, else the constructor parameter pushing the raw value.
fn timelock_operand(value: &str, unit: Option<TimeUnit>, csv: bool) -> Pushed {
    if value == OPERATOR_EXIT_DELAY {
        return Pushed::Operator("OPERATOR_EXIT_DELAY");
    }
    match timelock_number(value) {
        Some(n) if csv && unit == Some(TimeUnit::Seconds) => {
            Pushed::Literal(((n / 512) | (1 << 22)).to_string())
        }
        Some(n) => Pushed::Literal(n.to_string()),
        None => Pushed::Constructor(value.to_string()),
    }
}

/// Emit the multisig suffix (N-of-N CHECKSIG chain).
fn emit_multisig(keys: &[Pushed], asm: &mut Vec<String>) {
    for (i, k) in keys.iter().enumerate() {
        asm.push(k.asm());
        if i == keys.len() - 1 {
            asm.push(OP_CHECKSIG.to_string());
        } else {
            asm.push(OP_CHECKSIGVERIFY.to_string());
        }
    }
}

/// Assemble the full leaf ASM in arkd's closure byte order: condition? · timelock? · multisig.
pub fn emit_leaf_asm(script: &LeafScript) -> Vec<String> {
    let mut asm = Vec::new();

    // Condition prefix.
    if let Some((hash_fn, preimage_width, hash)) = &script.condition {
        if let Some(width) = preimage_width {
            asm.extend([
                OP_SIZE.to_string(),
                width.to_string(),
                OP_EQUALVERIFY.to_string(),
            ]);
        }
        asm.push(hash_fn.opcode().to_string());
        asm.push(hash.asm());
        asm.push(OP_EQUAL.to_string());
        asm.push(OP_VERIFY.to_string());
    }

    // Timelock prefix.
    if let Some((bound, csv)) = &script.timelock {
        asm.push(bound.asm());
        let op = if *csv {
            OP_CHECKSEQUENCEVERIFY
        } else {
            OP_CHECKLOCKTIMEVERIFY
        };
        asm.push(op.to_string());
        asm.push(OP_DROP.to_string());
    }

    emit_multisig(&script.keys, &mut asm);
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
                if key.is_operator() {
                    names.insert(sig.to_string());
                }
            }
        }
    }
    names
}

fn push_witness_param(p: &Parameter, injected: bool, out: &mut Vec<WitnessElement>) {
    out.push(WitnessElement {
        name: p.name.clone(),
        elem_type: p.param_type.to_string(),
        encoding: p.param_type.ark_type().encoding().to_string(),
        injected,
    });
}

/// An author-written leaf that passed its checks, with what emission needs from them.
pub(crate) struct CheckedLeaf {
    script: LeafScript,
    group_key: String,
}

/// Every check on one author-written leaf: closure shape, function binding, arkd
/// rules and its spend group.
pub(crate) fn check_tapscript(
    contract: &Contract,
    ts: &NamedTapscript,
) -> Result<CheckedLeaf, String> {
    let closure = assemble_closure(ts)?;
    validate_closure_shape(&closure, &ts.name)?;
    resolve_binding(contract, ts)?;
    let script = validate_arkd_rules(contract, ts, &closure)?;
    let group_key = shared_tweak_func(&ts.name, &closure.keys)?.unwrap_or_else(|| ts.name.clone());
    Ok(CheckedLeaf { script, group_key })
}

/// Build the unified `functions[]` ABI: one group per Arkade Script function plus
/// one group per pure-standalone leaf. `leaves` are the contract's tapscripts as
/// `prepare` checked them, in declaration order. `scripts`
/// holds each function's Arkade Script (built by mod.rs to avoid a cycle);
/// it is consumed as groups are assembled.
pub(crate) fn build_function_groups(
    contract: &Contract,
    leaves: &[CheckedLeaf],
    mut scripts: std::collections::HashMap<String, ArkadeScript>,
) -> Result<Vec<AbiFunctionGroup>, String> {
    // Resolve + validate every author-written tapscript; bucket by group key.
    // A tweak joins that function's group. A leaf that tweaks nothing keeps its own name.
    use std::collections::BTreeMap;
    let mut grouped: BTreeMap<String, Vec<AbiLeaf>> = BTreeMap::new();

    // A shorter list would silently drop leaves from the artifact.
    if leaves.len() != contract.tapscripts.len() {
        return Err("internal compiler error: checked leaves do not match the tapscripts".into());
    }
    for (ts, leaf) in contract.tapscripts.iter().zip(leaves) {
        let mut asm = emit_leaf_asm(&leaf.script);
        resolve_constructor_field_placeholders(&mut asm, contract)?;
        grouped
            .entry(leaf.group_key.clone())
            .or_default()
            .push(AbiLeaf {
                name: ts.name.clone(),
                witness: leaf_witness(ts),
                asm,
            });
    }

    let mut groups = Vec::new();

    // One group per Arkade Script function, in declaration order.
    for f in contract.functions.iter().filter(|f| !f.is_private) {
        let arkade = scripts.remove(&f.name);
        let mut leaves = grouped.remove(&f.name).unwrap_or_default();
        if keeps_default_leaf(contract, &f.name) {
            leaves.insert(0, synthesize_default_leaf(&f.name));
        }
        groups.push(AbiFunctionGroup {
            name: f.name.clone(),
            arkade,
            leaves,
        });
    }

    // Standalone groups follow Arkade Script function groups, in tapscript declaration order.
    for ts in &contract.tapscripts {
        if let Some((name, leaves)) = grouped.remove_entry(&ts.name) {
            groups.push(AbiFunctionGroup {
                name,
                arkade: None,
                leaves,
            });
        }
    }

    if !grouped.is_empty() {
        return Err("unassigned tapscript groups (compiler bug)".to_string());
    }

    Ok(groups)
}

fn resolve_constructor_field_placeholders(
    asm: &mut [String],
    contract: &Contract,
) -> Result<(), String> {
    let replacements = contract
        .parameters
        .iter()
        .map(|parameter| crate::models::flatten_parameter(parameter, &contract.structs))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .filter(|leaf| leaf.access.key() != leaf.emitted_name)
        .map(|leaf| {
            (
                format!("<{}>", leaf.access),
                format!("<{}>", leaf.emitted_name),
            )
        })
        .collect::<std::collections::HashMap<_, _>>();
    for token in asm {
        if let Some(replacement) = replacements.get(token) {
            *token = replacement.clone();
        }
    }
    Ok(())
}

/// The §5.4 default leaf: checkSig(operatorSig, tweak(operator, fn)).
fn synthesize_default_leaf(func: &str) -> AbiLeaf {
    let script = LeafScript {
        condition: None,
        timelock: None,
        keys: vec![Pushed::TweakedOperator(func.into())],
    };
    AbiLeaf {
        name: func.to_string(),
        witness: vec![WitnessElement {
            name: "operatorSig".into(),
            elem_type: "signature".into(),
            encoding: ArkType::Signature.encoding().to_string(),
            injected: true,
        }],
        asm: emit_leaf_asm(&script),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Contract, Function, Parameter, Path};

    fn ts(items: Vec<TapItem>) -> NamedTapscript {
        NamedTapscript {
            span: Default::default(),
            declaration: Default::default(),
            attributes: vec![],
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
            keys: vec![ident("operator"), ident("owner")],
            sigs: vec!["operatorSig".into(), "ownerSig".into()],
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
                hash: TapOperand::Name("preimageHash".into()),
            },
            TapItem::Sig {
                keys: vec![ident("operator"), ident("owner")],
                sigs: vec!["operatorSig".into(), "ownerSig".into()],
            },
        ]))
        .unwrap();
        assert_eq!(c.class, ClosureClass::ConditionMultisig);
    }

    #[test]
    fn older_then_multisig_is_csv_exit() {
        let c = assemble_closure(&ts(vec![
            TapItem::Older {
                value: TapOperand::Literal("512".into()),
                unit: None,
            },
            TapItem::Sig {
                keys: vec![ident("owner")],
                sigs: vec!["ownerSig".into()],
            },
        ]))
        .unwrap();
        assert_eq!(c.class, ClosureClass::CsvMultisig);
    }

    #[test]
    fn after_then_multisig_is_cltv_forfeit() {
        let c = assemble_closure(&ts(vec![
            TapItem::After {
                value: TapOperand::Name("cancelTime".into()),
                unit: None,
            },
            TapItem::Sig {
                keys: vec![ident("backup"), ident("operator")],
                sigs: vec!["backupSig".into(), "operatorSig".into()],
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
                hash: TapOperand::Name("h".into()),
            },
            TapItem::After {
                value: TapOperand::Name("t".into()),
                unit: None,
            },
            TapItem::Sig {
                keys: vec![ident("operator")],
                sigs: vec!["operatorSig".into()],
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
        let err = assemble_closure(&ts(vec![TapItem::Older {
            value: TapOperand::Name("x".into()),
            unit: None,
        }]))
        .unwrap_err();
        assert!(err.contains("multisig"), "got: {err}");
    }

    #[test]
    fn out_of_order_condition_after_multisig_is_rejected() {
        let err = assemble_closure(&ts(vec![
            TapItem::Sig {
                keys: vec![ident("operator")],
                sigs: vec!["operatorSig".into()],
            },
            TapItem::Hash {
                hash_fn: HashFn::Hash160,
                preimage: "p".into(),
                hash: TapOperand::Name("h".into()),
            },
        ]))
        .unwrap_err();
        assert!(err.contains("order"), "got: {err}");
    }

    #[test]
    fn empty_key_set_is_rejected() {
        let c = assemble_closure(&ts(vec![TapItem::Sig {
            keys: vec![],
            sigs: vec![],
        }]))
        .unwrap();
        assert!(validate_closure_shape(&c, "t").is_err());
    }

    fn contract_with(funcs: &[&str], tapscripts: Vec<NamedTapscript>) -> Contract {
        Contract {
            span: Default::default(),
            name: "C".into(),
            is_library: false,
            declaration: Default::default(),
            attributes: vec![],
            structs: vec![],
            parameters: vec![
                Parameter {
                    span: Default::default(),
                    name: "owner".into(),
                    param_type: "pubkey".into(),
                },
                Parameter {
                    span: Default::default(),
                    name: "backup".into(),
                    param_type: "pubkey".into(),
                },
            ],
            functions: funcs
                .iter()
                .map(|n| Function {
                    declaration: Default::default(),
                    name: (*n).into(),
                    span: crate::diagnostics::Span { start: 0, end: 0 },
                    parameters: vec![],
                    statements: vec![],
                    is_private: false,
                    is_static: false,
                    is_exported: false,
                    return_type: None,
                    attributes: vec![],
                })
                .collect(),
            tapscripts,
            imports: vec![],
            constants: vec![],
        }
    }

    fn sig(keys: Vec<KeyExpr>) -> TapItem {
        let sigs = keys
            .iter()
            .enumerate()
            .map(|(i, _)| Path::new(format!("s{i}")))
            .collect();
        TapItem::Sig { keys, sigs }
    }

    /// `signature` inputs `s0..sn` matching the names `sig()` generates.
    fn sig_params(n: usize) -> Vec<Parameter> {
        (0..n)
            .map(|i| Parameter {
                span: Default::default(),
                name: format!("s{i}"),
                param_type: "signature".into(),
            })
            .collect()
    }

    fn named(name: &str, keys: Vec<KeyExpr>) -> NamedTapscript {
        NamedTapscript {
            span: Default::default(),
            declaration: Default::default(),
            attributes: vec![],
            name: name.into(),
            inputs: sig_params(keys.len()),
            items: vec![sig(keys)],
        }
    }

    fn tweak(base: &str, func: &str) -> KeyExpr {
        KeyExpr::Tweak {
            base: base.into(),
            func: func.into(),
        }
    }

    #[test]
    fn name_matched_tweaks_a_key_to_its_function() {
        let c = contract_with(&["claim"], vec![]);
        for keys in [
            vec![tweak("operator", "claim")],
            vec![ident("operator"), tweak("owner", "claim")],
        ] {
            resolve_binding(&c, &named("claim", keys)).unwrap();
        }
    }

    #[test]
    fn name_matched_without_a_tweak_is_error() {
        let c = contract_with(&["claim"], vec![]);
        // Bare `operator` is never tweaked implicitly, even on a leaf named after a function.
        for keys in [
            vec![ident("operator")],
            vec![ident("operator"), ident("owner")],
        ] {
            let err = resolve_binding(&c, &named("claim", keys)).unwrap_err();
            assert!(err.contains("must tweak a key to `claim`"), "got: {err}");
        }
    }

    #[test]
    fn name_matched_with_a_tweak_to_another_function_is_error() {
        let c = contract_with(&["claim", "refund"], vec![]);
        let err =
            resolve_binding(&c, &named("claim", vec![tweak("operator", "refund")])).unwrap_err();
        assert!(
            err.contains("may tweak keys only to `claim`, not `refund`"),
            "got: {err}"
        );
    }

    #[test]
    fn bare_operator_pushes_the_untweaked_key() {
        let leaf = named("weird", vec![ident("operator"), ident("owner")]);
        let c = contract_with(&["claim"], vec![leaf.clone()]);
        resolve_binding(&c, &leaf).unwrap();
        assert_eq!(
            shared_tweak_func(&leaf.name, &closure_of(&leaf).keys),
            Ok(None)
        );
        let asm = emit_leaf_asm(&validate_arkd_rules(&c, &leaf, &closure_of(&leaf)).unwrap());
        assert_eq!(
            asm,
            [
                "<OPERATOR_KEY>",
                "OP_CHECKSIGVERIFY",
                "<owner>",
                "OP_CHECKSIG"
            ]
        );
    }

    #[test]
    fn standalone_tweak_groups_under_target() {
        let leaf = named("direct", vec![tweak("operator", "claim")]);
        let c = contract_with(&["claim"], vec![leaf.clone()]);
        resolve_binding(&c, &leaf).unwrap();
        assert_eq!(
            shared_tweak_func(&leaf.name, &closure_of(&leaf).keys).unwrap(),
            Some("claim".into())
        );
        let asm = emit_leaf_asm(&validate_arkd_rules(&c, &leaf, &closure_of(&leaf)).unwrap());
        assert_eq!(asm, ["<OPERATOR_KEY:claim>", "OP_CHECKSIG"]);
    }

    #[test]
    fn tweak_to_missing_function_is_error() {
        let leaf = named("direct", vec![tweak("operator", "nope")]);
        let c = contract_with(&["claim"], vec![leaf.clone()]);
        let err = validate_arkd_rules(&c, &leaf, &closure_of(&leaf)).unwrap_err();
        assert!(err.contains("no function named `nope`"), "got: {err}");
    }

    #[test]
    fn ambiguous_tweak_targets_are_error() {
        let leaf = named(
            "direct",
            vec![tweak("operator", "claim"), tweak("operator", "refund")],
        );
        let c = contract_with(&["claim", "refund"], vec![leaf.clone()]);
        let err = validate_arkd_rules(&c, &leaf, &closure_of(&leaf)).unwrap_err();
        assert!(
            err.contains("keys may be tweaked to only one Arkade Script function"),
            "got: {err}"
        );
    }

    #[test]
    fn pure_standalone_tweaks_nothing() {
        let leaf = NamedTapscript {
            span: Default::default(),
            declaration: Default::default(),
            attributes: vec![],
            name: "unilateral".into(),
            inputs: vec![],
            items: vec![sig(vec![ident("owner")])],
        };
        let c = contract_with(&["claim"], vec![leaf.clone()]);
        resolve_binding(&c, &leaf).unwrap();
    }

    fn closure_of(leaf: &NamedTapscript) -> Closure {
        assemble_closure(leaf).unwrap()
    }

    /// The leaf's assembly, resolved against a contract with these constructor parameters.
    fn leaf_asm(params: &[(&str, &str)], leaf: &NamedTapscript) -> Vec<String> {
        let mut c = contract_with(&[leaf.name.as_str()], vec![leaf.clone()]);
        c.parameters = params
            .iter()
            .map(|(name, param_type)| Parameter {
                span: Default::default(),
                name: (*name).into(),
                param_type: (*param_type).into(),
            })
            .collect();
        emit_leaf_asm(&validate_arkd_rules(&c, leaf, &closure_of(leaf)).unwrap())
    }

    #[test]
    fn forfeit_without_operator_is_rejected() {
        let leaf = NamedTapscript {
            span: Default::default(),
            declaration: Default::default(),
            attributes: vec![],
            name: "liquidate".into(),
            inputs: sig_params(2),
            items: vec![sig(vec![ident("owner"), ident("backup")])],
        };
        let c = contract_with(&[], vec![leaf.clone()]);
        let cl = closure_of(&leaf);
        resolve_binding(&c, &leaf).unwrap();
        let err = validate_arkd_rules(&c, &leaf, &cl).unwrap_err();
        assert!(
            err.contains("must include `operator` or `tweak(operator, fn)`"),
            "got: {err}"
        );
    }

    #[test]
    fn forfeit_with_a_tweaked_operator_is_accepted() {
        let leaf = named(
            "liquidate",
            vec![tweak("operator", "claim"), ident("owner")],
        );
        let c = contract_with(&["claim"], vec![leaf.clone()]);
        assert!(validate_arkd_rules(&c, &leaf, &closure_of(&leaf)).is_ok());
    }

    #[test]
    fn csv_exit_without_operator_is_accepted() {
        let leaf = NamedTapscript {
            span: Default::default(),
            declaration: Default::default(),
            attributes: vec![],
            name: "unilateral".into(),
            inputs: sig_params(1),
            items: vec![
                TapItem::Older {
                    value: TapOperand::Literal("512".into()),
                    unit: None,
                },
                sig(vec![ident("owner")]),
            ],
        };
        let c = contract_with(&[], vec![leaf.clone()]);
        let cl = closure_of(&leaf);
        resolve_binding(&c, &leaf).unwrap();
        assert!(validate_arkd_rules(&c, &leaf, &cl).is_ok());
    }

    #[test]
    fn unknown_key_is_rejected() {
        let leaf = NamedTapscript {
            span: Default::default(),
            declaration: Default::default(),
            attributes: vec![],
            name: "x".into(),
            inputs: vec![],
            items: vec![sig(vec![ident("operator"), ident("ghost")])],
        };
        let c = contract_with(&[], vec![leaf.clone()]);
        let cl = closure_of(&leaf);
        resolve_binding(&c, &leaf).unwrap();
        let err = validate_arkd_rules(&c, &leaf, &cl).unwrap_err();
        assert!(err.contains("unknown key"), "got: {err}");
    }

    #[test]
    fn timelock_operands_are_range_checked() {
        use TimeUnit::{Blocks, Seconds};
        for (csv, value, unit, expected) in [
            (true, "144", None, None),
            (true, "4194305", None, None),
            (true, "65536", None, Some("sets only the 16 value bits")),
            (
                true,
                "2147483648",
                None,
                Some("sets only the 16 value bits"),
            ),
            (true, "-1", None, Some("sets only the 16 value bits")),
            (true, "144", Some(Blocks), None),
            (true, "65535", Some(Blocks), None),
            (true, "0", Some(Blocks), Some("1..=65535 blocks")),
            (true, "65536", Some(Blocks), Some("1..=65535 blocks")),
            (true, "512", Some(Seconds), None),
            (true, "33553920", Some(Seconds), None),
            (
                true,
                "144",
                Some(Seconds),
                Some("multiple of 512 in 512..=33553920"),
            ),
            (
                true,
                "33554432",
                Some(Seconds),
                Some("multiple of 512 in 512..=33553920"),
            ),
            (
                true,
                "-512",
                Some(Seconds),
                Some("multiple of 512 in 512..=33553920"),
            ),
            (
                true,
                "99999999999999999999999999999999999999999",
                Some(Seconds),
                Some("33553920"),
            ),
            (true, "operatorExitDelay", None, None),
            (
                true,
                "operatorExitDelay",
                Some(Seconds),
                Some("has its own unit"),
            ),
            (
                true,
                "owner",
                Some(Blocks),
                Some("pass `owner` without a unit"),
            ),
            (
                true,
                "0x00",
                Some(Blocks),
                Some("takes an integer literal or constant"),
            ),
            (true, "typo", None, Some("is not a literal")),
            (false, "4294967295", None, None),
            (
                false,
                "4294967296",
                None,
                Some("locktime in 0..=4294967295"),
            ),
            (false, "800000", Some(Blocks), None),
            (
                false,
                "500000000",
                Some(Blocks),
                Some("block height in 1..=499999999"),
            ),
            (false, "1700000000", Some(Seconds), None),
            (
                false,
                "800000",
                Some(Seconds),
                Some("Unix timestamp in 500000000..=4294967295"),
            ),
        ] {
            let value = match value.parse::<i128>() {
                Ok(_) => TapOperand::Literal(value.to_string()),
                Err(_) => TapOperand::Name(value.into()),
            };
            let timelock = if csv {
                TapItem::Older {
                    value: value.clone(),
                    unit,
                }
            } else {
                TapItem::After {
                    value: value.clone(),
                    unit,
                }
            };
            let leaf = NamedTapscript {
                span: Default::default(),
                declaration: Default::default(),
                attributes: vec![],
                name: "exit".into(),
                inputs: sig_params(2),
                items: vec![timelock, sig(vec![ident("operator"), ident("owner")])],
            };
            let c = contract_with(&[], vec![leaf.clone()]);
            match (validate_arkd_rules(&c, &leaf, &closure_of(&leaf)), expected) {
                (Err(err), Some(expected)) => assert!(err.contains(expected), "{value}: {err}"),
                (result, expected) => {
                    assert!(result.is_ok() && expected.is_none(), "{value}: {result:?}")
                }
            }
        }
    }

    #[test]
    fn only_csv_seconds_are_encoded() {
        use TimeUnit::{Blocks, Seconds};
        let asm = |value, unit, csv| timelock_operand(value, unit, csv).asm();
        assert_eq!(asm("1024", Some(Seconds), true), "4194306");
        assert_eq!(asm("144", Some(Blocks), true), "144");
        assert_eq!(asm("144", None, true), "144");
        assert_eq!(asm("exitDelay", None, true), "<exitDelay>");
        assert_eq!(
            asm("operatorExitDelay", None, true),
            "<OPERATOR_EXIT_DELAY>"
        );
        assert_eq!(asm("1700000000", Some(Seconds), false), "1700000000");
    }

    #[test]
    fn misaligned_sig_and_key_count_is_rejected() {
        // 2 keys but 1 declared signature → witness cannot satisfy the closure.
        let leaf = NamedTapscript {
            span: Default::default(),
            declaration: Default::default(),
            attributes: vec![],
            name: "x".into(),
            inputs: vec![Parameter {
                span: Default::default(),
                name: "operatorSig".into(),
                param_type: "signature".into(),
            }],
            items: vec![TapItem::Sig {
                keys: vec![ident("operator"), tweak("operator", "x")],
                sigs: vec!["operatorSig".into()],
            }],
        };
        let c = contract_with(&["x"], vec![leaf.clone()]);
        let cl = closure_of(&leaf);
        resolve_binding(&c, &leaf).unwrap();
        let err = validate_arkd_rules(&c, &leaf, &cl).unwrap_err();
        assert!(err.contains("align 1:1"), "got: {err}");
    }

    #[test]
    fn undeclared_signature_operand_is_rejected() {
        // sig operand `ghostSig` is not declared as a `signature` input.
        let leaf = NamedTapscript {
            span: Default::default(),
            declaration: Default::default(),
            attributes: vec![],
            name: "x".into(),
            inputs: vec![],
            items: vec![TapItem::Sig {
                keys: vec![ident("operator")],
                sigs: vec!["ghostSig".into()],
            }],
        };
        let c = contract_with(&[], vec![leaf.clone()]);
        let cl = closure_of(&leaf);
        resolve_binding(&c, &leaf).unwrap();
        let err = validate_arkd_rules(&c, &leaf, &cl).unwrap_err();
        assert!(
            err.contains("not a declared `signature` input"),
            "got: {err}"
        );
    }

    #[test]
    fn undeclared_timelock_operand_is_rejected() {
        // after(typo) where `typo` is neither a literal nor a declared name.
        let leaf = NamedTapscript {
            span: Default::default(),
            declaration: Default::default(),
            attributes: vec![],
            name: "exit".into(),
            inputs: sig_params(1),
            items: vec![
                TapItem::After {
                    value: TapOperand::Name("typoDelay".into()),
                    unit: None,
                },
                sig(vec![ident("owner")]),
            ],
        };
        let c = contract_with(&[], vec![leaf.clone()]);
        let cl = closure_of(&leaf);
        resolve_binding(&c, &leaf).unwrap();
        let err = validate_arkd_rules(&c, &leaf, &cl).unwrap_err();
        assert!(err.contains("timelock `typoDelay`"), "got: {err}");
    }

    #[test]
    fn undeclared_hash_value_is_rejected() {
        // hash160(preimage) == typoHash where typoHash is not declared.
        let leaf = NamedTapscript {
            span: Default::default(),
            declaration: Default::default(),
            attributes: vec![],
            name: "claim".into(),
            inputs: vec![
                Parameter {
                    span: Default::default(),
                    name: "preimage".into(),
                    param_type: "bytes".into(),
                },
                Parameter {
                    span: Default::default(),
                    name: "operatorSig".into(),
                    param_type: "signature".into(),
                },
            ],
            items: vec![
                TapItem::Hash {
                    hash_fn: HashFn::Hash160,
                    preimage: "preimage".into(),
                    hash: TapOperand::Name("typoHash".into()),
                },
                TapItem::Sig {
                    keys: vec![ident("operator")],
                    sigs: vec!["operatorSig".into()],
                },
            ],
        };
        let c = contract_with(&[], vec![leaf.clone()]);
        let cl = closure_of(&leaf);
        resolve_binding(&c, &leaf).unwrap();
        let err = validate_arkd_rules(&c, &leaf, &cl).unwrap_err();
        assert!(err.contains("hash value `typoHash`"), "got: {err}");
    }

    use crate::opcodes::{
        OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_DROP, OP_EQUAL, OP_HASH160,
        OP_VERIFY,
    };

    #[test]
    fn emits_condition_multisig_like_golden_htlc_claim() {
        // ConditionMultisigClosure { HASH160 <preimageHash> EQUAL, [operator(claim)] }
        let leaf = NamedTapscript {
            span: Default::default(),
            declaration: Default::default(),
            attributes: vec![],
            name: "claim".into(),
            inputs: vec![
                Parameter {
                    span: Default::default(),
                    name: "preimage".into(),
                    param_type: "bytes".into(),
                },
                Parameter {
                    span: Default::default(),
                    name: "operatorSig".into(),
                    param_type: "signature".into(),
                },
            ],
            items: vec![
                TapItem::Hash {
                    hash_fn: HashFn::Hash160,
                    preimage: "preimage".into(),
                    hash: TapOperand::Name("preimageHash".into()),
                },
                TapItem::Sig {
                    keys: vec![tweak("operator", "claim")],
                    sigs: vec!["operatorSig".into()],
                },
            ],
        };
        let asm = leaf_asm(&[("preimageHash", "bytes20")], &leaf);
        assert_eq!(
            asm,
            vec![
                OP_HASH160.to_string(),
                "<preimageHash>".to_string(),
                OP_EQUAL.to_string(),
                OP_VERIFY.to_string(),
                "<OPERATOR_KEY:claim>".to_string(),
                OP_CHECKSIG.to_string(),
            ]
        );
        // Signatures are witness, not script.
        assert!(!asm.iter().any(|t| t.contains("Sig")));
        let w = leaf_witness(&leaf);
        let names: Vec<_> = w.iter().map(|e| e.name.clone()).collect();
        assert_eq!(names, vec!["preimage", "operatorSig"]);
        assert!(w[1].injected, "the operator's signature is injected");
    }

    #[test]
    fn emits_cltv_multisig_like_golden_htlc_refund() {
        let leaf = NamedTapscript {
            span: Default::default(),
            declaration: Default::default(),
            attributes: vec![],
            name: "refund".into(),
            inputs: sig_params(1),
            items: vec![
                TapItem::After {
                    value: TapOperand::Name("refundTime".into()),
                    unit: None,
                },
                sig(vec![tweak("operator", "refund")]),
            ],
        };
        let asm = leaf_asm(&[("refundTime", "int")], &leaf);
        assert_eq!(
            asm,
            vec![
                "<refundTime>".to_string(),
                OP_CHECKLOCKTIMEVERIFY.to_string(),
                OP_DROP.to_string(),
                "<OPERATOR_KEY:refund>".to_string(),
                OP_CHECKSIG.to_string(),
            ]
        );
    }

    #[test]
    fn emits_csv_single_sig_exit() {
        let leaf = NamedTapscript {
            span: Default::default(),
            declaration: Default::default(),
            attributes: vec![],
            name: "unilateral".into(),
            inputs: vec![Parameter {
                span: Default::default(),
                name: "senderSig".into(),
                param_type: "signature".into(),
            }],
            items: vec![
                TapItem::Older {
                    value: TapOperand::Literal("512".into()),
                    unit: Some(TimeUnit::Seconds),
                },
                TapItem::Sig {
                    keys: vec![ident("sender")],
                    sigs: vec!["senderSig".into()],
                },
            ],
        };
        let asm = leaf_asm(&[("sender", "pubkey")], &leaf);
        assert_eq!(
            asm,
            vec![
                // 512 seconds: one 512-second unit with the BIP68 type flag.
                "4194305".to_string(),
                OP_CHECKSEQUENCEVERIFY.to_string(),
                OP_DROP.to_string(),
                "<sender>".to_string(),
                OP_CHECKSIG.to_string(),
            ]
        );
    }

    /// `tweak(constructorPubkey, func)` binds that key to `func` on any leaf. A CSV leaf sits
    /// beside the default leaf; a forfeit leaf, which includes the operator key, replaces it.
    #[test]
    fn constructor_tweak_binds_the_key_and_only_a_forfeit_leaf_replaces_the_default() {
        let late = r#"
  function late(signature insurerSig) tapscript {
    require(older(512));
    require(checkSig(insurerSig, tweak(insurer, claim)));
  }"#;
        let race = r#"
  function race(signature operatorSig, signature insurerSig) tapscript {
    require(checkMultisig([operator, tweak(insurer, claim)], [operatorSig, insurerSig]));
  }"#;
        let claim = |leaves: &str| {
            let src = format!(
                r#"
pragma arkade ^0.1.0;
contract Demo(pubkey insurer) {{
  function claim() {{ require(tx.input.current.value >= 1, "funded"); }}{leaves}
}}
"#
            );
            let output = super::super::compile(&src).expect("constructor tweak");
            assert_eq!(
                output
                    .functions
                    .iter()
                    .map(|g| g.name.as_str())
                    .collect::<Vec<_>>(),
                ["claim"],
                "constructor tweaks are leaves of claim, not their own groups"
            );
            output.functions.into_iter().next().expect("claim")
        };
        let names = |group: &AbiFunctionGroup| {
            group
                .leaves
                .iter()
                .map(|leaf| leaf.name.clone())
                .collect::<Vec<_>>()
        };

        let csv_only = claim(late);
        assert!(csv_only.arkade.is_some());
        assert_eq!(names(&csv_only), ["claim", "late"]);
        assert_eq!(
            csv_only.leaves[0].asm,
            ["<OPERATOR_KEY:claim>", "OP_CHECKSIG"]
        );

        let with_forfeit = claim(&format!("{late}{race}"));
        assert_eq!(names(&with_forfeit), ["late", "race"]);
        assert_eq!(
            with_forfeit.leaves[1].asm,
            [
                "<OPERATOR_KEY>",
                "OP_CHECKSIGVERIFY",
                "<TWEAK:insurer:claim>",
                "OP_CHECKSIG"
            ]
        );
        for leaf in &with_forfeit.leaves {
            assert!(
                leaf.asm.contains(&"<TWEAK:insurer:claim>".to_string()),
                "{} binds the insurer key to claim: {:?}",
                leaf.name,
                leaf.asm
            );
            for w in &leaf.witness {
                assert_eq!(
                    w.injected,
                    w.name == "operatorSig",
                    "{}: only the operator's signature is injected",
                    leaf.name
                );
            }
        }
    }

    /// An author-written forfeit leaf replaces the default leaf. A CSV constructor tweak is
    /// another leaf of the same function, and no default is added back.
    #[test]
    fn an_author_leaf_replaces_the_default_and_a_csv_tweak_joins_it() {
        let src = r#"
pragma arkade ^0.1.0;
contract Demo(pubkey insurer) {
  function claim() {
    require(tx.input.current.value >= 1, "funded");
  }
  function claim(signature operatorSig, signature insurerSig) tapscript {
    require(checkMultisig([tweak(operator, claim), insurer], [operatorSig, insurerSig]));
  }
  function late(signature insurerSig) tapscript {
    require(older(512));
    require(checkSig(insurerSig, tweak(insurer, claim)));
  }
}
"#;
        let output = super::super::compile(src).expect("author leaf");
        let claim = output
            .functions
            .iter()
            .find(|g| g.name == "claim")
            .expect("claim");
        assert_eq!(claim.leaves.len(), 2);
        assert_eq!(
            claim.leaves[0].asm,
            [
                "<OPERATOR_KEY:claim>",
                "OP_CHECKSIGVERIFY",
                "<insurer>",
                "OP_CHECKSIG"
            ]
        );
        assert_eq!(claim.leaves[1].name, "late");
        assert!(claim.leaves[1]
            .asm
            .iter()
            .any(|t| t == "<TWEAK:insurer:claim>"));
    }

    #[test]
    fn constructor_tweak_rejects_an_unknown_base_or_function() {
        let unknown_base = r#"
pragma arkade ^0.1.0;
contract Demo(pubkey insurer) {
  function claim() { require(tx.input.current.value >= 1, "funded"); }
  function race(signature ownerSig, signature insurerSig) tapscript {
    require(checkMultisig([operator, tweak(owner, claim)], [ownerSig, insurerSig]));
  }
}
"#;
        let no_emulator_role = r#"
pragma arkade ^0.1.0;
contract Demo(pubkey insurer) {
  function claim() { require(tx.input.current.value >= 1, "funded"); }
  function race(signature operatorSig, signature emulatorSig) tapscript {
    require(checkMultisig([operator, tweak(emulator, claim)], [operatorSig, emulatorSig]));
  }
}
"#;
        let missing_fn = r#"
pragma arkade ^0.1.0;
contract Demo(pubkey insurer) {
  function claim() { require(tx.input.current.value >= 1, "funded"); }
  function race(signature operatorSig, signature insurerSig) tapscript {
    require(checkMultisig([operator, tweak(insurer, missing)], [operatorSig, insurerSig]));
  }
}
"#;
        let tapscript_fn = r#"
pragma arkade ^0.1.0;
contract Demo(pubkey insurer) {
  function claim() { require(tx.input.current.value >= 1, "funded"); }
  function late(signature insurerSig) tapscript {
    require(older(512));
    require(checkSig(insurerSig, tweak(insurer, late)));
  }
}
"#;
        let two_funcs = r#"
pragma arkade ^0.1.0;
contract Demo(pubkey insurer) {
  function claim() { require(tx.input.current.value >= 1, "funded"); }
  function refund() { require(tx.input.current.value >= 1, "funded"); }
  function race(signature aSig, signature bSig) tapscript {
    require(older(512));
    require(checkMultisig([tweak(insurer, claim), tweak(insurer, refund)], [aSig, bSig]));
  }
}
"#;
        for src in [unknown_base, no_emulator_role] {
            let err = super::super::compile(src).unwrap_err();
            assert!(
                err.contains("is not `operator` or a constructor pubkey"),
                "{err}"
            );
        }
        let err = super::super::compile(missing_fn).unwrap_err();
        assert!(err.contains("no function named `missing`"), "{err}");
        let err = super::super::compile(tapscript_fn).unwrap_err();
        assert!(err.contains("no function named `late`"), "{err}");
        let err = super::super::compile(two_funcs).unwrap_err();
        assert!(err.contains("ambiguous constructor tweak"), "{err}");
    }

    #[test]
    fn a_tapscript_may_tweak_keys_to_only_one_function() {
        let two_keys = r#"
pragma arkade ^0.1.0;
contract Demo(pubkey insurer, pubkey backup) {
  function claim() { require(tx.input.current.value >= 1, "funded"); }
  function refund() { require(tx.input.current.value >= 1, "funded"); }
  function race(signature aSig, signature bSig) tapscript {
    require(older(512));
    require(checkMultisig([tweak(insurer, claim), tweak(backup, refund)], [aSig, bSig]));
  }
}
"#;
        let operator_and_constructor = r#"
pragma arkade ^0.1.0;
contract Demo(pubkey insurer) {
  function claim() { require(tx.input.current.value >= 1, "funded"); }
  function refund() { require(tx.input.current.value >= 1, "funded"); }
  function race(signature operatorSig, signature insurerSig) tapscript {
    require(older(512));
    require(checkMultisig([tweak(operator, claim), tweak(insurer, refund)], [operatorSig, insurerSig]));
  }
}
"#;
        let name_matched = r#"
pragma arkade ^0.1.0;
contract Demo(pubkey insurer) {
  function claim() { require(tx.input.current.value >= 1, "funded"); }
  function refund() { require(tx.input.current.value >= 1, "funded"); }
  function claim(signature operatorSig, signature insurerSig) tapscript {
    require(checkMultisig(
      [tweak(operator, claim), tweak(insurer, refund)],
      [operatorSig, insurerSig]
    ));
  }
}
"#;
        for src in [two_keys, operator_and_constructor, name_matched] {
            let err = super::super::compile(src).unwrap_err();
            assert!(
                err.contains("keys may be tweaked to only one Arkade Script function"),
                "{err}"
            );
        }
    }
}
