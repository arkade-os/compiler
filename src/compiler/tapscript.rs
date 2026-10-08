//! Tapscript (L1 leaf) compilation: closure assembly, validation, and ASM
//! emission. Pure functions over `NamedTapscript`; ABI wiring lives in mod.rs.

use crate::models::{
    AbiFunctionGroup, AbiLeaf, ArkadeCovenant, Contract, HashFn, KeyExpr, NamedTapscript,
    Parameter, TapItem, TimeUnit, WitnessElement,
};
use crate::opcodes::{
    OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_DROP,
    OP_EQUAL, OP_VERIFY,
};
use crate::typechecker::{digest_accepts, ArkType};

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
    pub timelock: Option<(String, Option<TimeUnit>)>, // CSV or CLTV bound and its unit
    pub keys: Vec<KeyExpr>,
    pub threshold: Option<u16>,
}

/// Assemble a tapscript body into exactly one closure, enforcing the
/// `condition? · timelock? · multisig` template in source order. The compiler
/// does not reorder; any out-of-order, duplicate, or unrepresentable
/// combination is an error (§4.4, §5.2).
pub fn assemble_closure(ts: &NamedTapscript) -> Result<Closure, String> {
    let mut condition: Option<(HashFn, String)> = None;
    let mut timelock: Option<(String, Option<TimeUnit>)> = None;
    let mut is_csv = false; // older() → CSV; after() → CLTV
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
                timelock = Some((value.clone(), *unit));
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
    let name_matches = contract
        .functions
        .iter()
        .any(|f| !f.is_private && f.name == ts.name);

    // Collect bare-emulator usage and explicit tweak targets across all keys.
    let mut uses_bare_emulator = false;
    let mut tweak_targets: Vec<String> = Vec::new();
    for item in &ts.items {
        if let TapItem::Sig { keys, .. } = item {
            for k in keys {
                match k {
                    KeyExpr::Ident(id) if id == "emulator" => uses_bare_emulator = true,
                    KeyExpr::Tweak { base, func } if base == "emulator" => {
                        tweak_targets.push(func.clone())
                    }
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
            if !contract
                .functions
                .iter()
                .any(|f| !f.is_private && &f.name == func)
            {
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

/// The one arkade function this leaf tweaks a key to.
///
/// Bare `emulator` names the tapscript itself. `tweak(base, func)` names `func`.
/// A leaf can name only one function, so it has one `leaves` array to join.
fn shared_tweak_func(ts_name: &str, keys: &[KeyExpr]) -> Result<Option<String>, String> {
    let mut target: Option<String> = None;
    for key in keys {
        let func = match key {
            KeyExpr::Ident(id) if id == "emulator" => ts_name,
            KeyExpr::Tweak { func, .. } => func.as_str(),
            _ => continue,
        };
        if let Some(prev) = &target {
            if prev != func {
                return Err(format!(
                    "tapscript `{ts_name}`: keys may be tweaked to only one arkade function"
                ));
            }
        } else {
            target = Some(func.to_string());
        }
    }
    Ok(target)
}

/// arkd structural rules F2/F3/E1 + key resolution (§5.3).
pub fn validate_arkd_rules(
    contract: &Contract,
    ts: &NamedTapscript,
    c: &Closure,
) -> Result<(), String> {
    let constructor_scope =
        crate::typechecker::build_scope_with_structs(&contract.parameters, &contract.structs);
    // Pubkeys in scope: constructor pubkey params + pubkey tapscript inputs.
    let in_scope = |name: &str| -> bool {
        name == "server"
            || name == "emulator"
            || constructor_scope.get(name) == Some(&ArkType::Bytes)
            || ts
                .inputs
                .iter()
                .any(|p| p.name == name && p.param_type == "pubkey")
    };

    // Key resolution.
    let mut constructor_tweak_funcs: std::collections::BTreeMap<
        String,
        std::collections::BTreeSet<String>,
    > = std::collections::BTreeMap::new();
    for k in &c.keys {
        match k {
            KeyExpr::Ident(id) if !in_scope(id) => {
                return Err(format!("unknown key `{id}` in tapscript `{}`", ts.name));
            }
            KeyExpr::Tweak { base, func } if base != "emulator" => {
                if constructor_scope.get(base) != Some(&ArkType::Bytes) {
                    return Err(format!(
                        "tweak({base}, {func}) in tapscript `{}`: `{base}` is not a constructor pubkey",
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
                constructor_tweak_funcs
                    .entry(base.clone())
                    .or_default()
                    .insert(func.clone());
            }
            _ => {}
        }
    }
    for (base, funcs) in &constructor_tweak_funcs {
        if funcs.len() > 1 {
            return Err(format!(
                "ambiguous constructor tweak targets for `{base}` in tapscript `{}`",
                ts.name
            ));
        }
    }
    // Bare `emulator` names this tapscript. Every tweak must name that same function.
    shared_tweak_func(&ts.name, &c.keys)?;

    // Any scalar constructor binding or tapscript input.
    let name_declared = |name: &str| -> bool {
        constructor_scope.get(name).is_some_and(|binding_type| {
            !matches!(binding_type, ArkType::Struct(_) | ArkType::Array(..))
        }) || ts.inputs.iter().any(|p| p.name == name)
    };
    let name_type = |name: &str| -> Option<ArkType> {
        constructor_scope.get(name).cloned().or_else(|| {
            ts.inputs
                .iter()
                .find(|p| p.name == name)
                .map(|p| ArkType::parse(&p.param_type))
        })
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

    // Named condition operands must resolve to inputs or constructor parameters.
    // Hash values may also be byte literals; timelocks may be numeric literals.
    for item in &ts.items {
        match item {
            TapItem::Hash {
                hash_fn,
                preimage,
                hash,
            } => {
                if !name_declared(preimage) {
                    return Err(format!(
                        "tapscript `{}`: hash preimage `{preimage}` is not a declared input or constructor parameter",
                        ts.name
                    ));
                }
                if !hash.starts_with("0x") && !name_declared(hash) {
                    return Err(format!(
                        "tapscript `{}`: hash value `{hash}` is not a declared input or constructor parameter",
                        ts.name
                    ));
                }
                if let Some(t) = name_type(hash).filter(|t| !digest_accepts(hash_fn, t)) {
                    return Err(format!(
                        "tapscript `{}`: {} value `{hash}` has type '{}', expected {}",
                        ts.name,
                        hash_fn.name(),
                        t.as_str(),
                        hash_fn.digest_type()
                    ));
                }
            }
            TapItem::Older { value, unit } | TapItem::After { value, unit } => {
                let csv = matches!(item, TapItem::Older { .. });
                let call = if csv { "older" } else { "after" };
                let operand = match unit {
                    Some(TimeUnit::Blocks) => format!("blocks({value})"),
                    Some(TimeUnit::Seconds) => format!("seconds({value})"),
                    None => value.clone(),
                };
                if csv && value == "serverExitDelay" {
                    if unit.is_some() {
                        return Err(format!(
                            "tapscript `{}`: serverExitDelay has its own unit; write older(serverExitDelay)",
                            ts.name
                        ));
                    }
                    continue;
                }
                let Some(n) = timelock_number(value) else {
                    if unit.is_some() {
                        let hint = if name_declared(value) {
                            format!("; pass `{value}` without a unit to push it raw")
                        } else {
                            String::new()
                        };
                        return Err(format!(
                            "tapscript `{}`: {call}({operand}) takes an integer literal or constant{hint}",
                            ts.name
                        ));
                    }
                    if !name_declared(value) {
                        return Err(format!(
                            "tapscript `{}`: timelock `{value}` is not a literal, declared input, or constructor parameter",
                            ts.name
                        ));
                    }
                    if let Some(t) = name_type(value).filter(|t| *t != ArkType::Int) {
                        return Err(format!(
                            "tapscript `{}`: timelock `{value}` has type '{}', expected 'int'",
                            ts.name,
                            t.as_str()
                        ));
                    }
                    continue;
                };
                const MAX: i128 = u32::MAX as i128;
                let (valid, expected) = match (csv, unit) {
                    (true, None) => (
                        (0..=MAX).contains(&n) && n & (1 << 31) == 0,
                        "a BIP68 sequence in 0..=4294967295 without the disable flag (bit 31)",
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

    // F2: forfeit closures must contain `server`.
    if c.class.is_forfeit() && !c.keys.iter().any(KeyExpr::is_server) {
        return Err(format!(
            "forfeit tapscript `{}` must include `server` (arkd co-signer)",
            ts.name
        ));
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
        KeyExpr::Tweak { base, func } if base == "emulator" => format!("<EMULATOR_KEY:{func}>"),
        KeyExpr::Tweak { base, func } => format!("<TWEAK:{base}:{func}>"),
    }
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

/// Emit a timelock operand: `serverExitDelay` as arkd's unilateral exit delay,
/// `seconds(n)` in a CSV as its BIP68 time-based sequence, any other number
/// as-is, else a `<param>` placeholder pushing the raw value.
fn timelock_operand(value: &str, unit: Option<TimeUnit>, csv: bool) -> String {
    if value == "serverExitDelay" {
        return "<SERVER_EXIT_DELAY>".to_string();
    }
    match timelock_number(value) {
        Some(n) if csv && unit == Some(TimeUnit::Seconds) => ((n / 512) | (1 << 22)).to_string(),
        Some(n) => n.to_string(),
        None => format!("<{value}>"),
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
        asm.push(if hash == "0x" {
            "OP_0".to_string()
        } else if hash.starts_with("0x") {
            hash.clone()
        } else {
            format!("<{hash}>")
        });
        asm.push(OP_EQUAL.to_string());
        asm.push(OP_VERIFY.to_string());
    }

    // Timelock prefix.
    if let Some((value, unit)) = &c.timelock {
        let csv = c.class.is_exit();
        asm.push(timelock_operand(value, *unit, csv));
        let op = if csv {
            OP_CHECKSEQUENCEVERIFY
        } else {
            OP_CHECKLOCKTIMEVERIFY
        };
        asm.push(op.to_string());
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
    // A tweak joins that covenant. A leaf that tweaks nothing keeps its own name.
    use std::collections::BTreeMap;
    let mut grouped: BTreeMap<String, Vec<AbiLeaf>> = BTreeMap::new();

    for ts in &contract.tapscripts {
        let closure = assemble_closure(ts)?;
        validate_closure_shape(&closure, &ts.name)?;
        let binding = resolve_binding(contract, ts)?;
        validate_arkd_rules(contract, ts, &closure)?;

        let group_key =
            shared_tweak_func(&ts.name, &closure.keys)?.unwrap_or_else(|| ts.name.clone());

        let mut asm = emit_leaf_asm(&closure, &ts.name, &binding);
        resolve_constructor_field_placeholders(&mut asm, contract)?;
        grouped.entry(group_key).or_default().push(AbiLeaf {
            name: ts.name.clone(),
            witness: leaf_witness(ts),
            asm,
        });
    }

    let mut groups = Vec::new();

    // One group per covenant function, in declaration order.
    for f in contract.functions.iter().filter(|f| !f.is_private) {
        let arkade = covenants.remove(&f.name);
        let mut leaves = grouped.remove(&f.name).unwrap_or_default();
        // A constructor-pubkey tweak is an extra leaf. It does not replace the emulator path.
        if !leaves.iter().any(leaf_signs_emulator) {
            leaves.insert(0, synthesize_default_leaf(&f.name));
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
        .filter(|leaf| leaf.access_name != leaf.emitted_name)
        .map(|leaf| {
            (
                format!("<{}>", leaf.access_name),
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

fn leaf_signs_emulator(leaf: &AbiLeaf) -> bool {
    leaf.asm
        .iter()
        .any(|token| token.starts_with("<EMULATOR_KEY:"))
}

/// The §5.4 default collaborative leaf: checkMultisig([server, tweak(emulator, fn)], …, 2).
fn synthesize_default_leaf(func: &str) -> AbiLeaf {
    let closure = Closure {
        class: ClosureClass::Multisig,
        condition: None,
        timelock: None,
        keys: vec![
            KeyExpr::Ident("server".into()),
            KeyExpr::Tweak {
                base: "emulator".into(),
                func: func.into(),
            },
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
                value: "512".into(),
                unit: None,
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
                unit: None,
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
            TapItem::After {
                value: "t".into(),
                unit: None,
            },
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
        let err = assemble_closure(&ts(vec![TapItem::Older {
            value: "x".into(),
            unit: None,
        }]))
        .unwrap_err();
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
            is_library: false,
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
                    span: crate::diagnostics::Span { start: 0, end: 0 },
                    parameters: vec![],
                    statements: vec![],
                    is_private: false,
                    is_static: false,
                    is_exported: false,
                    return_type: None,
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
                base: "emulator".into(),
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
                base: "emulator".into(),
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
                base: "emulator".into(),
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
                    base: "emulator".into(),
                    func: "claim".into(),
                },
                KeyExpr::Tweak {
                    base: "emulator".into(),
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
        let err = validate_arkd_rules(&c, &leaf, &cl).unwrap_err();
        assert!(err.contains("server"), "got: {err}");
    }

    #[test]
    fn csv_exit_without_server_is_accepted() {
        let leaf = NamedTapscript {
            name: "unilateral".into(),
            inputs: sig_params(1),
            items: vec![
                TapItem::Older {
                    value: "512".into(),
                    unit: None,
                },
                sig(vec![ident("owner")]),
            ],
        };
        let c = contract_with(&[], vec![leaf.clone()]);
        let cl = closure_of(&leaf);
        let _binding = resolve_binding(&c, &leaf).unwrap();
        assert!(validate_arkd_rules(&c, &leaf, &cl).is_ok());
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
        let err = validate_arkd_rules(&c, &leaf, &cl).unwrap_err();
        assert!(err.contains("unknown key"), "got: {err}");
    }

    #[test]
    fn timelock_operands_are_range_checked() {
        use TimeUnit::{Blocks, Seconds};
        for (csv, value, unit, expected) in [
            (true, "144", None, None),
            (true, "4194305", None, None),
            (true, "2147483648", None, Some("without the disable flag")),
            (true, "-1", None, Some("BIP68 sequence in 0..=4294967295")),
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
            (true, "serverExitDelay", None, None),
            (
                true,
                "serverExitDelay",
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
            let value = value.to_string();
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
                name: "exit".into(),
                inputs: sig_params(2),
                items: vec![timelock, sig(vec![ident("server"), ident("owner")])],
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
        assert_eq!(timelock_operand("1024", Some(Seconds), true), "4194306");
        assert_eq!(timelock_operand("144", Some(Blocks), true), "144");
        assert_eq!(timelock_operand("144", None, true), "144");
        assert_eq!(timelock_operand("exitDelay", None, true), "<exitDelay>");
        assert_eq!(
            timelock_operand("serverExitDelay", None, true),
            "<SERVER_EXIT_DELAY>"
        );
        assert_eq!(
            timelock_operand("1700000000", Some(Seconds), false),
            "1700000000"
        );
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
        let err = validate_arkd_rules(&c, &leaf, &cl).unwrap_err();
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
            name: "exit".into(),
            inputs: sig_params(1),
            items: vec![
                TapItem::After {
                    value: "typoDelay".into(),
                    unit: None,
                },
                sig(vec![ident("owner")]),
            ],
        };
        let c = contract_with(&[], vec![leaf.clone()]);
        let cl = closure_of(&leaf);
        let _binding = resolve_binding(&c, &leaf).unwrap();
        let err = validate_arkd_rules(&c, &leaf, &cl).unwrap_err();
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
        let err = validate_arkd_rules(&c, &leaf, &cl).unwrap_err();
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
                    unit: None,
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
                    value: "512".into(),
                    unit: Some(TimeUnit::Seconds),
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
                // 512 seconds: one 512-second unit with the BIP68 type flag.
                "4194305".to_string(),
                OP_CHECKSEQUENCEVERIFY.to_string(),
                OP_DROP.to_string(),
                "<sender>".to_string(),
                OP_CHECKSIG.to_string(),
            ]
        );
    }

    /// `tweak(constructorPubkey, func)` binds that key to the covenant on any leaf.
    /// A forfeit leaf includes `server` as well.
    #[test]
    fn second_emulator_tweak_binds_the_constructor_key() {
        let src = r#"
pragma arkade ^0.1.0;
contract Demo(pubkey insurer) {
  function claim() {
    require(tx.input.current.value >= 1, "funded");
  }
  function late(signature insurerSig) tapscript {
    require(older(512));
    require(checkSig(insurerSig, tweak(insurer, claim)));
  }
  function race(signature serverSig, signature insurerSig) tapscript {
    require(checkMultisig([server, tweak(insurer, claim)], [serverSig, insurerSig], 2));
  }
}
"#;
        let output = super::super::compile(src).expect("second emulator");
        assert!(
            output.functions.iter().all(|g| g.name == "claim"),
            "constructor tweaks are leaves of claim, not their own groups"
        );
        let claim = output
            .functions
            .iter()
            .find(|g| g.name == "claim")
            .expect("claim");
        assert!(claim.arkade.is_some());
        assert_eq!(
            claim
                .leaves
                .iter()
                .map(|leaf| leaf.name.as_str())
                .collect::<Vec<_>>(),
            vec!["claim", "late", "race"]
        );
        let emulator = claim.leaves[0].asm.join(" ");
        assert!(
            emulator.contains("<SERVER_KEY>") && emulator.contains("<EMULATOR_KEY:claim>"),
            "the default emulator leaf stays: {emulator}"
        );
        assert!(
            !emulator.contains("TWEAK:insurer"),
            "the emulator leaf is not the constructor tweak: {emulator}"
        );
        for name in ["late", "race"] {
            let leaf = claim
                .leaves
                .iter()
                .find(|leaf| leaf.name == name)
                .expect(name);
            let asm = leaf.asm.join(" ");
            assert!(
                asm.contains("<TWEAK:insurer:claim>"),
                "{name} binds the insurer key to claim: {asm}"
            );
            assert!(
                !asm.contains("EMULATOR_KEY"),
                "{name} is not an emulator leaf: {asm}"
            );
            assert!(
                leaf.witness
                    .iter()
                    .any(|w| w.name == "insurerSig" && !w.injected),
                "{name}: insurerSig must not be injected"
            );
        }
    }

    /// An author-written emulator leaf stays the emulator path. The constructor
    /// tweak is another leaf of the same function, and no second default is added.
    #[test]
    fn constructor_tweak_keeps_an_author_emulator_leaf() {
        let src = r#"
pragma arkade ^0.1.0;
contract Demo(pubkey insurer) {
  function claim() {
    require(tx.input.current.value >= 1, "funded");
  }
  function claim(signature serverSig, signature emulatorSig) tapscript {
    require(checkMultisig([server, emulator], [serverSig, emulatorSig], 2));
  }
  function late(signature insurerSig) tapscript {
    require(older(512));
    require(checkSig(insurerSig, tweak(insurer, claim)));
  }
}
"#;
        let output = super::super::compile(src).expect("author emulator leaf");
        let claim = output
            .functions
            .iter()
            .find(|g| g.name == "claim")
            .expect("claim");
        assert_eq!(claim.leaves.len(), 2);
        assert!(claim.leaves[0]
            .asm
            .iter()
            .any(|t| t == "<EMULATOR_KEY:claim>"));
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
  function race(pubkey owner, signature ownerSig, signature insurerSig) tapscript {
    require(checkMultisig([server, tweak(owner, claim)], [ownerSig, insurerSig], 2));
  }
}
"#;
        let missing_fn = r#"
pragma arkade ^0.1.0;
contract Demo(pubkey insurer) {
  function claim() { require(tx.input.current.value >= 1, "funded"); }
  function race(signature serverSig, signature insurerSig) tapscript {
    require(checkMultisig([server, tweak(insurer, missing)], [serverSig, insurerSig], 2));
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
    require(checkMultisig([tweak(insurer, claim), tweak(insurer, refund)], [aSig, bSig], 2));
  }
}
"#;
        let err = super::super::compile(unknown_base).unwrap_err();
        assert!(err.contains("not a constructor pubkey"), "{err}");
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
    require(checkMultisig([tweak(insurer, claim), tweak(backup, refund)], [aSig, bSig], 2));
  }
}
"#;
        let emulator_and_constructor = r#"
pragma arkade ^0.1.0;
contract Demo(pubkey insurer) {
  function claim() { require(tx.input.current.value >= 1, "funded"); }
  function refund() { require(tx.input.current.value >= 1, "funded"); }
  function race(signature emulatorSig, signature insurerSig) tapscript {
    require(older(512));
    require(checkMultisig([tweak(emulator, claim), tweak(insurer, refund)], [emulatorSig, insurerSig], 2));
  }
}
"#;
        let name_matched = r#"
pragma arkade ^0.1.0;
contract Demo(pubkey insurer) {
  function claim() { require(tx.input.current.value >= 1, "funded"); }
  function refund() { require(tx.input.current.value >= 1, "funded"); }
  function claim(signature serverSig, signature emulatorSig, signature insurerSig) tapscript {
    require(checkMultisig(
      [server, emulator, tweak(insurer, refund)],
      [serverSig, emulatorSig, insurerSig],
      3
    ));
  }
}
"#;
        for src in [two_keys, emulator_and_constructor, name_matched] {
            let err = super::super::compile(src).unwrap_err();
            assert!(
                err.contains("keys may be tweaked to only one arkade function"),
                "{err}"
            );
        }
    }
}
