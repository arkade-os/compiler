use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_ADD, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_DIV, OP_GREATERTHAN, OP_GREATERTHANOREQUAL,
    OP_INSPECTINPUTVALUE, OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_INSPECTOUTPUTVALUE, OP_MUL, OP_SUB,
};

use crate::common::{
    arkade_asm, arkade_asm_tokens, arkade_inputs, group, leaf_asm, opcode_count_in_arkade,
    user_signatures, witness_names,
};

// Pull-payment alternative to PaymentAuthorization's escrow: the coin stays
// customer-spendable at all times, with a merchant allowance of exactly
// pullAmount per interval carved out by the covenant.
const CODE: &str = include_str!("../../examples/subscription/subscription.ark");

#[test]
fn test_subscription_compiles() {
    let output = compile(CODE).expect("compilation failed");
    assert_eq!(output.name, "Subscription");
    // 2 covenant functions (pull, cancel) + 1 standalone unilateral = 3 groups.
    assert_eq!(output.functions.len(), 3);

    let names: Vec<&str> = output.parameters.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "customerPk",
            "merchantPk",
            "merchantScript",
            "pullAmount",
            "interval",
            "nextPullTime",
            "exit",
        ]
    );
}

#[test]
fn test_pull_requires_merchant_sig_and_due_period() {
    let output = compile(CODE).expect("compilation failed");
    let asm = arkade_asm(&output, "pull");
    assert!(asm.contains(OP_CHECKSIG), "pull must verify merchant sig");
    assert!(
        asm.contains(OP_GREATERTHANOREQUAL),
        "pull must gate on tx.offchainTime >= nextPullTime"
    );

    // Exactly one user signature: the merchant's. The customer is not
    // involved in a pull.
    let user_sigs = user_signatures(&output, "pull");
    assert_eq!(
        user_sigs.len(),
        1,
        "pull must require exactly the merchant sig, got: {user_sigs:?}"
    );
    assert!(user_sigs.iter().any(|s| s == "merchantSig"));
}

#[test]
fn test_pull_checks_balance_and_pins_merchant_payout() {
    let output = compile(CODE).expect("compilation failed");
    let asm = arkade_asm(&output, "pull");
    assert!(
        asm.contains(OP_INSPECTINPUTVALUE),
        "pull must read the coin's current balance"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTVALUE),
        "pull must check output values"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "pull must pin output scriptPubKeys"
    );
    assert!(
        asm.contains(OP_SUB),
        "pull must compute the remainder (balance - pullAmount)"
    );

    // pull's covenant pins TWO outputs (merchant payout at 0, renewal VTXO at
    // 1) via structurally identical opcodes, so mere opcode presence can't
    // tell them apart — a regression that dropped the output-0 merchant pin
    // while keeping the output-1 renewal pin would still pass a
    // presence-only check. Anchor on the exact contiguous token sequence for
    // output index 0 instead.
    assert!(
        asm.contains(&format!(
            "0 {OP_INSPECTOUTPUTVALUE} <pullAmount> {OP_GREATERTHANOREQUAL}"
        )),
        "pull must check tx.outputs[0].value >= pullAmount, got: {asm}"
    );
    assert!(
        asm.contains(&format!(
            "0 {OP_INSPECTOUTPUTSCRIPTPUBKEY} OP_DROP <merchantScript> OP_EQUAL"
        )),
        "pull must pin tx.outputs[0].scriptPubKey == merchantScript, got: {asm}"
    );
}

#[test]
fn test_pull_renewal_recreates_subscription_with_advanced_schedule() {
    // The renewal output must be a recursive Subscription instantiation whose
    // nextPullTime argument is the ADVANCED schedule (nextPullTime +
    // interval), not tx.offchainTime — missed periods must accrue rather
    // than reset the anchor to "now". The whole instantiation lowers to a
    // single `<VTXO:Subscription(...)>` placeholder token (not split per
    // argument), so this checks for the newNextPullTime argument as a
    // substring of that one token rather than a standalone token.
    let output = compile(CODE).expect("compilation failed");
    let tokens = arkade_asm_tokens(&output, "pull");
    let vtxo_token = tokens
        .iter()
        .find(|t| t.starts_with("<VTXO:Subscription("))
        .unwrap_or_else(|| {
            panic!("pull must recreate a Subscription output for the renewal branch, tokens: {tokens:?}")
        });
    assert!(
        vtxo_token.contains("newNextPullTime"),
        "renewal output must derive nextPullTime from the newNextPullTime let-binding, not a literal or tx.offchainTime: {vtxo_token}"
    );
}

#[test]
fn test_cancel_requires_only_customer_sig() {
    let output = compile(CODE).expect("compilation failed");
    let asm = arkade_asm(&output, "cancel");
    assert!(asm.contains(OP_CHECKSIG), "cancel must verify customer sig");

    let user_sigs = user_signatures(&output, "cancel");
    assert_eq!(
        user_sigs.len(),
        1,
        "cancel must require exactly the customer sig, got: {user_sigs:?}"
    );
    assert!(user_sigs.iter().any(|s| s == "customerSig"));
}

#[test]
fn test_cancel_settles_due_periods_before_release() {
    // SECURITY: cancel must compute periodsDue and settle at least that much
    // to the merchant before the (unconstrained) remainder is released to
    // the customer. Without this, cancel would be a bare sig check and the
    // merchant could lose an already-due period to a same-block cancel.
    let output = compile(CODE).expect("compilation failed");
    let asm = arkade_asm(&output, "cancel");
    assert!(
        asm.contains(OP_DIV),
        "cancel must compute periodsDue = elapsed / interval + 1"
    );
    assert!(
        asm.contains(OP_ADD),
        "cancel must add 1 to account for the in-progress period"
    );
    assert!(
        asm.contains(OP_MUL),
        "cancel must compute owed = periodsDue * pullAmount in the bounded branch"
    );
    assert!(
        asm.contains(OP_GREATERTHANOREQUAL),
        "cancel must gate settlement on tx.offchainTime >= nextPullTime and compare periodsDue against maxPeriods"
    );
    // Exact-token count, not substring: OP_GREATERTHAN is a substring of
    // OP_GREATERTHANOREQUAL (which cancel also emits 4x), so a plain
    // `asm.contains(OP_GREATERTHAN)` on the joined string would pass
    // vacuously even if the dust-forgiveness check were deleted.
    assert!(
        opcode_count_in_arkade(&output, "cancel", OP_GREATERTHAN) >= 1,
        "cancel must forgive sub-dust debt via owed > 330"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTVALUE) && asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "cancel must pin the merchant settlement output when debt is owed"
    );
}

#[test]
fn test_cancel_caps_debt_before_multiplying() {
    // Overflow guard: cancel must compare periodsDue against maxPeriods
    // (balance / pullAmount + 1) BEFORE computing periodsDue * pullAmount,
    // so a long-neglected subscription can never overflow the product. The
    // OP_MUL for `owed` must be lexically reachable only after the
    // periodsDue >= maxPeriods branch has already been decided (OP_IF /
    // OP_ELSE), which we approximate by requiring an OP_ELSE between the
    // cap comparison and the multiplication.
    let output = compile(CODE).expect("compilation failed");
    let tokens = arkade_asm_tokens(&output, "cancel");
    let mul_idx = tokens
        .iter()
        .position(|t| t == OP_MUL)
        .expect("cancel must contain OP_MUL");
    let else_idx = tokens
        .iter()
        .position(|t| t == "OP_ELSE")
        .expect("cancel must branch on the debt cap via OP_ELSE");
    assert!(
        else_idx < mul_idx,
        "the periodsDue >= maxPeriods branch (OP_ELSE) must precede the owed = periodsDue * pullAmount multiplication, tokens: {tokens:?}"
    );
}

#[test]
fn test_unilateral_is_csv_and_customer_only() {
    let output = compile(CODE).expect("compilation failed");
    let unilateral_group = group(&output, "unilateral");
    assert!(
        unilateral_group.arkade.is_none(),
        "unilateral should have no arkade covenant (pure tapscript exit)"
    );

    let asm = leaf_asm(&output, "unilateral", "unilateral");
    assert!(
        asm.contains(OP_CHECKSEQUENCEVERIFY),
        "unilateral must enforce the exit CSV delay"
    );
    assert!(
        asm.contains("<customerPk>"),
        "unilateral must check the customer's key, not the merchant's"
    );
    assert!(asm.contains(OP_CHECKSIG));

    assert_eq!(
        witness_names(&output, "unilateral", "unilateral"),
        vec!["customerSig".to_string()],
        "unilateral witness must be exactly the customer's signature"
    );
}

#[test]
fn test_pull_and_cancel_have_no_customer_or_merchant_cross_signing() {
    // pull must never accept a customer sig (merchant alone triggers a
    // pull), and cancel must never accept a merchant sig (customer alone
    // triggers a cancel) — each function's authority is single-party by
    // design, with the settlement covenant (not a second signer) protecting
    // the other side.
    let output = compile(CODE).expect("compilation failed");
    let pull_inputs = arkade_inputs(&output, "pull");
    assert!(!pull_inputs.iter().any(|w| w == "customerSig"));
    let cancel_inputs = arkade_inputs(&output, "cancel");
    assert!(!cancel_inputs.iter().any(|w| w == "merchantSig"));
}

#[test]
fn test_subscription_cli() {
    use std::fs;
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let input = dir.path().join("subscription.ark");
    fs::write(&input, CODE).unwrap();
    let out = dir.path().join("subscription.json");

    let result = std::process::Command::new(env!("CARGO_BIN_EXE_arkadec"))
        .arg(input.to_str().unwrap())
        .arg("-o")
        .arg(out.to_str().unwrap())
        .output()
        .expect("failed to run arkadec");

    assert!(
        result.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let json = fs::read_to_string(&out).unwrap();
    assert!(json.contains("\"contractName\": \"Subscription\""));
}
