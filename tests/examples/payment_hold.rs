//! Authorize-and-capture payment hold examples (gas-pump flow).
//!
//! Both contracts share the same spend surface: `capture` settles a
//! witness-chosen amount up to the hold, `void` is the merchant's early
//! release, `refund` is the timelocked automatic release (no user witness),
//! and `unilateral` is the merchant's CSV exit leaf.

use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_INSPECTINASSETLOOKUP, OP_INSPECTOUTASSETLOOKUP,
    OP_INSPECTOUTPUTVALUE, OP_PUSHCURRENTINPUTINDEX,
};

fn group_names(output: &arkade_compiler::models::ContractJson) -> Vec<&str> {
    output.functions.iter().map(|g| g.name.as_str()).collect()
}

#[test]
fn test_payment_hold_contract() {
    let code = include_str!("../../examples/payment_hold/payment_hold.ark");
    let output = compile(code).expect("payment_hold.ark must compile");

    assert_eq!(output.name, "PaymentHold");
    assert_eq!(
        group_names(&output),
        vec!["capture", "void", "refund", "unilateral"]
    );

    // Capture settles a witness-chosen amount: the covenant must take the
    // amount and the merchant authorization from the spender.
    assert_eq!(
        crate::common::arkade_inputs(&output, "capture"),
        vec!["captureAmount", "merchantSig"]
    );
    let capture_asm = crate::common::arkade_asm(&output, "capture");
    assert!(
        capture_asm.contains(OP_INSPECTOUTPUTVALUE),
        "capture must pin output values: {capture_asm}"
    );

    // Refund is the automatic release: no user witness, only the timelock.
    assert!(
        crate::common::arkade_inputs(&output, "refund").is_empty(),
        "refund must not require a user witness"
    );

    // Unilateral exit is a merchant CSV leaf.
    let unilateral_asm = crate::common::leaf_asm(&output, "unilateral", "unilateral");
    assert!(unilateral_asm.contains(OP_CHECKSEQUENCEVERIFY));
    assert!(unilateral_asm.contains(OP_CHECKSIG));
}

#[test]
fn test_asset_payment_hold_contract() {
    let code = include_str!("../../examples/payment_hold/asset_payment_hold.ark");
    let output = compile(code).expect("asset_payment_hold.ark must compile");

    assert_eq!(output.name, "AssetPaymentHold");
    assert_eq!(
        group_names(&output),
        vec!["capture", "void", "refund", "unilateral"]
    );

    assert_eq!(
        crate::common::arkade_inputs(&output, "capture"),
        vec!["captureAmount", "merchantSig"]
    );

    // Every covenant path moves the held asset: input lookup for the hold,
    // output lookup(s) for the payout, pinned to input index 0.
    for name in ["capture", "void", "refund"] {
        let asm = crate::common::arkade_asm(&output, name);
        assert!(
            asm.contains(OP_INSPECTINASSETLOOKUP),
            "{name} must read the held asset amount: {asm}"
        );
        assert!(
            asm.contains(OP_INSPECTOUTASSETLOOKUP),
            "{name} must pin the output asset amount: {asm}"
        );
        assert!(
            asm.contains(OP_PUSHCURRENTINPUTINDEX),
            "{name} must pin the hold to input 0: {asm}"
        );
    }
}
