use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CAT, OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_CHECKSIGFROMSTACK,
    OP_CHECKSIGVERIFY, OP_DIV, OP_INSPECTINPUTVALUE, OP_INSPECTNUMINPUTS,
    OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_INSPECTOUTPUTVALUE, OP_MUL, OP_NUM2BIN, OP_SHA256,
};

use crate::common::{
    arkade_asm, arkade_inputs, group, leaf_asm, opcode_count_in_arkade, user_signatures,
    witness_names,
};

/// Oracle-settled covered call: 3-of-5 distinct-oracle attestations, median
/// settlement price, covenant-enforced payoff split.
const CODE: &str = include_str!("../../examples/options/oracle_covered_call.ark");

#[test]
fn test_oracle_covered_call_parses() {
    let result = compile(CODE);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

#[test]
fn test_oracle_covered_call_structure() {
    let output = compile(CODE).unwrap();

    assert_eq!(output.name, "OracleCoveredCall");
    let names: Vec<&str> = output.functions.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, vec!["settle", "coop", "refund", "unilateral"]);

    // Only settle carries a covenant; the other three are pure leaves.
    assert!(group(&output, "settle").arkade.is_some());
    for name in ["coop", "refund", "unilateral"] {
        assert!(
            group(&output, name).arkade.is_none(),
            "{name} must be a pure tapscript leaf"
        );
    }
}

#[test]
fn test_settle_witness_abi() {
    let output = compile(CODE).unwrap();

    // Spender-supplied covenant witness, in declared order, arrays grouped.
    assert_eq!(
        arkade_inputs(&output, "settle"),
        vec!["oracleIdx", "prices", "timestamps", "oracleSigs"]
    );
    // Settlement is a permissionless crank: no user tx-signature involved.
    assert!(user_signatures(&output, "settle").is_empty());

    // Leaf witness holds only the injected cosigners.
    assert_eq!(
        witness_names(&output, "settle", "settle"),
        vec!["serverSig", "emulatorSig"]
    );
}

#[test]
fn test_settle_covenant_verifies_three_attestations() {
    let output = compile(CODE).unwrap();

    // One signature check and one digest rebuild per attestation.
    assert_eq!(
        opcode_count_in_arkade(&output, "settle", OP_CHECKSIGFROMSTACK),
        3
    );
    assert_eq!(opcode_count_in_arkade(&output, "settle", OP_SHA256), 3);
    // Each digest concatenates tickerHash || price(8) || timestamp(8).
    assert_eq!(opcode_count_in_arkade(&output, "settle", OP_NUM2BIN), 6);
    assert_eq!(opcode_count_in_arkade(&output, "settle", OP_CAT), 6);
}

#[test]
fn test_settle_covenant_guards() {
    let output = compile(CODE).unwrap();
    let asm = arkade_asm(&output, "settle");

    // Double-satisfaction guard: exactly one vault input per settle tx.
    assert!(asm.contains(OP_INSPECTNUMINPUTS), "ASM: {asm}");
    // Surplus guard: the vault input must hold exactly the notional, so a
    // permissionless cranker cannot route excess value to themselves.
    assert!(asm.contains(OP_INSPECTINPUTVALUE), "ASM: {asm}");
    // Settlement opens at expiry (covenant reads nLockTime).
    assert!(asm.contains(OP_CHECKLOCKTIMEVERIFY), "ASM: {asm}");
    // Payoff math: PW = notional * strike / ST.
    assert!(asm.contains(OP_MUL), "ASM: {asm}");
    assert!(asm.contains(OP_DIV), "ASM: {asm}");
}

#[test]
fn test_settle_covenant_payout_branches() {
    let output = compile(CODE).unwrap();

    // Output assertions across the payoff branches: ITM split (2 outputs),
    // ITM sub-dust holder leg, ITM sub-dust writer leg, OTM (1 output).
    assert_eq!(
        opcode_count_in_arkade(&output, "settle", OP_INSPECTOUTPUTVALUE),
        5
    );
    assert_eq!(
        opcode_count_in_arkade(&output, "settle", OP_INSPECTOUTPUTSCRIPTPUBKEY),
        5
    );
}

#[test]
fn test_settle_leaf_is_cltv_server_emulator() {
    let output = compile(CODE).unwrap();
    let asm = leaf_asm(&output, "settle", "settle");

    // CLTV gate so the SDK stamps nLockTime >= expiry on the virtual tx,
    // then operator + function-tweaked emulator cosign.
    assert_eq!(
        asm,
        format!(
            "<expiry> {OP_CHECKLOCKTIMEVERIFY} OP_DROP <SERVER_KEY> {OP_CHECKSIGVERIFY} \
             <EMULATOR_KEY:settle> {OP_CHECKSIG}"
        )
    );
}

#[test]
fn test_refund_leaf_is_cltv_writer_server() {
    let output = compile(CODE).unwrap();
    let asm = leaf_asm(&output, "refund", "refund");

    assert_eq!(
        asm,
        format!(
            "<refundAt> {OP_CHECKLOCKTIMEVERIFY} OP_DROP <writerPk> {OP_CHECKSIGVERIFY} \
             <SERVER_KEY> {OP_CHECKSIG}"
        )
    );
}

#[test]
fn test_coop_and_unilateral_are_csv_leaves() {
    let output = compile(CODE).unwrap();

    let coop = leaf_asm(&output, "coop", "coop");
    assert_eq!(
        coop,
        format!(
            "<coopExit> {OP_CHECKSEQUENCEVERIFY} OP_DROP <holderPk> {OP_CHECKSIGVERIFY} \
             <writerPk> {OP_CHECKSIG}"
        )
    );

    let unilateral = leaf_asm(&output, "unilateral", "unilateral");
    assert_eq!(
        unilateral,
        format!("<exit> {OP_CHECKSEQUENCEVERIFY} OP_DROP <writerPk> {OP_CHECKSIG}")
    );
}

#[test]
fn test_oracle_array_abi_stays_grouped() {
    let output = compile(CODE).unwrap();

    let oracles = output
        .parameters
        .iter()
        .find(|p| p.name == "oracles")
        .expect("constructorInputs keeps one entry per source parameter");
    assert_eq!(oracles.param_type, "pubkey[5]");

    // The asm prologue pushes one placeholder per element; oracles[idx] is a
    // runtime bounds-checked pick, so no literal <oracles_N> reads appear
    // beyond the prologue pushes.
    let asm = arkade_asm(&output, "settle");
    for placeholder in [
        "<oracles_0>",
        "<oracles_1>",
        "<oracles_2>",
        "<oracles_3>",
        "<oracles_4>",
    ] {
        assert!(asm.contains(placeholder), "missing {placeholder}");
    }
}
