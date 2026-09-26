use arkade_compiler::compile_file;
use arkade_compiler::opcodes::{
    OP_CAT, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_CHECKTIME, OP_DIV,
    OP_DROP, OP_EQUAL, OP_INSPECTINPUTSCRIPTPUBKEY, OP_INSPECTNUMINPUTS, OP_MUL, OP_NOT,
    OP_NUM2BIN, OP_PUSHCURRENTINPUTINDEX, OP_SHA256,
};
use std::path::Path;

use crate::common::{arkade_asm_tokens, arkade_inputs, group, leaf_asm, opcode_count_in_arkade};

fn compile(path: &str) -> arkade_compiler::models::ContractJson {
    let full = Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    compile_file(&full).unwrap_or_else(|err| panic!("{path} should compile: {err}"))
}

#[test]
fn vault_settles_from_nine_oracle_signatures_and_stack_arithmetic() {
    let out = compile("examples/option/option_vault.ark");
    assert_eq!(out.name, "OptionVault");
    let names: Vec<&str> = out.functions.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, ["settle", "close", "unilateral"]);

    let inputs = arkade_inputs(&out, "settle");
    assert_eq!(
        inputs,
        [
            "price0", "time0", "who0", "sig0", "price1", "time1", "who1", "sig1", "price2",
            "time2", "who2", "sig2",
        ]
    );
    assert_eq!(
        opcode_count_in_arkade(&out, "settle", OP_CHECKSIGFROMSTACK),
        9
    );
    assert_eq!(opcode_count_in_arkade(&out, "settle", OP_SHA256), 9);
    assert_eq!(opcode_count_in_arkade(&out, "settle", OP_CAT), 18);
    assert_eq!(opcode_count_in_arkade(&out, "settle", OP_NUM2BIN), 18);
    assert_eq!(opcode_count_in_arkade(&out, "settle", OP_MUL), 5);
    assert_eq!(opcode_count_in_arkade(&out, "settle", OP_DIV), 3);

    let asm = arkade_asm_tokens(&out, "settle");
    assert!(asm.iter().any(|tok| tok == "900"), "open and mid weights");
    assert!(asm.iter().any(|tok| tok == "1860"), "twap divisor");
    assert_eq!(
        leaf_asm(&out, "settle", "settle"),
        "<SERVER_KEY> OP_CHECKSIGVERIFY <EMULATOR_KEY:settle> OP_CHECKSIG"
    );
}

#[test]
fn vault_close_needs_both_parties_and_exit_is_the_writer_csv() {
    let out = compile("examples/option/option_vault.ark");
    assert_eq!(arkade_inputs(&out, "close"), ["writerSig", "holderSig"]);
    let close = arkade_asm_tokens(&out, "close");
    let sigs = close
        .iter()
        .filter(|tok| tok.as_str() == OP_CHECKSIG || tok.as_str() == "OP_CHECKSIGVERIFY")
        .count();
    assert_eq!(sigs, 2, "{close:?}");
    assert!(close.iter().any(|tok| tok == "<writerPk>"), "{close:?}");
    assert!(close.iter().any(|tok| tok == "<holderPk>"), "{close:?}");
    let exit = leaf_asm(&out, "unilateral", "unilateral");
    assert!(exit.contains(OP_CHECKSEQUENCEVERIFY), "{exit}");
    assert!(exit.contains("<writerPk>"), "{exit}");
    assert!(group(&out, "settle").arkade.is_some());
}

#[test]
fn intent_finalize_and_cancel_are_opposite_clock_checks() {
    let out = compile("examples/option/option_intent.ark");
    assert_eq!(out.name, "OptionIntent");
    let names: Vec<&str> = out.functions.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, ["finalize", "cancel", "unilateral"]);

    let finalize = arkade_asm_tokens(&out, "finalize").join(" ");
    let cancel = arkade_asm_tokens(&out, "cancel").join(" ");
    assert!(
        finalize.contains(&format!("{OP_CHECKTIME} {OP_NOT} OP_VERIFY")),
        "{finalize}"
    );
    assert!(
        finalize.contains(&format!("{OP_PUSHCURRENTINPUTINDEX} 0 OP_EQUALVERIFY")),
        "{finalize}"
    );
    assert_eq!(
        opcode_count_in_arkade(&out, "finalize", OP_INSPECTNUMINPUTS),
        1
    );
    assert!(
        finalize.contains(&format!("{OP_INSPECTNUMINPUTS} 2 OP_EQUALVERIFY")),
        "{finalize}"
    );
    assert!(
        finalize.contains(&format!(
            "1 {OP_INSPECTINPUTSCRIPTPUBKEY} {OP_DROP} {OP_PUSHCURRENTINPUTINDEX} {OP_INSPECTINPUTSCRIPTPUBKEY} {OP_DROP} {OP_EQUAL} {OP_NOT} OP_VERIFY"
        )),
        "{finalize}"
    );
    assert!(
        cancel.contains(&format!("{OP_CHECKTIME} OP_VERIFY")),
        "{cancel}"
    );
    assert!(
        !cancel.contains(OP_NOT),
        "cancel must not negate the clock check"
    );
    assert_eq!(arkade_inputs(&out, "cancel"), Vec::<String>::new());
    let exit = leaf_asm(&out, "unilateral", "unilateral");
    assert!(exit.contains(OP_CHECKSEQUENCEVERIFY), "{exit}");
}
