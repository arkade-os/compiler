use arkade_compiler::compile;
use arkade_compiler::opcodes::{OP_ADD, OP_CAT, OP_NUM2BIN, OP_SHA256};

// `+` between bytes-like values should compile to OP_CAT, not OP_ADD.
// An int operand carries no width of its own, so the contract states one with
// num2bin; the compiler never inserts a conversion on its own.
const CONCAT_CODE: &str = r#"
contract Mix(
  pubkey  signer,
  bytes32 ticker,
  int     price,
  int     time
) {
  function check(signature sig) {
    require(checkSig(sig, signer), "bad sig");
    let msg = sha256(ticker + num2bin(price, 8) + num2bin(time, 8));
    require(checkSigFromStack(sig, signer, msg), "bad msg sig");
  }
}
"#;

#[test]
fn test_plus_on_bytes32_emits_op_cat() {
    let out = compile(CONCAT_CODE).expect("compile");
    let asm = crate::common::arkade_asm(&out, "check");

    assert!(
        asm.contains(OP_CAT),
        "Expected OP_CAT for bytes32 + int + int; asm:\n{}",
        asm
    );
    assert!(
        asm.contains(OP_SHA256),
        "Expected OP_SHA256 for sha256(...) call; asm:\n{}",
        asm
    );
    assert_eq!(
        asm.matches(OP_NUM2BIN).count(),
        2,
        "Expected exactly the two num2bin conversions the contract asks for; asm:\n{}",
        asm
    );
    assert!(
        !asm.contains(OP_ADD),
        "OP_ADD should not appear — bytes32 + int must route to OP_CAT, not arithmetic; asm:\n{}",
        asm
    );
}

#[test]
fn test_plus_on_ints_emits_op_add() {
    let code = r#"
contract IntMath(int a, int b) {
  function check() {
    int sum = a + b;
    require(sum > 0, "neg");
  }
}
"#;
    let out = compile(code).expect("compile");
    let asm = crate::common::arkade_asm(&out, "check");
    assert!(
        asm.contains(OP_ADD),
        "int + int should use OP_ADD; asm:\n{}",
        asm
    );
    assert!(
        !asm.contains(OP_CAT),
        "int + int must NOT route to OP_CAT; asm:\n{}",
        asm
    );
}

// Unrolling a loop must carry the index substitution through every operand,
// including the byte operations a hashed message is built from.
#[test]
fn test_loop_body_substitutes_index_through_byte_ops() {
    let code = r#"
contract LoopHash(bytes32 tag) {
  function check(int[] prices) {
    for (i, p) in prices {
      let m = sha256(tag + num2bin(p, 8));
      require(m == tag);
    }
  }
}
"#;
    let out = compile(code).expect("compile");
    let asm = crate::common::arkade_asm(&out, "check");
    for (k, depth) in [2, 3, 4].into_iter().enumerate() {
        assert!(
            asm.contains(&format!("OP_{depth} OP_PICK 8 OP_NUM2BIN")),
            "Expected iteration {k} to read its array element slot; asm:\n{asm}"
        );
    }
    assert!(
        !asm.contains("<p>"),
        "Loop value variable must not survive unrolling; asm:\n{asm}"
    );
}
