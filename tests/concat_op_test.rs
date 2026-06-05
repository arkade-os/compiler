use arkade_compiler::compile;
use arkade_compiler::opcodes::{OP_ADD64, OP_CAT, OP_SCRIPTNUMTOLE64, OP_SHA256};

// `+` between bytes-like values should compile to OP_CAT, not OP_ADD64.
// Ints concatenated with bytes get an OP_SCRIPTNUMTOLE64 coercion first
// so off-chain hashing can use a fixed 8-byte LE encoding.
const CONCAT_CODE: &str = r#"
options {
  server = server;
  exit = exit;
}

contract Mix(
  pubkey  signer,
  bytes32 ticker,
  int     price,
  int     time,
  int     exit
) {
  function check(signature sig) {
    require(checkSig(sig, signer), "bad sig");
    let msg = sha256(ticker + price + time);
    require(checkSigFromStack(sig, signer, msg), "bad msg sig");
  }
}
"#;

#[test]
fn test_plus_on_bytes32_emits_op_cat() {
    let out = compile(CONCAT_CODE).expect("compile");
    let f = out
        .functions
        .iter()
        .find(|f| f.name == "check" && f.server_variant)
        .unwrap();
    let asm = f.asm.join(" ");

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
    assert!(
        asm.contains(OP_SCRIPTNUMTOLE64),
        "Expected OP_SCRIPTNUMTOLE64 to coerce int sides; asm:\n{}",
        asm
    );
    assert!(
        !asm.contains(OP_ADD64),
        "OP_ADD64 should not appear — bytes32 + int must route to OP_CAT, not arithmetic; asm:\n{}",
        asm
    );
}

#[test]
fn test_plus_on_ints_still_emits_op_add64() {
    let code = r#"
options {
  server = server;
  exit = exit;
}

contract IntMath(int a, int b, int exit) {
  function check() {
    int sum = a + b;
    require(sum > 0, "neg");
  }
}
"#;
    let out = compile(code).expect("compile");
    let f = out
        .functions
        .iter()
        .find(|f| f.name == "check" && f.server_variant)
        .unwrap();
    let asm = f.asm.join(" ");
    assert!(
        asm.contains(OP_ADD64),
        "int + int should still use OP_ADD64; asm:\n{}",
        asm
    );
    assert!(
        !asm.contains(OP_CAT),
        "int + int must NOT route to OP_CAT; asm:\n{}",
        asm
    );
}
