use arkade_compiler::compile;

// ─── Import statement parsing ──────────────────────────────────────────────────

#[test]
fn test_import_statement_is_parsed() {
    // A contract file that declares an import before the contract keyword.
    // The import path is captured in the AST (not resolved at compile time).
    let code = r#"
import "single_sig.ark";

options {
  server = operator;
  exit = 144;
}

contract BareVtxo(pubkey ownerPk) {
  function spend(signature ownerSig) {
    require(checkSig(ownerSig, ownerPk));
  }
}
"#;

    let result = compile(code);
    assert!(result.is_ok(), "Compile failed: {:?}", result.err());
}

#[test]
fn test_multiple_import_statements() {
    let code = r#"
import "single_sig.ark";
import "htlc.ark";

options {
  server = operator;
  exit = 144;
}

contract MultiImport(pubkey ownerPk) {
  function spend(signature ownerSig) {
    require(checkSig(ownerSig, ownerPk));
  }
}
"#;

    let result = compile(code);
    assert!(result.is_ok(), "Compile failed: {:?}", result.err());
}

#[test]
fn test_contract_without_imports_still_compiles() {
    // Regression: existing contracts with no import should still compile.
    let code = r#"
options {
  server = operator;
  exit = 144;
}

contract SingleSig(pubkey ownerPk) {
  function spend(signature ownerSig) {
    require(checkSig(ownerSig, ownerPk));
  }
}
"#;

    let result = compile(code);
    assert!(result.is_ok(), "Compile failed: {:?}", result.err());
    assert_eq!(result.unwrap().name, "SingleSig");
}

// ─── Contract instantiation expression ────────────────────────────────────────

#[test]
fn test_new_expression_compiles() {
    // `new SingleSig(ownerPk)` on the right of an output scriptPubKey comparison.
    // This is the canonical recursion-enforcement pattern.
    let code = r#"
import "single_sig.ark";

options {
  server = operator;
  exit = 144;
}

contract RecursiveVtxo(pubkey ownerPk) {
  function send(signature ownerSig) {
    require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk));
    require(checkSig(ownerSig, ownerPk));
  }
}
"#;

    let result = compile(code);
    assert!(result.is_ok(), "Compile failed: {:?}", result.err());
}

#[test]
fn test_new_expression_asm_output() {
    // Verify the cooperative path ASM contains:
    //   0 OP_INSPECTOUTPUTSCRIPTPUBKEY  (introspect output[0].scriptPubKey)
    //   <VTXO:SingleSig(<ownerPk>)>     (expected scriptPubKey placeholder)
    //   OP_EQUAL                        (equality check)
    let code = r#"
import "single_sig.ark";

options {
  server = operator;
  exit = 144;
}

contract RecursiveVtxo(pubkey ownerPk) {
  function send(signature ownerSig) {
    require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk));
    require(checkSig(ownerSig, ownerPk));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    let send_coop = result
        .functions
        .iter()
        .find(|f| f.name == "send" && f.server_variant)
        .expect("No cooperative send function");

    // Must contain the output introspection opcode
    assert!(
        send_coop
            .asm
            .iter()
            .any(|op| op == "OP_INSPECTOUTPUTSCRIPTPUBKEY"),
        "Missing OP_INSPECTOUTPUTSCRIPTPUBKEY in {:?}",
        send_coop.asm
    );

    // Must contain the VTXO placeholder with the correct contract name and arg
    assert!(
        send_coop
            .asm
            .iter()
            .any(|op| op.contains("VTXO:SingleSig") && op.contains("<ownerPk>")),
        "Missing VTXO:SingleSig(<ownerPk>) placeholder in {:?}",
        send_coop.asm
    );

    // The comparison operator must be present
    assert!(
        send_coop.asm.iter().any(|op| op == "OP_EQUAL"),
        "Missing OP_EQUAL in {:?}",
        send_coop.asm
    );
}

#[test]
fn test_new_expression_multi_arg() {
    // Constructor with multiple arguments: new HTLC(sender, receiver, hash, refundTime)
    let code = r#"
import "htlc.ark";

options {
  server = operator;
  exit = 144;
}

contract HtlcForwarder(pubkey sender, pubkey receiver, bytes hash, int refundTime) {
  function forward(signature senderSig) {
    require(tx.outputs[0].scriptPubKey == new HTLC(sender, receiver, hash, refundTime));
    require(checkSig(senderSig, sender));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    let forward_coop = result
        .functions
        .iter()
        .find(|f| f.name == "forward" && f.server_variant)
        .expect("No cooperative forward function");

    // The VTXO placeholder must include all four args
    let vtxo_op = forward_coop
        .asm
        .iter()
        .find(|op| op.contains("VTXO:HTLC"))
        .expect("No VTXO:HTLC placeholder in ASM");

    assert!(vtxo_op.contains("<sender>"), "Missing <sender> in {}", vtxo_op);
    assert!(vtxo_op.contains("<receiver>"), "Missing <receiver> in {}", vtxo_op);
    assert!(vtxo_op.contains("<hash>"), "Missing <hash> in {}", vtxo_op);
    assert!(vtxo_op.contains("<refundTime>"), "Missing <refundTime> in {}", vtxo_op);
}

// ─── Introspection detection / value-preservation exit path ───────────────────

#[test]
fn test_new_expression_exit_path_is_value_preservation() {
    // A function using `new ContractName(...)` triggers a value-preservation exit
    // path instead of N-of-N CHECKSIG.  The exit script enforces that the same
    // output's value is >= the current input value, requiring no witness signatures.
    let code = r#"
import "single_sig.ark";

options {
  server = operator;
  exit = 144;
}

contract RecursiveVtxo(pubkey ownerPk) {
  function send(signature ownerSig) {
    require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk));
    require(checkSig(ownerSig, ownerPk));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    let send_exit = result
        .functions
        .iter()
        .find(|f| f.name == "send" && !f.server_variant)
        .expect("No exit send function");

    // Exit path must NOT use OP_CHECKSIG (that's N-of-N fallback, not needed here)
    assert!(
        !send_exit.asm.iter().any(|op| op.contains("OP_CHECKSIG")),
        "Exit path must not contain OP_CHECKSIG, got {:?}",
        send_exit.asm
    );

    // Must NOT contain the scriptPubKey introspection opcode
    assert!(
        !send_exit
            .asm
            .iter()
            .any(|op| op == "OP_INSPECTOUTPUTSCRIPTPUBKEY"),
        "Exit path must not contain OP_INSPECTOUTPUTSCRIPTPUBKEY, got {:?}",
        send_exit.asm
    );

    // Must contain the value-preservation check opcodes
    assert!(
        send_exit
            .asm
            .iter()
            .any(|op| op == "OP_INSPECTOUTPUTVALUE"),
        "Exit path should contain OP_INSPECTOUTPUTVALUE, got {:?}",
        send_exit.asm
    );
    assert!(
        send_exit
            .asm
            .iter()
            .any(|op| op == "OP_INSPECTINPUTVALUE"),
        "Exit path should contain OP_INSPECTINPUTVALUE, got {:?}",
        send_exit.asm
    );
    assert!(
        send_exit
            .asm
            .iter()
            .any(|op| op == "OP_GREATERTHANOREQUAL64"),
        "Exit path should contain OP_GREATERTHANOREQUAL64, got {:?}",
        send_exit.asm
    );

    // No witness inputs needed for the covenant exit path
    assert!(
        send_exit.function_inputs.is_empty(),
        "Exit path function_inputs should be empty (covenant), got {:?}",
        send_exit.function_inputs
    );

    // Exit timelock must still be appended
    assert!(
        send_exit.asm.iter().any(|op| op == "OP_CHECKSEQUENCEVERIFY"),
        "Exit path must end with OP_CHECKSEQUENCEVERIFY, got {:?}",
        send_exit.asm
    );
}

#[test]
fn test_exit_path_asm_order() {
    // Verify exact ASM sequence for the exit path:
    //   <outputIdx> OP_INSPECTOUTPUTVALUE
    //   OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTVALUE
    //   OP_GREATERTHANOREQUAL64 OP_VERIFY
    //   <timelock> OP_CHECKSEQUENCEVERIFY OP_DROP
    let code = r#"
import "single_sig.ark";

options {
  server = operator;
  exit = 144;
}

contract RecursiveVtxo(pubkey ownerPk) {
  function send(signature ownerSig) {
    require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk));
    require(checkSig(ownerSig, ownerPk));
  }
}
"#;

    let result = compile(code).expect("Compile failed");
    let send_exit = result
        .functions
        .iter()
        .find(|f| f.name == "send" && !f.server_variant)
        .expect("No exit send function");

    let expected: &[&str] = &[
        "0",
        "OP_INSPECTOUTPUTVALUE",
        "OP_PUSHCURRENTINPUTINDEX",
        "OP_INSPECTINPUTVALUE",
        "OP_GREATERTHANOREQUAL64",
        "OP_VERIFY",
        "144",
        "OP_CHECKSEQUENCEVERIFY",
        "OP_DROP",
    ];

    assert_eq!(
        send_exit.asm.as_slice(),
        expected,
        "Unexpected exit ASM: {:?}",
        send_exit.asm
    );
}

// ─── Options inheritance ───────────────────────────────────────────────────────

#[test]
fn test_placeholder_format() {
    // The VTXO placeholder format is `<VTXO:ContractName(<arg1>,<arg2>)>`.
    // Verify the exact format the runtime expects.
    let code = r#"
import "single_sig.ark";

options {
  server = operator;
  exit = 144;
}

contract RecursiveVtxo(pubkey ownerPk) {
  function send(signature ownerSig) {
    require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk));
    require(checkSig(ownerSig, ownerPk));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    let send_coop = result
        .functions
        .iter()
        .find(|f| f.name == "send" && f.server_variant)
        .expect("No cooperative send function");

    let vtxo_op = send_coop
        .asm
        .iter()
        .find(|op| op.contains("VTXO:"))
        .expect("No VTXO placeholder in ASM");

    assert_eq!(
        vtxo_op, "<VTXO:SingleSig(<ownerPk>)>",
        "Unexpected placeholder format: {}",
        vtxo_op
    );
}

// ─── Input-side instantiation ──────────────────────────────────────────────────

#[test]
fn test_new_expression_on_input_scriptpubkey() {
    // `new` can also appear on the right of an input scriptPubKey comparison.
    let code = r#"
import "single_sig.ark";

options {
  server = operator;
  exit = 144;
}

contract SpendChecker(pubkey ownerPk) {
  function check(signature ownerSig) {
    require(tx.inputs[0].scriptPubKey == new SingleSig(ownerPk));
    require(checkSig(ownerSig, ownerPk));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    let check_coop = result
        .functions
        .iter()
        .find(|f| f.name == "check" && f.server_variant)
        .expect("No cooperative check function");

    assert!(
        check_coop
            .asm
            .iter()
            .any(|op| op == "OP_INSPECTINPUTSCRIPTPUBKEY"),
        "Missing OP_INSPECTINPUTSCRIPTPUBKEY in {:?}",
        check_coop.asm
    );

    assert!(
        check_coop
            .asm
            .iter()
            .any(|op| op.contains("VTXO:SingleSig")),
        "Missing VTXO:SingleSig placeholder in {:?}",
        check_coop.asm
    );
}

// ─── Current-input self-reference ────────────────────────────────────────────

#[test]
fn test_self_referential_contract() {
    // A contract that enforces its own output script matches itself (the most
    // common recursion pattern for VTXOs).
    let code = r#"
import "self.ark";

options {
  server = operator;
  exit = 144;
}

contract SelfRef(pubkey ownerPk) {
  function renew(signature ownerSig) {
    require(tx.outputs[0].scriptPubKey == new SelfRef(ownerPk));
    require(checkSig(ownerSig, ownerPk));
  }
}
"#;

    let result = compile(code).expect("Compile failed");
    let renew_coop = result
        .functions
        .iter()
        .find(|f| f.name == "renew" && f.server_variant)
        .expect("No cooperative renew function");

    assert!(
        renew_coop
            .asm
            .iter()
            .any(|op| op.contains("VTXO:SelfRef(<ownerPk>)")),
        "Missing VTXO:SelfRef(<ownerPk>) in {:?}",
        renew_coop.asm
    );
}
