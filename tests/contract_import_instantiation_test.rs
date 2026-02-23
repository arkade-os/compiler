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
  function send() {
    require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk));
  }
}
"#;

    let result = compile(code);
    assert!(result.is_ok(), "Compile failed: {:?}", result.err());
}

#[test]
fn test_new_expression_asm_output() {
    // Verify the cooperative path ASM contains the scriptPubKey check,
    // the VTXO placeholder, and the auto-appended value-equality check.
    let code = r#"
import "single_sig.ark";

options {
  server = operator;
  exit = 144;
}

contract RecursiveVtxo(pubkey ownerPk) {
  function send() {
    require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk));
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

// ─── Exit-path behavior for ContractInstance ──────────────────────────────────

#[test]
fn test_new_expression_exit_path_uses_nofn_checksig() {
    // ContractInstance uses non-Bitcoin-Script opcodes (OP_INSPECTOUTPUTSCRIPTPUBKEY),
    // so the exit path MUST fall back to N-of-N CHECKSIG — same rule as all
    // other introspection-using functions.  No introspection opcodes on exit.
    let code = r#"
import "single_sig.ark";

options {
  server = operator;
  exit = 144;
}

contract RecursiveVtxo(pubkey ownerPk) {
  function send() {
    require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk));
  }
}
"#;

    let result = compile(code).expect("Compile failed");
    let send_exit = result
        .functions
        .iter()
        .find(|f| f.name == "send" && !f.server_variant)
        .expect("No exit send function");

    // Must fall back to N-of-N CHECKSIG (pure Bitcoin Script)
    assert!(
        send_exit.asm.iter().any(|op| op == "OP_CHECKSIG" || op == "OP_CHECKSIGVERIFY"),
        "Exit path must use N-of-N CHECKSIG fallback, got {:?}",
        send_exit.asm
    );
    // Must NOT contain any introspection opcodes
    assert!(
        !send_exit.asm.iter().any(|op| op == "OP_INSPECTOUTPUTSCRIPTPUBKEY"),
        "Exit path must NOT contain OP_INSPECTOUTPUTSCRIPTPUBKEY, got {:?}",
        send_exit.asm
    );
    assert!(
        !send_exit.asm.iter().any(|op| op.contains("VTXO:")),
        "Exit path must NOT contain VTXO placeholder, got {:?}",
        send_exit.asm
    );
    // Exit timelock must still be appended after the CHECKSIG chain
    assert!(
        send_exit.asm.iter().any(|op| op == "OP_CHECKSEQUENCEVERIFY"),
        "Exit path missing OP_CHECKSEQUENCEVERIFY, got {:?}",
        send_exit.asm
    );
}

#[test]
fn test_cooperative_path_asm_order() {
    // Verify exact cooperative ASM (only the user's require statement + server sig):
    //   0 OP_INSPECTOUTPUTSCRIPTPUBKEY <VTXO:SingleSig(<ownerPk>)> OP_EQUAL
    //   <SERVER_KEY> <serverSig> OP_CHECKSIG
    let code = r#"
import "single_sig.ark";

options {
  server = operator;
  exit = 144;
}

contract RecursiveVtxo(pubkey ownerPk) {
  function send() {
    require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk));
  }
}
"#;

    let result = compile(code).expect("Compile failed");
    let send_coop = result
        .functions
        .iter()
        .find(|f| f.name == "send" && f.server_variant)
        .expect("No cooperative send function");

    let expected: &[&str] = &[
        "0",
        "OP_INSPECTOUTPUTSCRIPTPUBKEY",
        "<VTXO:SingleSig(<ownerPk>)>",
        "OP_EQUAL",
        "<SERVER_KEY>",
        "<serverSig>",
        "OP_CHECKSIG",
    ];

    assert_eq!(
        send_coop.asm.as_slice(),
        expected,
        "Unexpected cooperative ASM: {:?}",
        send_coop.asm
    );
}

#[test]
fn test_exit_path_asm_order() {
    // Verify exact exit ASM: N-of-N CHECKSIG chain + timelock.
    // ContractInstance uses non-Bitcoin-Script opcodes, so exit path falls
    // back to pure Bitcoin Script (no introspection opcodes allowed).
    //   <ownerPk> <ownerPkSig> OP_CHECKSIG
    //   144 OP_CHECKSEQUENCEVERIFY OP_DROP
    let code = r#"
import "single_sig.ark";

options {
  server = operator;
  exit = 144;
}

contract RecursiveVtxo(pubkey ownerPk) {
  function send() {
    require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk));
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
        "<ownerPk>",
        "<ownerPkSig>",
        "OP_CHECKSIG",
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
  function send() {
    require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk));
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
  function renew() {
    require(tx.outputs[0].scriptPubKey == new SelfRef(ownerPk));
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
