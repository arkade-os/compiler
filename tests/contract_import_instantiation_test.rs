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

// ─── Value-equality covenant (both paths) ─────────────────────────────────────

#[test]
fn test_new_expression_both_paths_get_value_check() {
    // When a function uses `new ContractName(args)` the compiler automatically
    // appends `output[i].value == tx.input.current.value` to BOTH the cooperative
    // and the exit path.  No CHECKSIG is needed; the covenant is sufficient.
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

    for variant in [true, false] {
        let f = result
            .functions
            .iter()
            .find(|f| f.name == "send" && f.server_variant == variant)
            .unwrap_or_else(|| panic!("Missing send (serverVariant={})", variant));

        // Both paths must check the output scriptPubKey
        assert!(
            f.asm.iter().any(|op| op == "OP_INSPECTOUTPUTSCRIPTPUBKEY"),
            "serverVariant={}: missing OP_INSPECTOUTPUTSCRIPTPUBKEY in {:?}",
            variant, f.asm
        );
        // Both paths must have the VTXO placeholder
        assert!(
            f.asm.iter().any(|op| op.contains("VTXO:SingleSig")),
            "serverVariant={}: missing VTXO:SingleSig placeholder in {:?}",
            variant, f.asm
        );
        // Both paths must append the value-equality check
        assert!(
            f.asm.iter().any(|op| op == "OP_INSPECTOUTPUTVALUE"),
            "serverVariant={}: missing OP_INSPECTOUTPUTVALUE in {:?}",
            variant, f.asm
        );
        assert!(
            f.asm.iter().any(|op| op == "OP_INSPECTINPUTVALUE"),
            "serverVariant={}: missing OP_INSPECTINPUTVALUE in {:?}",
            variant, f.asm
        );
        assert!(
            f.asm.iter().any(|op| op == "OP_PUSHCURRENTINPUTINDEX"),
            "serverVariant={}: missing OP_PUSHCURRENTINPUTINDEX in {:?}",
            variant, f.asm
        );
    }
}

#[test]
fn test_new_expression_exit_path_has_no_checksig() {
    // The exit path for a ContractInstance function must NOT fall back to
    // N-of-N CHECKSIG; the value-equality covenant replaces it.
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

    assert!(
        !send_exit.asm.iter().any(|op| op.contains("OP_CHECKSIG")),
        "Exit path must NOT contain OP_CHECKSIG, got {:?}",
        send_exit.asm
    );
}

#[test]
fn test_cooperative_path_asm_order() {
    // Verify exact cooperative ASM:
    //   0 OP_INSPECTOUTPUTSCRIPTPUBKEY <VTXO:SingleSig(<ownerPk>)> OP_EQUAL
    //   0 OP_INSPECTOUTPUTVALUE OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTVALUE OP_EQUAL OP_VERIFY
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
        "0",
        "OP_INSPECTOUTPUTVALUE",
        "OP_PUSHCURRENTINPUTINDEX",
        "OP_INSPECTINPUTVALUE",
        "OP_EQUAL",
        "OP_VERIFY",
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
    // Verify exact exit ASM:
    //   0 OP_INSPECTOUTPUTSCRIPTPUBKEY <VTXO:SingleSig(<ownerPk>)> OP_EQUAL
    //   0 OP_INSPECTOUTPUTVALUE OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTVALUE OP_EQUAL OP_VERIFY
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
        "0",
        "OP_INSPECTOUTPUTSCRIPTPUBKEY",
        "<VTXO:SingleSig(<ownerPk>)>",
        "OP_EQUAL",
        "0",
        "OP_INSPECTOUTPUTVALUE",
        "OP_PUSHCURRENTINPUTINDEX",
        "OP_INSPECTINPUTVALUE",
        "OP_EQUAL",
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
