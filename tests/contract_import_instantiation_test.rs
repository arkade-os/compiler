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
    // Verify the cooperative path ASM contains the scriptPubKey check
    // and the VTXO placeholder.
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

    assert!(
        vtxo_op.contains("<sender>"),
        "Missing <sender> in {}",
        vtxo_op
    );
    assert!(
        vtxo_op.contains("<receiver>"),
        "Missing <receiver> in {}",
        vtxo_op
    );
    assert!(vtxo_op.contains("<hash>"), "Missing <hash> in {}", vtxo_op);
    assert!(
        vtxo_op.contains("<refundTime>"),
        "Missing <refundTime> in {}",
        vtxo_op
    );
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
        send_exit
            .asm
            .iter()
            .any(|op| op == "OP_CHECKSIG" || op == "OP_CHECKSIGVERIFY"),
        "Exit path must use N-of-N CHECKSIG fallback, got {:?}",
        send_exit.asm
    );
    // Must NOT contain any introspection opcodes
    assert!(
        !send_exit
            .asm
            .iter()
            .any(|op| op == "OP_INSPECTOUTPUTSCRIPTPUBKEY"),
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
        send_exit
            .asm
            .iter()
            .any(|op| op == "OP_CHECKSEQUENCEVERIFY"),
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

// ─── Zero-argument constructor ────────────────────────────────────────────────

#[test]
fn test_zero_arg_constructor_compiles() {
    // Grammar marks constructor_args as optional, so new ContractName() with no
    // arguments must be accepted and produce an empty-arg VTXO placeholder.
    let code = r#"
import "random_num.ark";

options {
  server = operator;
  exit = 144;
}

contract ZeroArgUser(pubkey ownerPk) {
  function spend() {
    require(tx.outputs[0].scriptPubKey == new RandomNum());
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    let spend_coop = result
        .functions
        .iter()
        .find(|f| f.name == "spend" && f.server_variant)
        .expect("No cooperative spend function");

    // Zero-arg placeholder must use empty parens, not omit them.
    assert!(
        spend_coop.asm.iter().any(|op| op == "<VTXO:RandomNum()>"),
        "Expected <VTXO:RandomNum()> placeholder in {:?}",
        spend_coop.asm
    );
}

// ─── Literal argument in constructor ─────────────────────────────────────────

#[test]
fn test_literal_arg_constructor() {
    // Integer literals as constructor args should appear unquoted in the
    // placeholder (no angle brackets, just the raw value).
    let code = r#"
import "time_locked.ark";

options {
  server = operator;
  exit = 144;
}

contract TimedForwarder(pubkey ownerPk) {
  function forward() {
    require(tx.outputs[0].scriptPubKey == new TimeLocked(ownerPk, 144));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    let fwd_coop = result
        .functions
        .iter()
        .find(|f| f.name == "forward" && f.server_variant)
        .expect("No cooperative forward function");

    let vtxo_op = fwd_coop
        .asm
        .iter()
        .find(|op| op.contains("VTXO:TimeLocked"))
        .expect("No VTXO:TimeLocked placeholder in ASM");

    // Variable arg is wrapped in angle brackets; literal is not.
    assert!(
        vtxo_op.contains("<ownerPk>"),
        "Variable arg missing angle brackets in {}",
        vtxo_op
    );
    assert!(
        vtxo_op.contains("144"),
        "Literal arg 144 missing from {}",
        vtxo_op
    );
    // Literal must not be wrapped in extra angle brackets.
    assert!(
        !vtxo_op.contains("<144>"),
        "Literal 144 must not be wrapped in angle brackets in {}",
        vtxo_op
    );
}

// ─── Multiple ContractInstance in one function ────────────────────────────────

#[test]
fn test_multiple_contract_instances_in_one_function() {
    // A function that enforces two different outputs each matching a different
    // VTXO contract.  Both cooperative-path placeholders must appear in ASM.
    let code = r#"
import "single_sig.ark";
import "htlc.ark";

options {
  server = operator;
  exit = 144;
}

contract Splitter(pubkey alicePk, pubkey bobPk) {
  function split() {
    require(tx.outputs[0].scriptPubKey == new SingleSig(alicePk));
    require(tx.outputs[1].scriptPubKey == new SingleSig(bobPk));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    let split_coop = result
        .functions
        .iter()
        .find(|f| f.name == "split" && f.server_variant)
        .expect("No cooperative split function");

    // Both placeholders must appear.
    assert!(
        split_coop
            .asm
            .iter()
            .any(|op| op.contains("VTXO:SingleSig") && op.contains("<alicePk>")),
        "Missing VTXO:SingleSig(<alicePk>) in {:?}",
        split_coop.asm
    );
    assert!(
        split_coop
            .asm
            .iter()
            .any(|op| op.contains("VTXO:SingleSig") && op.contains("<bobPk>")),
        "Missing VTXO:SingleSig(<bobPk>) in {:?}",
        split_coop.asm
    );

    // Exit path must fall back to N-of-N CHECKSIG (no introspection).
    let split_exit = result
        .functions
        .iter()
        .find(|f| f.name == "split" && !f.server_variant)
        .expect("No exit split function");

    assert!(
        split_exit
            .asm
            .iter()
            .any(|op| op == "OP_CHECKSIG" || op == "OP_CHECKSIGVERIFY"),
        "Exit path must use N-of-N CHECKSIG, got {:?}",
        split_exit.asm
    );
    assert!(
        !split_exit.asm.iter().any(|op| op.contains("VTXO:")),
        "Exit path must not contain VTXO placeholders, got {:?}",
        split_exit.asm
    );
}

// ─── Mixed ContractInstance + checkSig in same function ──────────────────────

#[test]
fn test_mixed_contract_instance_and_checksig_cooperative_path() {
    // Cooperative path must include BOTH the introspection check and the
    // explicit checkSig requirement when they appear in the same function.
    let code = r#"
import "single_sig.ark";

options {
  server = operator;
  exit = 144;
}

contract ForwardAndSign(pubkey ownerPk) {
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

    // Both checks present on cooperative path.
    assert!(
        send_coop.asm.iter().any(|op| op.contains("VTXO:SingleSig")),
        "Cooperative path missing VTXO placeholder in {:?}",
        send_coop.asm
    );
    assert!(
        send_coop.asm.iter().any(|op| op == "OP_CHECKSIG"),
        "Cooperative path missing OP_CHECKSIG in {:?}",
        send_coop.asm
    );
}

#[test]
fn test_mixed_contract_instance_and_checksig_exit_path() {
    // When a function uses ContractInstance the exit path falls back to the
    // N-of-N CHECKSIG chain and does NOT include the introspection check —
    // the exit path is pure Bitcoin Script only.
    let code = r#"
import "single_sig.ark";

options {
  server = operator;
  exit = 144;
}

contract ForwardAndSign(pubkey ownerPk) {
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

    // Exit path: N-of-N CHECKSIG present, no introspection opcodes, no VTXO placeholders.
    assert!(
        send_exit
            .asm
            .iter()
            .any(|op| op == "OP_CHECKSIG" || op == "OP_CHECKSIGVERIFY"),
        "Exit path must use N-of-N CHECKSIG, got {:?}",
        send_exit.asm
    );
    assert!(
        !send_exit
            .asm
            .iter()
            .any(|op| op == "OP_INSPECTOUTPUTSCRIPTPUBKEY"),
        "Exit path must not contain OP_INSPECTOUTPUTSCRIPTPUBKEY, got {:?}",
        send_exit.asm
    );
    assert!(
        !send_exit.asm.iter().any(|op| op.contains("VTXO:")),
        "Exit path must not contain VTXO placeholders, got {:?}",
        send_exit.asm
    );
    assert!(
        send_exit
            .asm
            .iter()
            .any(|op| op == "OP_CHECKSEQUENCEVERIFY"),
        "Exit path missing OP_CHECKSEQUENCEVERIFY, got {:?}",
        send_exit.asm
    );
}

// ─── Per-function introspection detection ─────────────────────────────────────

#[test]
fn test_introspection_detection_is_per_function() {
    // Only the function that contains a ContractInstance should use the N-of-N
    // CHECKSIG exit fallback.  A sibling function with plain checkSig must keep
    // its normal exit path (checkSig + timelock).
    let code = r#"
import "single_sig.ark";

options {
  server = operator;
  exit = 144;
}

contract TwoFunctions(pubkey ownerPk) {
  function forward() {
    require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk));
  }

  function spend(signature ownerSig) {
    require(checkSig(ownerSig, ownerPk));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    // forward() exit path → N-of-N CHECKSIG (has ContractInstance)
    let forward_exit = result
        .functions
        .iter()
        .find(|f| f.name == "forward" && !f.server_variant)
        .expect("No exit forward function");

    assert!(
        forward_exit
            .asm
            .iter()
            .any(|op| op == "OP_CHECKSIG" || op == "OP_CHECKSIGVERIFY"),
        "forward() exit must use N-of-N CHECKSIG, got {:?}",
        forward_exit.asm
    );
    assert!(
        !forward_exit.asm.iter().any(|op| op.contains("VTXO:")),
        "forward() exit must not contain VTXO placeholders, got {:?}",
        forward_exit.asm
    );

    // spend() exit path → normal (checkSig + timelock), no N-of-N fallback
    let spend_exit = result
        .functions
        .iter()
        .find(|f| f.name == "spend" && !f.server_variant)
        .expect("No exit spend function");

    assert!(
        spend_exit.asm.iter().any(|op| op == "OP_CHECKSIG"),
        "spend() exit must contain OP_CHECKSIG, got {:?}",
        spend_exit.asm
    );
    assert!(
        spend_exit
            .asm
            .iter()
            .any(|op| op == "OP_CHECKSEQUENCEVERIFY"),
        "spend() exit must contain OP_CHECKSEQUENCEVERIFY, got {:?}",
        spend_exit.asm
    );
}

// ─── ContractInstance on current-input scriptPubKey ───────────────────────────

#[test]
fn test_new_expression_on_current_input_scriptpubkey() {
    // new ContractName(...) can appear on the RHS of a tx.input.current.scriptPubKey
    // comparison (recursive covenant enforcing the current UTXO's own script).
    let code = r#"
import "single_sig.ark";

options {
  server = operator;
  exit = 144;
}

contract SelfEnforcing(pubkey ownerPk) {
  function renew() {
    require(tx.input.current.scriptPubKey == new SingleSig(ownerPk));
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
            .any(|op| op.contains("VTXO:SingleSig")),
        "Missing VTXO:SingleSig placeholder in {:?}",
        renew_coop.asm
    );

    // Exit path must still fall back to N-of-N CHECKSIG (ContractInstance present).
    let renew_exit = result
        .functions
        .iter()
        .find(|f| f.name == "renew" && !f.server_variant)
        .expect("No exit renew function");

    assert!(
        renew_exit
            .asm
            .iter()
            .any(|op| op == "OP_CHECKSIG" || op == "OP_CHECKSIGVERIFY"),
        "Exit path must use N-of-N CHECKSIG, got {:?}",
        renew_exit.asm
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
