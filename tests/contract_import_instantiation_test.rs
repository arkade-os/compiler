use arkade_compiler::compile;

mod common;
use common::{arkade_asm, arkade_asm_tokens, leaf_asm, leaf_asm_tokens};

// ─── Import statement parsing ──────────────────────────────────────────────────

#[test]
fn test_import_statement_is_parsed() {
    // A contract file that declares an import before the contract keyword.
    // The import path is captured in the AST (not resolved at compile time).
    let code = r#"
import "single_sig.ark";

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
    // `new SingleSig(ownerPk, exit)` on the right of an output scriptPubKey comparison.
    // This is the canonical recursion-enforcement pattern.
    // SingleSig is now 2-param (pubkey user, int exit).
    let code = r#"
import "single_sig.ark";

contract RecursiveVtxo(pubkey ownerPk, int exit) {
  function send() {
    require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk, exit));
  }
}
"#;

    let result = compile(code);
    assert!(result.is_ok(), "Compile failed: {:?}", result.err());
}

#[test]
fn test_new_expression_asm_output() {
    // Verify the covenant ASM contains the scriptPubKey check
    // and the VTXO placeholder (now in arkade_asm, not a server-variant flat asm).
    let code = r#"
import "single_sig.ark";

contract RecursiveVtxo(pubkey ownerPk, int exit) {
  function send() {
    require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk, exit));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    // Must contain the output introspection opcode (in covenant/arkade asm)
    let send_asm = arkade_asm(&result, "send");
    assert!(
        send_asm.contains("OP_INSPECTOUTPUTSCRIPTPUBKEY"),
        "Missing OP_INSPECTOUTPUTSCRIPTPUBKEY in {:?}",
        send_asm
    );

    // Must contain the VTXO placeholder with the correct contract name and args
    assert!(
        send_asm.contains("VTXO:SingleSig") && send_asm.contains("<ownerPk>"),
        "Missing VTXO:SingleSig(<ownerPk>,...) placeholder in {:?}",
        send_asm
    );

    // The comparison operator must be present
    assert!(
        send_asm.contains("OP_EQUAL"),
        "Missing OP_EQUAL in {:?}",
        send_asm
    );
}

#[test]
fn test_new_expression_multi_arg() {
    // Constructor with multiple arguments: new HTLC(sender, receiver, hash, refundTime, exit)
    // HTLC is now 5-param (sender, receiver, preimageHash, refundTime, exit).
    let code = r#"
import "htlc.ark";

contract HtlcForwarder(pubkey sender, pubkey receiver, bytes hash, int refundTime, int exit) {
  function forward(signature senderSig) {
    require(tx.outputs[0].scriptPubKey == new HTLC(sender, receiver, hash, refundTime, exit));
    require(checkSig(senderSig, sender));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    let forward_asm = arkade_asm(&result, "forward");
    let vtxo_op = arkade_asm_tokens(&result, "forward")
        .into_iter()
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
    assert!(vtxo_op.contains("<exit>"), "Missing <exit> in {}", vtxo_op);
    let _ = forward_asm; // used implicitly above via arkade_asm_tokens
}

// ─── Exit-path behavior for ContractInstance ──────────────────────────────────

#[test]
fn test_new_expression_exit_path_uses_nofn_checksig() {
    // ContractInstance uses non-Bitcoin-Script opcodes (OP_INSPECTOUTPUTSCRIPTPUBKEY),
    // so the only L1 leaf is the synthesized server+emulator cosig guard — no
    // introspection opcodes appear there.
    let code = r#"
import "single_sig.ark";

contract RecursiveVtxo(pubkey ownerPk, int exit) {
  function send() {
    require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk, exit));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    // The synthesized default leaf must use CHECKSIG (server+emulator N-of-N cosig)
    let send_leaf = leaf_asm(&result, "send", "send");
    assert!(
        send_leaf.contains("OP_CHECKSIG") || send_leaf.contains("OP_CHECKSIGVERIFY"),
        "Default leaf must use CHECKSIG guard, got {:?}",
        send_leaf
    );
    // The leaf must NOT contain any introspection opcodes
    assert!(
        !send_leaf.contains("OP_INSPECTOUTPUTSCRIPTPUBKEY"),
        "Default leaf must NOT contain OP_INSPECTOUTPUTSCRIPTPUBKEY, got {:?}",
        send_leaf
    );
    assert!(
        !send_leaf.contains("VTXO:"),
        "Default leaf must NOT contain VTXO placeholder, got {:?}",
        send_leaf
    );
    // Explicit CSV exits require a named tapscript leaf.
}

#[test]
fn test_cooperative_path_asm_order() {
    // Verify exact covenant ASM (arkade) for 'send':
    //   0 OP_INSPECTOUTPUTSCRIPTPUBKEY <VTXO:SingleSig(<ownerPk>,<exit>)> OP_EQUAL
    // And verify exact default-leaf ASM:
    //   <SERVER_KEY> OP_CHECKSIGVERIFY <EMULATOR_KEY:send> OP_CHECKSIG
    let code = r#"
import "single_sig.ark";

contract RecursiveVtxo(pubkey ownerPk, int exit) {
  function send() {
    require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk, exit));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    // Covenant (arkade) ASM: introspection check + VTXO placeholder + comparison
    let expected_arkade: Vec<&str> = vec![
        "0",
        "OP_INSPECTOUTPUTSCRIPTPUBKEY",
        "<VTXO:SingleSig(<ownerPk>,<exit>)>",
        "OP_EQUAL",
    ];
    assert_eq!(
        arkade_asm_tokens(&result, "send"),
        expected_arkade,
        "Unexpected covenant ASM"
    );

    // Default leaf ASM: server+emulator cosig guard.
    let expected_leaf: Vec<&str> = vec![
        "<SERVER_KEY>",
        "OP_CHECKSIGVERIFY",
        "<EMULATOR_KEY:send>",
        "OP_CHECKSIG",
    ];
    assert_eq!(
        leaf_asm_tokens(&result, "send", "send"),
        expected_leaf,
        "Unexpected default leaf ASM"
    );
}

#[test]
fn test_exit_path_asm_order() {
    // Covenant-only functions get the synthesized server+emulator cosig leaf.
    let code = r#"
import "single_sig.ark";

contract RecursiveVtxo(pubkey ownerPk, int exit) {
  function send() {
    require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk, exit));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    // Default leaf: server+emulator cosig guard — no introspection, no VTXO, no CSV
    let expected_leaf: Vec<&str> = vec![
        "<SERVER_KEY>",
        "OP_CHECKSIGVERIFY",
        "<EMULATOR_KEY:send>",
        "OP_CHECKSIG",
    ];
    assert_eq!(
        leaf_asm_tokens(&result, "send", "send"),
        expected_leaf,
        "Unexpected default leaf ASM: {:?}",
        leaf_asm_tokens(&result, "send", "send")
    );
}

// ─── Options inheritance ───────────────────────────────────────────────────────

#[test]
fn test_placeholder_format() {
    // The VTXO placeholder format is `<VTXO:ContractName(<arg1>,<arg2>)>`.
    // Variable args are wrapped in `<>`; literals are not.
    // SingleSig is now 2-param, so the placeholder includes <exit>.
    let code = r#"
import "single_sig.ark";

contract RecursiveVtxo(pubkey ownerPk, int exit) {
  function send() {
    require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk, exit));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    let vtxo_op = arkade_asm_tokens(&result, "send")
        .into_iter()
        .find(|op| op.contains("VTXO:"))
        .expect("No VTXO placeholder in arkade ASM");

    assert_eq!(
        vtxo_op, "<VTXO:SingleSig(<ownerPk>,<exit>)>",
        "Unexpected placeholder format: {}",
        vtxo_op
    );
}

// ─── Input-side instantiation ──────────────────────────────────────────────────

#[test]
fn test_new_expression_on_input_scriptpubkey() {
    // `new` can also appear on the right of an input scriptPubKey comparison.
    // SingleSig is now 2-param, so we pass exit.
    let code = r#"
import "single_sig.ark";

contract SpendChecker(pubkey ownerPk, int exit) {
  function check(signature ownerSig) {
    require(tx.inputs[0].scriptPubKey == new SingleSig(ownerPk, exit));
    require(checkSig(ownerSig, ownerPk));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    let check_asm = arkade_asm(&result, "check");
    assert!(
        check_asm.contains("OP_INSPECTINPUTSCRIPTPUBKEY"),
        "Missing OP_INSPECTINPUTSCRIPTPUBKEY in {:?}",
        check_asm
    );

    assert!(
        check_asm.contains("VTXO:SingleSig"),
        "Missing VTXO:SingleSig placeholder in {:?}",
        check_asm
    );
}

// ─── Zero-argument constructor ────────────────────────────────────────────────

#[test]
fn test_zero_arg_constructor_compiles() {
    // Grammar marks constructor_args as optional, so new ContractName() with no
    // arguments must be accepted and produce an empty-arg VTXO placeholder.
    let code = r#"
import "random_num.ark";

contract ZeroArgUser(pubkey ownerPk) {
  function spend() {
    require(tx.outputs[0].scriptPubKey == new RandomNum());
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    let spend_asm = arkade_asm(&result, "spend");
    // Zero-arg placeholder must use empty parens, not omit them.
    assert!(
        spend_asm.contains("<VTXO:RandomNum()>"),
        "Expected <VTXO:RandomNum()> placeholder in {:?}",
        spend_asm
    );
}

// ─── Literal argument in constructor ─────────────────────────────────────────

#[test]
fn test_literal_arg_constructor() {
    // Integer literals as constructor args should appear unquoted in the
    // placeholder (no angle brackets, just the raw value).
    let code = r#"
import "time_locked.ark";

contract TimedForwarder(pubkey ownerPk) {
  function forward() {
    require(tx.outputs[0].scriptPubKey == new TimeLocked(ownerPk, 144));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    let vtxo_op = arkade_asm_tokens(&result, "forward")
        .into_iter()
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
    // VTXO contract.  Both covenant-path placeholders must appear in ASM.
    // SingleSig is now 2-param; Splitter passes its own exit to both instances.
    let code = r#"
import "single_sig.ark";
import "htlc.ark";

contract Splitter(pubkey alicePk, pubkey bobPk, int exit) {
  function split() {
    require(tx.outputs[0].scriptPubKey == new SingleSig(alicePk, exit));
    require(tx.outputs[1].scriptPubKey == new SingleSig(bobPk, exit));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    let split_asm = arkade_asm(&result, "split");

    // Both placeholders must appear in the covenant ASM.
    assert!(
        split_asm.contains("VTXO:SingleSig") && split_asm.contains("<alicePk>"),
        "Missing VTXO:SingleSig(<alicePk>,...) in {:?}",
        split_asm
    );
    assert!(
        split_asm.contains("VTXO:SingleSig") && split_asm.contains("<bobPk>"),
        "Missing VTXO:SingleSig(<bobPk>,...) in {:?}",
        split_asm
    );

    // The synthesized default leaf has no introspection opcodes and no VTXO placeholders.
    let split_leaf = leaf_asm(&result, "split", "split");
    assert!(
        split_leaf.contains("OP_CHECKSIG") || split_leaf.contains("OP_CHECKSIGVERIFY"),
        "Default leaf must use CHECKSIG guard, got {:?}",
        split_leaf
    );
    assert!(
        !split_leaf.contains("VTXO:"),
        "Default leaf must not contain VTXO placeholders, got {:?}",
        split_leaf
    );
}

// ─── Mixed ContractInstance + checkSig in same function ──────────────────────

#[test]
fn test_mixed_contract_instance_and_checksig_cooperative_path() {
    // Covenant ASM must include BOTH the introspection check and the
    // explicit checkSig requirement when they appear in the same function.
    let code = r#"
import "single_sig.ark";

contract ForwardAndSign(pubkey ownerPk, int exit) {
  function send(signature ownerSig) {
    require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk, exit));
    require(checkSig(ownerSig, ownerPk));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    let send_asm = arkade_asm(&result, "send");

    // Both checks present in covenant ASM.
    assert!(
        send_asm.contains("VTXO:SingleSig"),
        "Covenant ASM missing VTXO placeholder in {:?}",
        send_asm
    );
    assert!(
        send_asm.contains("OP_CHECKSIG"),
        "Covenant ASM missing OP_CHECKSIG in {:?}",
        send_asm
    );
}

#[test]
fn test_mixed_contract_instance_and_checksig_exit_path() {
    // The synthesized default leaf has no introspection opcodes and no VTXO
    // placeholders. Explicit exits require a named tapscript leaf.
    let code = r#"
import "single_sig.ark";

contract ForwardAndSign(pubkey ownerPk, int exit) {
  function send(signature ownerSig) {
    require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk, exit));
    require(checkSig(ownerSig, ownerPk));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    // Default leaf: server+emulator cosig guard — no introspection, no VTXO.
    let send_leaf = leaf_asm(&result, "send", "send");
    assert!(
        send_leaf.contains("OP_CHECKSIG") || send_leaf.contains("OP_CHECKSIGVERIFY"),
        "Default leaf must use CHECKSIG guard, got {:?}",
        send_leaf
    );
    assert!(
        !send_leaf.contains("OP_INSPECTOUTPUTSCRIPTPUBKEY"),
        "Default leaf must not contain OP_INSPECTOUTPUTSCRIPTPUBKEY, got {:?}",
        send_leaf
    );
    assert!(
        !send_leaf.contains("VTXO:"),
        "Default leaf must not contain VTXO placeholders, got {:?}",
        send_leaf
    );
    // Explicit CSV exits require a named tapscript leaf.
}

// ─── Per-function introspection detection ─────────────────────────────────────

#[test]
fn test_introspection_detection_is_per_function() {
    // Only the function that contains a ContractInstance gets its introspection
    // in the covenant ASM; the sibling function stays as a plain checkSig covenant.
    // Both get the synthesized default leaf (server+emulator cosig guard).
    let code = r#"
import "single_sig.ark";

contract TwoFunctions(pubkey ownerPk, int exit) {
  function forward() {
    require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk, exit));
  }

  function spend(signature ownerSig) {
    require(checkSig(ownerSig, ownerPk));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    // forward() covenant ASM has introspection; its default leaf does not
    let forward_asm = arkade_asm(&result, "forward");
    assert!(
        forward_asm.contains("OP_INSPECTOUTPUTSCRIPTPUBKEY"),
        "forward() covenant must have introspection, got {:?}",
        forward_asm
    );

    let forward_leaf = leaf_asm(&result, "forward", "forward");
    assert!(
        forward_leaf.contains("OP_CHECKSIG") || forward_leaf.contains("OP_CHECKSIGVERIFY"),
        "forward() default leaf must use CHECKSIG guard, got {:?}",
        forward_leaf
    );
    assert!(
        !forward_leaf.contains("VTXO:"),
        "forward() default leaf must not contain VTXO placeholders, got {:?}",
        forward_leaf
    );

    // spend() covenant ASM: plain checkSig, no introspection
    let spend_asm = arkade_asm(&result, "spend");
    assert!(
        spend_asm.contains("OP_CHECKSIG"),
        "spend() covenant must contain OP_CHECKSIG, got {:?}",
        spend_asm
    );
    assert!(
        !spend_asm.contains("VTXO:"),
        "spend() covenant must not have VTXO placeholders, got {:?}",
        spend_asm
    );

    // spend() default leaf: server+emulator cosig guard
    let spend_leaf = leaf_asm(&result, "spend", "spend");
    assert!(
        spend_leaf.contains("OP_CHECKSIG"),
        "spend() default leaf must contain OP_CHECKSIG, got {:?}",
        spend_leaf
    );
    // Default leaves do not carry CSV timelocks.
}

// ─── ContractInstance on current-input scriptPubKey ───────────────────────────

#[test]
fn test_new_expression_on_current_input_scriptpubkey() {
    // new ContractName(...) can appear on the RHS of a tx.input.current.scriptPubKey
    // comparison (recursive covenant enforcing the current UTXO's own script).
    let code = r#"
import "single_sig.ark";

contract SelfEnforcing(pubkey ownerPk, int exit) {
  function renew() {
    require(tx.input.current.scriptPubKey == new SingleSig(ownerPk, exit));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    let renew_asm = arkade_asm(&result, "renew");
    assert!(
        renew_asm.contains("VTXO:SingleSig"),
        "Missing VTXO:SingleSig placeholder in {:?}",
        renew_asm
    );

    // Default leaf: server+emulator cosig guard (no introspection opcodes).
    let renew_leaf = leaf_asm(&result, "renew", "renew");
    assert!(
        renew_leaf.contains("OP_CHECKSIG") || renew_leaf.contains("OP_CHECKSIGVERIFY"),
        "Default leaf must use CHECKSIG guard, got {:?}",
        renew_leaf
    );
    assert!(
        !renew_leaf.contains("VTXO:"),
        "Default leaf must not contain VTXO, got {:?}",
        renew_leaf
    );
}

// ─── Current-input self-reference ────────────────────────────────────────────

#[test]
fn test_self_referential_contract() {
    // A contract that enforces its own output script matches itself (the most
    // common recursion pattern for VTXOs). SelfRef has 1 param (ownerPk only)
    // as the inline contract defines it; renew passes ownerPk back to itself.
    let code = r#"
import "self.ark";

contract SelfRef(pubkey ownerPk) {
  function renew() {
    require(tx.outputs[0].scriptPubKey == new SelfRef(ownerPk));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    let renew_asm = arkade_asm(&result, "renew");
    assert!(
        renew_asm.contains("VTXO:SelfRef(<ownerPk>)"),
        "Missing VTXO:SelfRef(<ownerPk>) in {:?}",
        renew_asm
    );
}
