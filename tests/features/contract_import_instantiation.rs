fn compile(source: &str) -> Result<arkade_compiler::ContractJson, arkade_compiler::Error> {
    let files = [
        ("main.ark", source),
        ("single_sig.ark", "contract SingleSig(pubkey owner, int exit) { function spend() { require(tx.numOutputs == 1); } }"),
        ("htlc.ark", "contract HTLC(pubkey sender, pubkey receiver, bytes hash, int refundTime, int exit) { function spend() { require(tx.numOutputs == 1); } }"),
        ("random_num.ark", "contract RandomNum() { function spend() { require(tx.numOutputs == 1); } }"),
        ("time_locked.ark", "contract TimeLocked(pubkey owner, int exit) { function spend() { require(tx.numOutputs == 1); } }"),
        ("threshold_oracle.ark", "contract ThresholdOracle(pubkey[3] owners) { function spend() { require(tx.numOutputs == 1); } }"),
    ]
    .into_iter()
    .map(|(path, code)| (path.to_string(), code.to_string()))
    .collect();
    arkade_compiler::compile_sources_with_options("main.ark", &files, crate::common::options(false))
}

use crate::common::{arkade_asm, arkade_asm_tokens, leaf_asm, leaf_asm_tokens};

// ─── Import statement parsing ──────────────────────────────────────────────────

#[test]
fn test_import_statement_is_parsed() {
    // A contract file that declares an import before the contract keyword.
    // The imported file is loaded even when no declaration is referenced.
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
    // This is the canonical pattern for paying an output to another contract.
    let code = r#"
import "single_sig.ark";

contract RecursiveVtxo(pubkey ownerPk, int exit) {
  function send() {
    require(tx.outputs[0].script == new SingleSig(ownerPk, exit));
  }
}
"#;

    let result = compile(code);
    assert!(result.is_ok(), "Compile failed: {:?}", result.err());
}

#[test]
fn test_new_expression_asm_output() {
    // Verify the Arkade Script ASM contains the scriptPubKey check and contract placeholder.
    let code = r#"
import "single_sig.ark";

contract RecursiveVtxo(pubkey ownerPk, int exit) {
  function send() {
    require(tx.outputs[0].script == new SingleSig(ownerPk, exit));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    // Must contain the output introspection opcode (in Arkade Script asm)
    let send_asm = arkade_asm(&result, "send");
    assert!(
        send_asm.contains("OP_INSPECTOUTPUTSCRIPTPUBKEY"),
        "Missing OP_INSPECTOUTPUTSCRIPTPUBKEY in {send_asm:?}"
    );

    // Must contain the contract placeholder with the correct contract name and args
    assert!(
        send_asm.contains("CONTRACT:SingleSig") && send_asm.contains("<ownerPk>"),
        "Missing CONTRACT:SingleSig(<ownerPk>,...) placeholder in {send_asm:?}"
    );

    // The comparison operator must be present
    assert!(
        send_asm.contains("OP_EQUAL"),
        "Missing OP_EQUAL in {send_asm:?}"
    );
}

#[test]
fn test_new_expression_multi_arg() {
    // Constructor with multiple arguments: new HTLC(sender, receiver, hash, refundTime, exit).
    let code = r#"
import "htlc.ark";

contract HtlcForwarder(pubkey sender, pubkey receiver, bytes hash, int refundTime, int exit) {
  function forward(signature senderSig) {
    require(tx.outputs[0].script == new HTLC(sender, receiver, hash, refundTime, exit));
    require(checkSig(senderSig, sender));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    let forward_asm = arkade_asm(&result, "forward");
    let vtxo_op = arkade_asm_tokens(&result, "forward")
        .into_iter()
        .find(|op| op.contains("CONTRACT:HTLC"))
        .expect("No CONTRACT:HTLC placeholder in ASM");

    assert!(
        vtxo_op.contains("<sender>"),
        "Missing <sender> in {vtxo_op}"
    );
    assert!(
        vtxo_op.contains("<receiver>"),
        "Missing <receiver> in {vtxo_op}"
    );
    assert!(vtxo_op.contains("<hash>"), "Missing <hash> in {vtxo_op}");
    assert!(
        vtxo_op.contains("<refundTime>"),
        "Missing <refundTime> in {vtxo_op}"
    );
    assert!(vtxo_op.contains("<exit>"), "Missing <exit> in {vtxo_op}");
    let _ = forward_asm; // used implicitly above via arkade_asm_tokens
}

// ─── Exit-path behavior for ContractInstance ──────────────────────────────────

#[test]
fn test_new_expression_exit_path_uses_nofn_checksig() {
    // ContractInstance uses non-Bitcoin-Script opcodes (OP_INSPECTOUTPUTSCRIPTPUBKEY),
    // so the only L1 leaf is the synthesized operator cosig guard — no
    // introspection opcodes appear there.
    let code = r#"
import "single_sig.ark";

contract RecursiveVtxo(pubkey ownerPk, int exit) {
  function send() {
    require(tx.outputs[0].script == new SingleSig(ownerPk, exit));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    // The synthesized default leaf must use CHECKSIG (the operator cosig)
    let send_leaf = leaf_asm(&result, "send", "send");
    assert!(
        send_leaf.contains("OP_CHECKSIG") || send_leaf.contains("OP_CHECKSIGVERIFY"),
        "Default leaf must use CHECKSIG guard, got {send_leaf:?}"
    );
    // The leaf must NOT contain any introspection opcodes
    assert!(
        !send_leaf.contains("OP_INSPECTOUTPUTSCRIPTPUBKEY"),
        "Default leaf must NOT contain OP_INSPECTOUTPUTSCRIPTPUBKEY, got {send_leaf:?}"
    );
    assert!(
        !send_leaf.contains("CONTRACT:"),
        "Default leaf must NOT contain contract placeholder, got {send_leaf:?}"
    );
    // Explicit CSV exits require a named tapscript leaf.
}

#[test]
fn test_cooperative_path_asm_order() {
    let code = r#"
import "single_sig.ark";

contract RecursiveVtxo(pubkey ownerPk, int exit) {
  function send() {
    require(tx.outputs[0].script == new SingleSig(ownerPk, exit));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    // Parameters read only by the instantiation token need no stack slots.
    let expected_arkade: Vec<&str> = vec![
        "0",
        "OP_INSPECTOUTPUTSCRIPTPUBKEY",
        "OP_SWAP",
        "<CONTRACT:SingleSig(<ownerPk>,<exit>)>",
        "OP_1",
        "OP_SWAP",
        "OP_2",
        "OP_ROLL",
        "OP_EQUALVERIFY",
        "OP_NUMEQUALVERIFY",
        "OP_1",
    ];
    assert_eq!(
        arkade_asm_tokens(&result, "send"),
        expected_arkade,
        "Unexpected Arkade Script ASM"
    );

    // Default leaf ASM: operator cosig guard.
    let expected_leaf: Vec<&str> = vec!["<OPERATOR_KEY:send>", "OP_CHECKSIG"];
    assert_eq!(
        leaf_asm_tokens(&result, "send", "send"),
        expected_leaf,
        "Unexpected default leaf ASM"
    );
}

#[test]
fn test_exit_path_asm_order() {
    // Arkade Script functions without a tapscript get the synthesized operator cosig leaf.
    let code = r#"
import "single_sig.ark";

contract RecursiveVtxo(pubkey ownerPk, int exit) {
  function send() {
    require(tx.outputs[0].script == new SingleSig(ownerPk, exit));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    // Default leaf: operator cosig guard — no introspection, no contract placeholder, no CSV
    let expected_leaf: Vec<&str> = vec!["<OPERATOR_KEY:send>", "OP_CHECKSIG"];
    assert_eq!(
        leaf_asm_tokens(&result, "send", "send"),
        expected_leaf,
        "Unexpected default leaf ASM: {:?}",
        leaf_asm_tokens(&result, "send", "send")
    );
}

// ─── Placeholder formatting ────────────────────────────────────────────────────

#[test]
fn test_placeholder_format() {
    // The contract placeholder format is `<CONTRACT:ContractName(<arg1>,<arg2>)>`.
    // Variable args are wrapped in `<>`; literals are not.
    let code = r#"
import "single_sig.ark";

contract RecursiveVtxo(pubkey ownerPk, int exit) {
  function send() {
    require(tx.outputs[0].script == new SingleSig(ownerPk, exit));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    let vtxo_op = arkade_asm_tokens(&result, "send")
        .into_iter()
        .find(|op| op.contains("CONTRACT:"))
        .expect("No contract placeholder in arkade ASM");

    assert_eq!(
        vtxo_op, "<CONTRACT:SingleSig(<ownerPk>,<exit>)>",
        "Unexpected placeholder format: {vtxo_op}"
    );
}

// ─── Input-side instantiation ──────────────────────────────────────────────────

#[test]
fn test_new_expression_on_input_scriptpubkey() {
    // `new` can also appear on the right of an input scriptPubKey comparison.
    let code = r#"
import "single_sig.ark";

contract SpendChecker(pubkey ownerPk, int exit) {
  function check(signature ownerSig) {
    require(tx.inputs[0].script == new SingleSig(ownerPk, exit));
    require(checkSig(ownerSig, ownerPk));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    let check_asm = arkade_asm(&result, "check");
    assert!(
        check_asm.contains("OP_INSPECTINPUTSCRIPTPUBKEY"),
        "Missing OP_INSPECTINPUTSCRIPTPUBKEY in {check_asm:?}"
    );

    assert!(
        check_asm.contains("CONTRACT:SingleSig"),
        "Missing CONTRACT:SingleSig placeholder in {check_asm:?}"
    );
}

// ─── Zero-argument constructor ────────────────────────────────────────────────

#[test]
fn test_zero_arg_constructor_compiles() {
    // Grammar marks constructor_args as optional, so new ContractName() with no
    // arguments must be accepted and produce an empty-arg contract placeholder.
    let code = r#"
import "random_num.ark";

contract ZeroArgUser(pubkey ownerPk) {
  function spend() {
    require(tx.outputs[0].script == new RandomNum());
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    let spend_asm = arkade_asm(&result, "spend");
    // Zero-arg placeholder must use empty parens, not omit them.
    assert!(
        spend_asm.contains("<CONTRACT:RandomNum()>"),
        "Expected <CONTRACT:RandomNum()> placeholder in {spend_asm:?}"
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
    require(tx.outputs[0].script == new TimeLocked(ownerPk, 144));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    let vtxo_op = arkade_asm_tokens(&result, "forward")
        .into_iter()
        .find(|op| op.contains("CONTRACT:TimeLocked"))
        .expect("No CONTRACT:TimeLocked placeholder in ASM");

    // Variable arg is wrapped in angle brackets; literal is not.
    assert!(
        vtxo_op.contains("<ownerPk>"),
        "Variable arg missing angle brackets in {vtxo_op}"
    );
    assert!(
        vtxo_op.contains("144"),
        "Literal arg 144 missing from {vtxo_op}"
    );
    // Literal must not be wrapped in extra angle brackets.
    assert!(
        !vtxo_op.contains("<144>"),
        "Literal 144 must not be wrapped in angle brackets in {vtxo_op}"
    );
}

#[test]
fn test_function_input_constructor_arg_is_rejected() {
    let code = r#"
import "single_sig.ark";

contract Forwarder(int exit) {
  function forward(pubkey ownerPk) {
    require(tx.outputs[0].script == new SingleSig(ownerPk, exit));
  }
}
"#;

    let error = compile(code).expect_err("function inputs are unavailable at instantiation time");
    let error = error.to_string();
    assert!(
        error.contains("contract instance argument 'ownerPk' is a runtime value"),
        "{error}"
    );
}

#[test]
fn test_array_constructor_arg_is_flattened() {
    let code = r#"
import "threshold_oracle.ark";

contract Forwarder(pubkey[3] owners) {
  function forward() {
    require(tx.outputs[0].script == new ThresholdOracle(owners));
  }
}
"#;

    let output = compile(code).expect("array constructor argument");
    let placeholder = arkade_asm_tokens(&output, "forward")
        .into_iter()
        .find(|token| token.starts_with("<CONTRACT:"))
        .expect("contract placeholder");
    assert_eq!(
        placeholder,
        "<CONTRACT:ThresholdOracle(<owners.0>,<owners.1>,<owners.2>)>"
    );
}

// ─── Multiple ContractInstance in one function ────────────────────────────────

#[test]
fn test_multiple_contract_instances_in_one_function() {
    // A function that enforces two different outputs each matching a different
    // VTXO contract.  Both Arkade Script placeholders must appear in ASM.
    let code = r#"
import "single_sig.ark";
import "htlc.ark";

contract Splitter(pubkey alicePk, pubkey bobPk, int exit) {
  function split() {
    require(tx.outputs[0].script == new SingleSig(alicePk, exit));
    require(tx.outputs[1].script == new SingleSig(bobPk, exit));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    let split_asm = arkade_asm(&result, "split");

    // Both placeholders must appear in the Arkade Script ASM.
    assert!(
        split_asm.contains("CONTRACT:SingleSig") && split_asm.contains("<alicePk>"),
        "Missing CONTRACT:SingleSig(<alicePk>,...) in {split_asm:?}"
    );
    assert!(
        split_asm.contains("CONTRACT:SingleSig") && split_asm.contains("<bobPk>"),
        "Missing CONTRACT:SingleSig(<bobPk>,...) in {split_asm:?}"
    );

    // The synthesized default leaf has no introspection opcodes and no contract placeholders.
    let split_leaf = leaf_asm(&result, "split", "split");
    assert!(
        split_leaf.contains("OP_CHECKSIG") || split_leaf.contains("OP_CHECKSIGVERIFY"),
        "Default leaf must use CHECKSIG guard, got {split_leaf:?}"
    );
    assert!(
        !split_leaf.contains("CONTRACT:"),
        "Default leaf must not contain contract placeholders, got {split_leaf:?}"
    );
}

// ─── Mixed ContractInstance + checkSig in same function ──────────────────────

#[test]
fn test_mixed_contract_instance_and_checksig_cooperative_path() {
    // Arkade Script ASM must include BOTH the introspection check and the
    // explicit checkSig requirement when they appear in the same function.
    let code = r#"
import "single_sig.ark";

contract ForwardAndSign(pubkey ownerPk, int exit) {
  function send(signature ownerSig) {
    require(tx.outputs[0].script == new SingleSig(ownerPk, exit));
    require(checkSig(ownerSig, ownerPk));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    let send_asm = arkade_asm(&result, "send");

    // Both checks present in Arkade Script ASM.
    assert!(
        send_asm.contains("CONTRACT:SingleSig"),
        "Arkade Script ASM missing contract placeholder in {send_asm:?}"
    );
    assert!(
        send_asm.contains("OP_CHECKSIG"),
        "Arkade Script ASM missing OP_CHECKSIG in {send_asm:?}"
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
    require(tx.outputs[0].script == new SingleSig(ownerPk, exit));
    require(checkSig(ownerSig, ownerPk));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    // Default leaf: operator cosig guard — no introspection, no VTXO.
    let send_leaf = leaf_asm(&result, "send", "send");
    assert!(
        send_leaf.contains("OP_CHECKSIG") || send_leaf.contains("OP_CHECKSIGVERIFY"),
        "Default leaf must use CHECKSIG guard, got {send_leaf:?}"
    );
    assert!(
        !send_leaf.contains("OP_INSPECTOUTPUTSCRIPTPUBKEY"),
        "Default leaf must not contain OP_INSPECTOUTPUTSCRIPTPUBKEY, got {send_leaf:?}"
    );
    assert!(
        !send_leaf.contains("CONTRACT:"),
        "Default leaf must not contain contract placeholders, got {send_leaf:?}"
    );
    // Explicit CSV exits require a named tapscript leaf.
}

// ─── Per-function introspection detection ─────────────────────────────────────

#[test]
fn test_introspection_detection_is_per_function() {
    // Only the function that contains a ContractInstance gets its introspection
    // in the Arkade Script ASM; the sibling function stays a plain checkSig Arkade Script function.
    // Both get the synthesized default leaf (operator cosig guard).
    let code = r#"
import "single_sig.ark";

contract TwoFunctions(pubkey ownerPk, int exit) {
  function forward() {
    require(tx.outputs[0].script == new SingleSig(ownerPk, exit));
  }

  function spend(signature ownerSig) {
    require(checkSig(ownerSig, ownerPk));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    // forward() Arkade Script ASM has introspection; its default leaf does not
    let forward_asm = arkade_asm(&result, "forward");
    assert!(
        forward_asm.contains("OP_INSPECTOUTPUTSCRIPTPUBKEY"),
        "forward() Arkade Script must have introspection, got {forward_asm:?}"
    );

    let forward_leaf = leaf_asm(&result, "forward", "forward");
    assert!(
        forward_leaf.contains("OP_CHECKSIG") || forward_leaf.contains("OP_CHECKSIGVERIFY"),
        "forward() default leaf must use CHECKSIG guard, got {forward_leaf:?}"
    );
    assert!(
        !forward_leaf.contains("CONTRACT:"),
        "forward() default leaf must not contain contract placeholders, got {forward_leaf:?}"
    );

    // spend() Arkade Script ASM: plain checkSig, no introspection
    let spend_asm = arkade_asm(&result, "spend");
    assert!(
        spend_asm.contains("OP_CHECKSIG"),
        "spend() Arkade Script must contain OP_CHECKSIG, got {spend_asm:?}"
    );
    assert!(
        !spend_asm.contains("CONTRACT:"),
        "spend() Arkade Script must not have contract placeholders, got {spend_asm:?}"
    );

    // spend() default leaf: operator cosig guard
    let spend_leaf = leaf_asm(&result, "spend", "spend");
    assert!(
        spend_leaf.contains("OP_CHECKSIG"),
        "spend() default leaf must contain OP_CHECKSIG, got {spend_leaf:?}"
    );
    // Default leaves do not carry CSV timelocks.
}

// ─── ContractInstance on current-input scriptPubKey ───────────────────────────

#[test]
fn test_new_expression_on_current_input_scriptpubkey() {
    // new ContractName(...) can appear on the RHS of a tx.input.current.script
    // comparison (recursive covenant enforcing the current UTXO's own script).
    let code = r#"
import "single_sig.ark";

contract SelfEnforcing(pubkey ownerPk, int exit) {
  function renew() {
    require(tx.input.current.script == new SingleSig(ownerPk, exit));
  }
}
"#;

    let result = compile(code).expect("Compile failed");

    let renew_asm = arkade_asm(&result, "renew");
    assert!(
        renew_asm.contains("CONTRACT:SingleSig"),
        "Missing CONTRACT:SingleSig placeholder in {renew_asm:?}"
    );

    // Default leaf: operator cosig guard (no introspection opcodes).
    let renew_leaf = leaf_asm(&result, "renew", "renew");
    assert!(
        renew_leaf.contains("OP_CHECKSIG") || renew_leaf.contains("OP_CHECKSIGVERIFY"),
        "Default leaf must use CHECKSIG guard, got {renew_leaf:?}"
    );
    assert!(
        !renew_leaf.contains("CONTRACT:"),
        "Default leaf must not contain a contract placeholder, got {renew_leaf:?}"
    );
}

// ─── Instantiation loops ──────────────────────────────────────────────────────

#[test]
fn test_instantiation_loops_are_rejected() {
    // A contract's key would depend on its own key, so its address cannot be computed.
    let code = "contract SelfRef(pubkey ownerPk) {
  function renew() {
    require(tx.outputs[0].script == new SelfRef(ownerPk));
  }
}";
    let files = [("main.ark".to_string(), code.to_string())].into();
    let diagnostics = arkade_compiler::check("main.ark", &files);
    let [error] = &diagnostics[..] else {
        panic!("{diagnostics:?}")
    };
    let span = error.span.expect("located error");
    assert_eq!(&code[span.start..span.end], "new SelfRef(ownerPk)");
    assert!(
        error
            .message
            .contains("`tx.outputs[0].script == tx.input.current.script`"),
        "{}",
        error.message
    );

    // A -> B -> A: each file has to import the other.
    let files = [
        ("a.ark", "import \"b.ark\"; contract A(pubkey k) { function f() { require(tx.outputs[0].script == new B(k)); } }"),
        ("b.ark", "import \"a.ark\"; contract B(pubkey k) { function f() { require(tx.outputs[0].script == new A(k)); } }"),
    ]
    .map(|(path, source)| (path.to_string(), source.to_string()))
    .into();
    let error = arkade_compiler::compile_sources("a.ark", &files)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("circular import: a.ark -> b.ark -> a.ark"),
        "{error}"
    );
}

// ─── Rename-stable codeHash ───────────────────────────────────────────────────

const GRAND: &str = "contract {Grand}(pubkey {k}) {\n  function {go}(signature {s}) { require(checkSig({s}, {k})); }\n}\n";
const CHILD: &str = "import \"grand.ark\";\ncontract {Child}(pubkey {owner}) {\n  function {go}(signature {s}) {\n    require(tx.outputs[0].script == new {Grand}({owner}));\n    require(checkSig({s}, {owner}));\n  }\n}\n";
const MAIN: &str = "pragma arkade ^0.1.0;\nimport \"child.ark\";\nstruct {Policy} { int {maximum}; }\ncontract {Main}(pubkey {user}, pubkey {insurer}, {Policy} {p}, pubkey[2] {keys}) {\n  function {claim}(signature {sig}, {Policy} {q}) {\n    require(tx.input.current.value >= {p}.{maximum});\n    require(tx.input.current.value >= {q}.{maximum});\n    require(tx.outputs[0].script == new {Child}({user}));\n    require(checkSig({sig}, {keys}[1]));\n  }\n  function {late}(signature {insurerSig}) tapscript {\n    require(older(blocks(10)));\n    require(checkSig({insurerSig}, tweak({insurer}, {claim})));\n  }\n}\n";

const ORIGINAL: &[(&str, &str)] = &[
    ("Grand", "Grand"),
    ("k", "k"),
    ("go", "go"),
    ("s", "s"),
    ("Child", "Child"),
    ("owner", "owner"),
    ("Policy", "Policy"),
    ("maximum", "maximum"),
    ("Main", "Main"),
    ("user", "user"),
    ("insurer", "insurer"),
    ("p", "p"),
    ("keys", "keys"),
    ("claim", "claim"),
    ("sig", "sig"),
    ("q", "q"),
    ("late", "late"),
    ("insurerSig", "insurerSig"),
];
const RENAMED: &[(&str, &str)] = &[
    ("Grand", "Root"),
    ("k", "key"),
    ("go", "run"),
    ("s", "witnessSig"),
    ("Child", "Kid"),
    ("owner", "holder"),
    ("Policy", "Rule"),
    ("maximum", "cap"),
    ("Main", "Primary"),
    ("user", "alice"),
    ("insurer", "bob"),
    ("p", "rule"),
    ("keys", "signers"),
    ("claim", "take"),
    ("sig", "takerSig"),
    ("q", "limit"),
    ("late", "slow"),
    ("insurerSig", "bobSig"),
];

/// The fixture's `Main`, with `{name}` tokens filled from `names`.
fn chain(names: &[(&str, &str)]) -> arkade_compiler::ContractJson {
    let fill = |template: &str| {
        names.iter().fold(template.to_string(), |text, (from, to)| {
            text.replace(&format!("{{{from}}}"), to)
        })
    };
    let files = [
        ("grand.ark", GRAND),
        ("child.ark", CHILD),
        ("main.ark", MAIN),
    ]
    .map(|(path, template)| (path.to_string(), fill(template)))
    .into();
    arkade_compiler::compile_sources_with_options("main.ark", &files, crate::common::options(true))
        .unwrap()
}

#[test]
fn code_hash_survives_renames() {
    let (original, renamed) = (chain(ORIGINAL), chain(RENAMED));
    assert_eq!(original.code_hash, renamed.code_hash);
    assert_eq!(
        original.contracts.get("Child"),
        renamed.contracts.get("Kid")
    );
    assert_ne!(original.fingerprint, renamed.fingerprint);
}

#[test]
fn code_hash_follows_parameter_positions() {
    let body = "{\n  function spend(signature s, signature t) {\n    require(checkSig(s, a));\n    require(checkSig(t, b));\n  }\n}\n";
    let first =
        arkade_compiler::compile(&format!("contract C(pubkey a, pubkey b) {body}")).unwrap();
    let swapped =
        arkade_compiler::compile(&format!("contract C(pubkey b, pubkey a) {body}")).unwrap();
    assert_ne!(first.code_hash, swapped.code_hash);
}

#[test]
fn code_hash_tells_a_parameter_from_a_literal() {
    let contract = |value: &str, outputs: &str| {
        format!("contract C(pubkey k, int min) {{\n  function spend(signature s) {{\n    require(tx.input.current.value >= {value});\n    require(tx.numOutputs >= {outputs});\n    require(checkSig(s, k));\n  }}\n}}\n")
    };
    let read_first = arkade_compiler::compile(&contract("min", "0")).unwrap();
    let read_second = arkade_compiler::compile(&contract("0", "min")).unwrap();
    assert_ne!(read_first.code_hash, read_second.code_hash);
}
