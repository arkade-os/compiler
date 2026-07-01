use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_2, OP_CHECKLOCKTIMEVERIFY, OP_CHECKSIG, OP_CHECKSIGADD, OP_CHECKSIGVERIFY, OP_DROP,
    OP_NUMEQUAL,
};

mod common;
use common::{arkade_asm, arkade_asm_tokens, arkade_inputs, leaf_asm};

#[test]
fn test_bare_vtxo_contract() {
    // `server` is a constructor pubkey used in the multisig check.
    let vtxo_code = r#"
contract SingleSig(
  pubkey user,
  pubkey server,
  int timelock
) {
  // Cooperative spend path (user + server)
  function cooperative(signature userSig) {
    require(checkMultisig([user, server]));
  }

  // Timeout path (user after timelock)
  function timeout(signature userSig) {
    require(checkSig(userSig, user));
    require(tx.time >= timelock);
  }
}"#;

    // Compile the contract
    let result = compile(vtxo_code);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();

    // Verify contract name
    assert_eq!(output.name, "SingleSig");

    // Verify parameters
    assert_eq!(output.parameters.len(), 3);
    assert_eq!(output.parameters[0].name, "user");
    assert_eq!(output.parameters[0].param_type, "pubkey");
    assert_eq!(output.parameters[1].name, "server");
    assert_eq!(output.parameters[1].param_type, "pubkey");
    assert_eq!(output.parameters[2].name, "timelock");
    assert_eq!(output.parameters[2].param_type, "int");

    assert_eq!(output.functions.len(), 2);

    // ── cooperative group ─────────────────────────────────────────────────────
    // Covenant inputs: only userSig is declared (server cosig is in the leaf)
    let coop_inputs = arkade_inputs(&output, "cooperative");
    assert_eq!(coop_inputs.len(), 1);
    assert_eq!(coop_inputs[0], "userSig");

    // Covenant ASM: multisig pubkey check (no server append here)
    let coop_asm = arkade_asm(&output, "cooperative");
    assert!(
        coop_asm.contains(OP_CHECKSIG),
        "cooperative: missing OP_CHECKSIG"
    );
    assert!(
        coop_asm.contains(OP_CHECKSIGADD),
        "cooperative: missing OP_CHECKSIGADD"
    );
    assert!(coop_asm.contains(OP_2), "cooperative: missing OP_2");
    assert!(
        coop_asm.contains(OP_NUMEQUAL),
        "cooperative: missing OP_NUMEQUAL"
    );
    assert!(
        coop_asm.contains("<user>"),
        "cooperative: missing <user> pubkey"
    );
    assert!(
        coop_asm.contains("<server>"),
        "cooperative: missing <server> pubkey"
    );

    // Default leaf: synthesized SERVER_KEY + EMULATOR_KEY guard
    let coop_leaf = leaf_asm(&output, "cooperative", "cooperative");
    assert!(
        coop_leaf.contains("<SERVER_KEY>"),
        "cooperative leaf: missing <SERVER_KEY>"
    );
    assert!(
        coop_leaf.contains(OP_CHECKSIGVERIFY),
        "cooperative leaf: missing OP_CHECKSIGVERIFY"
    );
    assert!(
        coop_leaf.contains(OP_CHECKSIG),
        "cooperative leaf: missing OP_CHECKSIG"
    );

    // ── timeout group ─────────────────────────────────────────────────────────
    let timeout_tokens = arkade_asm_tokens(&output, "timeout");
    let timeout_asm = timeout_tokens.join(" ");

    // Verify user checksig present
    assert!(
        timeout_asm.contains("<user>"),
        "timeout: missing <user> pubkey"
    );
    assert!(
        timeout_asm.contains("<userSig>"),
        "timeout: missing <userSig>"
    );
    assert!(
        timeout_asm.contains(OP_CHECKSIG),
        "timeout: missing OP_CHECKSIG"
    );

    // Verify timelock check
    assert!(
        timeout_asm.contains("<timelock>"),
        "timeout: missing <timelock> operand"
    );
    assert!(
        timeout_asm.contains(OP_CHECKLOCKTIMEVERIFY),
        "timeout: missing OP_CHECKLOCKTIMEVERIFY"
    );
    assert!(
        timeout_asm.contains(OP_DROP),
        "timeout: missing OP_DROP after CLTV"
    );

    // Default leaf: synthesized server guard (no introspection)
    let timeout_leaf = leaf_asm(&output, "timeout", "timeout");
    assert!(
        timeout_leaf.contains("<SERVER_KEY>"),
        "timeout leaf: missing <SERVER_KEY>"
    );
    assert!(
        timeout_leaf.contains(OP_CHECKSIG),
        "timeout leaf: missing final OP_CHECKSIG"
    );
}
