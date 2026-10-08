use arkade_compiler::compile;
use arkade_compiler::opcodes::{OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_DROP};

use crate::common::{group, leaf_asm, witness_names};

// A bare VTXO has no arkade covenant — it is just L1 taproot leaves:
//   • a collaborative forfeit closure (server + user), and
//   • a unilateral CSV exit closure (user alone after a delay).
// Both are standalone `tapscript`s, so `server` is the reserved key role (→ <SERVER_KEY>).
#[test]
fn test_bare_vtxo_contract() {
    let vtxo_code = r#"
contract SingleSig(
  pubkey user,
  int exitDelay
) {
  // Collaborative path: server + user (N-of-N forfeit closure).
  function cooperative(signature serverSig, signature userSig) tapscript {
    require(checkMultisig([server, user], [serverSig, userSig], 2));
  }

  // Unilateral exit: user alone after a CSV delay (exit closure).
  function unilateral(signature userSig) tapscript {
    require(older(exitDelay));
    require(checkSig(userSig, user));
  }
}"#;

    let result = compile(vtxo_code);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
    let output = result.unwrap();

    assert_eq!(output.name, "SingleSig");

    // Parameters: user pubkey + exitDelay int (no serverPk — server is a reserved role).
    assert_eq!(output.parameters.len(), 2);
    assert_eq!(output.parameters[0].name, "user");
    assert_eq!(output.parameters[0].param_type, "pubkey");
    assert_eq!(output.parameters[1].name, "exitDelay");
    assert_eq!(output.parameters[1].param_type, "int");

    assert_eq!(output.functions.len(), 2);

    // ── cooperative closure: no covenant, [server, user] ──────────────
    let coop = group(&output, "cooperative");
    assert!(
        coop.arkade.is_none(),
        "bare VTXO cooperative path has no arkade covenant"
    );

    let coop_leaf = leaf_asm(&output, "cooperative", "cooperative");
    assert!(
        coop_leaf.contains("<SERVER_KEY>"),
        "cooperative: server role must lower to <SERVER_KEY>: {coop_leaf}"
    );
    assert!(
        coop_leaf.contains("<user>"),
        "cooperative: missing <user> pubkey: {coop_leaf}"
    );
    // N-of-N multisig: verify all-but-last, checksig the last.
    assert!(
        coop_leaf.contains(OP_CHECKSIGVERIFY) && coop_leaf.contains(OP_CHECKSIG),
        "cooperative: expected N-of-N checksig chain: {coop_leaf}"
    );

    // Witness carries both sigs; serverSig is infra-injected, userSig author-supplied.
    let coop_witness = witness_names(&output, "cooperative", "cooperative");
    assert_eq!(coop_witness, vec!["serverSig", "userSig"]);

    // ── unilateral closure: CSV delay + user checksig (exit closure) ─────────
    let uni = group(&output, "unilateral");
    assert!(
        uni.arkade.is_none(),
        "bare VTXO unilateral exit has no arkade covenant"
    );

    let uni_leaf = leaf_asm(&output, "unilateral", "unilateral");
    assert!(
        uni_leaf.contains("<exitDelay>"),
        "unilateral: missing <exitDelay> CSV operand: {uni_leaf}"
    );
    assert!(
        uni_leaf.contains(OP_CHECKSEQUENCEVERIFY),
        "unilateral: missing OP_CHECKSEQUENCEVERIFY: {uni_leaf}"
    );
    assert!(
        uni_leaf.contains(OP_DROP),
        "unilateral: missing OP_DROP after CSV: {uni_leaf}"
    );
    assert!(
        uni_leaf.contains("<user>") && uni_leaf.contains(OP_CHECKSIG),
        "unilateral: missing user checksig: {uni_leaf}"
    );

    let uni_witness = witness_names(&output, "unilateral", "unilateral");
    assert_eq!(uni_witness, vec!["userSig"]);
}
