use arkade_compiler::compile;

#[test]
fn test_bare_vtxo_contract() {
    // Bare VTXO contract source code
    let vtxo_code = r#"// Contract configuration options
options {
  // Arkade operator key (always external, never a contract party)
  server = operator;
  
  // Exit timelock: 24 hours (144 blocks)
  exit = 144;
}

contract SingleSig(
  pubkey user,
  pubkey server
) {
  // Cooperative spend path (user + server)
  function cooperative(signature userSig, signature serverSig) {
    require(checkMultisig([user, server], [userSig, serverSig]));
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
    assert_eq!(output.parameters.len(), 2);
    assert_eq!(output.parameters[0].name, "user");
    assert_eq!(output.parameters[0].param_type, "pubkey");
    assert_eq!(output.parameters[1].name, "server");
    assert_eq!(output.parameters[1].param_type, "pubkey");

    // Verify functions - we have 4 functions (2 functions x 2 variants)
    assert_eq!(output.functions.len(), 4);

    // Verify cooperative function with server variant
    let cooperative_function = output
        .functions
        .iter()
        .find(|f| f.name == "cooperative" && f.server_variant)
        .unwrap();

    // Check function inputs
    assert_eq!(cooperative_function.function_inputs.len(), 2);
    assert_eq!(cooperative_function.function_inputs[0].name, "userSig");
    assert_eq!(
        cooperative_function.function_inputs[0].param_type,
        "signature"
    );
    assert_eq!(cooperative_function.function_inputs[1].name, "serverSig");
    assert_eq!(
        cooperative_function.function_inputs[1].param_type,
        "signature"
    );

    // Check assembly instructions
    assert_eq!(cooperative_function.asm.len(), 10);
    assert_eq!(cooperative_function.asm[0], "OP_2");
    assert_eq!(cooperative_function.asm[1], "<user>");
    assert_eq!(cooperative_function.asm[2], "<server>");
    assert_eq!(cooperative_function.asm[3], "OP_2");
    assert_eq!(cooperative_function.asm[4], "<userSig>");
    assert_eq!(cooperative_function.asm[5], "<serverSig>");
    assert_eq!(cooperative_function.asm[6], "OP_CHECKMULTISIG");
    assert_eq!(cooperative_function.asm[7], "<SERVER_KEY>");
    assert_eq!(cooperative_function.asm[8], "<serverSig>");
    assert_eq!(cooperative_function.asm[9], "OP_CHECKSIG");

    // Verify timeout function with server variant
    let timeout_function = output
        .functions
        .iter()
        .find(|f| f.name == "timeout" && f.server_variant)
        .unwrap();

    // Check assembly instructions
    assert_eq!(timeout_function.asm.len(), 9);
    assert_eq!(timeout_function.asm[0], "<user>");
    assert_eq!(timeout_function.asm[1], "<userSig>");
    assert_eq!(timeout_function.asm[2], "OP_CHECKSIG");
    assert_eq!(timeout_function.asm[3], "<timelock>"); // Variable reference
    assert_eq!(timeout_function.asm[4], "OP_CHECKLOCKTIMEVERIFY");
    assert_eq!(timeout_function.asm[5], "OP_DROP");
    assert_eq!(timeout_function.asm[6], "<SERVER_KEY>");
    assert_eq!(timeout_function.asm[7], "<serverSig>");
    assert_eq!(timeout_function.asm[8], "OP_CHECKSIG");
}
