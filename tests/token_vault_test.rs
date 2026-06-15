use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_GREATERTHAN64, OP_GREATERTHANOREQUAL64,
    OP_INSPECTINASSETLOOKUP, OP_INSPECTOUTASSETLOOKUP, OP_VERIFY,
};

#[test]
fn test_token_vault_contract() {
    let code = include_str!("../examples/token_vault.ark");

    let result = compile(code);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();

    // Verify contract name
    assert_eq!(output.name, "TokenVault");

    // Verify parameters, including explicit Asset ID (Txid, Gidx) pairs.
    // ownerPk remains a scalar pubkey parameter.
    let param_names: Vec<&str> = output.parameters.iter().map(|p| p.name.as_str()).collect();
    assert!(param_names.contains(&"ownerPk"), "missing ownerPk");
    assert!(
        param_names.contains(&"tokenAssetIdTxid"),
        "missing explicit tokenAssetIdTxid"
    );
    assert!(
        param_names.contains(&"tokenAssetIdGidx"),
        "missing explicit tokenAssetIdGidx"
    );
    assert!(
        param_names.contains(&"ctrlAssetIdTxid"),
        "missing explicit ctrlAssetIdTxid"
    );
    assert!(
        param_names.contains(&"ctrlAssetIdGidx"),
        "missing explicit ctrlAssetIdGidx"
    );

    // Verify functions: 2 functions x 2 variants = 4
    assert_eq!(
        output.functions.len(),
        4,
        "expected 4 functions (2x2 variants)"
    );

    // Verify deposit function with server variant
    let deposit = output
        .functions
        .iter()
        .find(|f| f.name == "deposit" && f.server_variant)
        .expect("deposit server variant not found");

    // Check that assembly contains asset lookup opcodes
    let deposit_asm = deposit.asm.join(" ");
    assert!(
        deposit_asm.contains(OP_INSPECTINASSETLOOKUP),
        "missing {OP_INSPECTINASSETLOOKUP} in deposit asm: {}",
        deposit_asm
    );
    assert!(
        deposit_asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "missing {OP_INSPECTOUTASSETLOOKUP} in deposit asm: {}",
        deposit_asm
    );

    // Lookups assert presence by consuming the opcode success flag with a
    // single OP_VERIFY.
    assert!(
        deposit_asm.contains(&format!("{OP_INSPECTINASSETLOOKUP} {OP_VERIFY}")),
        "input lookup must be followed by OP_VERIFY flag-consume: {}",
        deposit_asm
    );
    assert!(
        deposit_asm.contains(&format!("{OP_INSPECTOUTASSETLOOKUP} {OP_VERIFY}")),
        "output lookup must be followed by OP_VERIFY flag-consume: {}",
        deposit_asm
    );

    // Check 64-bit comparison opcodes
    assert!(
        deposit_asm.contains(OP_GREATERTHAN64) || deposit_asm.contains(OP_GREATERTHANOREQUAL64),
        "missing 64-bit comparison opcodes in deposit asm: {}",
        deposit_asm
    );

    // Check requirement types
    assert!(
        deposit.require.iter().any(|r| r.req_type == "assetCheck"),
        "missing assetCheck requirement type"
    );
    assert!(
        deposit.require.iter().any(|r| r.req_type == "signature"),
        "missing signature requirement type"
    );
    assert!(
        deposit
            .require
            .iter()
            .any(|r| r.req_type == "serverSignature"),
        "missing serverSignature requirement type"
    );

    // Verify withdraw function with exit variant
    // Exit path with introspection should have N-of-N + CSV (no introspection opcodes)
    let withdraw_exit = output
        .functions
        .iter()
        .find(|f| f.name == "withdraw" && !f.server_variant)
        .expect("withdraw exit variant not found");

    let withdraw_asm = withdraw_exit.asm.join(" ");

    // Exit path should have N-of-N CHECKSIG chain (pure Bitcoin)
    assert!(
        withdraw_asm.contains(OP_CHECKSIG),
        "missing {OP_CHECKSIG} in withdraw exit: {}",
        withdraw_asm
    );

    // Exit path should use CSV (relative timelock)
    assert!(
        withdraw_asm.contains(OP_CHECKSEQUENCEVERIFY),
        "missing CSV exit timelock in withdraw exit variant: {}",
        withdraw_asm
    );

    // Exit path should NOT have introspection opcodes (pure Bitcoin fallback)
    assert!(
        !withdraw_asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "exit path should not have introspection: {}",
        withdraw_asm
    );

    // Should have N-of-N multisig requirement
    assert!(
        withdraw_exit
            .require
            .iter()
            .any(|r| r.req_type == "nOfNMultisig"),
        "missing nOfNMultisig requirement in exit path"
    );
}

#[test]
fn test_token_vault_cli() {
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let input_path = temp_dir.path().join("token_vault.ark");
    let output_path = temp_dir.path().join("token_vault.json");

    let code = include_str!("../examples/token_vault.ark");
    fs::write(&input_path, code).unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_arkadec"))
        .arg(input_path.to_str().unwrap())
        .arg("-o")
        .arg(output_path.to_str().unwrap())
        .output()
        .expect("Failed to execute command");

    assert!(
        output.status.success(),
        "Command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(Path::new(&output_path).exists());

    let json_output = fs::read_to_string(&output_path).unwrap();
    assert!(json_output.contains("\"contractName\": \"TokenVault\""));
    assert!(json_output.contains(OP_INSPECTINASSETLOOKUP));
    assert!(json_output.contains(OP_INSPECTOUTASSETLOOKUP));
    assert!(json_output.contains("tokenAssetIdTxid"));
    assert!(json_output.contains("ctrlAssetIdTxid"));
}
