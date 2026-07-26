use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_GREATERTHANOREQUAL, OP_INSPECTINASSETLOOKUP,
    OP_INSPECTOUTASSETLOOKUP, OP_VERIFY,
};

#[test]
fn test_token_vault_contract() {
    let code = include_str!("../../examples/token_vault/token_vault.ark");

    let result = compile(code);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();

    // Verify contract name
    assert_eq!(output.name, "TokenVault");

    // Verify parameters, including explicit Asset ID (Txid, Gidx) pairs.
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

    // 2 covenant functions (deposit, withdraw) + 1 standalone unilateral = 3 groups
    assert_eq!(
        output.functions.len(),
        3,
        "expected 3 groups (deposit, withdraw, unilateral)"
    );

    // Verify deposit function: arkade covenant holds all introspection logic
    let deposit_asm = crate::common::arkade_asm(&output, "deposit");

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

    // Lookups assert presence by consuming the opcode success flag with OP_VERIFY
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

    // The output token amount must be at least the input token amount.
    assert!(
        deposit_asm.contains(&format!(
            "{OP_INSPECTINASSETLOOKUP} {OP_VERIFY} {OP_GREATERTHANOREQUAL}"
        )),
        "missing output >= input token amount comparison in deposit asm: {}",
        deposit_asm
    );

    // deposit covenant should verify owner signature
    assert!(
        deposit_asm.contains(OP_CHECKSIG),
        "missing {OP_CHECKSIG} in deposit covenant: {}",
        deposit_asm
    );

    // deposit leaf carries server + emulator cosig
    let deposit_leaf = crate::common::leaf_asm(&output, "deposit", "deposit");
    assert!(
        deposit_leaf.contains("<SERVER_KEY>"),
        "deposit leaf should have SERVER_KEY: {}",
        deposit_leaf
    );

    // Unilateral exit: standalone CSV leaf with no introspection.
    let unilateral_asm = crate::common::leaf_asm(&output, "unilateral", "unilateral");

    assert!(
        unilateral_asm.contains(OP_CHECKSIG),
        "missing {OP_CHECKSIG} in unilateral exit: {}",
        unilateral_asm
    );
    assert!(
        unilateral_asm.contains(OP_CHECKSEQUENCEVERIFY),
        "missing CSV exit timelock in unilateral leaf: {}",
        unilateral_asm
    );
    assert!(
        !unilateral_asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "exit leaf should not have introspection: {}",
        unilateral_asm
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

    let code = include_str!("../../examples/token_vault/token_vault.ark");
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
    assert!(json_output.contains("tokenAssetIdGidx"));
    assert!(json_output.contains("ctrlAssetIdGidx"));
}
