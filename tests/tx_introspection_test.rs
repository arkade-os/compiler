use arkade_compiler::compile;

/// Test transaction introspection opcodes
#[test]
fn test_tx_version() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract VersionChecker(pubkey serverKey, pubkey owner) {
            function checkVersion(signature ownerSig, int expectedVersion) {
                require(checkSig(ownerSig, owner));
                require(tx.version == expectedVersion);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse tx.version: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "checkVersion" && f.server_variant)
        .expect("Should have checkVersion server variant");

    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains("OP_INSPECTVERSION"),
        "Expected OP_INSPECTVERSION in ASM: {}",
        asm_str
    );
}

#[test]
fn test_tx_locktime() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract LocktimeChecker(pubkey serverKey, pubkey owner) {
            function checkLocktime(signature ownerSig, int minLocktime) {
                require(checkSig(ownerSig, owner));
                require(tx.locktime >= minLocktime);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse tx.locktime: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "checkLocktime" && f.server_variant)
        .expect("Should have checkLocktime server variant");

    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains("OP_INSPECTLOCKTIME"),
        "Expected OP_INSPECTLOCKTIME in ASM: {}",
        asm_str
    );
}

#[test]
fn test_tx_num_inputs() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract InputCounter(pubkey serverKey, pubkey owner) {
            function checkInputs(signature ownerSig, int minInputs) {
                require(checkSig(ownerSig, owner));
                require(tx.numInputs >= minInputs);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse tx.numInputs: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "checkInputs" && f.server_variant)
        .expect("Should have checkInputs server variant");

    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains("OP_INSPECTNUMINPUTS"),
        "Expected OP_INSPECTNUMINPUTS in ASM: {}",
        asm_str
    );
}

#[test]
fn test_tx_num_outputs() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract OutputCounter(pubkey serverKey, pubkey owner) {
            function checkOutputs(signature ownerSig, int minOutputs) {
                require(checkSig(ownerSig, owner));
                require(tx.numOutputs >= minOutputs);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse tx.numOutputs: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "checkOutputs" && f.server_variant)
        .expect("Should have checkOutputs server variant");

    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains("OP_INSPECTNUMOUTPUTS"),
        "Expected OP_INSPECTNUMOUTPUTS in ASM: {}",
        asm_str
    );
}

#[test]
fn test_tx_weight() {
    let code = r#"
        options {
            server = serverKey;
            exit = 144;
        }

        contract WeightChecker(pubkey serverKey, pubkey owner) {
            function checkWeight(signature ownerSig, int maxWeight) {
                require(checkSig(ownerSig, owner));
                require(tx.weight <= maxWeight);
            }
        }
    "#;

    let result = compile(code);
    assert!(
        result.is_ok(),
        "Failed to parse tx.weight: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let func = output
        .functions
        .iter()
        .find(|f| f.name == "checkWeight" && f.server_variant)
        .expect("Should have checkWeight server variant");

    let asm_str = func.asm.join(" ");
    assert!(
        asm_str.contains("OP_TXWEIGHT"),
        "Expected OP_TXWEIGHT in ASM: {}",
        asm_str
    );
}
