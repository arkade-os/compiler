use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_INSPECTLOCKTIME, OP_INSPECTNUMINPUTS, OP_INSPECTNUMOUTPUTS, OP_INSPECTVERSION, OP_TXWEIGHT,
};

/// Test transaction introspection opcodes
#[test]
fn test_tx_version() {
    let code = r#"
        contract VersionChecker(pubkey owner) {
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
    let asm_str = crate::common::arkade_asm(&output, "checkVersion");
    assert!(
        asm_str.contains(OP_INSPECTVERSION),
        "Expected {OP_INSPECTVERSION} in ASM: {}",
        asm_str
    );
}

#[test]
fn test_tx_locktime() {
    let code = r#"
        contract LocktimeChecker(pubkey owner) {
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
    let asm_str = crate::common::arkade_asm(&output, "checkLocktime");
    assert!(
        asm_str.contains(OP_INSPECTLOCKTIME),
        "Expected {OP_INSPECTLOCKTIME} in ASM: {}",
        asm_str
    );
}

#[test]
fn test_tx_num_inputs() {
    let code = r#"
        contract InputCounter(pubkey owner) {
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
    let asm_str = crate::common::arkade_asm(&output, "checkInputs");
    assert!(
        asm_str.contains(OP_INSPECTNUMINPUTS),
        "Expected {OP_INSPECTNUMINPUTS} in ASM: {}",
        asm_str
    );
}

#[test]
fn test_tx_num_outputs() {
    let code = r#"
        contract OutputCounter(pubkey owner) {
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
    let asm_str = crate::common::arkade_asm(&output, "checkOutputs");
    assert!(
        asm_str.contains(OP_INSPECTNUMOUTPUTS),
        "Expected {OP_INSPECTNUMOUTPUTS} in ASM: {}",
        asm_str
    );
}

#[test]
fn test_tx_weight() {
    let code = r#"
        contract WeightChecker(pubkey owner) {
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
    let asm_str = crate::common::arkade_asm(&output, "checkWeight");
    assert!(
        asm_str.contains(OP_TXWEIGHT),
        "Expected {OP_TXWEIGHT} in ASM: {}",
        asm_str
    );
}
