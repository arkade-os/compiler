use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_INSPECTASSETGROUPASSETID, OP_INSPECTASSETGROUPCTRL, OP_INSPECTASSETGROUPMETADATAHASH,
    OP_INSPECTASSETGROUPSUM, OP_INSPECTOUTASSETLOOKUP, OP_SUB64, OP_TXHASH,
};

const ARKADE_KITTIES_CODE: &str = include_str!("../../examples/arkade_kitties/arkade_kitties.ark");

#[test]
fn test_arkade_kitties_compiles() {
    let result = compile(ARKADE_KITTIES_CODE);
    assert!(
        result.is_ok(),
        "ArkadeKitties compilation failed: {:?}",
        result.err()
    );
}

#[test]
fn test_arkade_kitties_structure() {
    let output = compile(ARKADE_KITTIES_CODE).unwrap();

    assert_eq!(output.name, "ArkadeKitties");

    // 2 covenant functions (breed, transfer) → 2 groups
    assert_eq!(output.functions.len(), 2, "expected 2 function groups");

    // Verify breed group exists with arkade covenant
    let breed = crate::common::group(&output, "breed");
    assert!(
        breed.arkade.is_some(),
        "breed group should have arkade covenant"
    );

    // Verify transfer group exists with arkade covenant
    let transfer = crate::common::group(&output, "transfer");
    assert!(
        transfer.arkade.is_some(),
        "transfer group should have arkade covenant"
    );
}

#[test]
fn test_breed_function_has_is_fresh() {
    let output = compile(ARKADE_KITTIES_CODE).unwrap();

    let asm_str = crate::common::arkade_asm(&output, "breed");

    // isFresh emits: <group> OP_INSPECTASSETGROUPASSETID OP_DROP OP_TXHASH OP_EQUAL
    assert!(
        asm_str.contains(OP_INSPECTASSETGROUPASSETID),
        "Expected {OP_INSPECTASSETGROUPASSETID} for isFresh check in breed: {}",
        asm_str
    );
    assert!(
        asm_str.contains(OP_TXHASH),
        "Expected {OP_TXHASH} for isFresh check in breed: {}",
        asm_str
    );
}

#[test]
fn test_breed_function_has_metadata_hash() {
    let output = compile(ARKADE_KITTIES_CODE).unwrap();

    let asm_str = crate::common::arkade_asm(&output, "breed");

    assert!(
        asm_str.contains(OP_INSPECTASSETGROUPMETADATAHASH),
        "Expected {OP_INSPECTASSETGROUPMETADATAHASH} in breed: {}",
        asm_str
    );
}

#[test]
fn test_breed_function_has_control_check() {
    let output = compile(ARKADE_KITTIES_CODE).unwrap();

    let asm_str = crate::common::arkade_asm(&output, "breed");

    assert!(
        asm_str.contains(OP_INSPECTASSETGROUPCTRL),
        "Expected {OP_INSPECTASSETGROUPCTRL} in breed: {}",
        asm_str
    );
}

#[test]
fn test_breed_function_has_delta_checks() {
    let output = compile(ARKADE_KITTIES_CODE).unwrap();

    let asm_str = crate::common::arkade_asm(&output, "breed");

    // delta uses OP_INSPECTASSETGROUPSUM twice (outputs - inputs) and OP_SUB64
    assert!(
        asm_str.contains(OP_INSPECTASSETGROUPSUM),
        "Expected {OP_INSPECTASSETGROUPSUM} for delta in breed: {}",
        asm_str
    );
    assert!(
        asm_str.contains(OP_SUB64),
        "Expected {OP_SUB64} for delta calculation in breed: {}",
        asm_str
    );
}

#[test]
fn test_transfer_verifies_not_fresh() {
    let output = compile(ARKADE_KITTIES_CODE).unwrap();

    let asm_str = crate::common::arkade_asm(&output, "transfer");

    // Transfer checks isFresh == 0, so it should have the isFresh opcode sequence
    assert!(
        asm_str.contains(OP_INSPECTASSETGROUPASSETID),
        "Expected {OP_INSPECTASSETGROUPASSETID} for isFresh check in transfer: {}",
        asm_str
    );
    assert!(
        asm_str.contains(OP_TXHASH),
        "Expected {OP_TXHASH} for isFresh check in transfer: {}",
        asm_str
    );
}

#[test]
fn test_transfer_has_control_check() {
    let output = compile(ARKADE_KITTIES_CODE).unwrap();

    let asm_str = crate::common::arkade_asm(&output, "transfer");

    assert!(
        asm_str.contains(OP_INSPECTASSETGROUPCTRL),
        "Expected {OP_INSPECTASSETGROUPCTRL} in transfer: {}",
        asm_str
    );
}

#[test]
fn test_breed_has_asset_lookups() {
    let output = compile(ARKADE_KITTIES_CODE).unwrap();

    let asm_str = crate::common::arkade_asm(&output, "breed");

    // Breed verifies outputs contain all assets
    assert!(
        asm_str.contains(OP_INSPECTOUTASSETLOOKUP),
        "Expected {OP_INSPECTOUTASSETLOOKUP} in breed for output verification: {}",
        asm_str
    );
}
