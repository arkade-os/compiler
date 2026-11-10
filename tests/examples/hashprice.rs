use arkade_compiler::compile_file;
use arkade_compiler::opcodes::{
    OP_CHECKSIGFROMSTACK, OP_HASH256, OP_INSPECTASSETGROUPNUM, OP_INSPECTASSETGROUPSUM,
    OP_INSPECTINPUTPACKET, OP_INSPECTPACKET, OP_TUNNEL,
};
use std::path::Path;

use crate::common::{arkade_asm, arkade_inputs};

fn compile(path: &str) -> arkade_compiler::models::ContractJson {
    let full = Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    compile_file(&full).unwrap_or_else(|err| panic!("{path} should compile: {err}"))
}

fn names(out: &arkade_compiler::models::ContractJson) -> Vec<&str> {
    out.functions
        .iter()
        .map(|group| group.name.as_str())
        .collect()
}

#[test]
fn beacon_derives_hashprice_from_six_headers() {
    let out = compile("examples/hashprice/hashprice_beacon.ark");
    assert_eq!(out.name, "HashpriceBeacon");
    assert_eq!(names(&out), ["update", "passthrough", "authorize"]);

    let update = arkade_asm(&out, "update");
    assert!(
        !update.contains(OP_CHECKSIGFROMSTACK),
        "update must not take an oracle signature: {update}"
    );
    assert_eq!(
        update.matches(OP_HASH256).count(),
        6,
        "each header is hashed once: {update}"
    );
    assert!(update.contains(OP_INSPECTINPUTPACKET), "{update}");
    assert!(update.contains(OP_INSPECTPACKET), "{update}");
    assert!(update.contains(OP_INSPECTASSETGROUPSUM), "{update}");
    assert!(update.contains(OP_TUNNEL), "{update}");
    assert_eq!(arkade_inputs(&out, "update"), ["headers"]);

    let passthrough = arkade_asm(&out, "passthrough");
    assert!(passthrough.contains(OP_TUNNEL), "{passthrough}");
    assert!(passthrough.contains(OP_INSPECTPACKET), "{passthrough}");
    assert!(
        passthrough.contains(OP_INSPECTASSETGROUPNUM),
        "{passthrough}"
    );
    assert!(
        !passthrough.contains(OP_HASH256),
        "passthrough copies the packet and does not re-hash headers"
    );
    assert!(arkade_inputs(&out, "passthrough").is_empty());

    let authorize = arkade_asm(&out, "authorize");
    assert!(
        authorize.contains("<CONTRACT:HashpriceAttestation("),
        "the split unit has to land on the attestation: {authorize}"
    );
    assert!(
        !authorize.contains("CONTRACT:HashpriceMinter("),
        "the beacon copies the co-spent script instead of naming the minter: {authorize}"
    );
    assert!(authorize.contains(OP_INSPECTASSETGROUPSUM), "{authorize}");
    assert!(!authorize.contains(OP_HASH256), "{authorize}");
    assert!(arkade_inputs(&out, "authorize").is_empty());
}

#[test]
fn minter_and_attestation_share_the_beacon_asset() {
    let minter = compile("examples/hashprice/hashprice_minter.ark");
    assert_eq!(minter.name, "HashpriceMinter");
    assert_eq!(names(&minter), ["mint", "copy"]);

    let mint = arkade_asm(&minter, "mint");
    assert!(
        mint.contains("<CONTRACT:HashpriceBeacon("),
        "mint must spend the beacon: {mint}"
    );
    assert!(
        mint.contains("<CONTRACT:HashpriceAttestation("),
        "the new unit must be an attestation: {mint}"
    );
    assert!(mint.contains(OP_INSPECTASSETGROUPNUM), "{mint}");
    assert!(mint.contains(OP_INSPECTASSETGROUPSUM), "{mint}");
    assert!(
        !mint.contains(OP_HASH256),
        "the beacon already checked the headers"
    );
    assert!(arkade_inputs(&minter, "mint").is_empty());

    let copy = arkade_asm(&minter, "copy");
    assert!(copy.contains(OP_TUNNEL), "{copy}");
    assert!(copy.contains(OP_INSPECTASSETGROUPNUM), "{copy}");
    assert!(arkade_inputs(&minter, "copy").is_empty());

    let attestation = compile("examples/hashprice/hashprice_attestation.ark");
    assert_eq!(attestation.name, "HashpriceAttestation");
    assert_eq!(names(&attestation), ["copy", "consume"]);

    let forward = arkade_asm(&attestation, "copy");
    assert!(forward.contains(OP_TUNNEL), "{forward}");
    assert!(forward.contains(OP_INSPECTPACKET), "{forward}");
    assert!(forward.contains(OP_INSPECTASSETGROUPSUM), "{forward}");
    assert!(arkade_inputs(&attestation, "copy").is_empty());

    let consume = arkade_asm(&attestation, "consume");
    assert!(
        !consume.contains(OP_TUNNEL),
        "consume burns the asset instead of copying it: {consume}"
    );
    assert!(consume.contains(OP_INSPECTASSETGROUPNUM), "{consume}");
    assert!(arkade_inputs(&attestation, "consume").is_empty());
}

#[test]
fn option_settles_by_consuming_the_attestation() {
    let out = compile("examples/hashprice/hashprice_option.ark");
    assert_eq!(out.name, "HashpriceOption");
    assert_eq!(names(&out), ["settle", "close", "unilateral"]);

    let settle = arkade_asm(&out, "settle");
    assert!(
        settle.contains("<CONTRACT:HashpriceAttestation("),
        "settle must authenticate the attestation program: {settle}"
    );
    assert!(
        !settle.contains("CONTRACT:HashpriceBeacon("),
        "settle reads the attestation, not a co-spent beacon: {settle}"
    );
    assert!(
        settle.contains(OP_INSPECTINPUTPACKET),
        "settle must read the attestation's packet: {settle}"
    );
    assert!(
        settle.contains(OP_INSPECTASSETGROUPNUM),
        "the attestation asset has to be consumed: {settle}"
    );
    assert!(arkade_inputs(&out, "settle").is_empty());
}
