use arkade_compiler::compile_file;
use arkade_compiler::opcodes::{
    OP_CHECKSIGFROMSTACK, OP_HASH256, OP_INSPECTINPUTPACKET, OP_INSPECTPACKET, OP_TUNNEL,
};
use std::path::Path;

use crate::common::{arkade_asm, arkade_inputs};

fn compile(path: &str) -> arkade_compiler::models::ContractJson {
    let full = Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    compile_file(&full).unwrap_or_else(|err| panic!("{path} should compile: {err}"))
}

#[test]
fn beacon_derives_hashprice_from_six_headers() {
    let out = compile("examples/hashprice/hashprice_beacon.ark");
    assert_eq!(out.name, "HashpriceBeacon");
    let names: Vec<&str> = out
        .functions
        .iter()
        .map(|group| group.name.as_str())
        .collect();
    assert_eq!(names, ["update", "passthrough"]);

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
    assert!(update.contains(OP_TUNNEL), "{update}");
    assert_eq!(arkade_inputs(&out, "update"), ["headers"]);

    let passthrough = arkade_asm(&out, "passthrough");
    assert!(passthrough.contains(OP_TUNNEL), "{passthrough}");
    assert!(passthrough.contains(OP_INSPECTPACKET), "{passthrough}");
    assert!(
        !passthrough.contains(OP_HASH256),
        "passthrough copies the packet and does not re-hash headers"
    );
    assert!(arkade_inputs(&out, "passthrough").is_empty());
}

#[test]
fn option_settles_against_the_beacon_program() {
    let out = compile("examples/hashprice/hashprice_option.ark");
    assert_eq!(out.name, "HashpriceOption");
    let names: Vec<&str> = out
        .functions
        .iter()
        .map(|group| group.name.as_str())
        .collect();
    assert_eq!(names, ["settle", "close", "unilateral"]);

    let settle = arkade_asm(&out, "settle");
    assert!(
        settle.contains("CONTRACT:HashpriceBeacon("),
        "settle must authenticate the beacon program: {settle}"
    );
    assert!(
        settle.contains(OP_INSPECTINPUTPACKET),
        "settle must read the beacon state packet: {settle}"
    );
    assert!(arkade_inputs(&out, "settle").is_empty());
}
