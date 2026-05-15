// Tests for new introspector primitives:
//   - tx.packet(packetType)         → OP_INSPECTPACKET
//   - tx.inputs[i].packet(...)      → OP_INSPECTINPUTPACKET
//   - substr / cat / bin2num / num2bin / size
//   - tx.inputs[i].arkadeScriptHash → OP_INSPECTINPUTARKADESCRIPTHASH
//   - tx.id                         → OP_TXID
//
// These primitives match the canonical introspector opcode set
// (https://github.com/ArkLabsHQ/introspector). The LayerZero / USDT0 demo
// scripts use exactly this surface for packet-level enforcement, so this
// test file pins the language-to-opcode mapping the LayerZero contracts
// depend on.

use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_BIN2NUM, OP_CAT, OP_EQUALVERIFY, OP_INSPECTINPUTARKADESCRIPTHASH,
    OP_INSPECTINPUTARKADEWITNESSHASH, OP_INSPECTINPUTPACKET, OP_INSPECTPACKET, OP_NIP, OP_NUM2BIN,
    OP_SIZE, OP_SUBSTR, OP_TXID,
};

fn compile_first_function_asm(src: &str) -> Vec<String> {
    let out = compile(src).unwrap_or_else(|e| panic!("compile: {:?}", e));
    out.functions
        .iter()
        .find(|f| f.server_variant)
        .expect("server variant")
        .asm
        .clone()
}

const PROLOGUE: &str = r#"
options { server = server; exit = exit; }
"#;

#[test]
fn test_packet_inspect_emits_op_inspectpacket_with_presence_check() {
    let src = format!(
        r#"{}
contract PacketDemo(int exit) {{
  function probe(int packetType) {{
    require(tx.packet(packetType));
  }}
}}"#,
        PROLOGUE
    );

    let asm = compile_first_function_asm(&src);
    assert!(
        asm.iter().any(|s| s == OP_INSPECTPACKET),
        "expected OP_INSPECTPACKET; got {:?}",
        asm
    );

    // Presence is asserted via "OP_1 OP_EQUALVERIFY" after the opcode.
    let idx = asm
        .iter()
        .position(|s| s == OP_INSPECTPACKET)
        .expect("inspect packet present");
    assert!(idx + 2 < asm.len(), "missing follow-on ops");
    assert_eq!(asm[idx + 1], "OP_1");
    assert_eq!(asm[idx + 2], OP_EQUALVERIFY);
}

#[test]
fn test_input_packet_inspect_emits_op_inspectinputpacket() {
    let src = format!(
        r#"{}
contract InputPacketDemo(int exit) {{
  function probe(int packetType, int i) {{
    require(tx.inputs[i].packet(packetType));
  }}
}}"#,
        PROLOGUE
    );

    let asm = compile_first_function_asm(&src);
    assert!(
        asm.iter().any(|s| s == OP_INSPECTINPUTPACKET),
        "expected OP_INSPECTINPUTPACKET; got {:?}",
        asm
    );
}

#[test]
fn test_substr_emits_op_substr() {
    let src = format!(
        r#"{}
contract SubstrDemo(int exit) {{
  function probe(bytes data, int offset, int length) {{
    require(substr(data, offset, length));
  }}
}}"#,
        PROLOGUE
    );

    let asm = compile_first_function_asm(&src);
    assert!(
        asm.iter().any(|s| s == OP_SUBSTR),
        "expected OP_SUBSTR; got {:?}",
        asm
    );
}

#[test]
fn test_cat_emits_op_cat() {
    let src = format!(
        r#"{}
contract CatDemo(int exit) {{
  function probe(bytes a, bytes b) {{
    require(cat(a, b));
  }}
}}"#,
        PROLOGUE
    );

    let asm = compile_first_function_asm(&src);
    assert!(
        asm.iter().any(|s| s == OP_CAT),
        "expected OP_CAT; got {:?}",
        asm
    );
}

#[test]
fn test_bin2num_emits_op_bin2num() {
    let src = format!(
        r#"{}
contract Bin2NumDemo(int exit) {{
  function probe(bytes data) {{
    require(bin2num(data));
  }}
}}"#,
        PROLOGUE
    );

    let asm = compile_first_function_asm(&src);
    assert!(
        asm.iter().any(|s| s == OP_BIN2NUM),
        "expected OP_BIN2NUM; got {:?}",
        asm
    );
}

#[test]
fn test_num2bin_emits_op_num2bin() {
    let src = format!(
        r#"{}
contract Num2BinDemo(int exit) {{
  function probe(int value, int size) {{
    require(num2bin(value, size));
  }}
}}"#,
        PROLOGUE
    );

    let asm = compile_first_function_asm(&src);
    assert!(
        asm.iter().any(|s| s == OP_NUM2BIN),
        "expected OP_NUM2BIN; got {:?}",
        asm
    );
}

#[test]
fn test_size_emits_op_size_and_op_nip() {
    let src = format!(
        r#"{}
contract SizeDemo(int exit) {{
  function probe(bytes data) {{
    require(size(data));
  }}
}}"#,
        PROLOGUE
    );

    let asm = compile_first_function_asm(&src);
    let size_idx = asm
        .iter()
        .position(|s| s == OP_SIZE)
        .expect("OP_SIZE missing");
    assert_eq!(
        asm.get(size_idx + 1).map(String::as_str),
        Some(OP_NIP),
        "OP_SIZE must be followed by OP_NIP to leave only the length on the stack"
    );
}

#[test]
fn test_arkade_script_hash_emits_op_inspectinputarkadescripthash() {
    let src = format!(
        r#"{}
contract MarkerDemo(bytes32 expectedHash, int exit) {{
  function consume() {{
    require(tx.inputs[1].arkadeScriptHash == expectedHash, "wrong closure");
  }}
}}"#,
        PROLOGUE
    );

    let asm = compile_first_function_asm(&src);
    assert!(
        asm.iter().any(|s| s == OP_INSPECTINPUTARKADESCRIPTHASH),
        "expected OP_INSPECTINPUTARKADESCRIPTHASH; got {:?}",
        asm
    );
}

#[test]
fn test_arkade_witness_hash_emits_op_inspectinputarkadewitnesshash() {
    let src = format!(
        r#"{}
contract WitnessDemo(bytes32 expectedHash, int exit) {{
  function consume() {{
    require(tx.inputs[0].arkadeWitnessHash == expectedHash);
  }}
}}"#,
        PROLOGUE
    );

    let asm = compile_first_function_asm(&src);
    assert!(
        asm.iter().any(|s| s == OP_INSPECTINPUTARKADEWITNESSHASH),
        "expected OP_INSPECTINPUTARKADEWITNESSHASH; got {:?}",
        asm
    );
}

#[test]
fn test_tx_id_emits_op_txid() {
    let src = format!(
        r#"{}
contract TxIdDemo(bytes32 expected, int exit) {{
  function probe() {{
    require(tx.id == expected, "txid mismatch");
  }}
}}"#,
        PROLOGUE
    );

    let asm = compile_first_function_asm(&src);
    assert!(
        asm.iter().any(|s| s == OP_TXID),
        "expected OP_TXID; got {:?}",
        asm
    );
}
