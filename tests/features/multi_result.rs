use crate::common::{arkade_asm_tokens, compile_unoptimized as compile, opcode_count_in_arkade};
use arkade_compiler::opcodes::*;

#[test]
fn script_binds_program_and_version_from_one_inspection() {
    let code = r#"
        contract C(bytes program) {
            function spend() {
                let s = tx.outputs[0].script;
                require(s.program == program);
                require(s.version == 1);
                let current = tx.input.current.script;
                require(current.version == 1);
                let other = tx.inputs[1].script;
                require(other.program == program);
            }
        }
    "#;
    let output = compile(code).expect("script returns a ScriptPubKey struct");
    assert_eq!(
        opcode_count_in_arkade(&output, "spend", OP_INSPECTOUTPUTSCRIPTPUBKEY),
        1
    );
    assert_eq!(
        opcode_count_in_arkade(&output, "spend", OP_INSPECTINPUTSCRIPTPUBKEY),
        2
    );
    let asm = arkade_asm_tokens(&output, "spend");
    assert!(asm
        .windows(3)
        .any(|w| w == ["0", OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_SWAP]));
    assert!(asm
        .windows(3)
        .any(|w| w == ["1", OP_INSPECTINPUTSCRIPTPUBKEY, OP_SWAP]));
}

#[test]
fn bare_asset_entry_binds_asset_id_and_amount_from_one_inspection() {
    let code = r#"
        contract C(bytes32 txid) {
            function spend() {
                let entry = tx.inputs[1].assets[0];
                require(entry.assetId.txid == txid);
                require(entry.assetId.gidx == 2);
                require(entry.amount >= 100);
                require(tx.outputs[0].assets.lookup(entry.assetId.txid, entry.assetId.gidx) >= entry.amount);
                let out = tx.outputs[2].assets[1];
                require(out.amount == entry.amount);
            }
        }
    "#;
    let output = compile(code).expect("bare asset entry returns an AssetEntry struct");
    assert_eq!(
        opcode_count_in_arkade(&output, "spend", OP_INSPECTINASSETAT),
        1
    );
    let asm = arkade_asm_tokens(&output, "spend");
    // [txid gidx amount] reverses so the first field is nearest the top.
    assert!(asm
        .windows(6)
        .any(|w| w == ["1", "0", OP_INSPECTINASSETAT, OP_SWAP, OP_2, OP_ROLL]));
    assert!(asm
        .windows(6)
        .any(|w| w == ["2", "1", OP_INSPECTOUTASSETAT, OP_SWAP, OP_2, OP_ROLL]));
}

#[test]
fn try_lookup_binds_amount_and_presence_from_one_inspection() {
    let code = r#"
        contract C(bytes32 txid) {
            function spend() {
                let found = tx.outputs[0].assets.tryLookup(txid, 0);
                if (found.found) {
                    require(found.amount >= 100);
                } else {
                    require(tx.outputs[0].value >= 1000);
                }
            }
        }
    "#;
    let output = compile(code).expect("tryLookup returns an AssetLookup struct");
    assert_eq!(
        opcode_count_in_arkade(&output, "spend", OP_INSPECTOUTASSETLOOKUP),
        1
    );
    let asm = arkade_asm_tokens(&output, "spend");
    assert!(!asm
        .windows(2)
        .any(|w| w == [OP_INSPECTOUTASSETLOOKUP, OP_VERIFY]));
}

#[test]
fn whole_results_are_not_scalars() {
    for expression in [
        "tx.outputs[0].script",
        "tx.inputs[0].assets[0]",
        "tx.inputs[0].assets.tryLookup(t, 0)",
    ] {
        let code = format!(
            "contract C(bytes32 t) {{ function spend() {{ require({expression} == 1); }} }}"
        );
        assert!(compile(&code).is_err(), "{expression} compared to a scalar");
    }
}

#[test]
fn repeated_multi_result_inspections_warn_with_the_whole_read() {
    let code = r#"
        contract C(bytes program, bytes32 t, int g, AssetId id) {
            function spend() {
                require(tx.outputs[3].scriptPubKey == program);
                require(tx.outputs[3].witnessVersion == 1);
                require(tx.inputs[0].assets[1].amount >= 1);
                require(tx.inputs[0].assets[1].assetId == id);
                if (tx.outputs[0].assets.has(t, g)) {
                    require(tx.outputs[0].assets.lookup(t, g) >= 1);
                }
                require(tx.input.current.witnessVersion == 1);
                require(this.activeBytecode == program);
            }
        }
    "#;
    let warnings = compile(code).expect("compiles").warnings;
    for whole in [
        "tx.outputs[3].script",
        "tx.inputs[0].assets[1]",
        "tx.outputs[0].assets.tryLookup(t, g)",
        "tx.input.current.script",
    ] {
        assert!(
            warnings
                .iter()
                .any(|w| w.contains(&format!("`{whole}` is inspected more than once"))),
            "{whole}: {warnings:?}"
        );
    }
    assert!(
        warnings.iter().any(|w| w.contains("require(x.found);")),
        "{warnings:?}"
    );
}

#[test]
fn exclusive_or_unstable_reads_do_not_warn() {
    let code = r#"
        contract C(bytes program) {
            function spend(int i) {
                if (i == 0) {
                    require(tx.outputs[0].scriptPubKey == program);
                } else {
                    require(tx.outputs[0].witnessVersion == 1);
                }
                require(tx.outputs[i].scriptPubKey == program);
                i = i + 1;
                require(tx.outputs[i].witnessVersion == 1);
                let s = tx.outputs[1].script;
                require(s.program == program && s.version == 1);
            }
        }
    "#;
    let warnings = compile(code).expect("compiles").warnings;
    assert!(
        !warnings.iter().any(|w| w.contains("is inspected")),
        "{warnings:?}"
    );
}
