use arkade_compiler::compile;

#[test]
fn forfeit_leaf_without_server_is_rejected() {
    let src = r#"
contract Demo(pubkey owner, pubkey liquidator) {
    function liquidate(signature liquidatorSig, signature ownerSig) tapscript {
        require(checkMultisig([liquidator, owner], [liquidatorSig, ownerSig], 2));
    }
}
"#;
    let err = compile(src)
        .expect_err("forfeit without server must fail")
        .to_string();
    assert!(err.contains("server"), "got: {err}");
}

#[test]
fn standalone_emulator_is_rejected() {
    let src = r#"
contract Demo(pubkey owner) {
    function weird(signature serverSig, signature emulatorSig) tapscript {
        require(checkMultisig([server, emulator], [serverSig, emulatorSig], 2));
    }
}
"#;
    // `weird` matches no function → bare emulator forbidden.
    let err = compile(src)
        .expect_err("bare emulator in standalone must fail")
        .to_string();
    assert!(err.contains("standalone"), "got: {err}");
}

#[test]
fn output_invariant_every_group_has_at_least_one_leaf() {
    let src = r#"
contract Demo(pubkey owner) {
    function spend() { require(tx.outputs[0].value >= 1); }
}
"#;
    let out = compile(src).expect("compile");
    for g in &out.functions {
        assert!(!g.leaves.is_empty(), "group {} has no leaves", g.name);
        for leaf in &g.leaves {
            assert!(!leaf.asm.is_empty(), "leaf {} has empty asm", leaf.name);
        }
    }
}
