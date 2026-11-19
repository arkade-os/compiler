use arkade_compiler::compile;

use crate::common::group;

#[test]
fn htlc_emits_grouped_leaves_with_arkade_scripts() {
    let src = r#"
contract HTLC(pubkey receiver, pubkey sender, bytes20 preimageHash, int refundTime, int exit) {
    function claim() {
        require(tx.outputs[0].value >= tx.inputs[0].value);
    }
    function refund() {
        require(tx.outputs[0].value >= tx.inputs[0].value);
    }
    function claim(bytes preimage, signature operatorSig) tapscript {
        require(hash160(preimage) == preimageHash);
        require(checkSig(operatorSig, tweak(operator, claim)));
    }
    function refund(signature operatorSig) tapscript {
        require(after(refundTime));
        require(checkSig(operatorSig, tweak(operator, refund)));
    }
    function unilateral(signature senderSig) tapscript {
        require(older(exit));
        require(checkSig(senderSig, sender));
    }
}
"#;
    let out = compile(src).expect("compile");
    // Groups: claim, refund (function-backed) + unilateral (standalone).
    let names: Vec<_> = out.functions.iter().map(|g| g.name.clone()).collect();
    assert!(names.contains(&"claim".to_string()));
    assert!(names.contains(&"refund".to_string()));
    assert!(names.contains(&"unilateral".to_string()));

    let claim = out.functions.iter().find(|g| g.name == "claim").unwrap();
    assert!(claim.arkade.is_some(), "claim is function-backed");
    assert_eq!(claim.leaves.len(), 1);
    let leaf = &claim.leaves[0];
    // ASM: HASH160 condition + the operator key tweaked by claim; no sigs in asm.
    let joined = leaf.asm.join(" ");
    assert!(joined.contains("OP_HASH160"));
    assert!(joined.ends_with("<OPERATOR_KEY:claim> OP_CHECKSIG"));
    assert!(!joined.contains("Sig"));
    // Witness carries the sig + preimage.
    let wnames: Vec<_> = leaf.witness.iter().map(|w| w.name.clone()).collect();
    assert_eq!(wnames, vec!["preimage", "operatorSig"]);

    let uni = out
        .functions
        .iter()
        .find(|g| g.name == "unilateral")
        .unwrap();
    assert!(uni.arkade.is_none(), "standalone leaf has no Arkade Script");
}

#[test]
fn function_without_leaf_gets_synthesized_default() {
    let src = r#"
contract Demo(pubkey owner) {
    function spend() {
        require(tx.outputs[0].value >= 1);
    }
}
"#;
    let out = compile(src).expect("compile");
    let g = out.functions.iter().find(|g| g.name == "spend").unwrap();
    assert!(g.arkade.is_some());
    assert_eq!(g.leaves.len(), 1, "default collaborative leaf synthesized");
    let leaf = &g.leaves[0];
    assert_eq!(leaf.name, "spend");
    // The operator key tweaked by spend's Arkade Script hash.
    assert_eq!(leaf.asm, ["<OPERATOR_KEY:spend>", "OP_CHECKSIG"]);
    // One injected operator signature.
    let witness: Vec<_> = leaf
        .witness
        .iter()
        .map(|w| (w.name.as_str(), w.elem_type.as_str(), w.injected))
        .collect();
    assert_eq!(witness, [("operatorSig", "signature", true)]);
}

/// The legacy two-key stack, written by hand: the untweaked operator key plus a constructor
/// `emulator` key tweaked by `spend`. The leaf has no CSV delay, so it replaces the default.
#[test]
fn a_forfeit_leaf_tweaked_to_a_function_replaces_its_default_leaf() {
    let src = r#"
contract C(pubkey user, pubkey emulator) {
  function spend(signature userSig) { require(checkSig(userSig, user)); }
  function spendTap(signature operatorSig, signature emulatorSig) tapscript {
    require(checkMultisig([operator, tweak(emulator, spend)], [operatorSig, emulatorSig]));
  }
}
"#;
    let out = compile(src).expect("compile");
    let names: Vec<_> = out.functions.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, ["spend"], "spendTap joins spend's group");
    let spend = group(&out, "spend");
    assert!(spend.arkade.is_some());
    assert_eq!(spend.leaves.len(), 1, "spendTap replaces the default leaf");
    let leaf = &spend.leaves[0];
    assert_eq!(leaf.name, "spendTap");
    assert_eq!(
        leaf.asm,
        [
            "<OPERATOR_KEY>",
            "OP_CHECKSIGVERIFY",
            "<TWEAK:emulator:spend>",
            "OP_CHECKSIG"
        ]
    );
    let witness: Vec<_> = leaf
        .witness
        .iter()
        .map(|w| (w.name.as_str(), w.injected))
        .collect();
    assert_eq!(witness, [("operatorSig", true), ("emulatorSig", false)]);
}

#[test]
fn infrastructure_signatures_are_marked_as_injected() {
    let src = r#"
contract Demo(pubkey owner) {
    function claim() {
        require(tx.outputs[0].value >= 1);
    }
    function claim(signature operatorSig, signature boundSig, signature ownerSig) tapscript {
        require(checkMultisig([operator, tweak(operator, claim), owner], [operatorSig, boundSig, ownerSig]));
    }
}
"#;
    let out = compile(src).expect("compile");
    let leaf = &out
        .functions
        .iter()
        .find(|g| g.name == "claim")
        .expect("claim group")
        .leaves[0];

    let injected: Vec<_> = leaf
        .witness
        .iter()
        .filter(|w| w.injected)
        .map(|w| w.name.as_str())
        .collect();
    let user_supplied: Vec<_> = leaf
        .witness
        .iter()
        .filter(|w| !w.injected)
        .map(|w| w.name.as_str())
        .collect();

    assert_eq!(injected, vec!["operatorSig", "boundSig"]);
    assert_eq!(user_supplied, vec!["ownerSig"]);
}

#[test]
fn standalone_leaves_keep_declaration_order() {
    let src = r#"
contract Escrowish(pubkey a, pubkey b, pubkey c, int exit) {
    function exitZulu(signature bSig, signature cSig) tapscript {
        require(older(exit));
        require(checkMultisig([b, c], [bSig, cSig]));
    }
    function spend(signature aSig) {
        require(checkSig(aSig, a));
    }
    function boundZulu(signature aSig) tapscript {
        require(older(exit));
        require(checkSig(aSig, tweak(a, spend)));
    }
    function exitAlpha(signature aSig, signature bSig) tapscript {
        require(older(exit));
        require(checkMultisig([a, b], [aSig, bSig]));
    }
    function refund(signature cSig) {
        require(checkSig(cSig, c));
    }
    function boundAlpha(signature aSig) tapscript {
        require(older(exit));
        require(checkSig(aSig, tweak(a, spend)));
    }
    function exitMike(signature aSig, signature cSig) tapscript {
        require(older(exit));
        require(checkMultisig([a, c], [aSig, cSig]));
    }
}
"#;
    let out = compile(src).expect("compile");
    let names: Vec<_> = out.functions.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(
        names,
        ["spend", "refund", "exitZulu", "exitAlpha", "exitMike"],
        "Arkade Script function groups first, then standalone leaves as written"
    );

    let spend = group(&out, "spend");
    assert!(spend.arkade.is_some());
    assert_eq!(
        spend
            .leaves
            .iter()
            .map(|leaf| leaf.name.as_str())
            .collect::<Vec<_>>(),
        ["spend", "boundZulu", "boundAlpha"]
    );
    assert_eq!(spend.leaves[0].asm, ["<OPERATOR_KEY:spend>", "OP_CHECKSIG"]);
    for leaf in &spend.leaves[1..] {
        assert!(leaf.asm.contains(&"<TWEAK:a:spend>".to_string()));
    }
    assert!(group(&out, "refund").arkade.is_some());

    for (name, keys, witnesses) in [
        ("exitZulu", ["<b>", "<c>"], ["bSig", "cSig"]),
        ("exitAlpha", ["<a>", "<b>"], ["aSig", "bSig"]),
        ("exitMike", ["<a>", "<c>"], ["aSig", "cSig"]),
    ] {
        let standalone = group(&out, name);
        assert!(standalone.arkade.is_none());
        assert_eq!(standalone.leaves.len(), 1);
        let leaf = &standalone.leaves[0];
        assert_eq!(leaf.name, name);
        assert_eq!(
            leaf.asm,
            [
                "<exit>",
                "OP_CHECKSEQUENCEVERIFY",
                "OP_DROP",
                keys[0],
                "OP_CHECKSIGVERIFY",
                keys[1],
                "OP_CHECKSIG"
            ]
        );
        assert_eq!(
            leaf.witness
                .iter()
                .map(|w| w.name.as_str())
                .collect::<Vec<_>>(),
            witnesses
        );
        assert!(leaf
            .witness
            .iter()
            .all(|w| !w.injected && w.elem_type == "signature"));
    }
}

#[test]
fn standalone_only_leaves_keep_declaration_order() {
    let out = compile(
        r#"
contract Exits(pubkey owner) {
    function zulu(signature sig) tapscript {
        require(older(operatorExitDelay));
        require(checkSig(sig, owner));
    }
    function alpha(signature sig) tapscript {
        require(older(operatorExitDelay));
        require(checkSig(sig, owner));
    }
}
"#,
    )
    .expect("compile");
    assert_eq!(
        out.functions
            .iter()
            .map(|g| g.name.as_str())
            .collect::<Vec<_>>(),
        ["zulu", "alpha"]
    );
    assert!(out
        .functions
        .iter()
        .all(|g| g.arkade.is_none() && g.leaves.len() == 1));
}
