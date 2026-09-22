use arkade_compiler::compile;

#[test]
fn htlc_emits_grouped_leaves_with_arkade_covenants() {
    let src = r#"
contract HTLC(pubkey receiver, pubkey sender, bytes20 preimageHash, int refundTime, int exit) {
    function claim() {
        require(tx.outputs[0].value >= tx.inputs[0].value);
    }
    function refund() {
        require(tx.outputs[0].value >= tx.inputs[0].value);
    }
    function claim(bytes preimage, signature serverSig, signature emulatorSig) tapscript {
        require(hash160(preimage) == preimageHash);
        require(checkMultisig([server, emulator], [serverSig, emulatorSig], 2));
    }
    function refund(signature serverSig, signature emulatorSig) tapscript {
        require(after(refundTime));
        require(checkMultisig([server, emulator], [serverSig, emulatorSig], 2));
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
    // ASM: HASH160 condition + N-of-N [server, emulator(claim)]; no sigs in asm.
    let joined = leaf.asm.join(" ");
    assert!(joined.contains("OP_HASH160"));
    assert!(joined.contains("<SERVER_KEY>"));
    assert!(joined.contains("<EMULATOR_KEY:claim>"));
    assert!(!joined.contains("Sig"));
    // Witness carries the sigs + preimage.
    let wnames: Vec<_> = leaf.witness.iter().map(|w| w.name.clone()).collect();
    assert_eq!(wnames, vec!["preimage", "serverSig", "emulatorSig"]);

    let uni = out
        .functions
        .iter()
        .find(|g| g.name == "unilateral")
        .unwrap();
    assert!(
        uni.arkade.is_none(),
        "standalone leaf has no arkade covenant"
    );
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
    let joined = leaf.asm.join(" ");
    assert!(joined.contains("<SERVER_KEY>"));
    assert!(joined.contains("<EMULATOR_KEY:spend>"));
    // Synthesized leaf still lists serverSig/emulatorSig in witness.
    let wnames: Vec<_> = leaf.witness.iter().map(|w| w.name.clone()).collect();
    assert_eq!(wnames, vec!["serverSig", "emulatorSig"]);
}

#[test]
fn infrastructure_signatures_are_marked_as_injected() {
    let src = r#"
contract Demo(pubkey owner) {
    function claim() {
        require(tx.outputs[0].value >= 1);
    }
    function claim(signature serverSig, signature emulatorSig, signature ownerSig) tapscript {
        require(checkMultisig([server, emulator, owner], [serverSig, emulatorSig, ownerSig], 3));
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

    assert_eq!(injected, vec!["serverSig", "emulatorSig"]);
    assert_eq!(user_supplied, vec!["ownerSig"]);
}

/// Clients build the taproot tree from artifact order, so several standalone
/// leaves must arrive in the order they were declared — not sorted. A 2-of-3
/// exit is written as its pairs, because arkd recognizes only N-of-N closures.
#[test]
fn standalone_leaves_keep_declaration_order() {
    let src = r#"
contract Escrowish(pubkey a, pubkey b, pubkey c, int exit) {
    function spend(signature aSig) {
        require(checkSig(aSig, a));
    }
    function exitZulu(signature bSig, signature cSig) tapscript {
        require(older(exit));
        require(checkMultisig([b, c], [bSig, cSig], 2));
    }
    function exitAlpha(signature aSig, signature bSig) tapscript {
        require(older(exit));
        require(checkMultisig([a, b], [aSig, bSig], 2));
    }
    function exitMike(signature aSig, signature cSig) tapscript {
        require(older(exit));
        require(checkMultisig([a, c], [aSig, cSig], 2));
    }
}
"#;
    let out = compile(src).expect("compile");
    let names: Vec<_> = out.functions.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(
        names,
        ["spend", "exitZulu", "exitAlpha", "exitMike"],
        "covenant groups first, then standalone leaves as written"
    );
}
