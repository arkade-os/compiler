use arkade_compiler::compile;

#[test]
fn forfeit_leaf_without_operator_is_rejected() {
    let src = r#"
contract Demo(pubkey owner, pubkey liquidator) {
    function liquidate(signature liquidatorSig, signature ownerSig) tapscript {
        require(checkMultisig([liquidator, owner], [liquidatorSig, ownerSig]));
    }
}
"#;
    let err = compile(src)
        .expect_err("forfeit without the operator must fail")
        .to_string();
    assert!(
        err.contains("must include `operator` or `tweak(operator, fn)`"),
        "got: {err}"
    );
}

#[test]
fn forfeit_leaf_with_a_tweaked_operator_is_accepted() {
    let src = r#"
contract Demo(pubkey owner, pubkey liquidator) {
    function claim() { require(tx.outputs[0].value >= 1); }
    function liquidate(signature operatorSig, signature ownerSig) tapscript {
        require(checkMultisig([tweak(operator, claim), owner], [operatorSig, ownerSig]));
    }
}
"#;
    let out = compile(src).expect("a tweaked operator key satisfies F2");
    let claim = crate::common::group(&out, "claim");
    assert_eq!(
        claim.leaves.len(),
        1,
        "the forfeit leaf replaces the default"
    );
    assert_eq!(
        claim.leaves[0].asm,
        [
            "<OPERATOR_KEY:claim>",
            "OP_CHECKSIGVERIFY",
            "<owner>",
            "OP_CHECKSIG"
        ]
    );
}

#[test]
fn name_matched_leaf_without_a_tweak_is_rejected() {
    let src = r#"
contract Demo(pubkey owner) {
    function spend() { require(tx.outputs[0].value >= 1); }
    function spend(signature operatorSig, signature ownerSig) tapscript {
        require(checkMultisig([operator, owner], [operatorSig, ownerSig]));
    }
}
"#;
    // Bare `operator` is never tweaked implicitly, so the leaf binds no Arkade Script.
    let err = compile(src)
        .expect_err("a name-matched leaf must tweak a key to its function")
        .to_string();
    assert!(err.contains("must tweak a key to `spend`"), "got: {err}");
}

#[test]
fn name_matched_csv_leaf_is_rejected() {
    let source = |name: &str, preimage: &str, condition: &str| {
        format!(
            r#"
contract Demo(pubkey owner, bytes32 h) {{
    function claim(signature s) {{ require(checkSig(s, owner)); }}
    function {name}({preimage}signature ownerSig) tapscript {{
        {condition}require(older(blocks(144)));
        require(checkSig(ownerSig, tweak(owner, claim)));
    }}
}}"#
        )
    };
    for (preimage, condition) in [("", ""), ("bytes32 p, ", "require(sha256(p) == h); ")] {
        // The default leaf stays beside a CSV leaf and is named `claim` too.
        let err = compile(&source("claim", preimage, condition))
            .expect_err("a CSV leaf named after its function must fail")
            .to_string();
        assert!(
            err.contains("has a CSV delay") && err.contains("give the tapscript another name"),
            "got: {err}"
        );
        let out = compile(&source("claimExit", preimage, condition))
            .expect("a renamed CSV leaf joins the group");
        let claim = crate::common::group(&out, "claim");
        let names: Vec<_> = claim.leaves.iter().map(|leaf| leaf.name.as_str()).collect();
        assert_eq!(names, ["claim", "claimExit"], "{condition}");
        assert_eq!(claim.leaves[0].asm, ["<OPERATOR_KEY:claim>", "OP_CHECKSIG"]);
    }
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

#[test]
fn a_tapscript_input_cannot_be_a_pushed_operand() {
    let cases = [
        (
            "pubkey k",
            "require(checkMultisig([operator, k], [operatorSig, sig]));",
            "a key",
        ),
        (
            "pubkey k",
            "require(checkMultisig([operator, tweak(k, claim)], [operatorSig, sig]));",
            "a key",
        ),
        (
            "bytes32 pre, bytes32 h",
            "require(sha256(pre) == h); \
             require(checkMultisig([operator, owner], [operatorSig, sig]));",
            "a hash value",
        ),
        (
            "int t",
            "require(older(t)); require(checkMultisig([operator, owner], [operatorSig, sig]));",
            "a timelock",
        ),
    ];
    for (inputs, body, role) in cases {
        let src = format!(
            "contract K(pubkey owner) {{\n  function claim({inputs}, signature operatorSig, \
             signature sig) tapscript {{\n    {body}\n  }}\n}}"
        );
        let err = compile(&src)
            .expect_err("an input pushed by the leaf script must fail")
            .to_string();
        assert!(
            err.contains("is a tapscript input") && err.contains(role),
            "{role}: {err}"
        );
    }
}

#[test]
fn a_constructor_parameter_cannot_be_the_preimage() {
    let src = r#"
contract P(pubkey owner, bytes32 pre, bytes32 h) {
    function claim(signature operatorSig, signature sig) tapscript {
        require(sha256(pre) == h);
        require(checkMultisig([operator, owner], [operatorSig, sig]));
    }
}
"#;
    let err = compile(src)
        .expect_err("a preimage missing from the witness must fail")
        .to_string();
    assert!(
        err.contains("hash preimage `pre` is a constructor parameter"),
        "got: {err}"
    );
}

#[test]
fn a_tapscript_input_is_consumed_at_most_once() {
    for (body, location) in [
        (
            "require(checkMultisig([operator, owner], [s, s]));",
            "line 3, column 50",
        ),
        (
            "require(sha256(s) == h); require(older(blocks(144))); require(checkSig(s, owner));",
            "line 3, column 76",
        ),
    ] {
        let src = format!(
            "contract K(pubkey owner, bytes32 h) {{\n  function claim(signature s) tapscript {{\n    \
             {body}\n  }}\n}}"
        );
        let err = compile(&src)
            .expect_err("a leaf consuming one input twice must fail")
            .to_string();
        assert!(
            err.contains(&format!(
                "{location}: tapscript `claim`: input `s` is used more than once"
            )),
            "{body}: {err}"
        );
    }
}
