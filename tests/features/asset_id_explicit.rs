//! Tests for the `AssetId` operand of asset lookups: `lookup`, the
//! `has`/`controlIs`/`hasControl` predicates, the `(result, success_flag)`
//! opcode ABI handling, and fatal operand validation.

use crate::common::compile_unoptimized as compile;

/// Return the covenant ASM for `func` in the compiled output of `src`.
fn arkade_asm(src: &str, func: &str) -> String {
    let out = compile(src).unwrap_or_else(|e| panic!("compile failed: {e:?}"));
    crate::common::arkade_asm(&out, func)
}

// ─── Result + success flag ABI ──────────────────────────────────────────────

#[test]
fn lookup_consumes_success_flag_with_single_verify() {
    let src = "contract C(AssetId fooId, pubkey pk) {
            function f(signature sig) {
                require(tx.outputs[0].assets.lookup(fooId) >= 1);
                require(checkSig(sig, pk));
            }
        }";
    let asm = arkade_asm(src, "f");
    // lookup opcode is immediately followed by OP_VERIFY to consume the flag.
    assert!(asm.contains("OP_INSPECTOUTASSETLOOKUP OP_VERIFY"), "{asm}");
}

#[test]
fn group_lookup_leaves_k_via_verify_in_let_binding() {
    let src = "contract C(AssetId fooId, pubkey pk) {
            function f(signature sig) {
                let g = tx.assetGroups.lookup(fooId);
                require(g.delta == 0);
                require(checkSig(sig, pk));
            }
        }";
    let asm = arkade_asm(src, "f");
    assert!(
        asm.contains("OP_FINDASSETGROUPBYASSETID OP_VERIFY"),
        "lookup must consume the success flag with OP_VERIFY: {asm}"
    );
}

#[test]
fn group_lookup_takes_a_literal_typed_by_its_position() {
    let src = "contract C(bytes32 fooTxid, pubkey pk) {
            function f(signature sig) {
                let g = tx.assetGroups.lookup({ txid: fooTxid, gidx: 0 });
                require(g.delta == 0);
                require(checkSig(sig, pk));
            }
        }";
    let asm = arkade_asm(src, "f");
    assert!(
        asm.contains("<fooTxid> 0 OP_FINDASSETGROUPBYASSETID OP_VERIFY"),
        "{asm}"
    );
}

#[test]
fn bare_group_lookup_requirement_drops_k_and_pushes_true() {
    // k == 0 is a valid successful lookup but false as a Script boolean, so the
    // dummy `== true` path must emit `lookup … OP_DROP OP_1`, not leave k.
    let src = "contract C(AssetId fooId, pubkey pk) {
            function f(signature sig) {
                require(tx.assetGroups.lookup(fooId));
                require(checkSig(sig, pk));
            }
        }";
    let asm = arkade_asm(src, "f");
    assert!(
        asm.contains("OP_FINDASSETGROUPBYASSETID OP_VERIFY OP_DROP OP_1"),
        "bare lookup must emit lookup + OP_DROP OP_1: {asm}"
    );
}

// ─── has predicate (presence Bool) ──────────────────────────────────────────

#[test]
fn asset_has_keeps_flag_drops_amount() {
    let src = "contract C(AssetId fooId, pubkey pk) {
            function f(signature sig) {
                require(tx.outputs[0].assets.has(fooId));
                require(tx.inputs[0].assets.has(fooId) == false);
                require(checkSig(sig, pk));
            }
        }";
    let asm = arkade_asm(src, "f");
    assert!(asm.contains("OP_INSPECTOUTASSETLOOKUP OP_NIP"), "{asm}");
    assert!(asm.contains("OP_INSPECTINASSETLOOKUP OP_NIP"), "{asm}");
}

#[test]
fn group_has_keeps_flag_drops_k() {
    let src = "contract C(AssetId fooId, pubkey pk) {
            function f(signature sig) {
                require(tx.assetGroups.has(fooId));
                require(checkSig(sig, pk));
            }
        }";
    let asm = arkade_asm(src, "f");
    assert!(asm.contains("OP_FINDASSETGROUPBYASSETID OP_NIP"), "{asm}");
}

#[test]
fn general_expression_parses_group_has_in_if_condition() {
    let src = "contract C(AssetId fooId, pubkey pk) {
            function f(signature sig) {
                if (tx.assetGroups.has(fooId)) {
                    require(checkSig(sig, pk));
                } else {
                    require(checkSig(sig, pk));
                }
            }
        }";
    let asm = arkade_asm(src, "f");
    assert!(
        asm.contains("OP_FINDASSETGROUPBYASSETID OP_NIP OP_IF"),
        "{asm}"
    );
}

// ─── controlIs / hasControl ─────────────────────────────────────────────────

#[test]
fn control_is_compares_both_components_without_equalverify() {
    let src = "contract C(AssetId fooId, pubkey pk) {
            function f(signature sig) {
                let g = tx.assetGroups.lookup(fooId);
                require(g.controlIs(fooId));
                require(checkSig(sig, pk));
            }
        }";
    let asm = arkade_asm(src, "f");
    // [ctrl_txid, ctrl_gidx, flag] OP_DROP, then compare both, then OP_BOOLAND.
    assert!(
        asm.contains("OP_INSPECTASSETGROUPCTRL OP_DROP"),
        "controlIs must drop the success flag: {asm}"
    );
    assert!(asm.contains("OP_SWAP"), "{asm}");
    assert!(asm.contains("OP_BOOLAND"), "{asm}");
    assert!(
        !asm.contains("OP_EQUALVERIFY"),
        "controlIs equality must not abort on mismatch: {asm}"
    );
}

#[test]
fn has_control_is_presence_only() {
    let src = "contract C(AssetId fooId, pubkey pk) {
            function f(signature sig) {
                let g = tx.assetGroups.lookup(fooId);
                require(g.hasControl == true);
                require(checkSig(sig, pk));
            }
        }";
    let asm = arkade_asm(src, "f");
    assert!(
        asm.contains("OP_INSPECTASSETGROUPCTRL OP_NIP OP_NIP"),
        "{asm}"
    );
}

#[test]
fn control_asset_id_asserts_presence_and_binds_an_asset_id() {
    let src = "contract C(AssetId fooId, pubkey pk) {
            function f(signature sig) {
                let g = tx.assetGroups.lookup(fooId);
                AssetId control = g.controlAssetId;
                require(control.txid == fooId.txid);
                require(control.gidx == fooId.gidx);
                require(checkSig(sig, pk));
            }
        }";
    let asm = arkade_asm(src, "f");
    assert!(asm.contains("OP_INSPECTASSETGROUPCTRL OP_VERIFY"), "{asm}");
}

#[test]
fn control_asset_id_binds_without_a_declared_type() {
    let src = "contract C(AssetId fooId) {
            function f() {
                let g = tx.assetGroups.lookup(fooId);
                let control = g.controlAssetId;
                require(control.txid == fooId.txid);
                require(control.gidx == fooId.gidx);
            }
        }";
    let typed = src.replace("let control", "AssetId control");
    assert_eq!(arkade_asm(src, "f"), arkade_asm(&typed, "f"));
}

#[test]
fn control_asset_id_is_typed() {
    let src = "contract C(AssetId fooId) { function f() {
            let g = tx.assetGroups.lookup(fooId); require(g.controlAssetId == fooId.txid);
        } }";
    let error = compile(src).expect_err(src).to_string();
    assert!(
        error.contains("comparison '==' is not defined between 'AssetId' and 'bytes32'"),
        "{error}"
    );
}

#[test]
fn legacy_control_property_is_rejected() {
    let src = "contract C(AssetId fooId, pubkey pk) {
            function f(signature sig) {
                let g = tx.assetGroups.lookup(fooId);
                require(g.control == fooId.txid);
                require(checkSig(sig, pk));
            }
        }";
    assert!(compile(src).is_err(), "`.control` is not valid syntax");
}

// ─── Minimal ScriptNum encoding for a literal gidx ──────────────────────────

#[test]
fn literal_zero_gidx_is_minimal() {
    let src = "contract C(bytes32 fooTxid, pubkey pk) {
            function f(signature sig) {
                require(tx.outputs[0].assets.lookup(AssetId { txid: fooTxid, gidx: 0 }) >= 1);
                require(checkSig(sig, pk));
            }
        }";
    let asm = arkade_asm(src, "f");
    // gidx pushes a single minimal "0" token, not a padded "00 00".
    assert!(
        asm.contains("<fooTxid> 0 OP_INSPECTOUTASSETLOOKUP"),
        "{asm}"
    );
    assert!(!asm.contains("00 00"), "{asm}");
}

// ─── Rejection of malformed call forms ──────────────────────────────────────

fn rejects(body: &str) {
    let src = format!(
        "contract C(AssetId fooId, pubkey pk) {{
            function f(signature sig) {{ {body} require(checkSig(sig, pk)); }}
        }}"
    );
    assert!(compile(&src).is_err(), "expected rejection for: {body}");
}

#[test]
fn rejects_a_txid_alone() {
    rejects("require(tx.outputs[0].assets.lookup(fooId.txid) >= 1);");
}

#[test]
fn rejects_a_txid_alone_in_a_group_lookup() {
    rejects("let g = tx.assetGroups.lookup(fooId.txid); require(g.delta == 0);");
}

#[test]
fn rejects_txid_and_gidx_operands_and_find() {
    rejects("require(tx.outputs[0].assets.lookup(fooId.txid, fooId.gidx) >= 1);");
    rejects("require(tx.assetGroups.has(fooId.txid, fooId.gidx));");
    rejects("let g = tx.assetGroups[0]; require(g.controlIs(fooId.txid, fooId.gidx));");
    rejects("let g = tx.assetGroups.find(fooId); require(g.delta == 0);");
}

// ─── Fatal operand validation ───────────────────────────────────────────────

#[test]
fn rejects_swapped_txid_gidx_operands() {
    // txid is an int, gidx is a bytes32 -> both wrong.
    let src = "contract C(AssetId fooId, pubkey pk) {
            function f(signature sig) {
                require(tx.outputs[0].assets.lookup({ txid: fooId.gidx, gidx: fooId.txid }) >= 1);
                require(checkSig(sig, pk));
            }
        }";
    assert!(compile(src).is_err(), "swapped operands must be rejected");
}

#[test]
fn rejects_out_of_range_literal_gidx() {
    // An AssetId literal is range-checked wherever it is, and an untyped one as a lookup operand.
    for body in [
        "require(tx.outputs[0].assets.lookup({ txid: fooTxid, gidx: 70000 }) >= 1);",
        "let id = AssetId { txid: fooTxid, gidx: 70000 }; require(tx.outputs[0].assets.has(id));",
    ] {
        let src = format!(
            "contract C(bytes32 fooTxid, pubkey pk) {{
                function f(signature sig) {{ {body} require(checkSig(sig, pk)); }}
            }}"
        );
        let err = compile(&src)
            .expect_err("out-of-range gidx must be rejected")
            .to_string();
        assert!(err.contains("gidx 70000 is out of range"), "{body}: {err}");
    }
}

#[test]
fn rejects_bad_gidx_in_right_hand_comparison_operand() {
    // The Asset ID walker must validate *both* sides of a comparison, not just
    // the left. The left operand is a valid lookup; the malformed one (gidx
    // 70000) is the right-hand operand.
    let src = "contract C(bytes32 fooTxid, pubkey pk) {
            function f(signature sig) {
                require(tx.inputs[0].assets.lookup({ txid: fooTxid, gidx: 5 })
                    >= tx.outputs[0].assets.lookup({ txid: fooTxid, gidx: 70000 }));
                require(checkSig(sig, pk));
            }
        }";
    let err = compile(src)
        .expect_err("out-of-range gidx in RHS operand must be rejected")
        .to_string();
    assert!(err.contains("out of range"), "unexpected error: {err}");
}

#[test]
fn rejects_bad_gidx_in_if_condition_predicate() {
    // A `has()` predicate nested in an `if` condition must still be validated.
    let src = "contract C(bytes32 fooTxid, pubkey pk) {
            function f(signature sig) {
                if (tx.outputs[0].assets.has({ txid: fooTxid, gidx: 70000 })) {
                    require(checkSig(sig, pk));
                }
                require(checkSig(sig, pk));
            }
        }";
    let err = compile(src)
        .expect_err("out-of-range gidx in if-condition must be rejected")
        .to_string();
    assert!(err.contains("out of range"), "unexpected error: {err}");
}

#[test]
fn accepts_loop_index_as_gidx() {
    // The loop index variable is statically Int, so it is a valid gidx operand.
    let src = "contract C(bytes32 fooTxid, pubkey pk) {
            function f(signature sig, signature[3] sigs) {
                for (i, s) in sigs {
                    require(tx.outputs[i].assets.lookup(AssetId { txid: fooTxid, gidx: i }) >= 1);
                }
                require(checkSig(sig, pk));
            }
        }";
    assert!(
        compile(src).is_ok(),
        "loop index as gidx should compile: {:?}",
        compile(src).err()
    );
}

// ─── Computed indexes and Asset ID operands ─────────────────────────────────

#[test]
fn computed_indexes_unroll_in_nested_loops() {
    let asm = arkade_asm(
        "contract C(bytes32 fooTxid, int packetType) {
            function f(int[2] xs, int[2] ys) {
                for (i, x) in xs {
                    for (j, y) in ys {
                        require(tx.inputs[i + j].value >= tx.outputs[i * 2 + j].value);
                        require(tx.outputs[j].assets.lookup({ txid: fooTxid, gidx: i + j }) >= x + y);
                        require(tx.assetGroups[i + j].delta >= 0);
                        require(size(tx.inputs[i].packet(packetType + j)) > 0);
                    }
                }
            }
        }",
        "f",
    );
    for fragment in [
        "1 1 OP_ADD OP_INSPECTINPUTVALUE 1 2 OP_MUL 1 OP_ADD OP_INSPECTOUTPUTVALUE",
        "1 OP_1 OP_PICK 1 1 OP_ADD OP_INSPECTOUTASSETLOOKUP",
        "1 1 OP_ADD OP_DUP OP_1 OP_INSPECTASSETGROUPSUM",
        "1 OP_ADD 1 OP_INSPECTINPUTPACKET",
    ] {
        assert!(asm.contains(fragment), "missing `{fragment}` in:\n{asm}");
    }
}

#[test]
fn constant_gidx_expressions_are_typed_and_range_checked() {
    let gidx_error = |gidx: &str| {
        compile(&format!(
            "contract C(bytes32 fooTxid) {{
                const int G = 65535;
                function f() {{ require(tx.outputs[0].assets.lookup(AssetId {{ txid: fooTxid, gidx: {gidx} }}) >= 1); }}
            }}"
        ))
        .err()
        .map(|err| err.to_string())
    };
    assert_eq!(gidx_error("G - 1"), None);
    for (gidx, expected) in [
        ("G + 1", "gidx 65536 is out of range"),
        ("-1", "gidx -1 is out of range"),
        ("0 - 1", "gidx -1 is out of range"),
        (
            "99999999999999999999",
            "gidx 99999999999999999999 is out of range",
        ),
        (
            "170141183460469231731687303715884105727 + 1",
            "integer overflow",
        ),
        ("~0x0001", "field 'gidx': expected 'int', got 'bytes'"),
        ("1 == 1", "field 'gidx': expected 'int', got 'bool'"),
    ] {
        let err = gidx_error(gidx).unwrap_or_else(|| panic!("{gidx} must be rejected"));
        assert!(err.contains(expected), "{gidx}: {err}");
    }
}

#[test]
fn unnamed_asset_id_literals_are_range_checked_wherever_typed() {
    for body in [
        "AssetId id = { txid: t, gidx: 70000 }; require(tx.inputs[0].assets.lookup(id) >= 1);",
        "AssetEntry e = { assetId: { txid: t, gidx: 70000 }, amount: 1 }; require(tx.inputs[0].assets.lookup(e.assetId) >= e.amount);",
        "require(h({ txid: t, gidx: 70000 }) >= 1);",
        "require(w == { txid: t, gidx: 70000 });",
    ] {
        let err = compile(&format!(
            "contract C(bytes32 t, AssetId w) {{
                private function h(AssetId id) int {{ return tx.inputs[0].assets.lookup(id); }}
                function f() {{ {body} }}
            }}"
        ))
        .err()
        .unwrap_or_else(|| panic!("{body} must be rejected"))
        .to_string();
        assert!(err.contains("gidx 70000 is out of range"), "{body}: {err}");
    }
}

#[test]
fn control_is_accepts_computed_gidx() {
    let asm = arkade_asm(
        "contract C(bytes32 fooTxid) {
            function f(int k) {
                let g = tx.assetGroups[k];
                require(g.controlIs(AssetId { txid: fooTxid, gidx: k + 1 }));
            }
        }",
        "f",
    );
    assert!(
        asm.contains("OP_INSPECTASSETGROUPCTRL OP_DROP") && asm.contains("1 OP_ADD OP_NUMEQUAL"),
        "{asm}"
    );
}

#[test]
fn control_is_compares_a_computed_asset_id_evaluated_once() {
    let asm = arkade_asm(
        "contract C() {
            function f() {
                require(tx.assetGroups[0].controlIs(tx.inputs[0].assets[1].assetId));
            }
        }",
        "f",
    );
    assert!(
        asm.contains("OP_INSPECTASSETGROUPCTRL OP_DROP 0 1 OP_INSPECTINASSETAT OP_DROP OP_ROT OP_NUMEQUAL OP_SWAP OP_ROT OP_EQUAL OP_BOOLAND"),
        "{asm}"
    );
}

#[test]
fn asset_id_operands_accept_any_asset_id_expression_at_every_site() {
    let compile_site = |site: &str, id: &str| {
        compile(&format!(
            "struct Holder {{ AssetId id; }}
            @allow(unused-parameter, \"each site reads one\")
            contract C(bytes data, AssetId[2] ids, Holder holder, AssetId param) {{
                function f() {{ {} }}
                private function id(bytes d) bytes32 {{ return sha256(d + d); }}
                private function make(int n) AssetId {{ return ids[n]; }}
            }}",
            site.replace("ID", id)
        ))
    };
    let literal = format!("0x{}", "01".repeat(32));
    for site in [
        "require(tx.inputs[0].assets.lookup(ID) >= 1);",
        "let x = tx.outputs[0].assets.tryLookup(ID); require(x.found);",
        "require(tx.outputs[0].assets.has(ID));",
        "require(tx.assetGroups.has(ID));",
        "require(tx.assetGroups.lookup(ID).delta == 0);",
        "require(tx.assetGroups[0].controlIs(ID));",
        "let g = tx.assetGroups[0]; require(g.controlIs(ID));",
    ] {
        // A binding's fields are pushed like a literal's.
        let fields = compile_site(site, "{ txid: param.txid, gidx: param.gidx }").unwrap();
        let whole = compile_site(site, "param").unwrap();
        assert_eq!(
            crate::common::arkade_asm(&fields, "f"),
            crate::common::arkade_asm(&whole, "f"),
            "{site}"
        );
        for id in [
            "holder.id",
            "ids[1]",
            "make(1)",
            "tx.inputs[0].assets[0].assetId",
            "tx.assetGroups[1].controlAssetId",
            "AssetId { txid: ids[0].txid, gidx: 1 }",
        ] {
            compile_site(site, id).unwrap_or_else(|error| panic!("{site} with {id}: {error}"));
        }
        // Each txid is emitted exactly once.
        for (txid, emitted) in [
            (literal.as_str(), literal.as_str()),
            ("sha256(data)", "OP_SHA256"),
            ("id(data)", "OP_CAT OP_SHA256"),
            ("ids[1].txid", "<ids.1.txid>"),
        ] {
            let id = format!("AssetId {{ txid: {txid}, gidx: 2 }}");
            let output =
                compile_site(site, &id).unwrap_or_else(|error| panic!("{site} with {id}: {error}"));
            let asm = crate::common::arkade_asm(&output, "f");
            assert_eq!(asm.matches(emitted).count(), 1, "{site} with {id}: {asm}");
        }
        for (id, expected) in [
            (
                "{ txid: 0x0101, gidx: 2 }",
                "field 'txid': expected 'bytes32', got 'bytes'",
            ),
            (
                "{ txid: ids[1].gidx, gidx: 2 }",
                "expected 'bytes32', got 'int'",
            ),
            (
                "{ txid: sha256(data), gidx: 70000 }",
                "gidx 70000 is out of range",
            ),
            ("ids[1].txid", "asset id: expected 'AssetId', got 'bytes32'"),
            (
                "tx.inputs[0].assets[0]",
                "expected 'AssetId', got 'AssetEntry'",
            ),
            (
                "ECPoint { x: 1, y: 2 }",
                "expected 'AssetId', got 'ECPoint'",
            ),
        ] {
            let error = compile_site(site, id)
                .expect_err("invalid Asset ID operand must be rejected")
                .to_string();
            assert!(error.contains(expected), "{site} with {id}: {error}");
        }
    }
}
