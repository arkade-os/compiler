//! Tests for the explicit canonical `(asset_txid, asset_gidx)` Asset ID design:
//! two-operand lookup/find, the `has`/`controlIs`/`hasControl` predicates, the
//! `(result, success_flag)` opcode ABI handling, fatal operand validation, and
//! parser rejection of the legacy single-argument forms.

mod common;

use arkade_compiler::compile;

/// Return the covenant ASM for `func` in the compiled output of `src`.
fn arkade_asm(src: &str, func: &str) -> String {
    let out = compile(src).unwrap_or_else(|e| panic!("compile failed: {e:?}"));
    common::arkade_asm(&out, func)
}

// ─── Result + success flag ABI ──────────────────────────────────────────────

#[test]
fn lookup_consumes_success_flag_with_single_verify() {
    let src = "contract C(bytes32 fooTxid, int fooGidx, pubkey pk) {
            function f(signature sig) {
                require(tx.outputs[0].assets.lookup(fooTxid, fooGidx) >= 1);
                require(checkSig(sig, pk));
            }
        }";
    let asm = arkade_asm(src, "f");
    // lookup opcode is immediately followed by OP_VERIFY to consume the flag.
    assert!(asm.contains("OP_INSPECTOUTASSETLOOKUP OP_VERIFY"), "{asm}");
}

#[test]
fn find_leaves_k_via_verify_in_let_binding() {
    let src = "contract C(bytes32 fooTxid, int fooGidx, pubkey pk) {
            function f(signature sig) {
                let g = tx.assetGroups.find(fooTxid, fooGidx);
                require(g.delta == 0);
                require(checkSig(sig, pk));
            }
        }";
    let asm = arkade_asm(src, "f");
    assert!(
        asm.contains("OP_FINDASSETGROUPBYASSETID OP_VERIFY"),
        "find must consume the success flag with OP_VERIFY: {asm}"
    );
}

#[test]
fn general_expression_parses_group_find_with_literal_gidx_in_let_binding() {
    let src = "contract C(bytes32 fooTxid, pubkey pk) {
            function f(signature sig) {
                let g = tx.assetGroups.find(fooTxid, 0);
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
fn bare_find_requirement_drops_k_and_pushes_true() {
    // k == 0 is a valid successful find but false as a Script boolean, so the
    // dummy `== true` path must emit `find … OP_DROP OP_1`, not leave k.
    let src = "contract C(bytes32 fooTxid, int fooGidx, pubkey pk) {
            function f(signature sig) {
                require(tx.assetGroups.find(fooTxid, fooGidx));
                require(checkSig(sig, pk));
            }
        }";
    let asm = arkade_asm(src, "f");
    assert!(
        asm.contains("OP_FINDASSETGROUPBYASSETID OP_VERIFY OP_DROP OP_1"),
        "bare find must emit find + OP_DROP OP_1: {asm}"
    );
}

// ─── has predicate (presence Bool) ──────────────────────────────────────────

#[test]
fn asset_has_keeps_flag_drops_amount() {
    let src = "contract C(bytes32 fooTxid, int fooGidx, pubkey pk) {
            function f(signature sig) {
                require(tx.outputs[0].assets.has(fooTxid, fooGidx));
                require(tx.inputs[0].assets.has(fooTxid, fooGidx) == 0);
                require(checkSig(sig, pk));
            }
        }";
    let asm = arkade_asm(src, "f");
    assert!(asm.contains("OP_INSPECTOUTASSETLOOKUP OP_NIP"), "{asm}");
    assert!(asm.contains("OP_INSPECTINASSETLOOKUP OP_NIP"), "{asm}");
}

#[test]
fn group_has_keeps_flag_drops_k() {
    let src = "contract C(bytes32 fooTxid, int fooGidx, pubkey pk) {
            function f(signature sig) {
                require(tx.assetGroups.has(fooTxid, fooGidx));
                require(checkSig(sig, pk));
            }
        }";
    let asm = arkade_asm(src, "f");
    assert!(asm.contains("OP_FINDASSETGROUPBYASSETID OP_NIP"), "{asm}");
}

#[test]
fn general_expression_parses_group_has_in_if_condition() {
    let src = "contract C(bytes32 fooTxid, int fooGidx, pubkey pk) {
            function f(signature sig) {
                if (tx.assetGroups.has(fooTxid, fooGidx)) {
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
    let src = "contract C(bytes32 fooTxid, int fooGidx, pubkey pk) {
            function f(signature sig) {
                let g = tx.assetGroups.find(fooTxid, fooGidx);
                require(g.controlIs(fooTxid, fooGidx));
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
    let src = "contract C(bytes32 fooTxid, int fooGidx, pubkey pk) {
            function f(signature sig) {
                let g = tx.assetGroups.find(fooTxid, fooGidx);
                require(g.hasControl == 1);
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
fn legacy_control_property_is_rejected() {
    let src = "contract C(bytes32 fooTxid, int fooGidx, pubkey pk) {
            function f(signature sig) {
                let g = tx.assetGroups.find(fooTxid, fooGidx);
                require(g.control == fooTxid);
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
                require(tx.outputs[0].assets.lookup(fooTxid, 0) >= 1);
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

// ─── Parser rejection of legacy / malformed call forms ──────────────────────

fn rejects(body: &str) {
    let src = format!(
        "contract C(bytes32 fooTxid, int fooGidx, pubkey pk) {{
            function f(signature sig) {{ {body} require(checkSig(sig, pk)); }}
        }}"
    );
    assert!(compile(&src).is_err(), "expected rejection for: {body}");
}

#[test]
fn rejects_legacy_single_arg_lookup() {
    rejects("require(tx.outputs[0].assets.lookup(fooTxid) >= 1);");
}

#[test]
fn rejects_single_arg_find() {
    rejects("let g = tx.assetGroups.find(fooTxid); require(g.delta == 0);");
}

#[test]
fn rejects_extra_arg_lookup() {
    rejects("require(tx.outputs[0].assets.lookup(fooTxid, fooGidx, fooGidx) >= 1);");
}

// ─── Fatal operand validation ───────────────────────────────────────────────

#[test]
fn rejects_swapped_txid_gidx_operands() {
    // txid is an int param, gidx is a bytes32 param -> both wrong.
    let src = "contract C(bytes32 fooTxid, int fooGidx, pubkey pk) {
            function f(signature sig) {
                require(tx.outputs[0].assets.lookup(fooGidx, fooTxid) >= 1);
                require(checkSig(sig, pk));
            }
        }";
    assert!(compile(src).is_err(), "swapped operands must be rejected");
}

#[test]
fn rejects_out_of_range_literal_gidx() {
    let src = "contract C(bytes32 fooTxid, pubkey pk) {
            function f(signature sig) {
                require(tx.outputs[0].assets.lookup(fooTxid, 70000) >= 1);
                require(checkSig(sig, pk));
            }
        }";
    let err = compile(src)
        .expect_err("out-of-range gidx must be rejected")
        .to_string();
    assert!(err.contains("out of range"), "unexpected error: {err}");
}

#[test]
fn rejects_bad_gidx_in_right_hand_comparison_operand() {
    // The Asset ID walker must validate *both* sides of a comparison, not just
    // the left. The left operand is a valid lookup; the malformed one (gidx
    // 70000) is the right-hand operand.
    let src = "contract C(bytes32 fooTxid, pubkey pk) {
            function f(signature sig) {
                require(tx.inputs[0].assets.lookup(fooTxid, 5)
                    >= tx.outputs[0].assets.lookup(fooTxid, 70000));
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
                if (tx.outputs[0].assets.has(fooTxid, 70000)) {
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
            function f(signature sig, signature[] sigs) {
                for (i, s) in sigs {
                    require(tx.outputs[i].assets.lookup(fooTxid, i) >= 1);
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
