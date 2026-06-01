use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CAT, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_DIV64,
    OP_FINDASSETGROUPBYASSETID, OP_INSPECTASSETGROUPCTRL, OP_INSPECTASSETGROUPSUM,
    OP_INSPECTINPUTSCRIPTPUBKEY, OP_INSPECTOUTASSETLOOKUP, OP_INSPECTOUTPUTSCRIPTPUBKEY,
    OP_INSPECTOUTPUTVALUE, OP_LESSTHAN, OP_LESSTHANOREQUAL, OP_MUL64, OP_SHA256,
};

mod common;
use common::{asm_of, asm_tokens, asm_variant, opcode_count, user_signatures, witness_names};

const CODE: &str = include_str!("../examples/bonds/repayment_pool.ark");

#[test]
fn test_repayment_pool_compiles() {
    let output = compile(CODE).expect("compilation failed");
    assert_eq!(output.name, "RepaymentPool");
    // 5 functions (issue, acceptRepayment, liquidate, acceptAuction, redeem)
    // × 2 variants = 10
    // 7 functions (issue, acceptRepayment, rollOut, rollIn, liquidate,
    // acceptAuction, redeem) × 2 variants = 14
    assert_eq!(output.functions.len(), 14, "expected 14 functions");

    let names: Vec<&str> = output.parameters.iter().map(|p| p.name.as_str()).collect();
    for id in [
        "usdtAssetId",
        "creditAssetId",
        "creditCtrlId",
        "debitAssetId",
        "debitCtrlId",
    ] {
        assert!(
            names.contains(&format!("{id}_txid").as_str())
                && names.contains(&format!("{id}_gidx").as_str()),
            "{id} not decomposed, got: {names:?}"
        );
    }
    // Phased timeline + margin-call threshold + auction-incentive surface.
    assert!(
        names.contains(&"liqThresholdBps"),
        "liqThresholdBps (margin-call trigger) must be a constructor parameter"
    );
    assert!(
        names.contains(&"auctionWindow"),
        "auctionWindow must be a constructor parameter"
    );
    assert!(
        names.contains(&"auctionDiscountBps"),
        "auctionDiscountBps must be a constructor parameter"
    );
    assert!(
        names.contains(&"initRatioBps"),
        "initRatioBps must be a constructor parameter"
    );
}

#[test]
fn test_all_burn_checks_are_strict_equality() {
    // SECURITY-CRITICAL invariant: every settlement-side burn check must use
    // strict equality (`sumInputs == sumOutputs + N`), never the loose lower
    // bound `sumInputs >= sumOutputs + N`.
    //
    // The loose form allows multi-vault batching attacks: an attacker
    // includes the legitimate vault input the pool function processes PLUS
    // extra vault inputs, all burning their debit globally. With `>=`, every
    // individual function's burn check passes vacuously because the GLOBAL
    // delta exceeds any single mintedAmount. The pool only accounts for ONE
    // vault, but the extra vaults' collateral can be redirected to the
    // attacker (via output[1]=auctioneerPk pins), and the extra vaults'
    // debit is silently extinguished without their mintedAmount being
    // removed from totalDebitOutstanding. Net: collateral theft from
    // borrowers of the extra vaults + tracked-debt desync that degrades the
    // future redemption rate.
    //
    // Strict equality bounds the global delta to exactly the pool function's
    // accounted amount, making multi-vault batching impossible to satisfy.
    //
    // Source-text grep. Matches any line containing `sumInputs` — the
    // *only* use of `sumInputs` in either contract is for burn checks
    // (debit, credit, or any future group), so the filter doesn't depend on
    // the variable being named `debitGroup`/`creditGroup`. A refactor that
    // renames the variable to e.g. `let g = tx.assetGroups.find(...)` is
    // still caught because the access `g.sumInputs` is the matched token.
    let src_pool = include_str!("../examples/bonds/repayment_pool.ark");
    let src_vault = include_str!("../examples/bonds/bond_mint.ark");
    let mut burn_check_lines = 0usize;
    for (path, src) in [
        ("repayment_pool.ark", src_pool),
        ("bond_mint.ark", src_vault),
    ] {
        for (i, line) in src.lines().enumerate() {
            // Ignore comments (which legitimately discuss the historical
            // `>=` form).
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            if line.contains("sumInputs") {
                burn_check_lines += 1;
                assert!(
                    line.contains("=="),
                    "{path}:{} uses a sumInputs check WITHOUT `==` (must be strict equality, never `>=`): {}",
                    i + 1,
                    line.trim()
                );
                assert!(
                    !line.contains(">="),
                    "{path}:{} contains `>=` on a sumInputs line: {}",
                    i + 1,
                    line.trim()
                );
            }
        }
    }
    // Floor on burn-check coverage so this test fails CLOSED if someone
    // refactors burn checks out entirely or moves them to a different
    // expression shape that doesn't mention sumInputs. Current settlement
    // surface: pool acceptRepayment + rollOut + liquidate + acceptAuction +
    // redeem (5) + vault repay + liquidate + auction + roll (4) = 9.
    assert!(
        burn_check_lines >= 9,
        "expected ≥ 9 sumInputs-burn-check lines across pool + vault (one per settlement function), saw {burn_check_lines} — the burn-check pattern may have been refactored into a shape this grep no longer detects."
    );
}

#[test]
fn test_pool_retains_debit_ctrl_in_every_function() {
    // SECURITY: BondMint authenticates "genuine pool co-spent" only by
    // `tx.inputs[poolIdx].assets.lookup(debitCtrlId) >= 1` — no scriptPubKey
    // reconstruction. The safety of every BondMint settlement therefore
    // depends on the asset-registry invariant that NO RepaymentPool function
    // ever lets debitCtrlId leak from its output[0] (or outIdxPool for
    // variable-output functions).
    //
    // If a future function omits the `tx.outputs[*].assets.lookup(debitCtrlId)
    // >= 1` retention check, the control asset can migrate into a malicious
    // covenant that the BondMint will then accept as "the pool" on its next
    // settlement, redirecting collateral to the attacker.
    //
    // This test asserts every function that writes to a pool output also
    // performs the debitCtrlId retention check at the ASM level, by counting
    // OP_INSPECTOUTASSETLOOKUP opcodes. Every pool-recreating function emits
    // at least three: usdtAssetId balance + creditCtrlId retention +
    // debitCtrlId retention. (issue, rollIn additionally check credit/debit
    // delivery to the borrower output, so they emit more.)
    let output = compile(CODE).expect("pool compilation failed");
    let pool_recreating_fns = [
        "issue",
        "acceptRepayment",
        "rollOut",
        "rollIn",
        "liquidate",
        "acceptAuction",
        "redeem",
    ];
    for fn_name in pool_recreating_fns {
        let lookups = opcode_count(&output, fn_name, OP_INSPECTOUTASSETLOOKUP);
        assert!(
            lookups >= 3,
            "function `{fn_name}` emits only {lookups} OP_INSPECTOUTASSETLOOKUP — at minimum it must check usdtAssetId balance + creditCtrlId retention + debitCtrlId retention on the recreated pool output, or BondMint pool-authentication breaks."
        );
    }
}

#[test]
fn test_no_interest_rate_anywhere() {
    // The bond market design is intentionally interest-rate-free: yield is the
    // discount the market sets at credit-sale time. Adding ratePerSec /
    // lastAccrual / interestBps / accrualRate-style state would silently
    // change the contract's economic model.
    //
    // This test denies a CLASS of accrual-related identifiers (substring
    // match, case-insensitive) rather than a hard-coded pair of names — so
    // a future regression that re-adds interest accrual under any plausible
    // name is caught.
    let output = compile(CODE).expect("compilation failed");
    let names: Vec<String> = output
        .parameters
        .iter()
        .map(|p| p.name.to_lowercase())
        .collect();
    // Substring denylist for accrual-related concepts. Each entry should be
    // a token that no legitimate non-interest field would contain.
    const ACCRUAL_TOKENS: &[&str] = &[
        "interest",
        "accrual",
        "accrue",
        "ratepers", // ratePerSec, ratePerBlock, etc.
        "apybps",
        "apr",
        "yieldrate",
    ];
    for tok in ACCRUAL_TOKENS {
        for n in &names {
            assert!(
                !n.contains(tok),
                "RepaymentPool must remain interest-rate-free; field '{n}' \
                 contains accrual token '{tok}'. Full params: {names:?}"
            );
        }
    }
}

#[test]
fn test_issue_is_oracle_priced_and_dual_mints() {
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "issue");
    assert!(
        asm.contains(OP_CHECKSIGFROMSTACK),
        "issue verifies oracle sig"
    );
    assert!(
        asm.contains(OP_SHA256) && asm.contains(OP_CAT),
        "issue rebuilds oracle msg"
    );
    assert!(
        asm.contains(OP_MUL64) && asm.contains(OP_DIV64),
        "issue computes collateral value"
    );
    assert!(
        asm.contains(OP_LESSTHANOREQUAL),
        "issue enforces origination ratio"
    );
    assert!(
        asm.contains(OP_FINDASSETGROUPBYASSETID) && asm.contains(OP_INSPECTASSETGROUPCTRL),
        "issue mints credit + debit gated by control assets"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "issue pins pool + credit + vault outputs"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTVALUE),
        "issue locks collateral in the vault"
    );
    assert!(asm.contains(OP_CHECKSIG), "issue needs borrower sig");
}

#[test]
fn test_issue_enforces_deployment_invariants() {
    // Deployment-safety invariants: issue must reject a misconfigured pool at
    // origination, before any vault is created. Specifically:
    //   - initRatioBps > liqThresholdBps: a vault minted at the minimum
    //     collateral must not be immediately liquidatable.
    //   - liqThresholdBps > 0: a non-positive threshold inverts the health
    //     gate (every vault liquidatable, or none).
    //   - auctionWindow > 0: a zero-length auction window means no defaulted
    //     vault can ever be settled (`tx.time >= maturity && tx.time <
    //     maturity` is empty), so totalDebitOutstanding accumulates forever.
    //   - auctionDiscountBps ∈ [0, 10000): an out-of-range discount bricks
    //     every liquidate + acceptAuction at the runtime check, leaving the
    //     pool unsettleable.
    //
    // issue carries exactly five strict `>` comparisons that lower to
    // OP_GREATERTHAN sites: amount > 0, collateral > 0, oraclePrice > 0,
    // initRatioBps > liqThresholdBps, liqThresholdBps > 0, auctionWindow > 0.
    // Total: 3 `> 0` value guards + 3 deployment invariants = 6. Asserting
    // the EXACT count means removing any single invariant fails the test —
    // a `>= 5` lower bound would let one be silently deleted.
    // (OP_GREATERTHANOREQUAL / *_64 are distinct opcodes, not counted here.)
    let output = compile(CODE).expect("compilation failed");
    let gt = opcode_count(&output, "issue", "OP_GREATERTHAN");
    assert_eq!(
        gt, 6,
        "issue must carry initRatioBps > liqThresholdBps + liqThresholdBps > 0 \
         + auctionWindow > 0 (expected exactly 6 OP_GREATERTHAN incl. the 3 \
         `> 0` value guards, found {gt})"
    );

    // Targeted check for `auctionDiscountBps >= 0` — must anchor to the
    // specific guard's tokens, not just count any `>=` opcode. arkanaai O1
    // and CodeRabbit's review both flagged that a bare `gte >= 1` floor on
    // OP_GREATERTHANOREQUAL64 would still pass if the discount guard were
    // deleted, because issue() emits many asset-amount `>=` checks
    // (`output.assets.lookup(...) >= N`) that satisfy that floor.
    //
    // The compiler emits the comparison block with `<auctionDiscountBps>`,
    // `OP_GREATERTHANOREQUAL`, and `0` clustered within a 3-token window
    // (display order is `<auctionDiscountBps> OP_GREATERTHANOREQUAL 0` in
    // the current emitter — execution order may differ; we accept any
    // permutation to stay robust to that).
    assert!(
        contains_window_3(
            &output,
            "issue",
            "<auctionDiscountBps>",
            "OP_GREATERTHANOREQUAL",
            "0"
        ),
        "issue must carry the `auctionDiscountBps >= 0` deployment guard \
         (expected window of <auctionDiscountBps>, OP_GREATERTHANOREQUAL, 0 \
         within 3 consecutive ASM tokens of `issue`)"
    );
    assert!(
        contains_window_3(
            &output,
            "issue",
            "<auctionDiscountBps>",
            "OP_LESSTHAN",
            "10000"
        ),
        "issue must carry the `auctionDiscountBps < 10000` deployment guard \
         (expected window of <auctionDiscountBps>, OP_LESSTHAN, 10000 within \
         3 consecutive ASM tokens of `issue`)"
    );
}

/// True iff the function `name`'s server-variant ASM contains three given
/// tokens in any order within a 3-token sliding window. Used for targeted
/// regression checks where the compiler may emit a comparison's operands
/// and opcode in a non-postfix display order — what matters is adjacency,
/// not exact sequence.
fn contains_window_3(
    output: &arkade_compiler::models::ContractJson,
    name: &str,
    a: &str,
    b: &str,
    c: &str,
) -> bool {
    let tokens = asm_tokens(output, name);
    if tokens.len() < 3 {
        return false;
    }
    let target: std::collections::BTreeSet<&str> = [a, b, c].into_iter().collect();
    tokens.windows(3).any(|w| {
        let s: std::collections::BTreeSet<&str> = w.iter().map(|t| t.as_str()).collect();
        s == target
    })
}

#[test]
fn test_issue_uses_ceiling_division_on_required_collateral() {
    // Dust-issuance defence: the required-collateral floor is computed via
    // CEILING division — `(amount * initRatioBps + 9999) / 10000` — not the
    // naive `amount * initRatioBps / 10000`. Without ceiling, an attacker
    // can mint 1 credit + 1 debit for 1 sat of collateral (amount=1,
    // initRatioBps=14999 → required floors to 1), then flood the auction
    // window with thousands of dust defaults that are unprofitable for
    // auctioneers to settle.
    //
    // The signature of the ceiling form in the emitted ASM is the literal
    // 9999 pushed before the OP_ADD64 that precedes the OP_DIV64. Asserting
    // on the presence of `9999` as a token in both issue + rollIn locks in
    // the fix at the ASM level — a regression to floor division (or to
    // a different bias like + 5000) trips this test.
    let output = compile(CODE).expect("compilation failed");
    for fn_name in ["issue", "rollIn"] {
        let tokens = asm_tokens(&output, fn_name);
        assert!(
            tokens.iter().any(|t| t == "9999"),
            "{fn_name} must use ceiling division on the required-collateral \
             floor (expected literal `9999` token in ASM; absent means \
             dust-issuance defence regressed). Tokens: {tokens:?}"
        );
    }
}

#[test]
fn test_accept_repayment_validates_vault_and_burns_debit() {
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "acceptRepayment");
    assert!(
        asm.contains(OP_INSPECTINPUTSCRIPTPUBKEY),
        "acceptRepayment validates the BondMint input"
    );
    assert!(
        asm.contains(OP_INSPECTASSETGROUPSUM),
        "acceptRepayment burns the debit"
    );
    assert!(
        asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "acceptRepayment routes USDT into the pool"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTVALUE),
        "acceptRepayment returns collateral"
    );
    assert!(
        asm.contains(OP_LESSTHAN),
        "acceptRepayment gated on tx.time < maturity"
    );
}

#[test]
fn test_accept_auction_is_permissionless_oracle_priced_phased() {
    // Oracle witness only. Auctioneer identity = witness pubkey.
    // Phased gate: tx.time >= maturity AND tx.time < maturity + auctionWindow.
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "acceptAuction");
    assert!(
        asm.contains(OP_CHECKSIGFROMSTACK),
        "acceptAuction verifies oracle sig"
    );
    assert!(
        asm.contains(OP_SHA256) && asm.contains(OP_CAT),
        "acceptAuction rebuilds oracle msg"
    );
    assert!(
        asm.contains(OP_INSPECTINPUTSCRIPTPUBKEY),
        "acceptAuction validates the BondMint input"
    );
    assert!(
        asm.contains(OP_INSPECTASSETGROUPSUM),
        "acceptAuction burns the debit"
    );
    assert!(
        asm.contains(OP_MUL64) && asm.contains(OP_DIV64),
        "acceptAuction computes collateralValue + discount math"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTVALUE),
        "acceptAuction pays collateral sats out"
    );
    assert!(
        asm.contains(OP_LESSTHAN),
        "acceptAuction enforces auction-window upper bound"
    );

    // Excluding serverSig (the Arkade cooperative-path sig auto-injected on
    // every server-variant function), exactly ONE signature witness remains:
    // the oracle. No auctioneer signature — auction is permissionless.
    let ws = witness_names(&output, "acceptAuction");
    let user_sigs = user_signatures(&output, "acceptAuction");
    assert_eq!(
        user_sigs.len(),
        1,
        "acceptAuction must have exactly one user signature (the oracle), got: {ws:?}"
    );
    assert!(
        user_sigs[0].to_lowercase().contains("oracle"),
        "the sole user signature must be the oracle, got: {:?}",
        user_sigs[0]
    );
    assert!(
        ws.iter().any(|w| w == "auctioneerPk"),
        "auctioneerPk must be a witness parameter, got: {ws:?}"
    );
}

#[test]
fn test_liquidate_is_oracle_priced_health_gated_permissionless() {
    // Margin call (pre-maturity, permissionless): oracle-priced sale of the
    // collateral when collateralValue < liqThresholdBps × mintedAmount / 10000.
    // Same two-branch payout as acceptAuction, same auctioneer-discount
    // incentive — but pre-maturity and triggered by the health threshold.
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "liquidate");
    assert!(
        asm.contains(OP_CHECKSIGFROMSTACK),
        "liquidate verifies oracle sig"
    );
    assert!(
        asm.contains(OP_SHA256) && asm.contains(OP_CAT),
        "liquidate rebuilds oracle msg"
    );
    assert!(
        asm.contains(OP_INSPECTINPUTSCRIPTPUBKEY),
        "liquidate validates the BondMint input"
    );
    assert!(
        asm.contains(OP_INSPECTASSETGROUPSUM),
        "liquidate burns the debit"
    );
    assert!(
        asm.contains(OP_MUL64) && asm.contains(OP_DIV64),
        "liquidate computes collateralValue + health-threshold + payout"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTVALUE),
        "liquidate pays collateral sats out"
    );
    // liquidate carries exactly THREE strict less-than comparisons:
    //   1. auctionDiscountBps < 10000  (discount bound)
    //   2. tx.time < maturity          (pre-maturity gate)
    //   3. collateralValue < healthFloor (the margin-call trigger)
    // Asserting the exact count (3) means removing ANY of them — in particular
    // the health gate, the single most important liquidate invariant — fails
    // the test. A `>= 2` lower bound would let the health gate be silently
    // deleted (dropping 3 -> 2 while still passing).
    let lt = opcode_count(&output, "liquidate", "OP_LESSTHAN");
    assert_eq!(
        lt, 3,
        "liquidate must gate on discount-bound AND tx.time<maturity AND \
         collateralValue<healthFloor (expected exactly 3 OP_LESSTHAN, found {lt})"
    );

    let ws = witness_names(&output, "liquidate");
    let user_sigs = user_signatures(&output, "liquidate");
    assert_eq!(
        user_sigs.len(),
        1,
        "liquidate must have exactly one user signature (the oracle), got: {ws:?}"
    );
    assert!(
        user_sigs[0].to_lowercase().contains("oracle"),
        "the sole user signature must be the oracle, got: {:?}",
        user_sigs[0]
    );
    assert!(
        ws.iter().any(|w| w == "auctioneerPk"),
        "auctioneerPk must be a witness parameter, got: {ws:?}"
    );
}

#[test]
fn test_liquidate_and_accept_auction_are_phase_disjoint() {
    // Margin-call and post-maturity auction must NEVER both fire on the same
    // vault in the same block: liquidate is gated on tx.time < maturity,
    // acceptAuction on tx.time >= maturity. liquidate carries 3 OP_LESSTHAN
    // (discount bound + pre-maturity gate + health gate); acceptAuction carries
    // an OP_LESSTHAN for its window upper bound but its lower bound is a
    // >= comparison — so the two paths can never both be valid at one height.
    let output = compile(CODE).expect("compilation failed");
    assert_eq!(
        opcode_count(&output, "liquidate", "OP_LESSTHAN"),
        3,
        "liquidate must carry its discount-bound, pre-maturity, and health-floor comparisons"
    );
    assert!(
        asm_of(&output, "acceptAuction").contains(OP_LESSTHAN),
        "acceptAuction must carry its window upper-bound comparison"
    );
}

#[test]
fn test_redeem_is_pro_rata_post_window() {
    // redeem only opens AFTER the auction window closes, so the rate
    // (usdtBalance / totalCreditOutstanding) is locked and fair for all orderings.
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "redeem");
    assert!(
        asm.contains(OP_MUL64) && asm.contains(OP_DIV64),
        "redeem computes pro-rata payout"
    );
    assert!(
        asm.contains(OP_INSPECTASSETGROUPSUM),
        "redeem burns the credit"
    );
    assert!(
        asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "redeem pays USDT to the holder"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "redeem re-creates the pool covenant + pins payout destination"
    );
    assert!(asm.contains(OP_CHECKSIG), "redeem needs holder sig");

    // The post-window gate `require(tx.time >= maturity + auctionWindow)` is
    // what makes the redemption rate (usdtBalance / totalCreditOutstanding)
    // fixed and fair for all orderings — it is the keystone of the phased
    // design. The compiler lowers `tx.time >= redeemStart` to
    // OP_CHECKLOCKTIMEVERIFY (the dedicated Bitcoin time-lock opcode),
    // because that's exactly the "block height ≥ N" semantic.
    assert_eq!(
        opcode_count(&output, "redeem", "OP_CHECKLOCKTIMEVERIFY"),
        1,
        "redeem must gate on tx.time >= maturity + auctionWindow (CLTV, post-window phase)"
    );

    // Verify the CLTV operand actually DERIVES FROM the contract's two
    // time-axis constructor parameters: a future refactor that accidentally
    // lowered `tx.time >= 0` (or any literal) to a CLTV would pass the
    // opcode-count check above but bypass the gate semantically. Both
    // `<maturity>` and `<auctionWindow>` placeholders must appear in the
    // redeem ASM for the gate's operand to be the intended sum.
    let tokens = asm_tokens(&output, "redeem");
    assert!(
        tokens.iter().any(|t| t == "<maturity>"),
        "redeem CLTV operand must derive from maturity (placeholder missing)"
    );
    assert!(
        tokens.iter().any(|t| t == "<auctionWindow>"),
        "redeem CLTV operand must derive from auctionWindow (placeholder missing)"
    );
    // Structural check: the token IMMEDIATELY BEFORE OP_CHECKLOCKTIMEVERIFY
    // must be the redeemStart let-binding placeholder — not a literal, not
    // an unrelated placeholder. A refactor that accidentally locked CLTV to
    // a literal (e.g. `tx.time >= 0`) would push something other than
    // <redeemStart> here and fail the test.
    let cltv_idx = tokens
        .iter()
        .position(|op| op == "OP_CHECKLOCKTIMEVERIFY")
        .expect("OP_CHECKLOCKTIMEVERIFY missing");
    assert!(cltv_idx > 0, "OP_CHECKLOCKTIMEVERIFY must have an operand");
    let operand = &tokens[cltv_idx - 1];
    assert_eq!(
        operand, "<redeemStart>",
        "CLTV operand must be the redeemStart let-binding (= maturity + auctionWindow), got: {operand}"
    );
}

#[test]
fn test_roll_out_extinguishes_old_obligation_at_witness_index() {
    // ROLL OUT — on the OLD pool. Burns the old vault's debit, requires the
    // pool's recreated USDT to grow by exactly `expectedDischarge ==
    // oldMintedAmount`, and uses witness output indices throughout so it
    // composes with rollIn on the next-maturity pool and a non_interactive_swap
    // fill in one tx.
    //
    // SECURITY: rollOut REQUIRES a borrower signature on the pool side, NOT
    // just on the vault side. Without it, an attacker could pair the
    // permissionless `vault.liquidate` (no sig) with `pool.rollOut` (no sig)
    // and force-liquidate a healthy vault at par price, bypassing
    // pool.liquidate's oracle + healthFloor gate entirely. The pool-side sig
    // is the gate that blocks that pairing.
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "rollOut");
    assert!(
        asm.contains(OP_INSPECTINPUTSCRIPTPUBKEY),
        "rollOut validates the OLD BondMint at input[vaultIdx]"
    );
    assert!(
        asm.contains(OP_INSPECTASSETGROUPSUM),
        "rollOut burns the old debit"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "rollOut pins the pool recreation at outputs[outIdxPool]"
    );
    assert!(
        asm.contains(OP_INSPECTOUTASSETLOOKUP),
        "rollOut verifies usdt + control retention on the recreated pool"
    );
    assert!(
        asm.contains(OP_LESSTHAN),
        "rollOut gated on tx.time < maturity (pre-maturity)"
    );
    assert!(
        asm.contains(OP_CHECKSIG),
        "rollOut REQUIRES borrower sig (blocks vault.liquidate + rollOut force-liquidation attack)"
    );

    // The discharge gate is `expectedDischarge == oldMintedAmount` — strict
    // equality, symmetric with the strict-burn invariant. Both are witnesses.
    let ws = witness_names(&output, "rollOut");
    assert!(
        ws.iter().any(|w| w == "expectedDischarge"),
        "expectedDischarge must be a witness, got: {ws:?}"
    );
    assert!(
        ws.iter().any(|w| w == "outIdxPool"),
        "outIdxPool must be a witness (variable output index), got: {ws:?}"
    );
    assert!(
        ws.iter().any(|w| w == "borrowerSig"),
        "borrowerSig must be a witness (blocks force-liquidation attack), got: {ws:?}"
    );

    // Exactly one user signature: the borrower's. The pool-side sig is the
    // gate that prevents the permissionless vault.liquidate path from being
    // paired with rollOut to siphon collateral.
    let user_sigs = user_signatures(&output, "rollOut");
    assert_eq!(
        user_sigs.len(),
        1,
        "rollOut must require exactly the borrower sig (P0 force-liquidation defence), got: {user_sigs:?}"
    );
    assert!(
        user_sigs.iter().any(|s| s == "borrowerSig"),
        "rollOut's user sig must be borrowerSig, got: {user_sigs:?}"
    );
}

#[test]
fn test_roll_in_oracle_priced_dual_mints_at_witness_indices() {
    // ROLL IN — on the NEW pool. Borrower-signed; oracle-priced
    // over-collateralisation; mints credit + debit; pins the new BondMint
    // vault + the credit destination + the pool recreation, all at witness
    // output indices.
    let output = compile(CODE).expect("compilation failed");
    let asm = asm_of(&output, "rollIn");
    assert!(
        asm.contains(OP_CHECKSIGFROMSTACK),
        "rollIn verifies oracle sig"
    );
    assert!(
        asm.contains(OP_SHA256) && asm.contains(OP_CAT),
        "rollIn rebuilds oracle msg"
    );
    assert!(
        asm.contains(OP_MUL64) && asm.contains(OP_DIV64),
        "rollIn computes collateralValue + origination ratio"
    );
    assert!(
        asm.contains(OP_LESSTHANOREQUAL),
        "rollIn enforces origination ratio (collateralValue >= required)"
    );
    assert!(
        asm.contains(OP_FINDASSETGROUPBYASSETID) && asm.contains(OP_INSPECTASSETGROUPCTRL),
        "rollIn mints credit + debit gated by their control assets"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        "rollIn pins pool + credit + new-vault outputs"
    );
    assert!(
        asm.contains(OP_INSPECTOUTPUTVALUE),
        "rollIn locks the migrated collateral in the new vault"
    );
    assert!(
        asm.contains(OP_CHECKSIG),
        "rollIn needs borrower sig (consent)"
    );

    let ws = witness_names(&output, "rollIn");
    for name in ["outIdxPool", "outIdxVault", "outIdxCredit"] {
        assert!(
            ws.iter().any(|w| w == name),
            "{name} must be a witness (variable output index), got: {ws:?}"
        );
    }

    // Exactly TWO user signatures: the oracle (price attestation) and the
    // borrower (consent to the new obligation). No keeper, no maker sig.
    let user_sigs = user_signatures(&output, "rollIn");
    assert_eq!(
        user_sigs.len(),
        2,
        "rollIn must have exactly two user sigs (oracle + borrower), got: {ws:?}"
    );
}

#[test]
fn test_roll_pair_enforces_all_deployment_invariants() {
    // rollIn is an alternate issuance entry and must enforce the SAME
    // deployment-safety invariants as issue (initRatioBps > liqThresholdBps,
    // liqThresholdBps > 0, auctionWindow > 0, auctionDiscountBps in
    // [0, 10000)). Without these re-checks a misconfigured pool that
    // somehow escaped issue could still mint fresh vaults via rollIn.
    let output = compile(CODE).expect("compilation failed");
    let gt = opcode_count(&output, "rollIn", "OP_GREATERTHAN");
    // 3 `> 0` value guards (newMintedAmount, newCollateral, oraclePrice) +
    // 3 deployment invariants (initRatioBps > liqThresholdBps,
    // liqThresholdBps > 0, auctionWindow > 0) = 6 OP_GREATERTHAN, matching
    // issue.
    assert_eq!(
        gt, 6,
        "rollIn must replicate issue's invariants (expected 6 OP_GREATERTHAN, found {gt})"
    );
    // Targeted check for `auctionDiscountBps >= 0` AND `< 10000` — see
    // the parallel test in `test_issue_enforces_deployment_invariants` for
    // the rationale (arkanaai O1 / CodeRabbit review).
    assert!(
        contains_window_3(
            &output,
            "rollIn",
            "<auctionDiscountBps>",
            "OP_GREATERTHANOREQUAL",
            "0"
        ),
        "rollIn must carry the `auctionDiscountBps >= 0` deployment guard \
         (expected window of <auctionDiscountBps>, OP_GREATERTHANOREQUAL, 0 \
         within 3 consecutive ASM tokens of `rollIn`)"
    );
    assert!(
        contains_window_3(
            &output,
            "rollIn",
            "<auctionDiscountBps>",
            "OP_LESSTHAN",
            "10000"
        ),
        "rollIn must carry the `auctionDiscountBps < 10000` deployment guard \
         (expected window of <auctionDiscountBps>, OP_LESSTHAN, 10000 within \
         3 consecutive ASM tokens of `rollIn`)"
    );
}

#[test]
fn test_exit_variants_are_unilateral_fallback() {
    let output = compile(CODE).expect("compilation failed");
    for name in [
        "issue",
        "acceptRepayment",
        "rollOut",
        "rollIn",
        "liquidate",
        "acceptAuction",
        "redeem",
    ] {
        let asm = asm_variant(&output, name, false);
        assert!(
            asm.contains(OP_CHECKSEQUENCEVERIFY),
            "{name} exit must be CSV-timelocked"
        );
        assert!(asm.contains(OP_CHECKSIG), "{name} exit must check sigs");
        assert!(
            !asm.contains(OP_INSPECTOUTPUTSCRIPTPUBKEY) && !asm.contains(OP_INSPECTASSETGROUPSUM),
            "{name} exit must not carry covenant introspection"
        );
    }
}

#[test]
fn test_repayment_pool_cli() {
    use std::fs;
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("bond_mint.ark"),
        include_str!("../examples/bonds/bond_mint.ark"),
    )
    .unwrap();
    let input = dir.path().join("repayment_pool.ark");
    fs::write(&input, CODE).unwrap();
    let out = dir.path().join("repayment_pool.json");

    let result = std::process::Command::new(env!("CARGO_BIN_EXE_arkadec"))
        .arg(input.to_str().unwrap())
        .arg("-o")
        .arg(out.to_str().unwrap())
        .output()
        .expect("failed to run arkadec");

    assert!(
        result.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let json = fs::read_to_string(&out).unwrap();
    assert!(json.contains("\"contractName\": \"RepaymentPool\""));
}
