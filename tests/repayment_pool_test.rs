use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_CAT, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_DIV64,
    OP_FINDASSETGROUPBYASSETID, OP_INSPECTASSETGROUPCTRL, OP_INSPECTASSETGROUPSUM,
    OP_INSPECTINPUTSCRIPTPUBKEY, OP_INSPECTOUTASSETLOOKUP, OP_INSPECTOUTPUTSCRIPTPUBKEY,
    OP_INSPECTOUTPUTVALUE, OP_LESSTHAN, OP_LESSTHANOREQUAL, OP_MUL64, OP_SHA256,
};

const CODE: &str = include_str!("../examples/bonds/repayment_pool.ark");

fn asm_of(output: &arkade_compiler::models::ContractJson, name: &str) -> String {
    asm_variant(output, name, true)
}

fn asm_variant(output: &arkade_compiler::models::ContractJson, name: &str, server: bool) -> String {
    output
        .functions
        .iter()
        .find(|f| f.name == name && f.server_variant == server)
        .unwrap_or_else(|| panic!("{name} (server={server}) variant not found"))
        .asm
        .join(" ")
}

fn witness_names(output: &arkade_compiler::models::ContractJson, name: &str) -> Vec<String> {
    output
        .functions
        .iter()
        .find(|f| f.name == name && f.server_variant)
        .unwrap()
        .witness_schema
        .iter()
        .map(|w| w.name.clone())
        .collect()
}

/// Count exact-token occurrences of an opcode in a function's server-variant
/// ASM. Exact match, so "OP_GREATERTHAN" does NOT match "OP_GREATERTHANOREQUAL"
/// or "OP_GREATERTHANOREQUAL64".
fn opcode_count(output: &arkade_compiler::models::ContractJson, name: &str, op: &str) -> usize {
    output
        .functions
        .iter()
        .find(|f| f.name == name && f.server_variant)
        .unwrap()
        .asm
        .iter()
        .filter(|tok| tok.as_str() == op)
        .count()
}

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
    let src_pool = include_str!("../examples/bonds/repayment_pool.ark");
    let src_vault = include_str!("../examples/bonds/bond_mint.ark");
    for (path, src) in [
        ("repayment_pool.ark", src_pool),
        ("bond_mint.ark", src_vault),
    ] {
        for (i, line) in src.lines().enumerate() {
            if line.contains("sumInputs") && (line.contains("debit") || line.contains("credit")) {
                assert!(
                    line.contains("=="),
                    "{path}:{} uses a loose burn check (must be `==`, not `>=`): {}",
                    i + 1,
                    line.trim()
                );
                assert!(
                    !line.contains(">="),
                    "{path}:{} contains `>=` in a burn-check line: {}",
                    i + 1,
                    line.trim()
                );
            }
        }
    }
}

#[test]
fn test_no_interest_rate_anywhere() {
    let output = compile(CODE).expect("compilation failed");
    let names: Vec<&str> = output.parameters.iter().map(|p| p.name.as_str()).collect();
    assert!(
        !names.contains(&"ratePerSec") && !names.contains(&"lastAccrual"),
        "RepaymentPool must not carry interest-rate state, got: {names:?}"
    );
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
fn test_issue_enforces_liq_threshold_invariants() {
    // Deployment-safety invariants: issue must reject a pool where the
    // margin-call threshold is not strictly below the origination ratio, or is
    // non-positive — otherwise a freshly-minted vault at minimum collateral
    // would be immediately liquidatable (guaranteed borrower loss), or the
    // health gate would be inverted by a negative threshold.
    //
    // issue carries exactly five strict `>` comparisons that lower to
    // OP_GREATERTHAN: amount > 0, collateral > 0, oraclePrice > 0, the invariant
    // initRatioBps > liqThresholdBps, and liqThresholdBps > 0. The bare `> 0`
    // guards account for 3; the two threshold invariants add 2. Asserting the
    // exact count (5) means removing EITHER threshold invariant fails the test —
    // a `>= 4` lower bound would let one be silently deleted.
    // (OP_GREATERTHANOREQUAL / *_64 are distinct opcodes, not counted here.)
    let output = compile(CODE).expect("compilation failed");
    let gt = opcode_count(&output, "issue", "OP_GREATERTHAN");
    assert_eq!(
        gt, 5,
        "issue must carry BOTH initRatioBps > liqThresholdBps AND \
         liqThresholdBps > 0 (expected exactly 5 OP_GREATERTHAN incl. the 3 \
         `> 0` value guards, found {gt})"
    );
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
    let user_sigs: Vec<&String> = ws
        .iter()
        .filter(|w| w.to_lowercase().ends_with("sig") && w.as_str() != "serverSig")
        .collect();
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
    let user_sigs: Vec<&String> = ws
        .iter()
        .filter(|w| w.to_lowercase().ends_with("sig") && w.as_str() != "serverSig")
        .collect();
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
    // design. The compiler lowers `tx.time >= redeemStart` to the dedicated
    // Bitcoin time-lock opcode OP_CHECKLOCKTIMEVERIFY (not a generic >=),
    // because that's exactly the "block height ≥ N" semantic. Asserting on
    // its presence means deleting the gate fails the test.
    assert_eq!(
        opcode_count(&output, "redeem", "OP_CHECKLOCKTIMEVERIFY"),
        1,
        "redeem must gate on tx.time >= maturity + auctionWindow (CLTV, post-window phase)"
    );
}

#[test]
fn test_roll_out_extinguishes_old_obligation_at_witness_index() {
    // ROLL OUT — on the OLD pool. Burns the old vault's debit, requires the
    // pool's recreated USDT to grow by `expectedDischarge >= oldMintedAmount`,
    // and uses witness output indices throughout so it composes with rollIn
    // on the next-maturity pool and a non_interactive_swap fill in one tx.
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

    // The discharge gate is `expectedDischarge >= oldMintedAmount` — a
    // witness-to-witness comparison.
    let ws = witness_names(&output, "rollOut");
    assert!(
        ws.iter().any(|w| w == "expectedDischarge"),
        "expectedDischarge must be a witness, got: {ws:?}"
    );
    assert!(
        ws.iter().any(|w| w == "outIdxPool"),
        "outIdxPool must be a witness (variable output index), got: {ws:?}"
    );

    // No user signature: rollOut authorises the OLD pool spend by virtue of
    // burning the vault's debit + receiving the discharge; the borrower's
    // consent is enforced on the vault side (BondMint.roll).
    let user_sigs: Vec<&String> = ws
        .iter()
        .filter(|w| w.to_lowercase().ends_with("sig") && w.as_str() != "serverSig")
        .collect();
    assert!(
        user_sigs.is_empty(),
        "rollOut must not require any user signature (consent lives on the vault), got: {user_sigs:?}"
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
    let user_sigs: Vec<&String> = ws
        .iter()
        .filter(|w| w.to_lowercase().ends_with("sig") && w.as_str() != "serverSig")
        .collect();
    assert_eq!(
        user_sigs.len(),
        2,
        "rollIn must have exactly two user sigs (oracle + borrower), got: {ws:?}"
    );
}

#[test]
fn test_roll_pair_enforces_both_threshold_invariants() {
    // The deployment-safety invariants (initRatioBps > liqThresholdBps AND
    // liqThresholdBps > 0) are re-checked in rollIn because rollIn is an
    // independent issuance path. Without re-checking, a misconfigured pool
    // that escaped issue could still mint vaults via rollIn.
    let output = compile(CODE).expect("compilation failed");
    let gt = opcode_count(&output, "rollIn", "OP_GREATERTHAN");
    // 3 `> 0` value guards (newMintedAmount, newCollateral, oraclePrice) +
    // 2 threshold invariants (initRatioBps > liqThresholdBps, liqThresholdBps > 0)
    // = 5 OP_GREATERTHAN, same as issue.
    assert_eq!(
        gt, 5,
        "rollIn must replicate issue's invariants (expected 5 OP_GREATERTHAN, found {gt})"
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
