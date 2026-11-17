use arkade_compiler::compile;

#[test]
fn comments_trailing_commas_and_digit_separators_compile_like_canonical_source() {
    let ergonomic = r#"
/* A vault with
   a timelocked exit. */
contract Vault(
    pubkey owner,
    pubkey backup,
    int[1_0] limits,
) {
    const int MIN = 1_000_000;
    function spend(signature sig, signature other, int amount,) {
        require(amount >= MIN /* sats */, "too small",);
        require(tx.outputs[0].value == int(0x0100 /* 256 */),);
        require(limits[9] <= 2_100_000_000_000_000);
        require(checkMultisig([owner, backup,], [sig, other,], 2,),);
    }
    function exit(signature sig, signature other,) tapscript {
        require(older(blocks(1_008) /* a week */),);
        require(checkMultisig([owner, backup,], [sig, other,],), "keys",);
    }
}"#;
    let canonical = r#"
contract Vault(pubkey owner, pubkey backup, int[10] limits) {
    const int MIN = 1000000;
    function spend(signature sig, signature other, int amount) {
        require(amount >= MIN, "too small");
        require(tx.outputs[0].value == int(0x0100));
        require(limits[9] <= 2100000000000000);
        require(checkMultisig([owner, backup], [sig, other], 2));
    }
    function exit(signature sig, signature other) tapscript {
        require(older(blocks(1008)));
        require(checkMultisig([owner, backup], [sig, other]), "keys");
    }
}"#;
    let code_hash = |source| compile(source).unwrap().code_hash.unwrap();
    assert_eq!(code_hash(ergonomic), code_hash(canonical));
}

#[test]
fn diagnostics_report_numbers_without_separators() {
    let error = compile(
        "contract C(pubkey a, pubkey b) { function spend(signature s, signature t) { require(checkMultisig([a, b], [s, t], 1_0)); } }",
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("number of public keys, got 10"), "{error}");
}
