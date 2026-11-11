use arkade_compiler::models::ContractJson;
use arkade_compiler::{analyze_file, compile_file};

fn source(name: &str) -> String {
    format!(
        "{}/examples/constant_product/{name}.ark",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn script_bytes(output: &ContractJson, function: &str) -> usize {
    crate::common::group(output, function)
        .arkade
        .as_ref()
        .unwrap_or_else(|| panic!("{function} has no covenant"))
        .costs
        .iter()
        .find(|cost| cost.name == "script bytes (min)")
        .unwrap_or_else(|| panic!("{function} has no script-size cost"))
        .used
}

fn compiles_clean(name: &str) -> ContractJson {
    let path = source(name);
    let diagnostics = analyze_file(&path).diagnostics();
    assert!(
        diagnostics.is_empty(),
        "{name} diagnostics: {diagnostics:?}"
    );
    compile_file(&path).unwrap_or_else(|error| panic!("{name} failed to compile: {error}"))
}

#[test]
fn constant_product_pool_is_one_counterparty() {
    let pool = compiles_clean("cp_pool");
    assert_eq!(pool.name, "ConstantProductPool");
    for (function, ceiling) in [("swap", 800), ("deposit", 800), ("withdraw", 800)] {
        let bytes = script_bytes(&pool, function);
        assert!(
            (200..ceiling).contains(&bytes),
            "{function} is {bytes} bytes; a batched unroll no longer fits the one-step pool"
        );
    }
    assert!(
        pool.parameters
            .iter()
            .all(|parameter| parameter.name != "noExitKey"),
        "the pool has no key-spend parameter"
    );
    for function in ["swap", "deposit", "withdraw"] {
        let leaf = crate::common::leaf_asm(&pool, function, function);
        assert!(
            leaf.contains("<SERVER_KEY>") && leaf.contains(&format!("<EMULATOR_KEY:{function}>")),
            "{function} should spend with the server and the emulator: {leaf}"
        );
        assert!(
            !leaf.contains("OP_CHECKSEQUENCEVERIFY"),
            "{function} should have no timelocked key leaf: {leaf}"
        );
    }
}

#[test]
fn constant_product_orders_pin_their_payout() {
    let swap = compiles_clean("cp_swap");
    let deposit = compiles_clean("cp_deposit");
    let exit = compiles_clean("cp_exit");
    assert_eq!(swap.name, "ConstantProductSwap");
    assert_eq!(deposit.name, "ConstantProductDeposit");
    assert_eq!(exit.name, "ConstantProductExit");

    for (output, function, ceiling) in [
        (&swap, "fill", 500),
        (&swap, "refund", 250),
        (&deposit, "fill", 500),
        (&deposit, "refund", 200),
        (&exit, "fill", 500),
        (&exit, "refund", 200),
    ] {
        let bytes = script_bytes(output, function);
        assert!(
            (40..ceiling).contains(&bytes),
            "{} {function} is {bytes} bytes",
            output.name
        );
    }

    for output in [&swap, &deposit, &exit] {
        let unilateral = crate::common::leaf_asm(output, "unilateral", "unilateral");
        assert!(
            unilateral.contains("<ownerPk>"),
            "{} unilateral should belong to ownerPk: {unilateral}",
            output.name
        );
        let fill = crate::common::arkade_asm(output, "fill");
        assert!(
            fill.contains("<CONTRACT:ConstantProductPool("),
            "{} fill should require the pool script: {fill}",
            output.name
        );
        assert!(
            fill.contains("<payScript.program>") && fill.contains("<payScript.version>"),
            "{} fill should pay payScript: {fill}",
            output.name
        );
    }
}
