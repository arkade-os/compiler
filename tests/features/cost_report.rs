use arkade_compiler::compile;
use arkade_compiler::models::Cost;

const SOURCE: &str = "contract C(pubkey[3] keys) {
    function spend(signature[3] sigs, int n) {
        require(n > 0);
        for (i, key) in keys { require(checkSig(sigs[i], key)); }
        require(n < 9);
    }
}";

#[test]
fn covenants_report_what_they_use_of_the_vm_limits() {
    let output = compile(SOURCE).unwrap();
    let covenant = output.functions[0].arkade.as_ref().unwrap();
    let cost = |name: &str| {
        covenant
            .costs
            .iter()
            .find(|cost| cost.name == name)
            .cloned()
    };
    let bytes = cost("script bytes (min)").unwrap();
    assert_eq!(bytes.limit, 10_000);
    assert!(bytes.used > 0);
    assert_eq!(cost("stack items").map(|c| c.limit), Some(1000));
    assert_eq!(
        cost("OP_CHECKSIGVERIFY"),
        Some(Cost {
            name: "OP_CHECKSIGVERIFY".into(),
            used: 3,
            limit: 50
        })
    );
    assert_eq!(cost("OP_ECMUL"), None);
    let json = serde_json::to_value(&output).unwrap();
    assert!(json["functions"][0]["arkade"].get("costs").is_none());
}

#[test]
fn report_prints_each_cost_against_its_limit() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("c.ark");
    std::fs::write(&source, SOURCE).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_arkadec"))
        .arg(&source)
        .arg("-o")
        .arg(dir.path().join("c.json"))
        .arg("--report")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("spend\n"), "{stdout}");
    let line = stdout
        .lines()
        .find(|line| line.contains("OP_CHECKSIGVERIFY"))
        .unwrap();
    assert_eq!(
        line.split_whitespace().collect::<Vec<_>>(),
        ["OP_CHECKSIGVERIFY", "3", "/", "50", "6%"]
    );
}
