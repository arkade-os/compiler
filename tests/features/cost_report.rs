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
fn covenants_report_resource_usage() {
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
    assert!(bytes.used > 0);
    assert!(cost("stack items (peak)").unwrap().used > 0);
    assert_eq!(
        cost("OP_CHECKSIGVERIFY"),
        Some(Cost {
            name: "OP_CHECKSIGVERIFY".into(),
            used: 3
        })
    );
    assert_eq!(cost("OP_GREATERTHAN").unwrap().used, 1);
    assert_eq!(cost("OP_ECMUL"), None);
    assert!(covenant.costs[2..]
        .windows(2)
        .all(|pair| pair[0].name < pair[1].name));
    let json = serde_json::to_value(&output).unwrap();
    assert!(json["functions"][0]["arkade"].get("costs").is_none());
}

#[test]
fn nested_branches_report_each_opcodes_maximum() {
    let check = "require(checkSig(sig, key));";
    let source = format!(
        "contract C(pubkey key) {{ function spend(signature sig, int n) {{
            if (n > 0) {{
                if (n > 1) {{ {} }} else {{ {} }}
            }} else {{ {} }}
            {check}
            require(n < 9);
        }} }}",
        check.repeat(2),
        check.repeat(3),
        check.repeat(4)
    );
    let output = compile(&source).unwrap();
    let costs = &output.functions[0].arkade.as_ref().unwrap().costs;
    for (opcode, expected) in [
        ("OP_CHECKSIGVERIFY", 5),
        ("OP_IF", 2),
        ("OP_ELSE", 2),
        ("OP_ENDIF", 2),
    ] {
        assert_eq!(
            costs.iter().find(|cost| cost.name == opcode).unwrap().used,
            expected,
            "{opcode}"
        );
    }
}

#[test]
fn report_prints_usage_without_limits() {
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
    assert!(
        stdout
            .lines()
            .filter(|line| line.starts_with("  "))
            .all(|line| !line.contains(['/', '%'])),
        "{stdout}"
    );
    let line = stdout
        .lines()
        .find(|line| line.contains("OP_CHECKSIGVERIFY"))
        .unwrap();
    assert_eq!(
        line.split_whitespace().collect::<Vec<_>>(),
        ["OP_CHECKSIGVERIFY", "3"]
    );
}
