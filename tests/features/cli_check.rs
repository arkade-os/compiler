use std::process::Command;

fn check(args: &[&str], files: &[(&str, &str)]) -> (i32, String) {
    let dir = tempfile::tempdir().unwrap();
    for (path, source) in files {
        let path = dir.path().join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, source).unwrap();
    }
    let output = Command::new(env!("CARGO_BIN_EXE_arkadec"))
        .current_dir(dir.path())
        .args(args)
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    (output.status.code().unwrap(), stdout)
}

const TWO_ERRORS: &str =
    "contract C() {\n  function f(int x) {\n    require(x > y);\n    require(sha256(x) == x);\n  }\n}\n";

#[test]
fn check_reports_every_error_with_its_location_and_fails() {
    let (status, stdout) = check(&["main.ark", "--check"], &[("main.ark", TWO_ERRORS)]);
    assert_eq!(status, 1);
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "{stdout}");
    assert!(
        lines[0].starts_with("main.ark:3:17: error[validation]: "),
        "{stdout}"
    );
    assert!(lines[0].contains("binding 'y' is undefined"), "{stdout}");
    assert!(lines[1].starts_with("main.ark:4:20: error"), "{stdout}");

    let (status, stdout) = check(
        &["main.ark", "--check"],
        &[
            (
                "main.ark",
                "import \"lib/l.ark\"; contract C() { function f() { require(true); } }",
            ),
            (
                "lib/l.ark",
                "library L { function g(Missing m) { require(true); } }",
            ),
        ],
    );
    assert_eq!(status, 1);
    assert!(stdout.starts_with("lib/l.ark:1:32: error"), "{stdout}");
}

#[test]
fn check_gives_file_and_import_errors_no_code() {
    let (status, stdout) = check(&["nothere.ark", "--check"], &[]);
    assert_eq!(status, 1);
    assert!(
        stdout.starts_with("nothere.ark: error: cannot read "),
        "{stdout}"
    );
    let main = "import \"gone.ark\"; contract C() { function f() { require(true); } }";
    let (status, stdout) = check(&["main.ark", "--check"], &[("main.ark", main)]);
    assert_eq!(status, 1);
    assert!(stdout.starts_with("main.ark:1:1: error: "), "{stdout}");
}

#[test]
fn check_json_lists_diagnostics_and_only_errors_fail() {
    let (status, stdout) = check(
        &["main.ark", "--check", "--json"],
        &[("main.ark", TWO_ERRORS)],
    );
    assert_eq!(status, 1);
    let diagnostics: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let first = &diagnostics[0];
    assert_eq!(first["severity"], "error");
    assert_eq!(
        first["start"],
        serde_json::json!({ "line": 3, "column": 17 })
    );
    assert_eq!(first["end"], serde_json::json!({ "line": 3, "column": 18 }));
    assert_eq!(first["file"], "main.ark");

    let clean = "contract C(pubkey k) { function f(signature s) { require(checkSig(s, k)); } }";
    let (status, stdout) = check(&["main.ark", "--check", "--json"], &[("main.ark", clean)]);
    assert_eq!((status, stdout.trim()), (0, "[]"));

    let warned = "contract C(int unused) { function f() { require(true); } }";
    let (status, stdout) = check(&["main.ark", "--check", "--json"], &[("main.ark", warned)]);
    let diagnostics: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        (status, &diagnostics[0]["severity"]),
        (0, &"warning".into())
    );
}

#[test]
fn debug_writes_the_source_maps_next_to_the_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let clean = "contract C(pubkey k) { function f(signature s) { require(checkSig(s, k)); } }";
    std::fs::write(dir.path().join("main.ark"), clean).unwrap();
    let run = |args: &[&str]| {
        let status = Command::new(env!("CARGO_BIN_EXE_arkadec"))
            .current_dir(dir.path())
            .args(args)
            .status()
            .unwrap();
        assert!(status.success());
    };
    let read = |path: &str| -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(dir.path().join(path)).unwrap()).unwrap()
    };

    run(&["main.ark"]);
    assert!(!dir.path().join("main.debug.json").exists());

    std::fs::create_dir(dir.path().join("out")).unwrap();
    run(&["main.ark", "-o", "out/c.json", "--debug"]);
    let debug = read("out/c.debug.json");
    assert_eq!(
        debug["artifactFingerprint"],
        read("out/c.json")["fingerprint"]
    );
    assert!(!debug["functions"]["f"]["sourceMap"]
        .as_array()
        .unwrap()
        .is_empty());
}
