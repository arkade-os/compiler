use std::collections::BTreeMap;

use crate::common::{arkade_asm_tokens, leaf_asm_tokens};
use arkade_compiler::{compile, compile_file, compile_sources, ContractJson};

fn project(
    entry: &str,
    sources: &[(&str, &str)],
) -> Result<ContractJson, Box<dyn std::error::Error>> {
    compile_sources(
        entry,
        &sources
            .iter()
            .map(|(path, source)| (path.to_string(), source.to_string()))
            .collect(),
    )
}

#[test]
fn imports_inline_helpers_fold_constants_and_preserve_sources() {
    let source = r#"// Original source and comments are embedded.
import "../shared/types.ark";
import "../shared/fees.ark";
contract Vault(Policy policy, int amount, pubkey owner) {
    function spend(int value) {
        require(Fees.calculate(value) <= policy.maximum);
        require(value >= Fees.MINIMUM);
        require(value != amount);
    }
    function exit(signature sig) tapscript { require(older(Fees.DELAY)); require(checkSig(sig, owner)); }
}"#;
    let types = "struct Policy { int maximum; } // end of file comment";
    let fees = r#"contract Fees() {
        const int MINIMUM = 10;
        const int DELAY = 144;
        static function twice(int amount) int { return amount * 2; }
        static function calculate(int amount) int { return twice(amount) + MINIMUM; }
    }"#;
    let output = project(
        "contracts/vault.ark",
        &[
            ("contracts/vault.ark", source),
            ("shared/types.ark", types),
            ("shared/fees.ark", fees),
            ("unused.ark", "invalid unused source"),
        ],
    )
    .expect("imports compile");
    let flat = compile(
        r#"struct Policy { int maximum; }
contract Vault(Policy policy, int amount, pubkey owner) {
    function spend(int value) {
        require(calculate(value) <= policy.maximum);
        require(value >= 10);
        require(value != amount);
    }
    static function twice(int n) int { return n * 2; }
    static function calculate(int n) int { return twice(n) + 10; }
    function exit(signature sig) tapscript { require(older(144)); require(checkSig(sig, owner)); }
}"#,
    )
    .unwrap();
    assert_eq!(
        arkade_asm_tokens(&output, "spend"),
        arkade_asm_tokens(&flat, "spend")
    );
    assert_eq!(
        leaf_asm_tokens(&output, "exit", "exit"),
        leaf_asm_tokens(&flat, "exit", "exit")
    );
    assert_eq!(output.functions.len(), 2);
    assert_eq!(output.structs.len(), 1);
    assert!(output.warnings.is_empty(), "{:?}", output.warnings);
    let bundle = output.source.as_ref().unwrap();
    assert_eq!(bundle.entry, "contracts/vault.ark");
    assert_eq!(bundle.files.len(), 3);
    assert_eq!(bundle.files["contracts/vault.ark"], source);
    assert_eq!(bundle.files["shared/types.ark"], types);
    let restored: ContractJson =
        serde_json::from_str(&serde_json::to_string(&output).unwrap()).unwrap();
    let bundle = restored.source.unwrap();
    let mut rebuilt = compile_sources(&bundle.entry, &bundle.files).unwrap();
    rebuilt.updated_at = output.updated_at.clone();
    assert_eq!(
        serde_json::to_value(rebuilt).unwrap(),
        serde_json::to_value(output).unwrap()
    );
}

#[test]
fn transitive_imports_keep_defining_scope_and_deduplicate_diamonds() {
    let output = project("main.ark", &[
        ("main.ark", r#"import "a.ark"; import "b.ark";
contract Main() { const int VALUE = 999; function spend() { require(A.value() == B.VALUE); } }"#),
        ("a.ark", r#"import "./b.ark"; contract A() { static function value() int { return B.VALUE; } }"#),
        ("b.ark", "contract B() { const int VALUE = 7; }"),
    ]).unwrap();
    assert_eq!(output.source.unwrap().files.len(), 3);
    let error = project("main.ark", &[
        ("main.ark", r#"import "a.ark"; contract Main() { function spend() { require(B.value() == 7); } }"#),
        ("a.ark", r#"import "b.ark"; contract A() {}"#),
        ("b.ark", "contract B() { static function value() int { return 7; } }"),
    ]).unwrap_err().to_string();
    assert!(error.contains("unknown contract 'B'"), "{error}");
}

#[test]
fn imported_struct_dependencies_are_available_for_layout_but_not_declaration() {
    for (ty, succeeds) in [("Policy", true), ("Hidden", false)] {
        let source = format!(
            r#"import "policy.ark"; contract Main({ty} policy) {{ function spend() {{ require(true); }} }}"#
        );
        let result = project(
            "main.ark",
            &[
                ("main.ark", &source),
                (
                    "policy.ark",
                    r#"import "hidden.ark"; struct Policy { Hidden value; }"#,
                ),
                ("hidden.ark", "struct Hidden { int number; }"),
            ],
        );
        assert_eq!(result.is_ok(), succeeds, "{result:?}");
    }
}

#[test]
fn imported_helpers_cannot_capture_callers_state_or_call_private_functions() {
    for (body, expected) in [
        (
            "static function value() int { return amount; }",
            "binding 'amount' is undefined",
        ),
        (
            "private function value() int { return 1; }",
            "not a static function",
        ),
        (
            "function value() { require(true); }",
            "not a static function",
        ),
    ] {
        let dependency = format!("contract Helper() {{ {body} }}");
        let error = project("main.ark", &[
            ("main.ark", r#"import "helper.ark"; contract Main(int amount) { function spend() { require(Helper.value() == amount); } }"#),
            ("helper.ark", &dependency),
        ]).unwrap_err().to_string();
        assert!(error.contains(expected), "{error}");
    }
}

#[test]
fn imports_validate_paths_cycles_and_name_collisions() {
    for (files, expected) in [
        (
            vec![("main.ark", r#"import "missing.ark"; contract Main() {}"#)],
            "missing.ark",
        ),
        (
            vec![("main.ark", r#"import "main.ark"; contract Main() {}"#)],
            "circular import",
        ),
        (
            vec![
                ("main.ark", r#"import "a.ark"; contract Main() {}"#),
                ("a.ark", r#"import "main.ark"; contract A() {}"#),
            ],
            "circular import",
        ),
        (
            vec![("main.ark", r#"import "../a.ark"; contract Main() {}"#)],
            "escapes the source root",
        ),
        (
            vec![("main.ark", r#"import "/a.ark"; contract Main() {}"#)],
            "relative .ark path",
        ),
        (
            vec![("main.ark", r#"import "a.txt"; contract Main() {}"#)],
            ".ark extension",
        ),
        (
            vec![
                ("main.ark", r#"import "a.ark"; contract Main() {}"#),
                ("a.ark", "contract Main() {}"),
            ],
            "duplicate declaration 'Main'",
        ),
        (
            vec![
                (
                    "main.ark",
                    r#"import "a.ark"; struct Policy { int a; } contract Main() {}"#,
                ),
                ("a.ark", "struct Policy { int b; }"),
            ],
            "duplicate declaration 'Policy'",
        ),
    ] {
        let error = project("main.ark", &files).unwrap_err().to_string();
        assert!(error.contains(expected), "{error}");
        assert!(error.contains("main.ark"), "{error}");
    }
    let error = compile(r#"import "a.ark"; contract Main() {}"#)
        .unwrap_err()
        .to_string();
    assert!(error.contains("imports require source files"), "{error}");
}

#[test]
fn import_depth_limit_includes_the_entry_file() {
    for count in [128, 129] {
        let files = (0..count)
            .map(|index| {
                let import = if index + 1 < count {
                    format!("import \"{}.ark\";", index + 1)
                } else {
                    String::new()
                };
                (
                    format!("{index}.ark"),
                    format!(
                        "{import} contract C{index}() {{ function spend() {{ require(true); }} }}"
                    ),
                )
            })
            .collect();
        let result = compile_sources("0.ark", &files);
        if count == 128 {
            assert_eq!(result.unwrap().source.unwrap().files.len(), count);
        } else {
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("import depth exceeds 128 files"));
        }
    }
}

#[test]
fn constructors_require_visible_contracts_and_matching_signatures() {
    for (call, succeeds) in [
        ("Other(owner)", true),
        ("Other()", false),
        ("Other(1)", false),
        ("Missing(owner)", false),
        ("Main(owner)", true),
    ] {
        let source = format!(
            r#"import "other.ark"; contract Main(pubkey owner) {{ function spend() {{ require(tx.outputs[0].scriptPubKey == new {call}); }} }}"#
        );
        let result = project(
            "main.ark",
            &[
                ("main.ark", &source),
                (
                    "other.ark",
                    "contract Other(pubkey owner) { function spend() { require(true); } }",
                ),
            ],
        );
        assert_eq!(result.is_ok(), succeeds, "{call}: {result:?}");
    }
}

#[test]
fn native_and_virtual_compilation_match_and_bundle_is_portable() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("contracts")).unwrap();
    let source = r#"import "../helper.ark"; contract Main() { function spend() { require(Helper.VALUE == 1); require(1); } }"#;
    let helper = "contract Helper() { const int VALUE = 1; function spend() { require(2); } }";
    std::fs::write(dir.path().join("contracts/main.ark"), source).unwrap();
    std::fs::write(dir.path().join("helper.ark"), helper).unwrap();
    let output = compile_file(dir.path().join("contracts/main.ark")).unwrap();
    assert_eq!(output.warnings.len(), 2);
    for path in ["contracts/main.ark", "helper.ark"] {
        assert!(
            output.warnings.iter().any(|warning| {
                warning.starts_with("warning[type]:") && warning.ends_with(&format!(" ({path})"))
            }),
            "{:?}",
            output.warnings
        );
    }
    let mut virtual_output = project(
        "contracts/main.ark",
        &[("contracts/main.ark", source), ("helper.ark", helper)],
    )
    .unwrap();
    virtual_output.updated_at = output.updated_at.clone();
    assert_eq!(
        serde_json::to_value(output).unwrap(),
        serde_json::to_value(virtual_output).unwrap()
    );
    let files = BTreeMap::from([
        ("./main.ark".to_string(), source.to_string()),
        ("main.ark".to_string(), source.to_string()),
    ]);
    assert!(compile_sources("main.ark", &files)
        .unwrap_err()
        .to_string()
        .contains("duplicate source path"));
}

#[test]
fn imported_constants_work_in_named_indices_and_multisig_thresholds() {
    let output = project("main.ark", &[
        ("main.ark", r#"import "limits.ark";
contract Main(pubkey[2] keys, pubkey owner) {
    function spend(signature sig) {
        require(checkMultisig([keys[Limits.INDEX]], [sig], Limits.THRESHOLD));
    }
    function exit(signature sig) tapscript {
        require(older(Limits.DELAY));
        require(checkMultisig([owner], [sig], Limits.THRESHOLD));
    }
}"#),
        ("limits.ark", "contract Limits() { const int INDEX = 1; const int THRESHOLD = 1; const int DELAY = 144; }"),
    ]).unwrap();
    assert!(arkade_asm_tokens(&output, "spend").contains(&"<keys.1>".to_string()));
    assert!(
        leaf_asm_tokens(&output, "exit", "exit").contains(&"OP_CHECKSEQUENCEVERIFY".to_string())
    );
}

#[test]
fn imported_helpers_do_not_retain_unreferenced_caller_parameters() {
    let output = project("main.ark", &[
        ("main.ark", r#"import "helper.ark"; contract Main(int value) { function spend(int input) { require(Helper.double(input) > 0); } }"#),
        ("helper.ark", "contract Helper() { static function double(int value) int { return value * 2; } }"),
    ]).unwrap();
    assert!(!arkade_asm_tokens(&output, "spend").contains(&"<value>".to_string()));
}

#[test]
fn imported_helpers_check_returns_recursion_and_namespace_shadowing() {
    for (entry, helper, expected) in [
        (
            "contract Main() { function spend() { require(Helper.value(1) == 1); } }",
            "contract Helper() { static function value(int x) int { if (x > 0) { return x; } } }",
            "must return a value on every path",
        ),
        (
            "contract Main() { function spend() { require(Helper.value() == 1); } }",
            "contract Helper() { static function value() int { return value(); } }",
            "recursive",
        ),
        (
            "contract Main(int Helper) { function spend() { require(Helper.VALUE > 0); } }",
            "contract Helper() { const int VALUE = 1; }",
            "shadows a contract namespace",
        ),
        (
            "contract Main() { function spend() { int Helper = 1; require(Helper.VALUE > 0); } }",
            "contract Helper() { const int VALUE = 1; }",
            "shadows a contract namespace",
        ),
        (
            "contract Main() { function spend() { require(Helper.MISSING > 0); } }",
            "contract Helper() { const int VALUE = 1; }",
            "unknown constant",
        ),
    ] {
        let source = format!("import \"helper.ark\"; {entry}");
        let error = project("main.ark", &[("main.ark", &source), ("helper.ark", helper)])
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{error}");
    }
}

#[test]
fn qualified_static_calls_are_distinct_from_group_methods() {
    project("main.ark", &[
        ("main.ark", r#"import "helper.ark"; contract Main(bytes32 txid) { function spend(int index) { require(Helper.controlIs(txid, index)); } }"#),
        ("helper.ark", "contract Helper() { static function controlIs(bytes32 txid, int index) bool { return index == 0; } }"),
    ]).unwrap();
}

#[test]
fn qualified_constants_in_builtin_operands_and_transaction_indices_match_literals() {
    let body = r#"contract Main(bytes32 txid) {
        function spend() {
            require(size(num2bin(Limits.VALUE, Limits.WIDTH)) == Limits.WIDTH);
            require(size(tx.inputs[Limits.INDEX].packet(Limits.PACKET)) >= 0);
            require(size(tx.packet(Limits.PACKET)) >= 0);
            require(tx.inputs[Limits.INDEX].value >= Limits.VALUE);
            require(tx.outputs[Limits.INDEX].value >= Limits.VALUE);
            require(tx.outputs[Limits.INDEX].assets.length >= Limits.INDEX);
            require(tx.outputs[Limits.INDEX].assets[Limits.INDEX].amount >= Limits.VALUE);
            require(tx.inputs[Limits.INDEX].assets.lookup(txid, Limits.INDEX) >= Limits.VALUE);
            require(tx.outputs[Limits.INDEX].scriptPubKey == new Limits(Limits.VALUE));
        }
    }"#;
    let helper = "contract Limits(int value) { const int INDEX = 0; const int VALUE = 7; const int WIDTH = 8; const int PACKET = 16; }";
    let source = format!("import \"limits.ark\"; {body}");
    let output = project("main.ark", &[("main.ark", &source), ("limits.ark", helper)]).unwrap();
    let literal_source = source
        .replace("Limits.INDEX", "0")
        .replace("Limits.VALUE", "7")
        .replace("Limits.WIDTH", "8")
        .replace("Limits.PACKET", "16");
    let literal = project(
        "main.ark",
        &[("main.ark", &literal_source), ("limits.ark", helper)],
    )
    .unwrap();
    assert_eq!(
        arkade_asm_tokens(&output, "spend"),
        arkade_asm_tokens(&literal, "spend")
    );
}
