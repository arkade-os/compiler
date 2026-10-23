use arkade_compiler::{analyze, compile_sources_with_options, CompileOptions, Severity};
use std::collections::BTreeMap;

fn files(source: &str) -> BTreeMap<String, String> {
    BTreeMap::from([("main.ark".to_string(), source.to_string())])
}

#[test]
fn one_analysis_gives_diagnostics_the_typed_ast_and_the_artifact() {
    let source = "contract C(pubkey owner) { function spend(signature s, int n) { require(checkSig(s, owner)); require(n + 1 > 2); } }";
    let analysis = analyze("main.ark", &files(source));
    assert!(analysis.diagnostics().is_empty());
    let contract = analysis.contract().expect("analyzed");
    let arkade_compiler::models::Statement::Require(requirement) =
        &contract.functions[0].statements[1].statement
    else {
        panic!("expected a requirement");
    };
    let arkade_compiler::Requirement::Comparison { left, .. } = requirement else {
        panic!("expected a comparison");
    };
    assert_eq!(left.ty(), &arkade_compiler::ArkType::Int);
    for optimize in [true, false] {
        let options = CompileOptions { optimize };
        let mut staged = analysis.compile(options).unwrap();
        let mut direct = compile_sources_with_options("main.ark", &files(source), options).unwrap();
        staged.updated_at = None;
        direct.updated_at = None;
        assert_eq!(
            serde_json::to_value(&staged).unwrap(),
            serde_json::to_value(&direct).unwrap()
        );
    }
}

#[test]
fn analysis_errors_stop_compilation_and_code_generation_errors_wait_for_it() {
    let invalid = analyze(
        "main.ark",
        &files("contract C() { function spend(int n) { require(m > 0); } }"),
    );
    assert!(invalid.contract().is_none());
    let errors = invalid.diagnostics();
    assert!(
        errors.iter().any(|d| d.severity == Severity::Error),
        "{errors:?}"
    );
    assert_eq!(
        invalid.compile(CompileOptions::default()).unwrap_err(),
        errors
    );

    let source = "contract C() {\n    function spend(int[2] xs) {\n        for (i, x) in xs {\n            require(xs[i + 1] == x);\n        }\n    }\n}";
    let analysis = analyze("main.ark", &files(source));
    assert!(analysis
        .diagnostics()
        .iter()
        .all(|d| d.lint.is_some_and(crate::common::is_covenant_lint)));
    let [error] = analysis
        .compile(CompileOptions::default())
        .unwrap_err()
        .try_into()
        .unwrap();
    assert_eq!(error.code.as_deref(), Some("emission"));
    let span = error.span.expect("located");
    assert_eq!(&source[span.start..span.end], "require(xs[i + 1] == x);");
}

#[test]
fn a_library_analyzes_but_does_not_compile() {
    let source =
        "library L { function persists() { require(tx.outputs[0].value >= tx.inputs[0].value); } }";
    let analysis = analyze("main.ark", &files(source));
    assert!(analysis.contract().expect("analyzed").is_library);
    let [error] = analysis
        .compile(CompileOptions::default())
        .unwrap_err()
        .try_into()
        .unwrap();
    assert!(
        error.message.contains("entry file must declare a contract"),
        "{error:?}"
    );
}

#[test]
fn a_syntax_error_in_an_import_is_located_in_that_file() {
    let broken = "library Fees { function f() int { return 1 } }";
    let mut project =
        files("import \"fees.ark\"; contract C() { function spend() { require(Fees.f() == 1); } }");
    project.insert("fees.ark".to_string(), broken.to_string());
    let [error] = analyze("main.ark", &project)
        .diagnostics()
        .try_into()
        .unwrap();
    assert_eq!(error.file, "fees.ark");
    let span = error.span.expect("located");
    assert_eq!(&broken[span.start..span.end], "}");
    let message = arkade_compiler::compile_sources("main.ark", &project)
        .unwrap_err()
        .to_string();
    assert!(message.starts_with("fees.ark: Parse error:"), "{message}");
}
