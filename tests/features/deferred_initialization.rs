use arkade_compiler::{compile, compile_sources_with_options, CompileOptions};

fn source(body: &str) -> String {
    let parameters = [("bool", "choose"), ("int", "input"), ("int", "index")]
        .into_iter()
        .filter(|(_, name)| {
            body.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .any(|word| word == *name)
        })
        .map(|(ty, name)| format!("{ty} {name}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("struct Pair {{ int a; int[2] b; }} contract Deferred() {{ function spend({parameters}) {{ {body} }} }}")
}

fn artifact(body: &str, optimize: bool) -> arkade_compiler::ContractJson {
    compile_sources_with_options(
        "main.ark",
        &[("main.ark".into(), source(body))].into_iter().collect(),
        CompileOptions { optimize },
    )
    .unwrap()
}

#[test]
fn deferred_declarations_allocate_on_assignment_and_reduce_assembly() {
    for optimize in [false, true] {
        for (deferred, filled) in [
            (
                "int x; x = 7; require(x == 7);",
                "int x = 0; x = 7; require(x == 7);",
            ),
            (
                "int x; if (choose) { x = 7; } else { x = 9; } require(x > 0);",
                "int x = 0; if (choose) { x = 7; } else { x = 9; } require(x > 0);",
            ),
            (
                "int[2] x; if (choose) { x = [7, 9]; } else { x = [9, 7]; } require(x[index] > 0);",
                "int[2] x = [0, 0]; if (choose) { x = [7, 9]; } else { x = [9, 7]; } require(x[index] > 0);",
            ),
            (
                "Pair x; x = { a: 7, b: [9, 11] }; require(x.b[index] > x.a);",
                "Pair x = { a: 0, b: [0, 0] }; x = { a: 7, b: [9, 11] }; require(x.b[index] > x.a);",
            ),
        ] {
            let output = artifact(deferred, optimize);
            let asm = crate::common::arkade_asm_tokens(&output, "spend");
            let filled = artifact(filled, optimize);
            let filled_asm = crate::common::arkade_asm_tokens(&filled, "spend");
            assert!(asm.len() < filled_asm.len(), "{deferred}: {asm:?} vs {filled_asm:?}");
            assert!(!asm.iter().any(|token| token == "OP_PUT"), "{asm:?}");
            assert_eq!(crate::common::arkade_inputs(&output, "spend"), crate::common::arkade_inputs(&filled, "spend"));
            assert_eq!(crate::common::witness_names(&output, "spend", "spend"), ["serverSig", "emulatorSig"]);
            assert_eq!(crate::common::group(&output, "spend").leaves.len(), 1);
        }
        let output = artifact("int x; x = 7; require(x == 7);", optimize);
        let asm = crate::common::arkade_asm_tokens(&output, "spend");
        let initialized = artifact("int x = 7; require(x == 7);", optimize);
        assert_eq!(asm, crate::common::arkade_asm_tokens(&initialized, "spend"));
    }
}

#[test]
fn deferred_initialization_handles_branches_loops_and_later_reassignment() {
    for optimize in [false, true] {
        for body in [
            "int x; if (choose) { x = 7; require(x > 0); } x = input; require(x == input);",
            "int x; int y; if (choose) { x = 7; int tmp = input; y = tmp; } else { y = input; x = 9; } require(x > 0); require(y == input);",
            "Pair x; int y; if (choose) { x = { a: 7, b: [9, 11] }; y = input; } else { y = input; x = { a: 9, b: [11, 13] }; } require(x.b[index] > x.a); require(y == input);",
            "int x; for (2) { x = input; require(x == input); } require(x == input);",
            "int x; int[2] inputs = [7, 9]; for (i, value) in inputs { x = value; } require(x == 9);",
            "int x; if (choose) { if (input > 0) { x = 7; } else { x = 9; } } else { x = 11; } x = x + 1; require(x > 0);",
            "Pair x; x = { a: input, b: [7, 9] }; x.b[index] = x.a; require(x.b[index] == input);",
            "int[2] x; require(x.length == 2); x = [7, 9]; require(x[index] > 0);",
            "Pair x; require(x.b.length == 2); x = { a: input, b: [7, 9] }; require(x.a == input);",
            "int x; for (0) { x = 7; } x = 9; require(x == 9);",
        ] {
            artifact(body, optimize);
        }
    }
}

#[test]
fn rejects_reads_without_definite_initialization() {
    for body in [
        "int x; require(x == 0);",
        "int x; x = x + 1; require(x > 0);",
        "int x; if (choose) { x = 7; } require(x > 0);",
        "int x; if (choose) { x = 7; } else { require(x > 0); } require(true);",
        "int x; for (0) { x = 7; } require(x > 0);",
        "int x; for (2) { x = x + 1; } require(x > 0);",
        "Pair x; x.a = 7; require(x.a == 7);",
        "int[2] x; x[index] = 7; require(x[index] > 0);",
        "int[2] x; for (i, value) in x { require(value > 0); }",
        "Pair x; Pair y = x; require(y.a > 0);",
        "bytes x; require(sha256(x) == 0x00);",
    ] {
        let error = compile(&source(body)).unwrap_err().to_string();
        assert!(error.contains("uninitialized"), "{body}: {error}");
    }
    for body in [
        "int x; x = false; require(x > 0);",
        "int[2] x; x = [7]; require(x[0] > 0);",
        "Pair x; x = { a: 7 }; require(x.a > 0);",
        "int x; if (choose) { int x = 7; require(x > 0); } x = 9; require(x > 0);",
        "if (choose) { int x; x = 7; require(x > 0); } require(x > 0);",
        "let x; x = 7; require(x > 0);",
    ] {
        assert!(compile(&source(body)).is_err(), "{body}");
    }
}

#[test]
fn deferred_initialization_supports_helpers_returns_and_constant_array_sizes() {
    let source = r#"
        struct Pair { int a; int[2] b; }
        contract Deferred() {
            const int SIZE = 2;
            function spend(bool choose, int input) {
                int[SIZE] values;
                Pair pair;
                values = [7, 9];
                pair = make(choose, input);
                require(pair.a == input);
                require(pair.b == values);
            }
            private function make(bool choose, int input) Pair {
                Pair pair;
                if (choose) { return { a: input, b: [7, 9] }; }
                pair = { a: input, b: [7, 9] };
                return pair;
            }
        }
    "#;
    for optimize in [false, true] {
        compile_sources_with_options(
            "main.ark",
            &[("main.ark".into(), source.into())].into_iter().collect(),
            CompileOptions { optimize },
        )
        .unwrap();
    }
}

#[test]
fn deferred_initialization_after_conditional_return_in_loops() {
    let source = r#"
        contract Deferred() {
            function spend(bool choose, int input) {
                require(counted(choose, input) == input);
                require(arrays(choose, input) == input);
            }
            private function counted(bool choose, int input) int {
                int x;
                for (2) { if (choose) { return input; } x = input; }
                return x;
            }
            private function arrays(bool choose, int input) int {
                int x;
                int[2] values = [7, 9];
                for (i, value) in values { if (choose) { return input; } x = value; }
                return x;
            }
        }
    "#;
    for optimize in [false, true] {
        compile_sources_with_options(
            "main.ark",
            &[("main.ark".into(), source.into())].into_iter().collect(),
            CompileOptions { optimize },
        )
        .unwrap();
    }
}

#[test]
fn imported_helpers_can_initialize_deferred_composites() {
    let files = [
        ("main.ark".into(), "import \"values.ark\"; contract Main() { function spend(int input) { int[Values.SIZE] values; values = Values.make(input); require(values[1] == input + 1); } }".into()),
        ("values.ark".into(), "library Values { const int SIZE = 2; function make(int input) int[SIZE] { int[SIZE] result; result = [input, input + 1]; return result; } }".into()),
    ].into_iter().collect();
    for optimize in [false, true] {
        compile_sources_with_options("main.ark", &files, CompileOptions { optimize }).unwrap();
    }
}
