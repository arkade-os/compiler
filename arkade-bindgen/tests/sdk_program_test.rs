//! `sdk-program` target: `ContractJson` → the TypeScript SDK's Program JSON.
//!
//! The golden file is the contract with the SDK. `packages/ts-sdk` carries the
//! same bytes as a test fixture and asserts that `parseArtifact` accepts them
//! and derives a stable address, so a change here that the SDK cannot consume
//! shows up as a diff in both repositories.

use std::path::{Path, PathBuf};

use arkade_bindgen::ir::build_ir;
use arkade_bindgen::targets::sdk_program::render;
use arkade_bindgen::{generate_from_str, Options, Target};
use serde_json::Value;

fn examples_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples")
}

/// Compile an example and render its SDK program as written to disk.
fn render_for(relative: &str) -> String {
    let artifact = arkade_compiler::compile_file(examples_dir().join(relative))
        .unwrap_or_else(|e| panic!("compile {relative}: {e}"));
    render(&build_ir(&artifact).expect("build IR")).expect("render program")
}

/// The same program parsed. Note that `serde_json` sorts object keys, so
/// anything order-sensitive has to be asserted against the rendered text.
fn program_for(relative: &str) -> Value {
    serde_json::from_str(&render_for(relative)).expect("program is valid JSON")
}

fn function<'a>(program: &'a Value, name: &str) -> &'a Value {
    program
        .get("functions")
        .and_then(|f| f.get(name))
        .unwrap_or_else(|| panic!("function {name} missing"))
}

fn names(list: &Value) -> Vec<&str> {
    list.as_array()
        .expect("array")
        .iter()
        .map(|entry| {
            entry
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_else(|| entry.as_str().expect("name or string"))
        })
        .collect()
}

#[test]
fn target_is_selectable_and_names_its_file() {
    let artifact = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/htlc.json"),
    )
    .expect("htlc fixture");
    let generated = generate_from_str(&artifact, Target::SdkProgram, &Options::default())
        .expect("codegen should succeed");
    assert_eq!(generated.filename, "htlc.program.json");
    let program: Value = serde_json::from_str(&generated.content).expect("valid JSON");
    assert_eq!(program["version"], 0);
    assert_eq!(program["name"], "HTLC");
}

/// Spend groups must reach the SDK in artifact order: it builds the taproot
/// tree from `Object.keys(functions)`, so reordering changes the address.
#[test]
fn functions_keep_artifact_order() {
    let rendered = render_for("escrow/escrow.ark");
    let positions: Vec<usize> = ["release", "refund", "resolve", "unilateral"]
        .iter()
        .map(|name| {
            rendered
                .find(&format!("\"{name}\": {{"))
                .unwrap_or_else(|| panic!("{name} missing from:\n{rendered}"))
        })
        .collect();
    assert!(
        positions.windows(2).all(|pair| pair[0] < pair[1]),
        "functions are out of artifact order: {positions:?}"
    );
}

/// The three leaf shapes the compiler emits map onto the SDK's structured
/// tapscript fields rather than staying as assembly.
#[test]
fn leaves_map_onto_structured_tapscript_fields() {
    let program = program_for("htlc/htlc.ark");

    // Hash condition: the SDK appends the VERIFY itself, so it is dropped here.
    let claim = &function(&program, "claim")["tapscript"];
    assert_eq!(
        claim["asm"],
        serde_json::json!(["HASH160", "$preimageHash", "EQUAL"])
    );
    assert_eq!(claim["witness"], serde_json::json!(["preimage"]));
    assert_eq!(claim["signers"], serde_json::json!(["$server"]));

    assert_eq!(
        function(&program, "refund")["tapscript"]["cltv"],
        "$refundTime"
    );

    let unilateral = &function(&program, "unilateral")["tapscript"];
    assert_eq!(
        unilateral["csv"],
        serde_json::json!({"type": "blocks", "value": "$exit"})
    );
    assert_eq!(unilateral["signers"], serde_json::json!(["$sender"]));
}

/// The SDK derives the tweaked co-signer key from the function's own arkade
/// script and appends it, so `<EMULATOR_KEY:fn>` must not be listed as a signer.
#[test]
fn the_tweaked_cosigner_is_left_to_the_sdk() {
    let program = program_for("escrow/escrow.ark");
    for name in ["release", "refund", "resolve"] {
        let signers = &function(&program, name)["tapscript"]["signers"];
        assert_eq!(signers, &serde_json::json!(["$server"]), "{name}");
    }
    // A standalone leaf has no covenant and therefore no co-signer at all.
    assert_eq!(
        function(&program, "unilateral")["tapscript"]["signers"],
        serde_json::json!(["$buyerPk", "$sellerPk"])
    );
}

/// The artifact documents that covenant inputs are pushed in reverse
/// declaration order; the emitted witness carries that stack so a client does
/// not have to know the convention.
#[test]
fn covenant_witness_is_the_reversed_input_stack() {
    let program = program_for("escrow/escrow.ark");
    let resolve = function(&program, "resolve");
    assert_eq!(
        names(&resolve["inputs"]),
        ["sellerShareBps", "attestedAt", "oracleSig"]
    );
    assert_eq!(
        resolve["arkadeScript"]["witness"],
        serde_json::json!(["oracleSig", "attestedAt", "sellerShareBps"])
    );
}

/// Arrays and structs have no counterpart in the SDK's flat parameter model,
/// so they arrive expanded into their scalar leaves, dotted paths and all.
#[test]
fn composite_parameters_arrive_flattened() {
    let program = program_for("threshold_oracle/threshold_oracle.ark");
    let params = names(&program["params"]);
    for leaf in ["oracles.0", "oracles.1", "oracles.2"] {
        assert!(params.contains(&leaf), "missing {leaf} in {params:?}");
    }
    assert_eq!(
        function(&program, "attest")["arkadeScript"]["witness"],
        serde_json::json!([
            "oracleSigs.2",
            "oracleSigs.1",
            "oracleSigs.0",
            "recipientScriptPubKey",
            "messageHash",
            "amount"
        ])
    );
}

/// `new Contract(...)` has no SDK equivalent, so each distinct instantiation
/// becomes a parameter the caller binds to the child's witness program.
#[test]
fn instantiations_become_declared_parameters() {
    let program = program_for("escrow/escrow.ark");
    let params = names(&program["params"]);
    for expected in [
        "server",
        "vtxo_SingleSig_sellerPk_exit",
        "vtxo_SingleSig_buyerPk_exit",
        "vtxo_SingleSig_mediatorPk_exit",
    ] {
        assert!(
            params.contains(&expected),
            "missing {expected} in {params:?}"
        );
    }

    // Every `$name` the program references must be declared, or the SDK's
    // validateProgram rejects it.
    let text = serde_json::to_string(&program).expect("serialize");
    for reference in text.split('"').filter(|t| t.starts_with('$')) {
        let name = &reference[1..];
        assert!(
            params.contains(&name),
            "'{reference}' is used but not declared"
        );
    }
}

/// Every shipped example has to survive the bridge; a contract the target
/// cannot express should fail loudly here rather than in a client.
#[test]
fn every_example_renders() {
    let mut checked = 0;
    let mut stack = vec![examples_dir()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read examples") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "ark") {
                continue;
            }
            let artifact = match arkade_compiler::compile_file(&path) {
                Ok(artifact) => artifact,
                // Import-only files without a contract are not entry points.
                Err(_) => continue,
            };
            let ir = build_ir(&artifact).expect("build IR");
            render(&ir).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            checked += 1;
        }
    }
    assert!(
        checked >= 20,
        "expected the full example set, rendered {checked}"
    );
}

/// The golden the SDK's fixture is copied from. Regenerate with:
/// `cargo run -p arkade-bindgen -- <escrow artifact> --lang sdk-program -o arkade-bindgen/tests/fixtures/`
#[test]
fn escrow_program_matches_the_golden() {
    let artifact = arkade_compiler::compile_file(examples_dir().join("escrow/escrow.ark"))
        .expect("compile escrow");
    let generated = render(&build_ir(&artifact).expect("build IR")).expect("render");
    let golden = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/escrow.program.json"),
    )
    .expect("escrow golden");
    assert_eq!(
        generated, golden,
        "escrow program drifted from the golden; regenerate it and update the SDK fixture"
    );
}
