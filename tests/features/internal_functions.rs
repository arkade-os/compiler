use arkade_compiler::compile;
use arkade_compiler::opcodes::{OP_CHECKSIG, OP_INSPECTNUMOUTPUTS};

/// A call to an internal helper inlines the helper's statements into the
/// caller's covenant.
#[test]
fn internal_call_inlines_helper_requires() {
    let code = r#"
        contract Helper(pubkey owner) {
            function checkOutputs() internal {
                require(tx.numOutputs >= 1);
            }

            function spend(signature ownerSig) {
                checkOutputs();
                require(checkSig(ownerSig, owner));
            }
        }
    "#;

    let output = compile(code).expect("compile");
    let asm = crate::common::arkade_asm(&output, "spend");
    assert!(
        asm.contains(OP_INSPECTNUMOUTPUTS),
        "helper require missing from caller ASM: {asm}"
    );
    assert!(asm.contains(OP_CHECKSIG), "caller require missing: {asm}");
    assert_eq!(
        output.functions.len(),
        1,
        "internal helper must not become a spend group"
    );
}

/// Helpers may be declared after their callers.
#[test]
fn internal_call_resolves_helper_declared_later() {
    let code = r#"
        contract Helper(pubkey owner) {
            function spend(signature ownerSig) {
                checkOutputs();
                require(checkSig(ownerSig, owner));
            }

            function checkOutputs() internal {
                require(tx.numOutputs >= 1);
            }
        }
    "#;

    let output = compile(code).expect("compile");
    let asm = crate::common::arkade_asm(&output, "spend");
    assert!(
        asm.contains(OP_INSPECTNUMOUTPUTS),
        "helper require missing from caller ASM: {asm}"
    );
}

#[test]
fn call_to_unknown_helper_is_an_error() {
    let code = r#"
        contract Helper(pubkey owner) {
            function spend(signature ownerSig) {
                missing();
                require(checkSig(ownerSig, owner));
            }
        }
    "#;

    let err = compile(code)
        .map(|_| ())
        .expect_err("unknown helper must fail");
    assert!(
        err.to_string()
            .contains("unknown internal function 'missing'"),
        "unexpected error: {err}"
    );
}

#[test]
fn helper_call_with_arguments_is_an_error() {
    let code = r#"
        contract Helper(pubkey owner) {
            function checkOutputs() internal {
                require(tx.numOutputs >= 1);
            }

            function spend(signature ownerSig) {
                checkOutputs(1);
                require(checkSig(ownerSig, owner));
            }
        }
    "#;

    let err = compile(code).map(|_| ()).expect_err("arguments must fail");
    assert!(
        err.to_string().contains("cannot take arguments"),
        "unexpected error: {err}"
    );
}
