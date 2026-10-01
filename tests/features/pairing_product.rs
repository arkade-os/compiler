use crate::common::{arkade_asm_tokens, compile_unoptimized};
use arkade_compiler::opcodes::OP_ECPAIRING;

#[test]
fn pairing_product_accepts_every_supported_arity() {
    for pairs in 1..=16 {
        let source = format!(
            "contract Product() {{ function spend(int[{}] points) {{ require(ecPairingProduct(points, 2)); }} }}",
            6 * pairs
        );
        for optimize in [false, true] {
            let artifact = if optimize {
                arkade_compiler::compile(&source).unwrap()
            } else {
                compile_unoptimized(&source).unwrap()
            };
            let asm = arkade_asm_tokens(&artifact, "spend");
            assert_eq!(asm.iter().filter(|op| *op == OP_ECPAIRING).count(), 1);
        }
    }
}

#[test]
fn pairing_product_preserves_live_bindings_and_supports_helpers() {
    let source = r#"
        contract Product(int curve) {
            private function check(int[24] points, int selected) bool {
                return ecPairingProduct(points, selected);
            }
            function spend(int[24] points, int sentinel) {
                require(check(points, curve));
                require(sentinel == 37);
                require(points[0] == 0);
            }
        }
    "#;
    for optimize in [false, true] {
        let artifact = if optimize {
            arkade_compiler::compile(source).unwrap()
        } else {
            compile_unoptimized(source).unwrap()
        };
        assert_eq!(
            arkade_asm_tokens(&artifact, "spend")
                .iter()
                .filter(|op| *op == OP_ECPAIRING)
                .count(),
            1
        );
    }
}

#[test]
fn pairing_product_accepts_literals_and_array_returning_helpers() {
    let source = r#"
        contract Product() {
            private function points() int[6] { return [0, 0, 0, 0, 0, 0]; }
            function spend() {
                require(ecPairingProduct(points(), 2));
                require(ecPairingProduct([0, 0, 0, 0, 0, 0], 2));
            }
        }
    "#;
    compile_unoptimized(source).unwrap();
    arkade_compiler::compile(source).unwrap();
}

#[test]
fn pairing_product_rejects_wrong_type_and_arity() {
    for ty in [
        "int", "int[1]", "int[5]", "int[7]", "int[97]", "int[102]", "bytes[6]", "bool[6]",
    ] {
        let source = format!(
            "contract Product() {{ function spend({ty} points) {{ require(ecPairingProduct(points, 2)); }} }}"
        );
        assert!(arkade_compiler::compile(&source).is_err(), "accepted {ty}");
    }
    assert!(arkade_compiler::compile("contract Product() { function spend(int[6] points) { require(ecPairingProduct(points, true)); } }").is_err());
}

#[test]
fn pairing_product_works_in_loop_and_short_circuit_expression() {
    let source = r#"
        contract Product() {
            function spend(int[6] points, int[2] curves) {
                for (i, curve) in curves {
                    require(i == 0 || ecPairingProduct(points, curve));
                }
            }
        }
    "#;
    compile_unoptimized(source).unwrap();
    arkade_compiler::compile(source).unwrap();
}

#[test]
fn pairing_product_rejects_mixed_literal_elements() {
    for bad in ["true", "0x01", "[1]"] {
        let source = format!(
            "contract Product() {{ function spend() {{ require(ecPairingProduct([0, 0, 0, 0, 0, {bad}], 2)); }} }}"
        );
        assert!(arkade_compiler::compile(&source).is_err(), "accepted {bad}");
    }
}
