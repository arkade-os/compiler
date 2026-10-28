use arkade_compiler::compile;

fn compile_error(source: &str) -> String {
    compile(source).expect_err(source).to_string()
}

#[test]
fn constant_operands_outside_the_vm_domain_do_not_compile() {
    for (body, expected) in [
        (
            "require(size(digest(d, 9)) == 32);",
            "digest hashType must be 1 to 5, got 9",
        ),
        (
            "require(sighash(7) == h);",
            "sighash hashType must be 0 to 3 or 129 to 131, got 7",
        ),
        (
            "require(size(tx.packet(300)) > 0);",
            "tx.packet packet type must be 0 to 255, got 300",
        ),
        (
            "require(checkTime(-5));",
            "checkTime timestamp must be at least 0, got -5",
        ),
        (
            "require(modExp(n, 2, 0) == 1);",
            "modExp modulus must be at least 1, got 0",
        ),
        (
            "require(modExp(n, -1, 7) == 1);",
            "modExp exponent must be at least 0, got -1",
        ),
        (
            "require(size(num2bin(n, 521)) == 521);",
            "num2bin size must be 0 to 520, got 521",
        ),
        (
            "require(checkSigFromStack(s, h, sha160x));",
            "checkSigFromStack message must be 32 bytes, got 20",
        ),
        (
            "require(merkleRoot(0x00, 0x01, 0x0000, h) == h);",
            "merkleRoot proof must be a multiple of 32 bytes, got 2",
        ),
    ] {
        let source = format!(
            "contract C(bytes32 h) {{ function f(bytes d, signature s, bytes20 sha160x, int n) {{ {body} require(size(d) + n + size(sha160x) > 0 && checkSig(s, h)); }} }}"
        );
        let error = compile_error(&source);
        assert!(error.contains(expected), "{body}: {error}");
    }
}

#[test]
fn constant_operands_inside_the_vm_domain_compile() {
    for body in [
        "require(size(digest(d, 4)) == 32);",
        "require(sighash(131) == h);",
        "require(size(tx.packet(255)) > 0);",
        "require(checkSigFromStack(s, h, h));",
        "require(merkleRoot(0x00, 0x01, d, h) == h);",
    ] {
        let source = format!(
            "contract C(bytes32 h) {{ function f(bytes d, signature s) {{ {body} require(size(d) > 0 && checkSig(s, h)); }} }}"
        );
        compile(&source).unwrap_or_else(|error| panic!("{body}: {error}"));
    }
}

fn signatures(keys: usize, body: &str) -> String {
    format!(
        "contract C(pubkey[{keys}] keys) {{ function f(signature[{keys}] sigs, int n) {{ {body} }} }}"
    )
}

const EACH_KEY: &str = "for (i, key) in keys { require(checkSig(sigs[i], key)); }";

#[test]
fn opcode_counts_do_not_enforce_emulator_compute_limits() {
    let count = |source: &str, opcode: &str| {
        let output = compile(source).unwrap();
        output.functions[0]
            .arkade
            .as_ref()
            .unwrap()
            .costs
            .iter()
            .find(|cost| cost.name == opcode)
            .unwrap()
            .used
    };
    for keys in [50, 51] {
        assert_eq!(
            count(
                &signatures(keys, &format!("require(n > 0); {EACH_KEY}")),
                "OP_CHECKSIGVERIFY"
            ),
            keys
        );
    }
    // The first key uses OP_CHECKSIG; the rest use OP_CHECKSIGADD.
    for keys in [51, 52] {
        assert_eq!(
            count(
                &signatures(keys, "require(n > 0); require(checkMultisig(keys, sigs));"),
                "OP_CHECKSIGADD"
            ),
            keys - 1
        );
    }
    let branches = format!("if (n > 0) {{ {EACH_KEY} }} else {{ {EACH_KEY} }}");
    assert_eq!(count(&signatures(30, &branches), "OP_CHECKSIGVERIFY"), 30);
    assert_eq!(
        count(
            &signatures(30, &format!("require(n > 0); {EACH_KEY} {EACH_KEY}")),
            "OP_CHECKSIGVERIFY"
        ),
        60
    );
}

#[test]
fn pushes_above_the_vm_element_size_do_not_compile() {
    let source = |bytes: usize| {
        format!(
            "contract C(bytes32 h) {{ function f() {{ require(sha256(0x{}) == h); }} }}",
            "ab".repeat(bytes)
        )
    };
    compile(&source(520)).unwrap();
    let error = compile_error(&source(521));
    assert!(
        error.contains("pushes a 521-byte value, above the VM element limit of 520"),
        "{error}"
    );
}

#[test]
fn signature_checks_that_may_be_false_warn() {
    let warnings = |body: &str| {
        let source = format!(
            "contract C(pubkey a, pubkey b) {{ function f(signature x, signature y, int n) {{ require(n > 0); {body} }} }}"
        );
        compile(&source)
            .unwrap_or_else(|error| panic!("{body}: {error}"))
            .warnings
            .iter()
            .filter(|warning| warning.contains("invalid non-empty signature"))
            .count()
    };
    for (body, expected) in [
        ("require(checkSig(x, a)); require(checkSig(y, b));", 0),
        ("require(checkSig(x, a) && checkSig(y, b));", 0),
        (
            "bool ok = checkSig(x, a); require(ok && checkSig(y, b));",
            0,
        ),
        ("require(checkSig(x, a) || checkSig(y, b));", 2),
        (
            "if (checkSig(x, a)) { require(n > 1); } require(checkSig(y, b));",
            1,
        ),
        ("require(!checkSig(x, a) && checkSig(y, b));", 1),
        ("require(checkSig(x, a) == checkSig(y, b));", 2),
    ] {
        assert_eq!(warnings(body), expected, "{body}");
    }
}
