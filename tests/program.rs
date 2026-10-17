use arkade_artifact::program::*;
use arkade_artifact::{program_from_artifact, program_from_json, ARTIFACT_FORMAT_VERSION};
use arkade_compiler::opcodes::{OP_EQUAL, OP_HASH160};

fn example(rel: &str) -> Program {
    let path = format!("{}/examples/{rel}", env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let artifact = arkade_compiler::compile(&source).unwrap_or_else(|e| panic!("{rel}: {e}"));
    let json = serde_json::to_string(&artifact).unwrap();
    let from_json = program_from_json(&json).unwrap_or_else(|e| panic!("{rel}: {e}"));
    let from_artifact = program_from_artifact(&artifact).unwrap_or_else(|e| panic!("{rel}: {e}"));
    assert_eq!(from_json, from_artifact);
    from_artifact
}

fn param(name: &str, value_type: ValueType) -> Param {
    Param {
        name: name.to_string(),
        value_type,
    }
}

#[test]
fn artifact_versions_are_checked_for_both_entry_points() {
    let source = "contract Demo(pubkey user) { function spend(signature sig) { require(checkSig(sig, user)); } }";
    let mut artifact = arkade_compiler::compile(source).unwrap();
    assert_eq!(artifact.format_version, Some(ARTIFACT_FORMAT_VERSION));
    let current = program_from_artifact(&artifact).unwrap();
    artifact.format_version = None;
    assert_eq!(program_from_artifact(&artifact).unwrap(), current);
    artifact.format_version = Some(ARTIFACT_FORMAT_VERSION + 1);
    let expected = format!(
        "program_from_artifact: unsupported artifact format version: {}",
        ARTIFACT_FORMAT_VERSION + 1
    );
    assert_eq!(program_from_artifact(&artifact).unwrap_err(), expected);
    assert_eq!(
        program_from_json(&serde_json::to_string(&artifact).unwrap()).unwrap_err(),
        expected
    );
}

#[test]
fn sized_preimage_checks_remain_in_the_condition() {
    for (declared_type, value_type, width) in [
        ("bytes20", ValueType::Bytes20, 20),
        ("bytes32", ValueType::Bytes32, 32),
    ] {
        let source = format!(
            "contract Lock(pubkey user, bytes32 digest) {{
                function claim({declared_type} preimage, signature sig) tapscript {{
                    require(sha256(preimage) == digest);
                    require(older(serverExitDelay));
                    require(checkSig(sig, user));
                }}
            }}"
        );
        let artifact = arkade_compiler::compile(&source).unwrap();
        let json = serde_json::to_string(&artifact).unwrap();
        let program = program_from_json(&json).unwrap();
        assert_eq!(program, program_from_artifact(&artifact).unwrap());
        let claim = program.function("claim").unwrap();
        assert_eq!(claim.inputs, vec![param("preimage", value_type)]);
        assert_eq!(claim.tapscript.witness, vec!["preimage"]);
        assert_eq!(claim.tapscript.csv, Some(CsvValue::ServerExitDelay));
        assert_eq!(claim.tapscript.signers, vec![Signer::Param("user".into())]);
        assert!(claim.arkade.is_none());
        assert_eq!(
            claim.tapscript.condition,
            vec![
                AsmToken::Opcode("OP_SIZE".into()),
                AsmToken::Number(width.to_string()),
                AsmToken::Opcode("OP_EQUALVERIFY".into()),
                AsmToken::Opcode("OP_SHA256".into()),
                AsmToken::Param("digest".into()),
                AsmToken::Opcode(OP_EQUAL.into()),
            ]
        );
        assert_eq!(
            serde_json::to_value(&claim.tapscript).unwrap()["csv"],
            "serverExitDelay"
        );
    }
}

#[test]
fn native_record_fields_and_asset_groups_keep_compiler_types() {
    let artifact = arkade_compiler::compile(
        "contract Records(AssetId assetId) {
            function spend(AssetGroup group, Outpoint previous) {
                require(group.delta >= 0);
                require(previous.txid == assetId.txid);
            }
        }",
    )
    .unwrap();
    let program = program_from_artifact(&artifact).unwrap();
    assert_eq!(
        program.params,
        vec![
            param("assetId.txid", ValueType::Bytes32),
            param("assetId.gidx", ValueType::Int),
            param("server", ValueType::Pubkey),
        ]
    );
    let spend = program.function("spend").unwrap();
    assert_eq!(
        spend.inputs,
        vec![
            param("group", ValueType::AssetGroup),
            param("previous.txid", ValueType::Bytes32),
            param("previous.vout", ValueType::Int),
        ]
    );
    assert_eq!(
        spend.arkade.as_ref().unwrap().witness,
        vec!["previous.vout", "previous.txid", "group"]
    );
    assert_eq!(
        serde_json::to_value(&spend.inputs[0]).unwrap()["type"],
        "AssetGroup"
    );
}

#[test]
fn integer_literals_remain_lossless_through_json() {
    for literal in [
        "9223372036854775808",
        "-9223372036854775809",
        "170141183460469231731687303715884105728",
        "115792089237316195423570985008687907853269984665640564039457584007913129639935",
    ] {
        let artifact = arkade_compiler::compile(&format!(
            "contract C() {{ function spend(int n) {{ require(n == {literal}); }} }}"
        ))
        .unwrap();
        let program = program_from_artifact(&artifact).unwrap();
        assert_eq!(
            program,
            program_from_json(&serde_json::to_string(&artifact).unwrap()).unwrap()
        );
        let asm = &program
            .function("spend")
            .unwrap()
            .arkade
            .as_ref()
            .unwrap()
            .asm;
        let number = AsmToken::Number(literal.into());
        assert!(asm.contains(&number), "{asm:?}");
        assert_eq!(serde_json::to_value(number).unwrap()["number"], literal);
    }
}

#[test]
fn emulator_signers_keep_their_position_and_can_sign_alone() {
    for (keys, sigs, expected) in [
        (
            "[emulator, server]",
            "[e, s]",
            vec![
                Signer::Emulator("spend".into()),
                Signer::Param("server".into()),
            ],
        ),
        (
            "[server, emulator]",
            "[s, e]",
            vec![
                Signer::Param("server".into()),
                Signer::Emulator("spend".into()),
            ],
        ),
        ("[emulator]", "[e]", vec![Signer::Emulator("spend".into())]),
    ] {
        let inputs = if keys.contains("server") {
            "signature e, signature s"
        } else {
            "signature e"
        };
        let artifact = arkade_compiler::compile(&format!(
            "contract C() {{
                function spend() {{ require(true); }}
                function spend({inputs}) tapscript {{
                    require(older(blocks(10)));
                    require(checkMultisig({keys}, {sigs}));
                }}
            }}"
        ))
        .unwrap();
        let program = program_from_artifact(&artifact).unwrap();
        assert_eq!(
            program,
            program_from_json(&serde_json::to_string(&artifact).unwrap()).unwrap()
        );
        let spend = program.function("spend").unwrap();
        assert_eq!(spend.tapscript.signers, expected);
        assert_eq!(spend.tapscript.csv, Some(CsvValue::Blocks(10)));
        assert!(spend.arkade.is_some());
        assert!(spend.inputs.is_empty());
        assert!(spend.tapscript.witness.is_empty());
    }
    for asm in [
        vec!["<user>", "OP_CHECKSIGVERIFY"],
        vec!["<user>", "OP_CHECKSIG", "<SERVER_KEY>", "OP_CHECKSIG"],
    ] {
        assert!(program_from_json(&leaf(&asm)).is_err());
    }
}

#[test]
fn colliding_tapleaf_inputs_keep_distinct_bindings_and_references() {
    for (input_type, body) in [
        ("bytes", "require(sha256(shared) == digest);"),
        ("bytes32", "require(sha256(preimage) == shared);"),
        ("int", "require(older(shared));"),
        ("int", "require(after(shared));"),
        ("pubkey", "require(older(blocks(10)));"),
    ] {
        let constructor = if input_type == "bytes" {
            "bytes32 digest"
        } else {
            ""
        };
        let preimage = if input_type == "bytes32" {
            ", bytes preimage"
        } else {
            ""
        };
        let (keys, sigs, signature_inputs) = if input_type == "pubkey" {
            ("[shared, emulator]", "[u, e]", "signature u, signature e")
        } else {
            ("[server, emulator]", "[s, e]", "signature s, signature e")
        };
        let artifact = arkade_compiler::compile(&format!(
            "contract C({constructor}) {{
                function spend(int shared) {{ require(shared > 0); }}
                function spend({input_type} shared{preimage}, {signature_inputs}) tapscript {{
                    {body}
                    require(checkMultisig({keys}, {sigs}));
                }}
            }}"
        ))
        .unwrap();
        let program = program_from_artifact(&artifact).unwrap();
        assert_eq!(
            program,
            program_from_json(&serde_json::to_string(&artifact).unwrap()).unwrap()
        );
        let spend = program.function("spend").unwrap();
        assert_eq!(spend.inputs[0], param("shared", ValueType::Int));
        assert_eq!(
            spend.inputs[1],
            param(
                "tapscript:shared",
                match input_type {
                    "bytes" => ValueType::Bytes,
                    "bytes32" => ValueType::Bytes32,
                    "int" => ValueType::Int,
                    "pubkey" => ValueType::Pubkey,
                    _ => unreachable!(),
                }
            )
        );
        assert_eq!(spend.arkade.as_ref().unwrap().witness, vec!["shared"]);
        assert_eq!(spend.tapscript.witness[0], "tapscript:shared");
        if input_type == "bytes32" {
            assert!(spend
                .tapscript
                .condition
                .contains(&AsmToken::Param("tapscript:shared".into())));
        } else if input_type == "int" && body.contains("older") {
            assert_eq!(
                spend.tapscript.csv,
                Some(CsvValue::Param("tapscript:shared".into()))
            );
        } else if input_type == "int" {
            assert_eq!(
                spend.tapscript.cltv,
                Some(LockValue::Param("tapscript:shared".into()))
            );
        } else if input_type == "pubkey" {
            assert_eq!(
                spend.tapscript.signers[0],
                Signer::Param("tapscript:shared".into())
            );
        }
    }
}

#[test]
fn compiled_raw_csv_literals_preserve_all_bits() {
    for operand in [70000, 1 << 30, (1 << 31) - 1] {
        let artifact = arkade_compiler::compile(&format!(
            "contract C(pubkey user) {{ function exit(signature sig) tapscript {{
                require(older({operand})); require(checkSig(sig, user));
            }} }}"
        ))
        .unwrap();
        let program = program_from_artifact(&artifact).unwrap();
        assert_eq!(
            program,
            program_from_json(&serde_json::to_string(&artifact).unwrap()).unwrap()
        );
        let exit = program.function("exit").unwrap();
        assert_eq!(exit.tapscript.csv, Some(CsvValue::Raw(operand)));
        assert_eq!(
            serde_json::to_value(&exit.tapscript.csv).unwrap()["raw"],
            operand
        );
        assert!(exit.arkade.is_none());
    }
}

#[test]
fn single_sig_splits_the_covenant_from_the_csv_exit() {
    let program = example("single_sig/single_sig.ark");
    assert_eq!(program.version, PROGRAM_VERSION);
    assert_eq!(program.name, "SingleSig");
    assert_eq!(
        program.params,
        vec![
            param("user", ValueType::Pubkey),
            param("server", ValueType::Pubkey),
        ]
    );

    let spend = program.function("spend").unwrap();
    assert_eq!(spend.inputs, vec![param("userSig", ValueType::Signature)]);
    assert_eq!(
        spend.tapscript.signers,
        vec![
            Signer::Param("server".into()),
            Signer::Emulator("spend".into())
        ]
    );
    assert!(spend.tapscript.csv.is_none());
    assert_eq!(
        spend.arkade.as_ref().unwrap().witness,
        vec!["userSig".to_string()]
    );

    let exit = program.function("unilateral").unwrap();
    assert!(exit.inputs.is_empty());
    assert!(exit.arkade.is_none());
    assert_eq!(exit.tapscript.signers, vec![Signer::Param("user".into())]);
    assert_eq!(exit.tapscript.csv, Some(CsvValue::ServerExitDelay));
}

#[test]
fn htlc_keeps_hash_timelock_and_preimage_witness() {
    let program = example("htlc/htlc.ark");
    assert_eq!(
        program.params,
        vec![
            param("sender", ValueType::Pubkey),
            param("receiver", ValueType::Pubkey),
            param("preimageHash", ValueType::Bytes20),
            param("refundTime", ValueType::Int),
            param("server", ValueType::Pubkey),
        ]
    );

    let claim = program.function("claim").unwrap();
    assert_eq!(claim.inputs, vec![param("preimage", ValueType::Bytes)]);
    assert_eq!(claim.tapscript.witness, vec!["preimage".to_string()]);
    assert_eq!(
        claim.tapscript.condition,
        vec![
            AsmToken::Opcode(OP_HASH160.to_string()),
            AsmToken::Param("preimageHash".into()),
            AsmToken::Opcode(OP_EQUAL.to_string()),
        ]
    );
    assert_eq!(
        claim.tapscript.signers,
        vec![
            Signer::Param("server".into()),
            Signer::Emulator("claim".into())
        ]
    );
    assert!(claim.arkade.is_some());

    let refund = program.function("refund").unwrap();
    assert!(refund.inputs.is_empty());
    assert_eq!(
        refund.tapscript.cltv,
        Some(LockValue::Param("refundTime".into()))
    );
    assert!(refund
        .tapscript
        .signers
        .contains(&Signer::Emulator("refund".into())));

    let exit = program.function("unilateral").unwrap();
    assert_eq!(exit.tapscript.csv, Some(CsvValue::ServerExitDelay));
    assert_eq!(exit.tapscript.signers, vec![Signer::Param("sender".into())]);

    let json = serde_json::to_string(&program).unwrap();
    assert!(json.contains("OP_HASH160"));
    assert!(json.contains("\"bytes20\""));
    assert!(!json.contains("$preimageHash"));
    assert!(!json.contains("\"hash\""));
}

#[test]
fn struct_vault_flattens_policy_fields() {
    let program = example("struct_vault/struct_vault.ark");
    assert_eq!(
        program.params,
        vec![
            param("policy.primary.key", ValueType::Pubkey),
            param("policy.primary.weight", ValueType::Int),
            param("policy.limits.0", ValueType::Int),
            param("policy.limits.1", ValueType::Int),
            param("policy.exitDelay", ValueType::Int),
            param("server", ValueType::Pubkey),
        ]
    );

    let update = program.function("update").unwrap();
    assert_eq!(
        update
            .inputs
            .iter()
            .map(|input| input.name.as_str())
            .collect::<Vec<_>>(),
        vec![
            "next.primary.key",
            "next.primary.weight",
            "next.limits.0",
            "next.limits.1",
            "next.exitDelay",
            "sig",
            "message",
        ]
    );
    assert_eq!(
        update
            .inputs
            .iter()
            .find(|input| input.name == "message")
            .unwrap()
            .value_type,
        ValueType::Bytes32
    );
    assert_eq!(
        update.arkade.as_ref().unwrap().witness,
        update
            .inputs
            .iter()
            .rev()
            .map(|input| input.name.clone())
            .collect::<Vec<_>>()
    );
    assert!(update
        .tapscript
        .signers
        .contains(&Signer::Emulator("update".into())));

    let exit = program.function("unilateral").unwrap();
    assert_eq!(
        exit.tapscript.csv,
        Some(CsvValue::Param("policy.exitDelay".into()))
    );
    assert_eq!(
        exit.tapscript.signers,
        vec![Signer::Param("policy.primary.key".into())]
    );
}

#[test]
fn child_output_placeholder_becomes_a_bytes32_parameter() {
    let files = [
        (
            "single_sig.ark",
            "contract SingleSig(pubkey owner, int exit) {}",
        ),
        (
            "main.ark",
            r#"
            import "single_sig.ark";
            contract Recursive(pubkey ownerPk, int exit) {
                function send() {
                    require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk, exit));
                }
            }
            "#,
        ),
    ]
    .into_iter()
    .map(|(path, source)| (path.to_string(), source.to_string()))
    .collect();
    let artifact = arkade_compiler::compile_sources("main.ark", &files).unwrap();
    let emitted = &artifact.functions[0].arkade.as_ref().unwrap().asm;
    assert!(
        emitted.iter().any(|token| token.starts_with("<CONTRACT:")),
        "compiler emits <CONTRACT:...>, got {emitted:?}"
    );
    let program = program_from_artifact(&artifact).unwrap();
    let send = program.function("send").unwrap();
    let child = "contract_SingleSig_ownerPk_exit";
    assert!(send
        .arkade
        .as_ref()
        .unwrap()
        .asm
        .iter()
        .any(|token| { matches!(token, AsmToken::Param(name) if name == child) }));
    assert_eq!(
        program.params.last().unwrap(),
        &param(child, ValueType::Bytes32)
    );
}

fn leaf(asm: &[&str]) -> String {
    let asm = asm
        .iter()
        .map(|token| format!("\"{token}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{
            "contractName": "Demo",
            "constructorInputs": [{{"name": "user", "type": "pubkey"}}],
            "functions": [{{
                "name": "spend",
                "leaves": [{{
                    "name": "spend",
                    "witness": [],
                    "asm": [{asm}]
                }}]
            }}]
        }}"#
    )
}

#[test]
fn csv_literals_decode_bip68_blocks_and_seconds() {
    for (literal, expected) in [
        ("144", CsvValue::Blocks(144)),
        ("4194314", CsvValue::Seconds(5120)),
        ("70000", CsvValue::Raw(70000)),
    ] {
        let program = program_from_json(&leaf(&[
            literal,
            "OP_CHECKSEQUENCEVERIFY",
            "OP_DROP",
            "<SERVER_KEY>",
            "OP_CHECKSIG",
        ]))
        .unwrap();
        assert_eq!(
            program.function("spend").unwrap().tapscript.csv,
            Some(expected)
        );
    }

    let rejected = program_from_json(&leaf(&[
        "2147483648",
        "OP_CHECKSEQUENCEVERIFY",
        "OP_DROP",
        "<SERVER_KEY>",
        "OP_CHECKSIG",
    ]));
    assert_eq!(
        rejected.unwrap_err(),
        "program_from_artifact: leaf 'spend': CSV literal 2147483648 must fit in 31 bits without the disable flag"
    );
}

#[test]
fn constructor_tweak_is_its_own_signer() {
    let program = program_from_json(&leaf(&["<TWEAK:insurer:late>", "OP_CHECKSIG"])).unwrap();
    assert_eq!(
        program.function("spend").unwrap().tapscript.signers,
        vec![Signer::Tweaked {
            base: "insurer".into(),
            func: "late".into(),
        }]
    );
}

#[test]
fn constructor_tweak_stays_on_the_covenant() {
    let json = r#"{
        "contractName": "Demo",
        "constructorInputs": [{"name": "insurer", "type": "pubkey"}],
        "functions": [{
            "name": "claim",
            "arkade": {"inputs": [], "asm": ["OP_1"]},
            "leaves": [
                {
                    "name": "claim",
                    "witness": [],
                    "asm": ["<SERVER_KEY>", "OP_CHECKSIGVERIFY", "<EMULATOR_KEY:claim>", "OP_CHECKSIG"]
                },
                {
                    "name": "race",
                    "witness": [],
                    "asm": ["<SERVER_KEY>", "OP_CHECKSIGVERIFY", "<TWEAK:insurer:claim>", "OP_CHECKSIG"]
                }
            ]
        }]
    }"#;
    let program = program_from_json(json).unwrap();
    let claim = program.function("claim").unwrap();
    assert!(claim
        .tapscript
        .signers
        .contains(&Signer::Emulator("claim".into())));
    assert!(claim.arkade.is_some());
    let race = program.function("claim/1:race").unwrap();
    assert_eq!(
        race.tapscript.signers,
        vec![
            Signer::Param("server".into()),
            Signer::Tweaked {
                base: "insurer".into(),
                func: "claim".into(),
            },
        ]
    );
    assert_eq!(race.arkade, claim.arkade);
}

#[test]
fn rejects_a_malformed_tweak_and_duplicate_server() {
    let tweak = program_from_json(&leaf(&["<TWEAK:insurer:late:extra>", "OP_CHECKSIG"]));
    assert_eq!(
        tweak.unwrap_err(),
        "program_from_artifact: leaf 'spend': malformed tweak '<TWEAK:insurer:late:extra>'"
    );

    let server = r#"{
        "contractName": "Demo",
        "constructorInputs": [{"name": "server", "type": "pubkey"}],
        "functions": [{
            "name": "spend",
            "leaves": [{
                "name": "spend",
                "witness": [],
                "asm": ["<server>", "OP_CHECKSIG"]
            }]
        }]
    }"#;
    assert_eq!(
        program_from_json(server).unwrap_err(),
        "program_from_artifact: duplicate program parameter 'server'"
    );

    let shadow = r#"{
        "contractName": "Demo",
        "constructorInputs": [],
        "structs": [{"name": "pubkey", "fields": []}],
        "functions": [{
            "name": "spend",
            "leaves": [{
                "name": "spend",
                "witness": [],
                "asm": ["<SERVER_KEY>", "OP_CHECKSIG"]
            }]
        }]
    }"#;
    assert_eq!(
        program_from_json(shadow).unwrap_err(),
        "program_from_artifact: struct name 'pubkey' shadows a built-in type"
    );

    let missing_emulator = r#"{
        "contractName": "Demo",
        "constructorInputs": [{"name": "user", "type": "pubkey"}],
        "functions": [{
            "name": "spend",
            "arkade": {"inputs": [], "asm": ["OP_1"]},
            "leaves": [{
                "name": "spend",
                "witness": [],
                "asm": ["<user>", "OP_CHECKSIG"]
            }]
        }]
    }"#;
    assert_eq!(
        program_from_json(missing_emulator).unwrap_err(),
        "program_from_artifact: leaf 'spend': covenant leaf must sign with the emulator or a tweaked constructor key"
    );

    let collision = r#"{
        "contractName": "Demo",
        "constructorInputs": [],
        "functions": [{
            "name": "spend",
            "arkade": {"inputs": [], "asm": ["<CONTRACT:A-B>", "<CONTRACT:A_B>"]},
            "leaves": [{
                "name": "spend",
                "witness": [],
                "asm": ["<SERVER_KEY>", "OP_CHECKSIGVERIFY", "<EMULATOR_KEY:spend>", "OP_CHECKSIG"]
            }]
        }]
    }"#;
    assert_eq!(
        program_from_json(collision).unwrap_err(),
        "program_from_artifact: instantiations 'A-B' and 'A_B' both map to parameter 'contract_A_B'"
    );
}

#[test]
fn hash_condition_drops_verify_and_keeps_the_preimage() {
    let json = r#"{
        "contractName": "Lock",
        "constructorInputs": [{"name": "hash", "type": "bytes32"}, {"name": "user", "type": "pubkey"}],
        "functions": [{
            "name": "claim",
            "leaves": [{
                "name": "claim",
                "witness": [
                    {"name": "preimage", "type": "bytes32", "encoding": "raw-32"},
                    {"name": "userSig", "type": "signature", "encoding": "schnorr-64"}
                ],
                "asm": ["OP_SHA256", "<hash>", "OP_EQUAL", "OP_VERIFY", "<user>", "OP_CHECKSIG"]
            }]
        }]
    }"#;
    let program = program_from_json(json).unwrap();
    let claim = program.function("claim").unwrap();
    assert_eq!(claim.tapscript.witness, vec!["preimage".to_string()]);
    assert_eq!(claim.inputs, vec![param("preimage", ValueType::Bytes32)]);
    assert!(claim
        .tapscript
        .condition
        .iter()
        .all(|token| !matches!(token, AsmToken::Opcode(op) if op == "OP_VERIFY")));
    assert_eq!(
        program
            .params
            .iter()
            .find(|p| p.name == "hash")
            .unwrap()
            .value_type,
        ValueType::Bytes32
    );
}

#[test]
fn later_leaves_are_named_by_group_and_index() {
    let json = r#"{
        "contractName": "Demo",
        "constructorInputs": [{"name": "user", "type": "pubkey"}],
        "functions": [{
            "name": "spend",
            "leaves": [
                {"name": "first", "witness": [], "asm": ["<user>", "OP_CHECKSIG"]},
                {"name": "second", "witness": [], "asm": ["<user>", "OP_CHECKSIG"]}
            ]
        }]
    }"#;
    let program = program_from_json(json).unwrap();
    assert_eq!(
        program
            .functions
            .iter()
            .map(|f| f.name.as_str())
            .collect::<Vec<_>>(),
        vec!["spend", "spend/1:second"]
    );
}

#[test]
fn old_vtxo_placeholder_is_rejected() {
    let json = r#"{
        "contractName": "Demo",
        "constructorInputs": [{"name": "owner", "type": "pubkey"}],
        "functions": [{
            "name": "spend",
            "arkade": {"inputs": [], "asm": ["<VTXO:SingleSig(<owner>)>", "OP_DROP"]},
            "leaves": [{
                "name": "spend",
                "witness": [],
                "asm": ["<SERVER_KEY>", "OP_CHECKSIGVERIFY", "<EMULATOR_KEY:spend>", "OP_CHECKSIG"]
            }]
        }]
    }"#;
    assert_eq!(
        program_from_json(json).unwrap_err(),
        "program_from_artifact: '<VTXO:SingleSig(<owner>)>' is not a placeholder; the compiler emits <CONTRACT:...>"
    );
}

#[test]
fn contract_placeholder_is_one_bytes32_parameter() {
    let json = r#"{
        "contractName": "Demo",
        "constructorInputs": [{"name": "owner", "type": "pubkey"}],
        "functions": [{
            "name": "spend",
            "arkade": {
                "inputs": [],
                "asm": ["<CONTRACT:SingleSig(<owner>)>", "OP_DROP"]
            },
            "leaves": [{
                "name": "spend",
                "witness": [],
                "asm": ["<SERVER_KEY>", "OP_CHECKSIGVERIFY", "<EMULATOR_KEY:spend>", "OP_CHECKSIG"]
            }]
        }]
    }"#;
    let program = program_from_json(json).unwrap();
    let child: Vec<_> = program
        .params
        .iter()
        .filter(|param| param.name.starts_with("contract_"))
        .collect();
    assert_eq!(child.len(), 1);
    assert_eq!(
        child[0],
        &param("contract_SingleSig_owner", ValueType::Bytes32)
    );
}
