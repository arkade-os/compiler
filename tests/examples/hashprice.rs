use arkade_compiler::compile_file;

#[test]
fn hashprice_contract_interfaces() {
    for (file, name, functions) in [
        (
            "block_header_beacon",
            "BlockHeaderBeacon",
            vec!["mint", "challenge", "burn"],
        ),
        (
            "hashprice_beacon",
            "HashPriceBeacon",
            vec!["mint", "challenge", "burn"],
        ),
        ("beacon_coin", "BeaconCoin", vec!["continue", "burn"]),
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("examples/hashprice/{file}.ark"));
        let contract = compile_file(path).unwrap();
        assert_eq!(contract.name, name);
        assert_eq!(
            contract
                .functions
                .iter()
                .map(|g| g.name.as_str())
                .collect::<Vec<_>>(),
            functions
        );
        for group in &contract.functions {
            assert_eq!(group.leaves.len(), 1);
            let asm = crate::common::arkade_asm(&contract, &group.name);
            assert!(asm.contains("OP_INSPECTINPUTPACKET"));
            if name != "BeaconCoin" || group.name != "burn" {
                assert!(asm.contains("OP_INSPECTPACKET"));
            }
            assert!(!asm.contains("OP_CHECKSIG"));
            assert!(group.leaves[0].asm.iter().any(|op| op == "OP_CHECKSIG"));
        }
        if name == "BeaconCoin" {
            assert_eq!(
                contract
                    .parameters
                    .iter()
                    .map(|p| (p.name.as_str(), p.param_type.to_string()))
                    .collect::<Vec<_>>(),
                [("controlGidx", "int")].map(|(name, kind)| (name, kind.to_string()))
            );
            let group = crate::common::group(&contract, "continue");
            assert!(group.arkade.as_ref().unwrap().inputs.is_empty());
            let asm = crate::common::arkade_asm(&contract, "continue");
            assert!(asm.contains("OP_TUNNEL"));
            assert!(!asm.contains("OP_FINDASSETGROUPBYASSETID"));
            let burn = crate::common::group(&contract, "burn");
            assert!(burn.arkade.as_ref().unwrap().inputs.is_empty());
            assert!(
                crate::common::arkade_asm(&contract, "burn").contains("OP_INSPECTASSETGROUPSUM")
            );
        }
        if name == "HashPriceBeacon" {
            let mint = crate::common::group(&contract, "mint");
            let inputs = &mint.arkade.as_ref().unwrap().inputs;
            assert_eq!(
                inputs
                    .iter()
                    .map(|p| (p.name.as_str(), p.param_type.as_str()))
                    .collect::<Vec<_>>(),
                [
                    ("mintedAt", "int"),
                    ("coinbaseTxid", "bytes32"),
                    ("reward", "int"),
                    ("merkleDepth", "int"),
                    ("siblings", "bytes32[20]"),
                    ("proof", "Groth16Proof")
                ]
            );
            let asm = crate::common::arkade_asm(&contract, "mint");
            assert_eq!(
                asm.split_whitespace()
                    .filter(|op| *op == "OP_CHECKTIME")
                    .count(),
                2
            );
            assert!(asm.contains("OP_SHA256"));
            assert!(asm.contains("OP_HASH256"));
            for (opcode, count) in [("OP_ECMUL", 3), ("OP_ECADD", 3), ("OP_ECPAIRING", 1)] {
                assert_eq!(
                    asm.split_whitespace().filter(|op| *op == opcode).count(),
                    count
                );
                assert!(!mint.leaves[0].asm.iter().any(|op| op == opcode));
            }
            assert!(!mint.leaves[0].asm.iter().any(|op| op == "OP_CHECKTIME"));
            for path in ["challenge", "burn"] {
                assert!(crate::common::group(&contract, path)
                    .arkade
                    .as_ref()
                    .unwrap()
                    .inputs
                    .is_empty());
                assert!(
                    crate::common::arkade_asm(&contract, path).contains("OP_INSPECTASSETGROUPSUM")
                );
            }
            assert!(crate::common::arkade_asm(&contract, "challenge").contains("OP_SHA256"));
        }
        if name == "BlockHeaderBeacon" {
            let group = crate::common::group(&contract, "mint");
            let abi = &group.arkade.as_ref().unwrap().inputs;
            assert_eq!(
                abi.iter()
                    .map(|p| (p.name.as_str(), p.param_type.as_str()))
                    .collect::<Vec<_>>(),
                [("headers", "bytes[6]")]
            );
            assert!(crate::common::arkade_asm(&contract, "mint").contains("OP_HASH256"));
            let challenge = crate::common::group(&contract, "challenge");
            let inputs = &challenge.arkade.as_ref().unwrap().inputs;
            assert_eq!(inputs.len(), 1);
            assert_eq!(inputs[0].param_type, "bytes[6]");
            assert!(crate::common::arkade_asm(&contract, "challenge").contains("OP_GREATERTHAN"));
            assert!(
                crate::common::arkade_asm(&contract, "burn").contains("OP_INSPECTASSETGROUPSUM")
            );
        }
    }
}
