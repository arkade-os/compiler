use arkade_compiler::compile_file;

#[test]
fn hashprice_contract_interfaces() {
    for (file, name, functions) in [
        (
            "block_header_beacon",
            "BlockHeaderBeacon",
            vec!["mint", "clone"],
        ),
        ("hashprice_beacon", "HashPriceBeacon", vec!["mint", "clone"]),
        ("beacon_coin", "BeaconCoin", vec!["continue"]),
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
            assert!(asm.contains("OP_INSPECTPACKET"));
            assert!(!asm.contains("OP_CHECKSIG"));
        }
        if name == "BeaconCoin" {
            assert_eq!(
                contract
                    .parameters
                    .iter()
                    .map(|p| (p.name.as_str(), p.param_type.as_str()))
                    .collect::<Vec<_>>(),
                [("stateTag", "bytes"), ("stateLength", "int")]
            );
            let group = crate::common::group(&contract, "continue");
            assert!(group.arkade.as_ref().unwrap().inputs.is_empty());
            let asm = crate::common::arkade_asm(&contract, "continue");
            assert!(asm.contains("OP_TUNNEL"));
            assert!(!asm.contains("OP_FINDASSETGROUPBYASSETID"));
            assert!(group.leaves[0].asm.iter().any(|op| op == "OP_CHECKSIG"));
        }
        if name == "BlockHeaderBeacon" {
            let group = crate::common::group(&contract, "mint");
            let abi = &group.arkade.as_ref().unwrap().inputs;
            assert_eq!(
                abi.iter()
                    .map(|p| (p.name.as_str(), p.param_type.as_str()))
                    .collect::<Vec<_>>(),
                [
                    ("headers", "bytes[30]"),
                    ("coinbase", "bytes"),
                    ("merkleDepth", "int"),
                    ("siblings", "bytes32[20]")
                ]
            );
            assert!(crate::common::arkade_asm(&contract, "mint").contains("OP_SHA256"));
        }
    }
}
