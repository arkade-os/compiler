//! Parser-level tests for the `tapscript` modifier. These assert AST routing,
//! not ABI output (ABI comes in Phase 3).
use arkade_compiler::models::{HashFn, KeyExpr, TapItem};
use arkade_compiler::parser;

fn parse(src: &str) -> arkade_compiler::models::Contract {
    parser::parse(src).expect("parse should succeed")
}

#[test]
fn routes_tapscript_into_tapscripts_not_functions() {
    let src = r#"
contract Demo(pubkey owner) {
    function claim() {
        require(tx.outputs[0].value >= 1);
    }
    function claim(bytes preimage, signature serverSig, signature emulatorSig) tapscript {
        require(hash160(preimage) == preimageHash);
        require(checkMultisig([server, emulator], [serverSig, emulatorSig], 2));
    }
}
"#;
    let c = parse(src);
    assert_eq!(c.functions.len(), 1, "covenant function stays in functions");
    assert_eq!(c.functions[0].name, "claim");
    assert_eq!(c.tapscripts.len(), 1, "tapscript routed into tapscripts");
    let ts = &c.tapscripts[0];
    assert_eq!(ts.name, "claim");
    assert_eq!(ts.inputs.len(), 3);
    assert_eq!(ts.inputs[0].name, "preimage");
    // First item: HASH160 condition.
    match &ts.items[0] {
        TapItem::Hash {
            hash_fn,
            preimage,
            hash,
        } => {
            assert_eq!(*hash_fn, HashFn::Hash160);
            assert_eq!(preimage, "preimage");
            assert_eq!(hash, "preimageHash");
        }
        other => panic!("expected Hash item, got {other:?}"),
    }
    // Second item: multisig with two keys, two sigs, threshold 2.
    match &ts.items[1] {
        TapItem::Sig {
            keys,
            sigs,
            threshold,
        } => {
            assert_eq!(
                keys,
                &vec![
                    KeyExpr::Ident("server".into()),
                    KeyExpr::Ident("emulator".into())
                ]
            );
            assert_eq!(
                sigs,
                &vec!["serverSig".to_string(), "emulatorSig".to_string()]
            );
            assert_eq!(*threshold, Some(2));
        }
        other => panic!("expected Sig item, got {other:?}"),
    }
}

#[test]
fn parses_older_after_and_tweak_key() {
    let src = r#"
contract Demo(pubkey owner) {
    function exit(signature ownerSig) tapscript {
        require(older(exitDelay));
        require(checkSig(ownerSig, owner));
    }
    function direct(signature emulatorSig) tapscript {
        require(checkSig(emulatorSig, tweak(emulator, exit)));
    }
    function cancel(signature backupSig, signature serverSig) tapscript {
        require(after(cancelTime));
        require(checkMultisig([backup, server], [backupSig, serverSig]));
    }
}
"#;
    let c = parse(src);
    assert_eq!(c.tapscripts.len(), 3);
    let exit = c.tapscripts.iter().find(|t| t.name == "exit").unwrap();
    assert!(matches!(&exit.items[0], TapItem::Older { value } if value == "exitDelay"));
    let direct = c.tapscripts.iter().find(|t| t.name == "direct").unwrap();
    match &direct.items[0] {
        TapItem::Sig { keys, .. } => assert_eq!(
            keys,
            &vec![KeyExpr::Tweak {
                func: "exit".into()
            }]
        ),
        other => panic!("expected Sig with tweak key, got {other:?}"),
    }
    let cancel = c.tapscripts.iter().find(|t| t.name == "cancel").unwrap();
    assert!(matches!(&cancel.items[0], TapItem::After { value } if value == "cancelTime"));
    // Omitted threshold → N-of-N (None).
    match &cancel.items[1] {
        TapItem::Sig { threshold, .. } => assert_eq!(*threshold, None),
        other => panic!("expected Sig, got {other:?}"),
    }
}
