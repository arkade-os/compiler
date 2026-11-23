use anyhow::{ensure, Result};
use bitcoin::{
    absolute, consensus::serialize, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Witness,
};

pub fn fixture(size: usize) -> Result<Transaction> {
    ensure!(
        (100..=1_000_000).contains(&size),
        "fixture size must be 100..=1000000"
    );
    let count = (size - 64) / 9;
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![3, 0x40, 0x42, 0x0f]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: (0..count)
            .map(|i| TxOut {
                value: Amount::from_sat(if i + 1 == count {
                    0
                } else {
                    1 + (i % 100) as u64
                }),
                script_pubkey: ScriptBuf::new(),
            })
            .collect(),
    };
    let padding = size - serialize(&tx).len();
    ensure!(
        (1..253).contains(&padding),
        "fixture padding changes CompactSize width"
    );
    let mut script = vec![0; padding];
    script[0] = 0x6a; // OP_RETURN followed by OP_0 padding.
    tx.output
        .last_mut()
        .expect("non-empty fixture")
        .script_pubkey = ScriptBuf::from_bytes(script);
    ensure!(serialize(&tx).len() == size, "fixture size mismatch");
    Ok(tx)
}

#[cfg(test)]
#[path = "../../program/src/transaction.rs"]
mod guest;

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{consensus::deserialize, hashes::Hash};
    use guest::txid_and_sum;

    fn check(tx: &Transaction) {
        let input = serialize(tx);
        let (txid, sum) = txid_and_sum(&input, false).unwrap();
        assert_eq!(txid, tx.compute_txid().to_byte_array());
        assert_eq!(sum, tx.output.iter().map(|o| o.value.to_sat()).sum::<u64>());
    }

    #[test]
    fn parses_legacy_segwit_and_exact_one_mb() {
        let mut tx = fixture(1024).unwrap();
        check(&tx);
        tx.input[0].witness.push([1, 2, 3]);
        assert_ne!(
            tx.compute_txid().to_byte_array(),
            tx.compute_wtxid().to_byte_array()
        );
        check(&tx);
        let original = txid_and_sum(&serialize(&tx), false).unwrap();
        tx.input[0].witness.push([4, 5]);
        assert_eq!(txid_and_sum(&serialize(&tx), false).unwrap(), original);
        tx.output[0].value = Amount::from_sat(2);
        let changed = txid_and_sum(&serialize(&tx), false).unwrap();
        assert_ne!(changed.0, original.0);
        assert_eq!(changed.1, original.1 + 1);

        let large = fixture(1_000_000).unwrap();
        assert!(large.is_coinbase());
        assert_eq!(large.output.len(), 111_104);
        assert_eq!(serialize(&large).len(), 1_000_000);
        check(&large);
        assert_eq!(
            txid_and_sum(&serialize(&large), false).unwrap().1,
            5_610_556
        );
    }

    #[test]
    fn rejects_bad_lengths_counts_and_witness_encoding() {
        let tx = fixture(100).unwrap();
        let input = serialize(&tx);
        for len in 0..input.len() {
            assert!(
                txid_and_sum(&input[..len], false).is_err(),
                "accepted truncation at {len}"
            );
        }
        let mut trailing = input.clone();
        trailing.push(0);
        assert!(txid_and_sum(&trailing, false).is_err());
        assert!(txid_and_sum(&vec![0; 1_000_001], false).is_err());

        // Replace canonical vin count 1 with three non-minimal encodings.
        for count in [
            vec![0xfd, 1, 0],
            vec![0xfe, 1, 0, 0, 0],
            vec![0xff, 1, 0, 0, 0, 0, 0, 0, 0],
        ] {
            let mut bad = input[..4].to_vec();
            bad.extend(count);
            bad.extend_from_slice(&input[5..]);
            assert!(txid_and_sum(&bad, false).is_err());
        }
        let mut huge_count = input.clone();
        huge_count.splice(4..5, [0xff; 9]);
        assert!(txid_and_sum(&huge_count, false).is_err());
        let mut bad_witness = tx.clone();
        bad_witness.input[0].witness.push([1]);
        let mut encoded = serialize(&bad_witness);
        encoded[5] = 2;
        assert!(txid_and_sum(&encoded, false).is_err());
        let mut empty_witness = input[..4].to_vec();
        empty_witness.extend([0, 1]);
        empty_witness.extend_from_slice(&input[4..input.len() - 4]);
        empty_witness.push(0);
        empty_witness.extend_from_slice(&input[input.len() - 4..]);
        assert!(txid_and_sum(&empty_witness, false).is_err());
        assert!(deserialize::<Transaction>(&empty_witness).is_err());

        let mut no_outputs = tx.clone();
        no_outputs.output.clear();
        assert!(txid_and_sum(&serialize(&no_outputs), false).is_err());
        let mut no_inputs = tx;
        no_inputs.input.clear();
        assert!(txid_and_sum(&serialize(&no_inputs), false).is_err());
    }

    #[test]
    fn rejects_negative_excessive_and_excessive_total_amounts() {
        let mut tx = fixture(100).unwrap();
        for amount in [u64::MAX, Amount::MAX_MONEY.to_sat() + 1, 1 << 63] {
            tx.output[0].value = Amount::from_sat(amount);
            assert!(txid_and_sum(&serialize(&tx), false).is_err());
        }
        tx.output[0].value = Amount::MAX_MONEY;
        tx.output[1].value = Amount::ONE_SAT;
        assert!(txid_and_sum(&serialize(&tx), false).is_err());
        tx.output.iter_mut().for_each(|o| o.value = Amount::ZERO);
        tx.output[0].value = Amount::MAX_MONEY;
        check(&tx);
    }

    #[test]
    fn coinbase_guest_requires_null_prevout_and_script_size() {
        let mut tx = fixture(512).unwrap();
        let input = serialize(&tx);
        assert_eq!(
            txid_and_sum(&input, true).unwrap(),
            txid_and_sum(&input, false).unwrap()
        );
        tx.input[0].previous_output.vout = 0;
        assert!(txid_and_sum(&serialize(&tx), true).is_err());
        assert!(txid_and_sum(&serialize(&tx), false).is_ok());
        tx.input[0].previous_output = OutPoint::null();
        for length in [0, 1, 101] {
            tx.input[0].script_sig = ScriptBuf::from_bytes(vec![0; length]);
            assert!(txid_and_sum(&serialize(&tx), true).is_err());
        }
        tx.input[0].script_sig = ScriptBuf::from_bytes(vec![3, 1, 2, 3]);
        // One large output makes the serialized transaction exactly 1 MiB.
        tx.output.truncate(1);
        tx.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x51; 1_048_508]);
        let input = serialize(&tx);
        assert_eq!(input.len(), 1_048_576);
        assert!(txid_and_sum(&input, true).is_ok());
        assert!(txid_and_sum(&input, false).is_err());
        assert!(txid_and_sum(&vec![0; 1_048_577], true).is_err());
    }
}
