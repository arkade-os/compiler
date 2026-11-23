use bitcoin::{
    consensus::{deserialize, Encodable},
    Amount, Transaction,
};
use sha2::{Digest, Sha256};

/// Return the txid in Bitcoin's internal byte order and the output sum in satoshis.
pub fn txid_and_sum(input: &[u8], require_coinbase: bool) -> Result<([u8; 32], u64), &'static str> {
    let maximum = if require_coinbase {
        1_048_576
    } else {
        1_000_000
    };
    if input.len() > maximum {
        return Err("transaction exceeds size bound");
    }
    // deserialize rejects trailing bytes, non-minimal CompactSize, and invalid witness flags.
    let tx: Transaction = deserialize(input).map_err(|_| "invalid transaction encoding")?;
    if tx.input.is_empty() || tx.output.is_empty() {
        return Err("transaction requires inputs and outputs");
    }
    if require_coinbase {
        if !tx.is_coinbase() {
            return Err("transaction is not a coinbase");
        }
        if !(2..=100).contains(&tx.input[0].script_sig.len()) {
            return Err("coinbase scriptSig length out of range");
        }
    }
    let mut sum = 0u64;
    for output in &tx.output {
        let value = output.value.to_sat();
        if value > Amount::MAX_MONEY.to_sat() {
            return Err("output amount out of range");
        }
        sum = sum.checked_add(value).ok_or("output sum overflow")?;
        if sum > Amount::MAX_MONEY.to_sat() {
            return Err("output sum out of range");
        }
    }

    // Match Transaction::compute_txid's encoding, but hash with SP1's patched sha2.
    // TxIn's consensus encoder excludes its witness; marker/flag are also omitted.
    let mut stripped = Vec::with_capacity(input.len());
    tx.version
        .consensus_encode(&mut stripped)
        .map_err(|_| "encode version")?;
    tx.input
        .consensus_encode(&mut stripped)
        .map_err(|_| "encode inputs")?;
    tx.output
        .consensus_encode(&mut stripped)
        .map_err(|_| "encode outputs")?;
    tx.lock_time
        .consensus_encode(&mut stripped)
        .map_err(|_| "encode locktime")?;
    Ok((Sha256::digest(Sha256::digest(&stripped)).into(), sum))
}
