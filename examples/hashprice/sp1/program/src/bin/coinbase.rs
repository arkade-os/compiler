#![no_main]

#[path = "../transaction.rs"]
mod transaction;

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let input = sp1_zkvm::io::read_vec();
    let (txid, sum) = transaction::txid_and_sum(&input, true).expect("invalid coinbase");
    sp1_zkvm::io::commit_slice(&txid);
    sp1_zkvm::io::commit_slice(&sum.to_le_bytes());
}
