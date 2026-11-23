#![no_main]

use sha2::{Digest, Sha256};

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let input = sp1_zkvm::io::read_vec();
    assert!(input.len() <= 1_000_000);
    let digest = Sha256::digest(Sha256::digest(&input));
    sp1_zkvm::io::commit_slice(&digest);
}
