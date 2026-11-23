use anyhow::{ensure, Context, Result};
use bitcoin::{
    consensus::{deserialize, serialize},
    hashes::Hash,
    Transaction,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    Elf, HashableKey, ProvingKey, SP1Proof, SP1PublicValues, SP1Stdin,
};
use std::{env, fs, time::Instant};

mod transaction;

fn main() -> Result<()> {
    sp1_sdk::utils::setup_logger();
    let args: Vec<String> = env::args().collect();
    let mode = args
        .get(1)
        .context("usage: sp1-sha256d-bench <install|execute|groth16> <elf> [bytes] [proof-file] [sha256d|transaction] [input-file]")?;
    if mode == "install" {
        // Download public ceremony artifacts before starting the timed run.
        let path = tokio::runtime::Runtime::new()?
            .block_on(sp1_sdk::install::try_install_circuit_artifacts("groth16"))?;
        println!("{}", json!({"event": "artifacts_installed", "path": path}));
        return Ok(());
    }
    ensure!(mode == "execute" || mode == "groth16", "unsupported mode");
    let elf = Elf::from(fs::read(args.get(2).context("missing ELF")?)?);
    let size: usize = args
        .get(3)
        .map(String::as_str)
        .unwrap_or("1000000")
        .parse()?;
    let workload = args.get(5).map(String::as_str).unwrap_or("sha256d");
    let maximum = if workload == "coinbase" {
        1_048_576
    } else {
        1_000_000
    };
    ensure!(size <= maximum, "input exceeds benchmark bound");
    let (input, expected, details) = match workload {
        "transaction" | "coinbase" => {
            let input = if let Some(path) = args.get(6) {
                fs::read(path)?
            } else {
                serialize(&transaction::fixture(size)?)
            };
            ensure!(
                input.len() == size,
                "transaction file size differs from requested size"
            );
            let tx: Transaction = deserialize(&input)?;
            ensure!(
                workload != "coinbase" || tx.is_coinbase(),
                "expected coinbase input"
            );
            let txid = tx.compute_txid();
            let sum: u64 = tx.output.iter().map(|output| output.value.to_sat()).sum();
            let mut public = txid.to_byte_array().to_vec();
            public.extend_from_slice(&sum.to_le_bytes());
            let details = json!({"txid": txid.to_string(),
                "txid_internal_bytes": hex::encode(txid.to_byte_array()), "output_sum_sats": sum,
                "inputs": tx.input.len(), "outputs": tx.output.len(), "coinbase": tx.is_coinbase(),
                "fixture": if args.get(6).is_some() { "external transaction file" } else { "synthetic coinbase with maximum-count empty-script outputs and final OP_RETURN padding" },
                "input_file": args.get(6),
                "public_value_bytes": public.len()});
            (input, public, details)
        }
        "sha256d" => {
            let input: Vec<u8> = (0..size).map(|i| (i * 131 + (i >> 8) + 17) as u8).collect();
            let expected = Sha256::digest(Sha256::digest(&input)).to_vec();
            let details =
                json!({"digest": hex::encode(&expected), "public_value_bytes": expected.len()});
            (input, expected, details)
        }
        _ => anyhow::bail!("unsupported workload"),
    };
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(input);
    println!(
        "{}",
        json!({"event": "input", "input_bytes": size, "workload": workload,
        "details": details, "mode": mode, "sp1_sdk": "6.10.0"})
    );

    let started = Instant::now();
    let client = ProverClient::builder().cpu().build();
    println!(
        "{}",
        json!({"event": "client_ready", "seconds": started.elapsed().as_secs_f64()})
    );
    if mode == "execute" {
        let started = Instant::now();
        let (public, report) = client.execute(elf, stdin).run()?;
        ensure!(
            public.as_slice() == &expected[..],
            "execution public values mismatch"
        );
        println!(
            "{}",
            json!({"event": "execute_complete", "seconds": started.elapsed().as_secs_f64(),
            "instructions": report.total_instruction_count(), "report": report})
        );
        return Ok(());
    }
    let started = Instant::now();
    let pk = client.setup(elf)?;
    println!(
        "{}",
        json!({"event": "setup_complete", "seconds": started.elapsed().as_secs_f64(),
        "program_vkey": pk.verifying_key().bytes32(), "circuit_version": client.version()})
    );

    let started = Instant::now();
    println!("{}", json!({"event": "prove_start"}));
    let proof = client.prove(&pk, stdin).groth16().run()?;
    let proving_seconds = started.elapsed().as_secs_f64();
    ensure!(
        matches!(&proof.proof, SP1Proof::Groth16(_)),
        "expected real Groth16 proof"
    );
    ensure!(!proof.bytes().is_empty(), "mock proof is not a benchmark");
    ensure!(
        proof.public_values.as_slice() == &expected[..],
        "proof public values mismatch"
    );
    println!(
        "{}",
        json!({"event": "prove_complete", "seconds": proving_seconds,
        "onchain_proof_bytes": proof.bytes().len(), "public_value_bytes": proof.public_values.as_slice().len()})
    );

    let started = Instant::now();
    client.verify(&proof, pk.verifying_key(), None)?;
    let verify_seconds = started.elapsed().as_secs_f64();
    let mut wrong = proof.clone();
    let mut wrong_public = expected.to_vec();
    wrong_public[0] ^= 1;
    wrong.public_values = SP1PublicValues::from(&wrong_public);
    ensure!(
        client.verify(&wrong, pk.verifying_key(), None).is_err(),
        "wrong digest accepted"
    );
    let wrong_sum_rejected = if workload == "transaction" || workload == "coinbase" {
        let mut wrong = proof.clone();
        let mut wrong_public = expected.clone();
        wrong_public[32] ^= 1;
        wrong.public_values = SP1PublicValues::from(&wrong_public);
        ensure!(
            client.verify(&wrong, pk.verifying_key(), None).is_err(),
            "wrong output sum accepted"
        );
        Some(true)
    } else {
        None
    };
    if let Some(path) = args.get(4) {
        proof.save(path)?;
        fs::write(format!("{path}.onchain"), proof.bytes())?;
        fs::write(
            format!("{path}.public-values"),
            proof.public_values.as_slice(),
        )?;
    }
    println!(
        "{}",
        json!({"event": "verification_complete", "seconds": verify_seconds,
        "verified": true, "wrong_digest_rejected": true, "wrong_output_sum_rejected": wrong_sum_rejected})
    );
    Ok(())
}
