# HashPriceBeacon SP1 prover

This standalone Rust workspace contains the CPU prover in `host/` and the
SP1 guest in [`program/src/bin/coinbase.rs`](program/src/bin/coinbase.rs).
The guest parses a private Bitcoin coinbase up to 1 MiB and commits only its
internal-order txid and output sum, encoded as 32 bytes followed by 8
little-endian bytes. The parser and its tests are included here; running the
prover does not require the benchmark directory.

The SDK is pinned to 6.10.0. Groth16 uses SP1's published v6.1.0 circuit
artifacts and ceremony, without a new setup. The workspace also retains the
`transaction` and `sha256d-program` guests used by the historical benchmarks;
HashPriceBeacon accepts only the pinned `coinbase` guest key.

## Build

Run from this directory. Install SP1's `cargo-prove` 6.10.0 and its
`succinct-1.96.0-64bit-v3` guest toolchain from their published releases, then
make `cargo-prove` available on `PATH` and link the guest compiler as the
`succinct` rustup toolchain. The commands below assume the existing isolated
installation in `/tmp/arkade-sp1-tools`:

```sh
nix shell --extra-experimental-features 'nix-command flakes' \
  nixpkgs#rustup nixpkgs#curl nixpkgs#git nixpkgs#protobuf \
  nixpkgs#pkg-config nixpkgs#clang nixpkgs#cmake nixpkgs#gnumake nixpkgs#go

export RUSTUP_HOME=/tmp/arkade-ec-rustup
export CARGO_HOME=/tmp/arkade-sp1-tools/cargo
export PATH=/tmp/arkade-sp1-tools/bin:$PATH
export GOTOOLCHAIN=go1.26.8
export SP1_GROTH16_CIRCUIT_PATH=/tmp/arkade-sp1-tools/circuits/groth16

rustup toolchain install 1.96.0 --profile minimal --no-self-update
rustup toolchain link succinct /tmp/arkade-sp1-tools/succinct
(cd program && rustup run 1.96.0 cargo prove build --locked --binaries coinbase)
```

On macOS, the host build additionally needs the Apple SDK and linker:

```sh
export SDKROOT="$(/usr/bin/xcrun --show-sdk-path)"
export LIBCLANG_PATH=/Library/Developer/CommandLineTools/usr/lib
export CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER=/usr/bin/clang
export CC=/usr/bin/clang CXX=/usr/bin/clang++
```

Build the host after setting these variables:

```sh
rustup run 1.96.0 cargo build --release --locked
```

Build the guest with Nix's Clang before setting the host's `CC`/`CXX`; it targets
RISC-V. Check the guest identity before using it with the covenant:

```sh
export COINBASE_ELF=program/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/coinbase
rustup run 1.96.0 cargo prove vkey --elf "$COINBASE_ELF"
```

The contract's program key is
`0077a029932c562085f49d781fe0b39b5e6d98569cac99c5f5eb0031512dc532`;
the corresponding ELF SHA256 is
`0627b6dad82b0ff690f398233e88578811b62bb6dd1b01f95dbf627b3a280db4`.
Source or compiler changes can change this identity; the covenant must pin the
key of the guest actually reviewed and proved.

## Prove

Download the public ceremony artifacts once before proving:

```sh
target/release/sp1-sha256d-bench install
```

The host retains its benchmark executable name. Its arguments are mode, guest
ELF, input length, proof output path, workload and input transaction file.
To limit parallel proving memory as in the measured 64 GiB Mac run:

```sh
export SP1_WORKER_NUM_CORE_WORKERS=1 SP1_WORKER_CORE_BUFFER_SIZE=1
export SP1_WORKER_NUM_SETUP_WORKERS=1 SP1_WORKER_SETUP_BUFFER_SIZE=1
export SP1_WORKER_NUM_RECURSION_EXECUTOR_WORKERS=1 SP1_WORKER_RECURSION_EXECUTOR_BUFFER_SIZE=1
export SP1_WORKER_NUM_RECURSION_PROVER_WORKERS=1 SP1_WORKER_RECURSION_PROVER_BUFFER_SIZE=1
export SP1_WORKER_NUM_PREPARE_REDUCE_WORKERS=1 SP1_WORKER_PREPARE_REDUCE_BUFFER_SIZE=1
export RAYON_NUM_THREADS=16 GOMAXPROCS=16 GOMEMLIMIT=20GiB GOGC=50

mkdir -p proofs
target/release/sp1-sha256d-bench groth16 "$COINBASE_ELF" \
  "$(wc -c < /path/to/coinbase.raw)" proofs/coinbase.bin coinbase /path/to/coinbase.raw
```

This verifies the generated proof and rejects altered public txid and sum.
It writes the SDK receipt, `proofs/coinbase.bin.onchain` (356 bytes) and
`proofs/coinbase.bin.public-values` (40 bytes). Use `execute` instead of
`groth16` to check execution without proving. The covenant consumes the eight
proof coordinates and the public txid/sum; the index-zero Merkle branch is
supplied separately, as described in the [contract README](../README.md#coinbase-proof-and-witness).

## Check

```sh
rustup run 1.96.0 cargo test --workspace --release --locked
rustup run 1.96.0 cargo clippy --workspace --all-targets --release --locked -- -D warnings
rustup run 1.96.0 cargo fmt --check
rustup run 1.96.0 cargo fmt --manifest-path program/Cargo.toml --check
```

The host's parser tests include SegWit txid handling, malformed encodings,
amount limits, coinbase structure and the exact 1 MiB input boundary.
