#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

cargo test --manifest-path "$root/Cargo.toml" --test examples hashprice
cargo build --manifest-path "$root/Cargo.toml" --bin arkadec

# Optimized and unoptimized covenants must behave the same on the Arkade VM.
ARKADEC="$root/target/debug/arkadec" go test -C "$root/tests/e2e" -count=1 -run 'TestHashprice$' .
ARKADEC="$root/target/debug/arkadec" ARKADEC_NO_OPTIMIZE=1 go test -C "$root/tests/e2e" -count=1 -run 'TestHashprice$' .
