#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

cargo build --manifest-path "$root/Cargo.toml" --bin arkadec
ARKADEC="$root/target/debug/arkadec" go test -C "$root/tests/e2e" "$@"
