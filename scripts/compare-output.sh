#!/bin/sh
# Compile every contract with the compiler at <ref> and with the working tree, optimized and
# not, and list each one whose artifact differs. updatedAt, fingerprint and compiler.version
# are ignored: they change on every build or version bump without changing any script.
# The corpus is examples/, tests/e2e/contracts/ and the differential fuzzer's cases.
# usage: scripts/compare-output.sh <ref>
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
ref=$1
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir "$work/base" "$work/fuzz"
git -C "$root" archive "$ref" | tar -x -C "$work/base"
cargo build --quiet --manifest-path "$work/base/Cargo.toml" --target-dir "$root/target/compare-output" --bin arkadec
cargo build --quiet --manifest-path "$root/Cargo.toml" --bin arkadec
base="$root/target/compare-output/debug/arkadec"
head="$root/target/debug/arkadec"
ARKADE_FUZZ_CORPUS="$work/fuzz" go test -C "$root/tests/e2e" -run '^TestWriteFuzzCorpus$' >/dev/null

cd "$root"
total=0
changed=0
for contract in $(find examples tests/e2e/contracts "$work/fuzz" -name '*.ark' | sort); do
  for flag in "" "--no-optimize"; do
    total=$((total + 1))
    "$base" "$contract" $flag -o "$work/base.json" >/dev/null 2>&1 && b=0 || b=$?
    "$head" "$contract" $flag -o "$work/head.json" >/dev/null 2>&1 && h=0 || h=$?
    if [ "$b" != "$h" ]; then
      echo "${contract#"$work/fuzz/"} $flag: exit status $b -> $h"
      changed=$((changed + 1))
    elif [ "$h" = 0 ] && ! python3 - "$work/base.json" "$work/head.json" <<'EOF'
import json, sys

def normalized(path):
    artifact = json.load(open(path))
    for key in ("updatedAt", "fingerprint"):
        artifact.pop(key, None)
    artifact.get("compiler", {}).pop("version", None)
    return artifact

sys.exit(normalized(sys.argv[1]) != normalized(sys.argv[2]))
EOF
    then
      echo "${contract#"$work/fuzz/"} $flag: artifact differs"
      changed=$((changed + 1))
    fi
  done
done

echo "$changed of $total compilations differ from $ref"
[ "$changed" = 0 ]
