#!/bin/sh
# Compile every contract with the compiler at <ref> and with the working tree, optimized and
# not, and list each one whose codeHash differs. codeHash covers every artifact field that
# determines the scripts and none of source, compiler, updatedAt or fingerprint.
# The corpus is examples/, tests/e2e/contracts/ and the differential fuzzer's cases.
# Exits like diff: 0 when every artifact matches, 1 when any differs, 2 when a step fails
# or the working tree's arkadec crashes.
# usage: scripts/compare-output.sh <ref>
set -u

root=$(cd "$(dirname "$0")/.." && pwd)
ref=$1
work=$(mktemp -d) || exit 2
trap 'rm -rf "$work"' EXIT

fail() {
  echo "compare-output: $1" >&2
  exit 2
}

code_hash() {
  sed -n 's/^  "codeHash": "\(sha256:[0-9a-f]*\)",$/\1/p' "$1" | grep .
}

mkdir "$work/base" "$work/fuzz" || fail "cannot create $work"
git -C "$root" archive -o "$work/base.tar" "$ref" || fail "cannot archive $ref"
tar -x -f "$work/base.tar" -C "$work/base" || fail "cannot extract $ref"
cargo build --quiet --manifest-path "$work/base/Cargo.toml" --target-dir "$root/target/compare-output" --bin arkadec ||
  fail "cannot build arkadec at $ref"
cargo build --quiet --manifest-path "$root/Cargo.toml" --target-dir "$root/target" --bin arkadec || fail "cannot build arkadec"
base="$root/target/compare-output/debug/arkadec"
head="$root/target/debug/arkadec"
ARKADE_FUZZ_CORPUS="$work/fuzz" go test -C "$root/tests/e2e" -run '^TestWriteFuzzCorpus$' >/dev/null ||
  fail "cannot write the fuzz corpus"

cd "$root" || fail "cannot enter $root"
find examples tests/e2e/contracts "$work/fuzz" -name '*.ark' >"$work/found" || fail "cannot list contracts"
sort "$work/found" >"$work/corpus" || fail "cannot sort contracts"
total=0
changed=0
while IFS= read -r contract; do
  for flag in "" "--no-optimize"; do
    total=$((total + 1))
    "$base" "$contract" $flag -o "$work/base.json" </dev/null >/dev/null 2>&1 && b=0 || b=$?
    "$head" "$contract" $flag -o "$work/head.json" </dev/null >/dev/null 2>&1 && h=0 || h=$?
    # arkadec exits 1 on a rejected contract; anything else is a crash or a failed launch.
    case $h in 0 | 1) ;; *) fail "arkadec exited with $h on $contract" ;; esac
    if [ "$b" != "$h" ]; then
      echo "${contract#"$work/fuzz/"} $flag: exit status $b -> $h"
      changed=$((changed + 1))
      continue
    fi
    [ "$h" = 0 ] || continue
    b=$(code_hash "$work/base.json") && h=$(code_hash "$work/head.json") ||
      fail "no codeHash in the artifacts of $contract"
    if [ "$b" != "$h" ]; then
      echo "${contract#"$work/fuzz/"} $flag: codeHash differs"
      changed=$((changed + 1))
    fi
  done
done <"$work/corpus"

echo "$changed of $total compilations differ from $ref"
[ "$changed" = 0 ]
