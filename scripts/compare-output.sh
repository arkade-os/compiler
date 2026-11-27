#!/bin/sh
# Compile every contract with the compiler at <ref> and with the working tree, optimized and
# not, and list each one whose artifact differs. updatedAt, fingerprint and compiler.version
# are ignored: they change on every build or version bump without changing any script.
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
    python3 - "$work/base.json" "$work/head.json" <<'EOF' && same=0 || same=$?
import json, sys

def normalized(path):
    artifact = json.load(open(path))
    for key in ("updatedAt", "fingerprint"):
        artifact.pop(key, None)
    artifact.get("compiler", {}).pop("version", None)
    return artifact

try:
    sys.exit(1 if normalized(sys.argv[1]) != normalized(sys.argv[2]) else 0)
except (OSError, ValueError) as error:
    print(error, file=sys.stderr)
    sys.exit(2)
EOF
    case $same in
      0) ;;
      1) echo "${contract#"$work/fuzz/"} $flag: artifact differs"; changed=$((changed + 1)) ;;
      *) fail "cannot compare the artifacts of $contract" ;;
    esac
  done
done <"$work/corpus"

echo "$changed of $total compilations differ from $ref"
[ "$changed" = 0 ]
