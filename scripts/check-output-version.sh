#!/bin/sh
# Fail when compiled contracts differ from the last release while the crate version still
# satisfies `^<last release>`: such a change must bump the version, so `pragma arkade ^...`
# no longer admits the new compiler and every contract opts in by raising its pragma.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
last=$(git -C "$root" describe --tags --abbrev=0 --match 'v[0-9]*.[0-9]*.[0-9]*' --exclude '*-*' HEAD)
version=$(cargo metadata --manifest-path "$root/Cargo.toml" --no-deps --format-version 1 |
  python3 -c 'import json, sys; print({p["name"]: p for p in json.load(sys.stdin)["packages"]}["arkade-compiler"]["version"])')
npm_version=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["version"])' "$root/npm/package.json")

status=0
"$root/scripts/compare-output.sh" "$last" || status=$?
case $status in
  0) exit 0 ;;
  1) ;;
  *) echo "::error::scripts/compare-output.sh failed (exit $status) before it could compare the contracts."; exit "$status" ;;
esac

python3 - "${last#v}" "$version" "$npm_version" <<'EOF'
import sys

last, version, npm_version = sys.argv[1:]
old = [int(part) for part in last.split(".")]
new = [int(part) for part in version.split("-")[0].split(".")]
# The leftmost nonzero component is the one `^last` pins.
pinned = next((i for i, part in enumerate(old) if part), 2)
bump = old[:pinned] + [old[pinned] + 1] + [0] * (2 - pinned)
if new[: pinned + 1] <= old[: pinned + 1]:
    print(
        f"::error::Compiled contracts differ from v{last} (listed above). Bump the version in "
        f"Cargo.toml [workspace.package] and npm/package.json to at least "
        f"{'.'.join(map(str, bump))}, then raise `pragma arkade` in examples/ and tests/e2e/contracts/."
    )
    sys.exit(1)
if npm_version != version:
    print(f"::error::npm/package.json version {npm_version} does not match crate version {version}.")
    sys.exit(1)
print(f"Compiled contracts differ from v{last}; version {version} leaves ^{last}.")
EOF
