# Development

## Tests

```bash
cargo test --workspace                                   # unit, feature, and example tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
(cd npm && npm test)                                     # npm package; see npm/README.md
node playground/imports.test.mjs                         # after the playground build
node playground/completions.test.mjs
./scripts/e2e.sh -v                                      # builds arkadec, runs artifacts through the Arkade VM and btcd (Go)
git config core.hooksPath scripts                       # fmt + test before every commit; runs the checked-out script, so re-run it if you installed by copying
```

- `core.hooksPath` replaces `.git/hooks`, so other hooks kept there stop running. To keep them, link the hook instead: `ln -sf ../../scripts/pre-commit "$(git rev-parse --git-path hooks)/pre-commit"`.
- [Build the playground](playground.md#run-it-locally) before the playground tests.
- `BLESS=1 cargo test --test diagnostics` rewrites the expected diagnostics in `tests/diagnostics/`.
- CI also checks every example with `arkadec --check --json --deny security`, so a security lint finding in `examples/` fails the build.
- CI compiles `examples/`, `tests/e2e/contracts/` and the fuzzer's cases with the last release and with the PR (`scripts/check-output-version.sh`). If any artifact differs, the version in `Cargo.toml` and `npm/package.json` must leave `^<last release>`, so contracts raise their `pragma arkade` to accept the new output. `scripts/compare-output.sh <ref>` runs the comparison against any ref.

### End-to-end tests

`scripts/e2e.sh` runs the Go suite in `tests/e2e/` twice, once with optimized and once with unoptimized Arkade Scripts, which must behave identically on the Arkade VM.

- The suite needs the Go version in `tests/e2e/go.mod`, which also pins its dependencies.
- No Docker or emulator checkout is needed.

### Differential fuzzing

The E2E suite includes a differential fuzzer that runs random contracts optimized and unoptimized on the VM. It defaults to seed 1 and 200 cases. To search further:

```bash
ARKADE_FUZZ_SEED=7 ARKADE_FUZZ_CASES=5000 ./scripts/e2e.sh -run TestDifferentialFuzz
```

Each case is a subtest such as `TestDifferentialFuzz/seed7_case42`. Pass `-run 'TestDifferentialFuzz/seed7_case42$'` in that command to replay only that case.

## Releasing

`arkade-compiler` and the npm package `@arkade-os/compiler` share one version: `[workspace.package]` in the root `Cargo.toml` and `version` in `npm/package.json`.

To release:

1. In a PR, bump both versions:
   - set `version` in `[workspace.package]` in the root `Cargo.toml`;
   - set `version` in `npm/package.json`, then run `npm install --package-lock-only` in `npm/` to update its lockfile;
   - run `cargo check --workspace` and commit the updated `Cargo.lock`, since the release builds with `--locked`.
2. Merge the PR.
3. Push `v<version>` from the merge commit.

`.github/workflows/release.yml` then:

- checks the tag against both versions;
- builds binaries for five targets and the tested npm tarball;
- creates a GitHub release with them and `SHA256SUMS`;
- publishes the crate to crates.io and the package to npm as the tag allows (see [Tags](#tags)), through [trusted publishing](#trusted-publishing).

### Tags

| Tag | GitHub release | npm | crates.io |
|---|---|---|---|
| Final, such as `v0.1.0` | Release | `latest` | Published |
| Pre-release version, such as `v0.1.0-rc.1` for `0.1.0-rc.1` | Pre-release | `next` | Skipped |
| Another suffix beyond the version, such as `v0.1.0-test` for `0.1.0` | Pre-release | Nothing | Skipped |

Release candidates use `-rc.N` versions. Install one with `npm install @arkade-os/compiler@next`. Remove a test tag with `gh release delete <tag> --cleanup-tag`.

### Trusted publishing

The crate and the npm package trust `release.yml` in `arkade-os/compiler` as their publisher, so the workflow publishes without a stored token. For a final tag, the `publish` job publishes the crate from the `crates-io` environment. For a final or pre-release version tag, the `publish-npm` job publishes the tarball from the `npm` environment. Each job skips a version that is already published, so a failed job can be re-run.
