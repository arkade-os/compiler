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
cp ./scripts/pre-commit "$(git rev-parse --git-path hooks)"   # fmt + test before every commit
```

- [Build the playground](playground.md#run-it-locally) before the playground tests.
- `BLESS=1 cargo test --test diagnostics` rewrites the expected diagnostics in `tests/diagnostics/`.
- CI also checks every example with `arkadec --check --json --deny security`, so a security lint finding in `examples/` fails the build.

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

`arkade-compiler`, `arkade-bindgen` and the npm package `@arkade-os/compiler` share one version: `[workspace.package]` in the root `Cargo.toml` and `version` in `npm/package.json`.

To release:

1. In a PR, bump both versions:
   - set `version` in `[workspace.package]` in the root `Cargo.toml`;
   - set `version` in `npm/package.json`, then run `npm install --package-lock-only` in `npm/` to update its lockfile;
   - on a minor bump or a release candidate, also set `arkade-bindgen`'s `arkade-compiler` requirement to the new version, since a `0.1.0` requirement does not accept `0.1.0-rc.1`;
   - run `cargo check --workspace` and commit the updated `Cargo.lock`, since the release builds with `--locked`.
2. Merge the PR.
3. Push `v<version>` from the merge commit.

`.github/workflows/release.yml` then:

- checks the tag against both versions;
- builds binaries for five targets and the tested npm tarball;
- creates a GitHub release with them and `SHA256SUMS`;
- publishes both crates to crates.io and the package to npm through trusted publishing.

### Tags

| Tag | GitHub release | npm | crates.io |
|---|---|---|---|
| Final, such as `v0.1.0` | Release | `latest` | Published |
| Pre-release version, such as `v0.1.0-rc.1` for `0.1.0-rc.1` | Pre-release | `next` | Skipped |
| Another suffix beyond the version, such as `v0.1.0-test` for `0.1.0` | Pre-release | Nothing | Skipped |

Release candidates use `-rc.N` versions. Install one with `npm install @arkade-os/compiler@next`. Remove a test tag with `gh release delete <tag> --cleanup-tag`.

### First publish

Trusted publishing can only be configured on an existing crate or package, so the first release to each registry is manual. Later releases publish from the workflow with provenance.

**crates.io.** From the commit to be tagged, a crate owner:

1. runs `cargo publish --locked -p arkade-compiler && cargo publish --locked -p arkade-bindgen`;
2. enables trusted publishing for both crates (repository `arkade-os/compiler`, workflow `release.yml`, environment `crates-io`);
3. pushes the tag.

The workflow skips crates whose version is already published.

**npm.** After the tag's workflow attaches the tarball to the GitHub release, an `@arkade-os` npm owner:

1. downloads it;
2. runs `npm publish arkade-os-compiler-<version>.tgz --access public --tag next`, or `--tag latest` for a final version;
3. adds a trusted publisher to the package (repository `arkade-os/compiler`, workflow `release.yml`, environment `npm`);
4. re-runs the failed `publish-npm` job, which then skips the published version.
