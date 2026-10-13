# @arkade-os/compiler

Compile Arkade source projects in Node.js and browser applications. The package includes prebuilt WebAssembly, generated bindings, and TypeScript declarations. Consumers do not need Rust or wasm-pack, and compilation requires no wallet, provider, or Arkade network connection.

This package is prepared for npm publication but is not published yet. To install a local build, run `npm pack` in this directory, then install the resulting tarball in your application:

```sh
npm install /path/to/arkade-os-compiler-0.1.0.tgz
```

After publication, install and pin the compiler with `npm install --save-exact @arkade-os/compiler@0.1.0`. Keep your application lockfile. Use a development dependency for build-time compilation, or a runtime dependency when your application compiles source at runtime.

```ts
import { compile, version } from "@arkade-os/compiler";

const artifact = await compile({
    entry: "contracts/main.ark",
    files: {
        "contracts/main.ark": `import "../shared/fees.ark";
contract Vault(int minimum) {
    function spend(int amount) {
        require(Fees.double(amount) >= minimum);
    }
}`,
        "shared/fees.ark": `library Fees {
    function double(int amount) int { return amount * 2; }
}`,
    },
});

console.log(await version(), artifact.contractName);
for (const warning of artifact.warnings) console.warn(warning);
```

CommonJS consumers can use `const { compile, version } = require("@arkade-os/compiler")` with the same asynchronous API.

## API

`compile(input: CompileInput, options?: CompileOptions): Promise<CompilerArtifact>` accepts an entry path and an object mapping relative `.ark` paths to source strings. Imports resolve relative to the importing file. The compiler normalizes paths and rejects source-root escapes, absolute paths, and duplicate normalized paths. Input and settings are captured when `compile` is called. Optimizations default to `true`; pass `{ optimize: false }` as the second argument to disable them. The artifact's `compiler.options` records the settings used.

The returned object preserves the compiler's JSON artifact, including constructor inputs, struct layouts, all spend groups and leaves, witness order and injected fields, source provenance, compiler version and settings, format version, timestamp, and fingerprint. Its additional `warnings: string[]` field retains compilation diagnostics; Rust's serialized artifacts omit warnings, and warnings do not participate in the fingerprint. The artifact is the compiler model, not an SDK `Program`. SDK conversion belongs to the separate SDK integration.

`symbols(input: CompileInput): Promise<SourceSymbols>` returns parsed declarations, struct layouts, and directly imported members for editor tooling. Each symbol includes its name, kind, optional type, 1-based `[line, column]` position, optional `[startLine, endLine]` scope, and optional imported file path. This parses source without semantic validation, so a library can be the entry file. Missing or invalid imports contribute no imported symbols; an invalid entry file rejects with an `Error`.

`version(): Promise<string>` reports the installed WASM compiler version. All three functions initialize WASM lazily and share initialization across concurrent calls. A failed initialization can be retried by calling any function again. Compilation and parsing failures reject with an `Error` containing the original compiler diagnostic; initialization errors retain their original cause.

## Runtime selection

Package exports automatically select the Node loader for Node.js ESM and CommonJS imports, and the browser loader for browser bundles. WebAssembly is portable across x86-64, aarch64, and other CPUs supported by the runtime, so there are no architecture-specific executables or downloads. Node loads assets from the installed package; browsers load assets from the application bundle. Importing the package alone does not initialize WASM.

Node.js 22.12 or newer is supported. Browser production bundles are tested with Vite and Chromium, including deployment under a URL prefix. Bundlers must preserve and emit the package's `new URL(..., import.meta.url)` WASM asset references; serve `.wasm` files with the `application/wasm` content type. The compiler uses no remote release lookup. Loading a browser bundle's local WASM asset may make an HTTP request to the application's own origin.

Compilation currently runs synchronously inside WASM after initialization; the Promise API does not move compilation off the JavaScript thread. Applications needing background compilation can import this package in a worker. Other runtimes, including Expo, require separate verification.

The static playground consumes the browser assets from a locally packed package through an import map. Its build script generates examples, builds and packs the compiler, and extracts `dist/browser/` into `playground/pkg/`. All compiler calls use the public package API; npm publication is not required to build or deploy it.

## Development and packing

Package development requires Rust with the `wasm32-unknown-unknown` target, wasm-pack 0.15.0, and Node.js 22.12 or newer:

```sh
rustup target add wasm32-unknown-unknown
npm ci
npm run build
npx playwright install chromium
npm test
npm pack
```

`npm test` installs a tarball into an isolated application, checks Node ESM/CommonJS and TypeScript declarations, and executes a production browser bundle. It also verifies relative imports, artifact and warning preservation, concurrent initialization, useful failures, and initialization retry. To use an existing Chrome installation locally, run `PLAYWRIGHT_CHANNEL=chrome npm test`.

`npm pack` runs the release build through `prepack`; installing the tarball has no build lifecycle scripts or runtime dependencies. Generated `dist/`, license copies, dependencies, and tarballs are ignored. Package builds require the npm version to match `[workspace.package].version` in the root `Cargo.toml`. Bump both for a compiler release. Package CI builds and tests the tarball without publishing it. npm publication must be configured separately once organization permissions are available.
