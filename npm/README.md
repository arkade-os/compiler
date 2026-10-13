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

`check(input: CompileInput): Promise<Diagnostic[]>` runs the compiler's existing parse, validation, and type checks without emitting an artifact. It returns source errors and warnings as data, including independent errors in a failing file and the correct filenames for imported diagnostics. A library may be the entry. Each diagnostic has `severity: "error" | "warning"`, `message`, `file`, optional `code`, and optional `span: { start, end }` containing UTF-8 byte offsets into that file. Missing optional fields are omitted. A successful check does not guarantee that assembly generation will succeed.

```ts
import { check } from "@arkade-os/compiler";

const diagnostics = await check({
    entry: "main.ark",
    files: { "main.ark": "contract C() { function spend() { require(missing); } }" },
});
for (const diagnostic of diagnostics) console.log(diagnostic.severity, diagnostic.file, diagnostic.message);
```

`version(): Promise<string>` reports the installed WASM compiler version. All four functions initialize WASM lazily and share initialization across concurrent calls. A failed initialization can be retried by calling any function again. Invalid JavaScript inputs reject with a `TypeError`; initialization failures reject with their original error. Compilation and symbol parsing failures reject with an `Error` containing the original compiler diagnostic, while `check` returns source failures as diagnostics.

## Runtime selection

Package exports automatically select the Node loader for Node.js ESM and CommonJS imports, and the browser loader for browser bundles. WebAssembly is portable across x86-64, aarch64, and other CPUs supported by the runtime, so there are no architecture-specific executables or downloads. Node loads assets from the installed package; browsers load assets from the application bundle. Importing the package alone does not initialize WASM.

Node.js 22.12 or newer is supported. Browser production bundles are tested with Vite and Chromium, including deployment under a URL prefix. Bundlers must preserve and emit the package's `new URL(..., import.meta.url)` WASM asset references; serve `.wasm` files with the `application/wasm` content type. The compiler uses no remote release lookup. Loading a browser bundle's local WASM asset may make an HTTP request to the application's own origin.

Compilation currently runs synchronously inside WASM after initialization; the Promise API does not move compilation off the JavaScript thread. Applications needing background compilation can import this package in a worker. Other runtimes, including Expo, require separate verification.

The static playground consumes the browser assets from a locally packed package in a module worker. Its build script generates examples, builds and packs the compiler, and extracts `dist/browser/` into `playground/pkg/`. All compiler calls use the public package API; npm publication is not required to build or deploy it. The playground requests structured diagnostics after compilation failures and maps UTF-8 spans to Monaco positions. Failed initialization can be retried by compiling again.

## Worker example

The repository's [compiler-client.js](https://github.com/arkade-os/compiler/blob/main/playground/compiler-client.js) and [compiler-worker.js](https://github.com/arkade-os/compiler/blob/main/playground/compiler-worker.js) are a tested consumer example. Copy both into the same directory in your application. In a bundler such as Vite, change the worker's compiler import to `import { compile, check, symbols, version } from "@arkade-os/compiler"`. Then call the client:

```js
import { compile, check } from "./compiler-client.js";

const input = { entry: "main.ark", files: { "main.ark": "contract C() { function spend() { require(true); } }" } };
console.log(await compile(input));
console.log(await check(input));
```

The client creates one module worker lazily, matches concurrent requests to their responses, preserves compiler errors, and recreates the worker after a fatal worker error. Calls and results must be structured-cloneable. Compiler work runs on the worker thread, leaving the page responsive. The package itself has no worker-management API. For static applications, use a relative import to the copied browser entrypoint inside the worker; document import maps do not apply inside workers. Both the Vite worker bundle and the playground's static worker are tested under URL prefixes.

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

`npm test` installs a tarball into an isolated application, checks Node ESM/CommonJS and TypeScript declarations, and executes a production browser bundle. It also verifies relative imports, artifact and warning preservation, structured diagnostics, concurrent initialization, useful failures, initialization retry, and the worker example's responsiveness and restart behavior. To use an existing Chrome installation locally, run `PLAYWRIGHT_CHANNEL=chrome npm test`.

`npm pack` runs the release build through `prepack`; installing the tarball has no build lifecycle scripts or runtime dependencies. Generated `dist/`, license copies, dependencies, and tarballs are ignored. Package builds require the npm version to match `[workspace.package].version` in the root `Cargo.toml`. Bump both for a compiler release. Package CI builds and tests the tarball without publishing it. npm publication must be configured separately once organization permissions are available.
