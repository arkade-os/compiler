# @arkade-os/compiler

Compile Arkade source projects in Node.js and browser applications. The package includes prebuilt WebAssembly, generated bindings, and TypeScript declarations. Consumers do not need Rust or wasm-pack, and compilation requires no wallet, provider, or Arkade network connection.

Install and pin the compiler with `npm install --save-exact @arkade-os/compiler`. Release candidates are published under the `next` dist-tag: `npm install --save-exact @arkade-os/compiler@next`. Each GitHub release also carries the package tarball, which installs without the registry (`npm install ./arkade-os-compiler-<version>.tgz`), as does a local build made with `npm pack` in this directory. Keep your application lockfile. Use a development dependency for build-time compilation, or a runtime dependency when your application compiles source at runtime.

```ts
import { compile, version } from "@arkade-os/compiler";

const { artifact, diagnostics } = await compile({
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

if (artifact === null) throw new Error(diagnostics.map(d => d.message).join("\n"));
console.log(await version(), artifact.contractName);
for (const d of diagnostics) console.warn(`${d.severity}: ${d.message} (${d.file}:${d.start?.line})`);
```

The package is ESM-only. CommonJS code can still load it with `require("@arkade-os/compiler")`, which Node.js 22.12 and newer support for ES modules.

## API

`compile(input: CompileInput, options?: CompileOptions): Promise<CompileResult>` accepts an entry path and an object mapping relative `.ark` paths to source strings. Imports resolve relative to the importing file. The compiler normalizes paths and rejects source-root escapes, absolute paths, and duplicate normalized paths. Input and settings are captured when `compile` is called. Optimizations default to `true`; pass `{ optimize: false }` as the second argument to disable them. The artifact's `compiler.options` records the settings used.

The result is `{ artifact, debug, diagnostics }`. `artifact` is the compiler's JSON artifact, including constructor inputs, struct layouts, all spend groups and leaves, witness order and injected fields, source provenance, compiler version and settings, format version, timestamp, and fingerprint. `debug` is the debug file: each covenant's source map, linked to the artifact by its fingerprint. `diagnostics` lists every error and warning; warnings are not part of the artifact or its fingerprint. Source errors do not reject: `artifact` and `debug` are both `null` and `diagnostics` lists every error. `CompileResult` is a union on `artifact`, so checking it narrows `debug` too. The artifact is the compiler model, not an SDK `Program`. SDK conversion belongs to the separate SDK integration.

`check(input: CompileInput, options?: CompileOptions): Promise<Diagnostic[]>` returns the diagnostics `compile` would, without an artifact, except that a library entry is not an error. It reports independent errors in a failing file, the files of imported diagnostics, and, when those pass, code generation's first error. Each diagnostic has `severity: "error" | "warning"`, `code` (the pass that raised it, or `null`), `message`, `file`, and 1-based `start` and `end` `{ line, column }` positions, or `null` when it has no location. Columns count UTF-16 code units, as editors such as Monaco and VS Code do.

```ts
import { check } from "@arkade-os/compiler";

const diagnostics = await check({
    entry: "main.ark",
    files: { "main.ark": "contract C() { function spend() { require(missing); } }" },
});
for (const d of diagnostics) console.log(d.severity, `${d.file}:${d.start?.line}`, d.message);
```

`symbolAt(input: CompileInput, position: Position): Promise<SymbolInfo | null>` returns the name at a 1-based `{ line, column }` of the entry file, for hover, go to definition and highlighting: its `name`, `kind`, `type`, the location it was found `at`, its `definition`, and its `references`, each `{ file, start, end }`. It returns `null` when no name is there.

`completionsAt(input: CompileInput, position: Position): Promise<Completions>` returns the names usable at a position: `symbols`, `members` (a library's or contract's names under its own), and `structs` with their fields. Files that fail validation still get symbols, but a file that does not parse gives none.

`version(): Promise<string>` reports the installed WASM compiler version. All functions initialize WASM lazily and share initialization across concurrent calls. A failed initialization can be retried by calling any function again. A WASM trap, such as a stack overflow on deeply nested source, rejects with the trap; in Node the next call loads a new instance, while a browser realm keeps the broken one, so reload the page, or run the compiler in a worker and replace the worker. Non-positive, non-integer or above-32-bit positions reject with a `TypeError`; initialization failures reject with their original error.

## Runtime selection

Package exports automatically select the Node loader for Node.js and the browser loader for browsers and bundlers; both share one WASM build. WebAssembly is portable across x86-64, aarch64, and other CPUs supported by the runtime, so there are no architecture-specific executables or downloads. Node loads assets from the installed package; browsers load assets from the application bundle. Importing the package alone does not initialize WASM.

Node.js 22.12 or newer is supported. The unbundled browser entrypoint is tested in Chromium under a URL prefix. Bundlers must preserve and emit the package's `new URL(..., import.meta.url)` WASM asset references; serve `.wasm` files with the `application/wasm` content type. The compiler uses no remote release lookup. Loading a browser bundle's local WASM asset may make an HTTP request to the application's own origin.

Compilation currently runs synchronously inside WASM after initialization; the Promise API does not move compilation off the JavaScript thread. Applications needing background compilation can import this package in a worker. Other runtimes, including Expo, require separate verification.

The static playground imports the browser entrypoint of a locally packed package. Its build script generates examples, builds and packs the compiler, and extracts `dist/browser/` and `dist/wasm/` into `playground/pkg/`. All compiler calls use the public package API; npm publication is not required to build or deploy it. The playground marks diagnostics at their positions, lints as you type with `check`, and drives hover, go to definition and completion with `symbolAt` and `completionsAt`. Failed initialization can be retried by compiling again.

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

`npm test` installs a tarball into an isolated application, checks that every function returns what the raw WASM bindings do under Node ESM, `require()` and Chromium, and checks the TypeScript declarations, concurrent initialization, initialization retry and recovery from a trap in Node. To use an existing Chrome installation locally, run `PLAYWRIGHT_CHANNEL=chrome npm test`.

`npm pack` runs the release build through `prepack`; installing the tarball has no build lifecycle scripts or runtime dependencies. Generated `dist/`, license copies, dependencies, and tarballs are ignored. Package builds require the npm version to match `[workspace.package].version` in the root `Cargo.toml`. Bump both for a compiler release. Package CI builds and tests the tarball without publishing it; a `v<version>` tag builds, tests and publishes it, as the root README's release section describes.
