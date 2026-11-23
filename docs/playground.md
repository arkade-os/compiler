# Playground

**[arkade-os.github.io/compiler](https://arkade-os.github.io/compiler)**

The playground runs the real compiler as WebAssembly. Nothing is installed and nothing leaves your browser. The footer shows the compiler version.

## Editing

Pick a contract from the Explorer and edit it. Errors and warnings appear as you type.

- **Hover** a name to see what it is, its type and where it is defined. Builtins and `tx`/`this` members show their docs.
- **F12** or **Ctrl+click** goes to its definition, in this file or another.
- The cursor highlights every use of the name under it.
- **Completion** offers the names in scope at the cursor, builtins, library members after `Lib.`, and struct fields along a path such as `policy.primary.`.
- **Ctrl+Enter** or **Ctrl+S** compiles; on macOS, use **Cmd**.
- The **Optimize** switch applies to both compiling and the as-you-type check.

## Output tabs

| Tab | What you get |
|---|---|
| JSON Output | The full artifact, the same bytes `arkadec` writes to disk, with sections of 50 or more lines folded |
| Assembly | Every spend group: its Arkade Script ASM and each tapscript leaf |
| Diagnostics | Every compiler error and warning with its location, updated as you type |

The copy button copies the current tab's output to the clipboard.

In the Assembly tab, the Arkade Script shows one source statement per line with its line number and `require` message.

- Hovering an Arkade Script line highlights its statement in the editor.
- Clicking it selects the statement.
- Moving the cursor highlights the cursor's statement.

Diagnostics are also underlined in the editor, and clicking one moves the cursor to it.

## Explorer

The Explorer ships the single-file examples (SingleSig, HTLC, Escrow, FujiSafe, StructVault, NonInteractiveSwap) and the multi-file projects (Stability, LayerZero / USDT0, Option, Bonds, Constant product).

- You can add files and folders, rename, delete through the context menu, and drag between folders.
- Everything persists in `localStorage`.
- The compiler resolves imports from the Explorer's files.

## Sharing

The link button compiles the selected contract and, when it compiles, copies a URL containing it and its dependencies. Shared bundles support up to 1 MiB of encoded URL content and 4 MiB of decompressed source data.

Every pull request to `master` from a branch of this repository gets its own build at `https://arkade-os.github.io/compiler/pr-previews/pr-<number>/`, posted as a comment on the PR.

## Run it locally

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
./playground/build.sh     # generates examples and installs packed compiler browser assets
./playground/serve.sh     # http://localhost:8080, pass a port to override
```

- Node.js 22.12 or newer is required, and `serve.sh` needs `python3`.
- The build script installs locked npm development dependencies and packs `@arkade-os/compiler` locally. It needs no npm publishing credentials.
- `playground/contracts.js` and `playground/pkg/` are generated and git-ignored.

To add a contract to the playground, add a `.ark` file under `examples/` and register it in `playground/main.js`: a single-file example needs entries in both `examples` and `examplePaths`. `contracts.js` exports each file by its basename, so the basename must be unique and a valid JavaScript identifier.
