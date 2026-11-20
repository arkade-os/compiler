# Artifact format

`arkadec` writes one JSON artifact per contract. Arkade libraries consume it directly. Typed client code follows the [Arkade Script stack ABI](#arkade-script-stack-abi).

This artifact is `examples/htlc` compiled, with `"..."` marking omitted values:

```json
{
  "formatVersion": 1,
  "contractName": "HTLC",
  "constructorInputs": [{ "name": "sender", "type": "pubkey" }, "..."],
  "functions": [
    {
      "name": "claim",
      "arkade": {
        "inputs": [],
        "asm": ["OP_PUSHCURRENTINPUTINDEX", "OP_INSPECTOUTPUTSCRIPTPUBKEY", "OP_SWAP", "<CONTRACT:SingleSig(<receiver>)>", "..."]
      },
      "leaves": [
        {
          "name": "claim",
          "witness": [
            { "name": "preimage", "type": "bytes", "encoding": "raw" },
            { "name": "operatorSig", "type": "signature", "encoding": "schnorr-64", "injected": true }
          ],
          "asm": ["OP_HASH160", "<preimageHash>", "OP_EQUAL", "OP_VERIFY", "<OPERATOR_KEY:claim>", "OP_CHECKSIG"]
        }
      ]
    },
    { "name": "refund", "arkade": { "inputs": [], "asm": ["..."] }, "leaves": ["..."] },
    { "name": "unilateral", "leaves": ["..."] }
  ],
  "contracts": { "SingleSig": "sha256:..." },
  "codeHash": "sha256:...",
  "source": {
    "entry": "htlc/htlc.ark",
    "files": { "htlc/htlc.ark": "...", "single_sig/single_sig.ark": "..." }
  },
  "compiler": { "name": "arkadec", "version": "0.1.0", "options": { "optimize": true } },
  "updatedAt": "2026-01-01T00:00:00Z",
  "fingerprint": "sha256:..."
}
```

## Fields

| Field | Meaning |
|---|---|
| `formatVersion` | Artifact schema version |
| `contractName` | The entry contract's name |
| `structs` | User struct layouts, so clients can flatten parameters the way the compiler does; absent when there are none |
| `constructorInputs` | One entry per source parameter, declaration order; arrays keep their size in the type, structs keep their type name |
| `functions[]` | Spend groups: `{ name, arkade?, leaves[] }` |
| `arkade` | `{ inputs, asm }`; absent for groups made only of standalone leaves |
| `leaves[]` | `{ name, witness, asm }`; `witness` lists spend-time values in source order, `injected: true` marks operator signatures |
| `contracts` | The `codeHash` of each contract a `<CONTRACT:Name(...)>` placeholder names, keyed by name; absent when there is none |
| `codeHash` | SHA-256 of compact artifact JSON with only the fields before it, `formatVersion` through `contracts`, which determine the scripts; `source`, `compiler`, `updatedAt` and `fingerprint` are left out |
| `source` | `{ entry, files }`: original entry source and every recursively imported file, including comments |
| `compiler.options` | Effective compilation settings; `optimize` enables constant folding, static branch removal, and assembly optimization for Arkade Scripts |
| `updatedAt` | Changes on every compile; ignore it when diffing artifacts |
| `fingerprint` | SHA-256 of compact artifact JSON before `fingerprint` and `updatedAt` are added; includes source, ABI, compiler settings, unresolved script templates, `contracts`, and `codeHash` |

Witness `encoding` values are `schnorr-64`, `raw`, `raw-20`, `raw-32` and `scriptnum`.

## Verifying artifacts

`codeHash` and `fingerprint` identify artifact content, but do not authenticate its origin. An artifact's own `codeHash` and `fingerprint` fields are claims: anyone supplying an artifact can copy them while changing its scripts.

> [!IMPORTANT]
> Never trust a received artifact's `codeHash` or `fingerprint` field as given. Recompute it, or recompile the bundled source with a trusted compiler.

A contract compiled on its own has the `codeHash` that an artifact instantiating it records in `contracts`, given the same compiler and options. So a client resolving `<CONTRACT:Name(...)>` from a separately supplied artifact can pin it to `contracts.Name`, in either of two ways:

- **Recompute its `codeHash`:** SHA-256 of the compact JSON, without whitespace, of the artifact's fields from `formatVersion` through `contracts` in serialized order, prefixed with `sha256:`. Compare that with `contracts.Name`.
- **Recompile its `source`** with a trusted compiler and the artifact's `compiler.options`, compare the recompiled `codeHash` with `contracts.Name`, and use the recompiled artifact.

What changes the `codeHash`:

- Edits outside the hashed fields, such as to comments or formatting, keep the `codeHash`.
- Edits inside them change it even when the scripts stay the same, such as renaming a witness parameter or reordering struct declarations.
- An instantiated contract's own `contracts` are part of its `codeHash`, so the pin covers indirect instantiations too.

## Spend group order

Clients use this order to build the Taproot tree:

1. Arkade Script function groups, in function declaration order.
2. Standalone tapscript groups, in tapscript declaration order.

This holds regardless of how the declarations are interleaved. Within an Arkade Script function's group, author-written leaves keep their declaration order, and a synthesized default leaf, when kept, comes first.

Reordering leaves can change the output key and address. Retain the original artifact to spend existing outputs.

A leaf's `witness` is not its stack order. The leaf script consumes the preimage first, if the tapscript has a condition, then a signature for each key in the order the keys are written in `checkSig` or `checkMultisig`, so a client builds the stack from the closure: the signatures by key, the last key's at the bottom, and the preimage on top.

## Source bundle

The `source` bundle contains the entry file and every loaded dependency, preserving their text verbatim, including comments.

- Paths are normalized and relative; native compilation strips the common directory prefix.
- Standalone compilation produces a one-file bundle with entry `main.ark`.
- Recompile a bundle with the same compiler version using `compile_sources_with_options(&source.entry, &source.files, options)`, with `options` from `compiler.options`. `compile_sources` always optimizes, so it reproduces only an optimized artifact.

Warnings are not serialized into artifacts. They remain available on the Rust compilation result, are printed by the CLI, and appear in the playground's Diagnostics tab. They identify their source file relative to the bundle root, including warnings from dependencies.

## Debug file

`--debug` also writes a debug file next to the artifact, with the artifact's extension replaced: `-o out/htlc.json` writes `out/htlc.debug.json`.

- It is not part of the artifact, so the fingerprint does not cover it.
- No consumer needs it to instantiate or spend a contract.
- The playground receives the same JSON, compact rather than pretty-printed, as `debug` from `compile_sources_with_diagnostics`.
- The Rust API keeps it on `ArkadeScript::source_map`, and `ContractJson::debug_info` builds the file.

```json
{
  "artifactFingerprint": "sha256:...",
  "formatVersion": 1,
  "functions": {
    "claim": { "sourceMap": [{ "asm": [0, 5], "start": [11, 5], "end": [11, 56] }] }
  }
}
```

- `artifactFingerprint` links the file to its artifact.
- `functions` is keyed by spend group name and lists only groups with an Arkade Script.
- Each `sourceMap` entry gives a run of `arkade.asm` tokens and the entry-file statement it comes from, as `{ asm: [from, to), start: [line, column], end: [line, column], message? }`. Positions are 1-based with columns in UTF-16 code units, and `message` is a `require`'s message.
- Code inlined from an imported helper maps to its call. The prologue's input checks and the final stack cleanup are not mapped.
- Positions point into the artifact's `source` bundle; the debug file holds no copy of the source.

## Arkade Script stack ABI

`constructorInputs`, `arkade.inputs`, and `witness` describe the source ABI, not the physical stack. Clients expand composite entries into scalar leaves:

- an array entry `oracles` of type `pubkey[3]` becomes `oracles.0`, `oracles.1`, `oracles.2`;
- a nested array entry `grid` of type `int[2][3]`, two rows of three, becomes `grid.0.0`, `grid.0.1`, `grid.0.2`, `grid.1.0`, `grid.1.1`, `grid.1.2`;
- a struct entry becomes its scalar leaves in field order, recursively, using dotted paths such as `policy.primary.key`.

Clients expand every `arkade.inputs` entry to its scalar leaves in that order, then push the whole list in reverse, so the first scalar ends up on top of the stack.

Every expanded constructor input the Arkade Script reads appears as exactly one `<name>` placeholder, which instantiation replaces with a data push before the Arkade Script hash is computed:

- Inputs read more than once, and every leaf of an input read through a runtime index, open the `asm` in reversed order.
- An input read once is pushed where it is read.
- An input never read from the stack, for example only through `new Child(...)` or an array's `.length`, is omitted.

The VM installs the function witness first, so prologue constructor values sit above function inputs. The body reaches everything through `OP_PICK` and friends and never emits function inputs as placeholders.

After instantiation the only remaining placeholders are `<CONTRACT:Contract(<a>,<b>)>` tokens, which the runtime resolves to the child contract's 32-byte Taproot output key (witness program).
