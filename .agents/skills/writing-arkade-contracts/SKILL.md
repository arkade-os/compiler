---
name: writing-arkade-contracts
description: Author and edit Arkade `.ark` contracts, compile them to artifacts, and compose several contracts. Use for constructor state, spend functions, tapscript leaves, witnesses, output layouts, oracle checks, recursive beacons, timelocks, fixed-point arithmetic, and contract-specific regression coverage. Do not use for compiler implementation work.
---

# Writing Arkade Contracts

## Start from working code

Read the closest contracts in `examples/`, then verify syntax against `src/parser/grammar.pest` and behavior against the compiler and tests. Treat examples and tests as authoritative when prose disagrees.

Compile early:

```bash
cargo run -- path/to/contract.ark -o /tmp/contract.json
```

## Model state and spend paths

- Put committed state in constructor parameters and per-spend data in function parameters. Declare those parameters in source order. A covenant witness is that list reversed; a tapscript witness follows the tapscript parameter list.
- Constructor parameters are placeholders until instantiation, then constants in the script. Spend paths assume the agreed values. There is no constructor hook, so a domain check inside a spend does not run at compile time and does not see a different value than the one already committed.
- Propagate immutable constructor fields unchanged when recreating a state-bearing contract.
- Construct the next state with `new ContractName(...)` and assert its output script and minimum value. `tx.outputs[i].scriptPubKey` is the 32-byte Taproot witness program, not the `5120…` script. `new` compiles to that same output key.
- Use covenant `function name(...) { ... }` bodies for introspection and state-transition rules.
- Use `function name(...) tapscript { ... }` only for L1 authorization, hashes, and timelocks supported by `src/compiler/tapscript.rs`.

A covenant function with no matching tapscript gets a synthesized collaborative leaf using `server` and the function-tweaked `emulator` key. Add an explicit matching tapscript only when that authorization is insufficient. A tapscript that matches a function by name must sign bare `emulator` and must not call `tweak(emulator, ...)`.

A leaf may sign `tweak(constructorPubkey, func)` so that key is bound to `func`'s covenant. Every tweaked key in one tapscript must name the same function.

Add unilateral exit as a separate CSV tapscript when required:

```ark
function unilateral(signature ownerSig) tapscript {
  require(older(serverExitDelay));
  require(checkSig(ownerSig, owner));
}
```

`serverExitDelay` is arkd's unilateral exit delay and needs no constructor parameter. Take a constructor `int` only when the contract needs a different delay.

Keep `server`, `emulator`, and `serverExitDelay` out of constructors and covenant bodies. Use them only as reserved key operands in tapscript signature checks. Declare the corresponding signature witnesses on author-written tapscripts.

Do not use the removed `options { ... }` syntax.

## Design outputs before code

Treat output positions as part of the contract interface. If an output is conditional, write complete assertions for each branch because later output indices shift.

Prefer routing a sub-dust amount into an existing output when ownership remains correct. Follow the current project convention:

- Require at least 330 sats for a viable Taproot output.
- Emit an optional output only when its value is greater than 330 sats.

Use `>=` for minimum funding assertions unless exact value is a genuine invariant.

## Handle witnesses and time safely

Reconstruct oracle messages with the exact field order and encoding used by the signer. Follow `examples/escrow/escrow.ark` or `examples/threshold_oracle/threshold_oracle.ark`.

Do not mix time domains:

- `checkTime(timestamp)` reads the emulator clock in Unix seconds and compiles to `OP_CHECKTIME`. Put it in `require`. The operator runs that clock and can accept the spend early. Offchain spends of the leaf are rebuilt with nLockTime 0, so `tx.time` does not enforce the same deadline.
- Use `tx.time` for Bitcoin nLockTime/CLTV.
- Write timelock literals as `older(blocks(n))`, `older(seconds(n))`, `after(blocks(height))`, or `after(seconds(timestamp))`. `seconds(n)` in `older` must be a multiple of 512 and compiles to the BIP68 time-based sequence. A parameter or a unitless literal is pushed raw, so a CSV parameter must already be the BIP68 sequence. Public arkd rejects block-type timelocks, so prefer `older(serverExitDelay)` on exit leaves. The CSV counter starts when the output is mined, not when the virtual coin is created.
- `tx.offchainTime` is gone.

```ark
require(checkTime(oracleTime), "future-dated oracle");
```

For multi-input covenant checks, compare `this.activeInputIndex` with the witness-selected sibling index and verify the sibling input script before using its values. Checks written against `tx.outputs` are transaction-wide: a second input that carries the same script can satisfy them without adding a second set of outputs. Name the input set the path allows. A path that spends only this coin requires `tx.numInputs == 1`. A path that needs other coins must identify those inputs by index and by script, not only by value.

## Keep arithmetic bounded

Assume signed 64-bit intermediates and truncating integer division.

- Bound user-controlled rates, fees, timestamps, and amounts before arithmetic.
- Interleave multiplication and division when a full product could overflow.
- Check whether truncation can produce a zero update while advancing state; require a meaningful delta when repeated zero-value updates would enable griefing.
- Document scale in names or nearby code and keep it consistent across state transitions.

## Respect grammar limits

- `&&` and `||` are available in covenant bodies and short-circuit; ternary expressions are not.
- Bind a computed array index to an identifier before indexing; array indices accept identifiers or number literals.
- Use assignments as statements, not expressions.
- Keep `require` messages short and descriptive.

Check the current grammar rather than preserving workarounds from old examples.

## Reuse representative examples

| Need | Start with |
|---|---|
| Basic covenant plus unilateral exit | `examples/htlc/htlc.ark` |
| Oracle attestation, introspection-pinned payouts, branching output layouts | `examples/escrow/escrow.ark` |
| Recursive state and cross-input validation | `examples/stability/stability_vault.ark` |
| Conditional output and dust routing | `examples/stability/stability_offer.ark` |
| Asset introspection | `examples/token_vault/token_vault.ark` |
| Threshold signatures | `examples/threshold_oracle/threshold_oracle.ark` |
| Several files, `new` child contracts | `examples/layerzero/`, `examples/non_interactive_swap/` |
| Recursive price beacon | `tests/features/beacon.rs` |

Most of `examples/stability/` is commented out and predates the current grammar. Read it for shape, not syntax.

## Compile an artifact

The artifact is the contract the SDK spends. Commit it when an application loads it. Do not hand-edit it.

```bash
cargo run -- path/to/contract.ark -o /tmp/contract.json
```

`compile_file` loads the entry and its relative imports. `compile_sources(entry, files)` compiles an in-memory project. The JSON shape is `contractName`, `constructorInputs`, `structs`, `functions` (spend groups of `{ name, arkade?, leaves }`), `source`, `compiler`, `warnings`, and `updatedAt`. Ignore `updatedAt` when diffing. `source.files` is every imported file, verbatim; recompile that bundle with the same compiler version.

`constructorInputs` and `arkade.inputs` are the source ABI. Clients expand arrays and structs into scalar leaves and serialize covenant inputs in reverse `arkade.inputs` order. After instantiation the only remaining placeholders are `<VTXO:Contract(...)>` tokens.

`playground/contracts.js` and `playground/pkg/` are generated. A playground folder is an entry in the `projects` object in `playground/main.js`. Regenerate the contract bundle with `./playground/generate_contracts.sh`. `examples/**/*.json` is compiler output and is ignored.

## Compose several contracts

One contract or library per file. `import "./other.ark";` is relative to the importing file, direct-import scope, depth 128, no cycles. The entry contract owns the artifact's spend groups. Imported files supply constructors, constants, and helpers.

`new Child(args)` checks the constructor and emits `<VTXO:Child(...)>`. The runtime resolves that to the child Taproot script. A `bytes32` compared with `scriptPubKey` is the 32-byte witness program. The output a transaction pays still carries the full script, `OP_1` plus those 32 bytes.

A contract instantiates itself, with no import, to continue state (`examples/fuji_safe`). Copy every field that must not change. A field omitted from `new` is not preserved.

## Continue state

Two places hold state, and they upgrade differently.

Script state is the constructor. Continuing it is `new SameContract(...)` on the output, copying every field that must stay and passing a new value only for a field this function is allowed to change. A changed constructor is a different script. Anything that pinned the old script stops matching.

A reading that must move without changing the script is an asset amount. The function continues the same constructor, then sets `tx.outputs[0].assets.lookup(...)` to the new amount. A clock is a second asset that the function requires not to move backwards. A passthrough function is the same continuation with each watched amount `output >= input`, so another contract can spend this coin in the same transaction without draining it. `tests/features/beacon.rs` is that pattern for an oracle. `examples/token_vault` is the control asset, amount 1, that has to be present on the way in and on the way out.

Another contract sees that coin only when it is an input of this transaction. Check the sibling script, or the control asset, read the amount, and require the continuation output. A signer copied into the constructor is fixed for that script. Rotating it is a new script. Consumers that must follow the rotation recognize the control asset on the new script, not the previous constructor.

An attestation is a signature over a message the contract rebuilds in the signer's field order. Several signatures over one message require distinct keys. Bound the attested values before arithmetic.

## Validate the contract

1. Sketch constructor state, witness inputs, authorizers, and output positions before writing the body.
2. Adapt the closest example instead of inventing a new pattern.
3. Compile after each structural change.
4. Do not add a unit test. One functional end-to-end test against a running regtest stack is the proof, written as the `arkade-regtest` skill describes. Helpers in that file go at the end.
5. Run `./playground/build.sh` when a playground example changes.

Spending that artifact, building the product UI, and running a regtest stack are the `arkade-contract`, `arkade-product-ui`, and `arkade-regtest` skills in the ts-sdk repo.
