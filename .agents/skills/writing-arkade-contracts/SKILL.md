---
name: writing-arkade-contracts
description: Author and edit Arkade `.ark` contracts. Use for constructor state, spend functions, tapscript leaves, witnesses, output layouts, oracle checks, timelocks, fixed-point arithmetic, and contract-specific regression coverage. Do not use for compiler implementation work.
---

# Writing Arkade Contracts

## Start from working code

Read the closest contracts in `examples/`, then verify syntax against `src/parser/grammar.pest` and behavior against the compiler and tests. Treat examples and tests as authoritative when prose disagrees.

Compile early:

```bash
cargo run -- path/to/contract.ark -o /tmp/contract.json
```

## Model state and spend paths

- Put committed state in constructor parameters and per-spend data in function parameters.
- Propagate immutable constructor fields unchanged when recreating a state-bearing contract.
- Construct the next state explicitly with `new ContractName(...)` and assert its output script and minimum value.
- Use covenant `function name(...) { ... }` bodies for introspection and state-transition rules.
- Use `function name(...) tapscript { ... }` only for L1 authorization, hashes, and timelocks supported by `src/compiler/tapscript.rs`.

A covenant function with no matching tapscript gets a synthesized collaborative leaf using `server` and the function-tweaked `emulator` key. Add an explicit matching tapscript only when that authorization is insufficient.

Add unilateral exit as a separate CSV tapscript when required:

```ark
function unilateral(signature ownerSig) tapscript {
  require(older(exit));
  require(checkSig(ownerSig, owner));
}
```

Keep `server` and `emulator` out of constructors and covenant bodies. Use them only as reserved key operands in tapscript signature checks. Declare the corresponding signature witnesses on author-written tapscripts.

Do not use the removed `options { ... }` syntax.

## Design outputs before code

Treat output positions as part of the contract interface. If an output is conditional, write complete assertions for each branch because later output indices shift.

Prefer routing a sub-dust amount into an existing output when ownership remains correct. Follow the current project convention:

- Require at least 330 sats for a viable Taproot output.
- Emit an optional output only when its value is greater than 330 sats.

Use `>=` for minimum funding assertions unless exact value is a genuine invariant.

## Handle witnesses and time safely

Keep function parameters in the order the spender must provide them.

Reconstruct oracle messages with the exact field order and encoding used by the signer. Follow an existing oracle contract such as `examples/stability/stability_vault.ark` or `examples/threshold_oracle/threshold_oracle.ark`.

Do not mix time domains:

- Use `tx.time` for Bitcoin nLockTime/CLTV values used by the contract.
- Use `tx.offchainTime` for introspector wall-clock seconds.

Guard subtraction before applying a freshness or elapsed-time upper bound:

```ark
int age = tx.offchainTime - oracleTime;
require(age >= 0, "future-dated oracle");
require(age <= maxAge, "stale oracle");
```

For multi-input covenant checks, compare `this.activeInputIndex` with the witness-selected sibling index and verify the sibling input script before using its values.

## Keep arithmetic bounded

Assume signed 64-bit intermediates and truncating integer division.

- Bound user-controlled rates, fees, timestamps, and amounts before arithmetic.
- Interleave multiplication and division when a full product could overflow.
- Check whether truncation can produce a zero update while advancing state; require a meaningful delta when repeated zero-value updates would enable griefing.
- Document scale in names or nearby code and keep it consistent across state transitions.

## Respect grammar limits

- Use nested `if` statements or separate requirements instead of `&&`, `||`, or ternary expressions.
- Bind a computed array index to an identifier before indexing; array indices accept identifiers or number literals.
- Use assignments as statements, not expressions.
- Keep `require` messages short and descriptive.

Check the current grammar rather than preserving workarounds from old examples.

## Reuse representative examples

| Need | Start with |
|---|---|
| Basic covenant plus unilateral exit | `examples/htlc/htlc.ark` |
| Recursive state, oracle checks, and cross-input validation | `examples/stability/stability_vault.ark` |
| Conditional output and dust routing | `examples/stability/stability_offer.ark` |
| Asset introspection | `examples/token_vault/token_vault.ark` |
| Threshold signatures | `examples/threshold_oracle/threshold_oracle.ark` |

## Validate the contract

1. Sketch constructor state, witness inputs, authorizers, and output positions before writing the body.
2. Adapt the closest example instead of inventing a new pattern.
3. Compile after each structural change.
4. Add focused assertions for spend groups, witnesses, placeholders, and critical opcodes when behavior is non-trivial.
5. Run the targeted integration test, then the workspace checks from `AGENTS.md`.
6. Run `./playground/build.sh` when a playground example changes.
