---
name: writing-arkade-contracts
description: Activate when authoring or editing `.ark` contract files (not the compiler itself). Use for any task involving constructor design, state transitions, tapleaf shape, witness layout, output assertions, oracle patterns, or working around grammar gotchas. Distinct from `language-feature-development` which is for compiler maintainers.
prerequisites: Read `docs/arkade-primitives-spec.md` and at least two reference contracts in `examples/` before starting.
---

# Writing Arkade Contracts

<purpose>
Codify the patterns and sharp edges that recur when authoring `.ark` contracts. The grammar is small but opinionated, and many idioms are not obvious from the README — this skill consolidates what's actually load-bearing across the working examples.
</purpose>

<audience>
Contract authors writing `.ark` files. Not the compiler/grammar maintainer audience (use `language-feature-development.md` for that).
</audience>

<core_patterns>

## 1. The two-tapleaf mental model

Every non-internal function compiles into **two variants**: `serverVariant=true` (cooperative; Arkade Operator co-signs) and `serverVariant=false` (exit; CLTV-gated unilateral fallback). Both enforce the same settlement math.

Canonical opening:
```ark
options {
  server = server;
  exit = exit;
}

contract Foo(
  ...,
  int exit  // unilateral-exit timelock in blocks; constructor param so playground can set it
) { ... }
```

Rules:
- **NEVER** put `pubkey serverPk` (or `operatorPk`, etc.) in the constructor. The Arkade Operator key is auto-injected as `<SERVER_KEY>` via `options.server`. The `server = server` binding is documentation/convention only.
- **`server = server` is the only valid form** — never `server = oraclePk` or `server = providerPk`.
- `exit` (and `renew` if applicable) MUST be `int` constructor parameters so the playground can parameterize timelocks. Never hardcode `exit = 144` as a literal in `options`.
- "Internal" functions (those that don't unlock the UTXO directly) emit only one variant. Most user-facing functions are non-internal.

## 2. State-bearing UTXOs via constructor recursion

The dominant pattern for mutable state is "self-replacement": the contract verifies its next state is a fresh instance of itself.

```ark
require(
  tx.outputs[0].scriptPubKey == new ThisContract(
    immutableField1, mutableField1_new, ...
  ),
  "invalid next state"
);
require(tx.outputs[0].value >= newCollateral, "underfunded");
```

Distinguish two classes of constructor params:
- **Immutable**: propagate unchanged through every state transition (`seekerPk`, `providerPk`, `oraclePk`, `ticker`).
- **Mutable**: change across spends (`targetUSD`, `lastUpdate`, `totalCollateral`, `fundingRatePerSec`).

Both are committed in the scriptPubKey; the distinction is purely about how the next-state expression is constructed.

Always use `value >= X` (not `==`). Over-funding is harmless — extra sats flow to whoever the residual claimant is on exit — and a strict equality breaks legitimate dust-routing patterns.

## 3. Output layout idioms

Outputs are positional. The compiler verifies `tx.outputs[i].scriptPubKey == ...` and `tx.outputs[i].value >= ...` against a fixed index `i`. **Output indices cannot be conditional via expressions** — if an output may not exist, downstream indices shift.

Two correct ways to handle conditional outputs:

**(a) Nested if-else with full assertions per branch.** Verbose but works:
```ark
if (takeFeeSats > 330) {
  // fee at output[1]; remaining at output[2]
  require(tx.outputs[1].scriptPubKey == new SingleSig(providerPk), "...");
  require(tx.outputs[1].value >= takeFeeSats, "...");
  if (remainingCapacity > 0) {
    require(tx.outputs[2].scriptPubKey == new Foo(...), "...");
  }
} else {
  // no fee output; remaining at output[1]
  if (remainingCapacity > 0) {
    require(tx.outputs[1].scriptPubKey == new Foo(...), "...");
  }
}
```

**(b) Roll dust into the next state-bearing UTXO.** When the residual claimant for that UTXO will receive any surplus anyway, this is cleaner:
```ark
require(tx.outputs[0].value >= totalCollateral + takeFeeSats, "...");
// Provider receives any surplus on exit via the existing settlement math.
```

The 330-sat **Taproot dust threshold** is the canonical floor: emit conditional outputs only when their value exceeds 330. Below that, route into a non-dust output.

## 4. Witness and introspection

Witness parameters are listed in the function signature in the order the spender provides them. Constructor params are state; witness params are arguments.

**Oracle signature pattern.** The off-chain oracle signs `sha256(field1 || field2 || ...)`. The contract reconstructs the same digest on stack and verifies:
```ark
let oracleMsg = sha256(ticker + oraclePrice + oracleTime);
require(checkSigFromStack(oracleSig, oraclePk, oracleMsg), "invalid oracle signature");
```
The `+` operator is type-dispatched: emits `OP_CAT` when at least one operand is bytes-like, with int operands auto-coerced to fixed 8-byte LE so the on-chain hash matches the off-chain one byte-for-byte.

**Freshness windows** — pick the right timebase:
- `tx.time` → Bitcoin `nLockTime` (block height). Consensus-enforced via CLTV on the exit path.
- `tx.offchainTime` → TEE-introspector wallclock in unix seconds. Tighter (10-minute windows are feasible) but trust depends on the TEE.

Always pair the freshness check with a non-negative guard:
```ark
int oracleAge = tx.offchainTime - oracleTime;
require(oracleAge >= 0, "future-dated oracle");
require(oracleAge <= 600, "stale oracle");
```
Same for `elapsed = tx.offchainTime - lastUpdate` — TEE wallclock is NOT monotonic-guaranteed, so a clock-regression guard is mandatory wherever `elapsed` is used.

**Cross-input verification** (for multi-UTXO functions like merge). Use `this.activeInputIndex` to identify the self-input, and pass `otherIdx` as a witness pointing at the sibling:
```ark
require(this.activeInputIndex != otherIdx, "self-merge disallowed");
require(
  tx.inputs[otherIdx].scriptPubKey == new SiblingContract(...),
  "input not matching sibling"
);
```
`this.activeInputIndex` compiles to `OP_PUSHCURRENTINPUTINDEX` and is enforceable on L1.

## 5. Arithmetic and fixed-point

Arithmetic is 8-byte signed integer. Plan for overflow.

Three-factor products (`rate × notional × elapsed`) typically overflow before any divide. Use **interleaved divides** to keep intermediates inside int64:
```ark
// Scale 1e12 split as 1e6 × 1e6 to avoid overflow on realistic inputs
int rateElapsedScaled = fundingRatePerSec * elapsed / 1000000;
int delta             = targetUSD * rateElapsedScaled / 1000000;
```

**Basis points (scale 1e4)** is the canonical fee/rate scale: 100 = 1%, 10000 = 100%. Always bound user-controlled fee inputs:
```ark
require(seekerExitFee >= 0, "negative fee");
require(seekerExitFee <= 10000, "fee > 100%");
```
A `(10000 - fee) × notional / 10000` shape applies the fee proportionally before sat conversion.

Truncation is silent. A product `rate × elapsed = 999_999` divided by `1_000_000` rounds to `0`. If a function advances state (e.g. `lastUpdate = now`) but truncates accrual to zero, it can be **griefed by frequent calls**. Guard with `require(delta > 0)` or equivalent.

</core_patterns>

<grammar_gotchas>

These will burn you if you don't know them. All confirmed against `src/parser/grammar.pest`.

| Gotcha | Workaround |
|---|---|
| No `\|\|` or `&&` operators | Nested `if (cond) { require(...) }` or split into multiple `require`s |
| No ternary expression | if-else with separate require chains; or compute value as witness and `require(value == expected)` |
| Comparison RHS can't be arithmetic — `require(value >= a + b)` parse-fails | Bind to a `let`/`int` first: `int min = a + b; require(value >= min, ...)` |
| Variables can't be reassigned | Design state as a single `let` declaration; use new names (`newTargetUSD` not `targetUSD = ...`) |
| `array_access` index must be number_literal or identifier | If you need a computed index, bind it as an `int` first |
| PEG alternative order matters | If a new construct doesn't parse, check the grammar's alternative ordering — `tx_property_access` must precede `identifier`, etc. |
| `this.activeInputIndex` parses but emits opcode | Now compiles to `OP_PUSHCURRENTINPUTINDEX` (post-PR #32); older revisions emit a placeholder |
| String literals in `require` are error messages, not expressions | Keep them short, lowercase, descriptive: "stale oracle", "underpaid", "invalid sig" |

</grammar_gotchas>

<style_conventions>

- **Always "Arkade"** — never "ASP" or "ARK" in code, comments, or error messages.
- 330-sat dust threshold is the universal Taproot floor — use `>= 330` for viability, `> 330` for emit decisions.
- Error messages: lowercase, short, action-describing. "underpaid", "stale oracle", "invalid seeker sig".
- Variable names: snake_case for locals, camelCase for constructor params (matches existing examples).
- Group related `require`s at the top of a function (precondition validation), then derive intermediate values, then assert outputs.

</style_conventions>

<reference_examples>

When in doubt, mine these for the pattern you need:

| Pattern | Reference |
|---|---|
| Self-transfer (key swap) | `examples/stability/stability_vault.ark` (`transfer`) |
| Proportional split into two state UTXOs | `examples/stability/stability_vault.ark` (`split`) |
| Oracle-priced settlement with clamping branches | `examples/stability/stability_vault.ark` (`seekerExit`) |
| Mutable state update under provider sig | `examples/stability/stability_vault.ark` (`settleAndUpdateFunding`) |
| Capital ops (add/remove) | `examples/stability/stability_vault.ark` (`addCapital`, `removeCapital`) |
| Sibling-input merge via `this.activeInputIndex` | `examples/stability/stability_vault.ark` (`merge`) |
| Non-interactive offer take with conditional dust-routed fee | `examples/stability/stability_offer.ark` (`take`) |
| Threshold (k-of-n) verification | `examples/threshold_multisig_htlc.ark`, `examples/threshold_oracle.ark` |
| Asset-group introspection | `examples/arkade_kitties.ark`, `examples/token_vault.ark` |
| Hash-locked contracts | `examples/htlc.ark` |
| Non-interactive atomic swaps | `examples/non_interactive_swap.ark` |

</reference_examples>

<workflow>

When writing a new contract:

1. **Sketch state first.** What's in the constructor (committed state) vs witness (per-spend inputs)? Mark each as immutable/mutable.
2. **List the functions** and which actor (signer) authorizes each. Note which require oracle witnesses.
3. **For each function, write the output layout** before the body. Diagram which outputs exist conditionally.
4. **Start from a reference example** (table above). Copy the closest pattern and adapt; don't write from scratch.
5. **Compile early and often.** `cargo run -- examples/foo.ark -o /tmp/foo.json` surfaces parse errors fast.
6. **Read the `output-invariant` warnings** in compile output. They identify placeholders that aren't bound to witness or constructor params — sometimes that's intentional (`<tx.offchainTime>`, `<SERVER_KEY>`), sometimes it's a bug (forgot to declare a witness param).
7. **Add a roundtrip test** in `tests/compilation_roundtrip_test.rs` (it auto-validates structural invariants — both variants emitted, non-empty witness schemas, etc).
8. **Add behavioral tests** for any non-trivial logic — what opcodes must be emitted, what placeholders, what dust thresholds.
9. **`cargo fmt && cargo test`** before committing.
10. **Regenerate playground**: `./playground/generate_contracts.sh` if you touched `examples/**/*.ark`.

</workflow>

<antipatterns>

- Putting `pubkey serverPk` (or any operator key alias) in the constructor.
- Hardcoding `exit = 144` as a literal in `options`.
- Computing output indices via expression (they're constants).
- Comparing `value` against an arithmetic expression directly (bind first).
- Skipping `require(elapsed >= 0)` on any `tx.offchainTime - X` subtraction.
- Skipping `require(oracleAge >= 0)` on any `tx.offchainTime - oracleTime` (allows future-dated replay).
- Emitting dust-sized outputs (≤ 330) instead of rolling into a non-dust output.
- Editing `playground/contracts.js` directly (auto-generated).
- Comparing JSON output byte-for-byte in tests without stripping `updatedAt`.

</antipatterns>
