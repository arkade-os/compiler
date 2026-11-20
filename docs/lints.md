# Lints

Lints report code that compiles but is likely unsafe or wrong. Each lint has:

- an id, which is the diagnostic's `code`;
- a category: `security`, `correctness`, `performance` or `style`;
- a default level: `allow` (not reported), `warn`, or `deny` (an error).

`arkadec --explain <lint>` prints what a lint reports, why it matters and how to fix it. `arkadec --explain` with no id lists every lint and error code.

## Lint list

| Lint | Category | Default | Reports |
|---|---|---|---|
| `unsigned-spend-path` | security | warn | An Arkade Script function with a spending path that checks no transaction signature (`checkSig`, `checkMultisig`). Such a path can still be sound, as a hash lock or a stateful covenant is, but its other conditions alone authorize the spend; introspection, a hash preimage and a `checkSigFromStack` message do not count as a signature. |
| `output-script-unchecked` | security | warn | An unsigned function that checks the value of `tx.outputs[N]` but not its `scriptPubKey`, so the value can be paid to any script |
| `output-value-unchecked` | security | warn | An unsigned function that checks the `scriptPubKey` of `tx.outputs[N]`, including one kept as `tx.input.current.script`, but not its value or assets |
| `oracle-message-unbound` | security | warn | A `checkSigFromStack` message that is a witness parameter used nowhere else, so one signed message authorizes any spend |
| `signer-from-witness` | security | warn | A `checkSig`, `checkSigFromStack` or `checkMultisig` key, or a multisig threshold, that is a witness parameter used nowhere else, so the spender chooses who must sign |
| `duplicate-multisig-key` | security | warn | A key listed twice in `checkMultisig`, so one signature counts for each |
| `ambiguous-hash-concat` | security | warn | A hash of two or more `bytes` parameters joined with `+`: their lengths vary, so other values can join to the same bytes |
| `offchain-locktime` | correctness | deny | `tx.locktime` in an Arkade Script function: arkd rebuilds offchain spends with nLockTime 0, so use `checkTime(t)` |
| `outputs-shared-across-inputs` | security | warn | An unsigned function whose outputs are constrained at fixed indexes without bounding `tx.numInputs`, comparing `this.activeInputIndex`, or reading an outpoint, so two inputs locked by the contract can be satisfied by the same outputs |
| `divide-before-multiply` | correctness | warn | `(a / b) * c`, which drops the remainder before it scales |
| `self-comparison` | correctness | warn | A comparison, `&&` or `\|\|` with the same operand on both sides |
| `unused-parameter` | correctness | warn | A constructor parameter no function reads |
| `unused-variable` | correctness | deny | A local variable nothing reads; an unread function parameter or tapscript input is an error, since anyone relaying the spend could replace it |
| `timelock-without-unit` | style | warn | `older(n)` or `after(n)` with a raw number |
| `repeated-inspection` | performance | warn | A multi-result inspection read more than once |
| `signature-may-fail` | correctness | warn | A signature check used as a value that can be false |
| `unknown-lint` | correctness | warn | A lint attribute naming a lint that does not exist |
| `unfulfilled-expectation` | correctness | warn | An `@expect` whose lint does not fire where it applies |

Outputs at a computed index are not tracked.

## In source

An attribute sets the level of the lints it names on the contract, function or statement after it and everything inside it, as in Rust. `@allow` and `@expect` need a reason; `@warn` and `@deny` take one optionally:

```solidity
@deny(self-comparison)
contract Vault(pubkey owner) {
  @allow(outputs-shared-across-inputs, "the control asset is a singleton")
  function receive() { ... }

  @expect(unsigned-spend-path, "a public puzzle")
  function solve(bytes32 answer) { ... }
}
```

- The innermost attribute wins.
- An attribute wins over the CLI, except that `--deny warnings` makes every warning an error, `@warn` ones included.
- `@expect` allows its lint and reports `unfulfilled-expectation` when the lint does not fire where it applies, so it goes once the code is fixed.
- A name that is no lint is reported as `unknown-lint`.
- A malformed attribute is an error.
- An imported file's lints, attributes included, are at most warnings: only the file being compiled decides what fails it.

## From the command line

The CLI sets levels with `--allow <lint>`, `--warn <lint>` and `--deny <lint>`. `<lint>` is one of:

- a lint id;
- a category: `security`, `correctness`, `performance` or `style`;
- `all`;
- `warnings`, every finding otherwise left at warn, most useful as `--deny warnings`.

Flags apply in the order given, so a later one wins. A lint named by its id overrides a category or `all` wherever it appears.

A denied lint is an error that stops compilation, in the CLI and in `compile_sources`. In the Rust API, `Analysis::diagnostics_with`, `compile_with` and `check_with` take levels; see [Analyze](api.md#analyze).
