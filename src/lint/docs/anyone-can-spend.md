A covenant function with a path that checks no transaction signature (`checkSig`, `checkMultisig`), constrains no output and checks no other input's script.

A check holds on every path when it sits outside any `if`, or in both arms of one. An arm that never passes, such as one with `require(1 == 2)`, leaves only the other arm. An empty arm, such as an absent `else`, is taken to be covered by sibling `if`s, so a signature checked only in an `if` without `else` counts as authorizing the spend.

Whoever satisfies such a function chooses the whole transaction, so they can send the coins anywhere. A revealed hash preimage or a `checkSigFromStack` message authorizes nothing about the outputs: anyone who sees it can reuse it.

Fix: require a transaction signature from the party the coins belong to, or pin the outputs.

```solidity
function claim(signature sig) {
  require(checkSig(sig, owner));
}
```

Allow it only for a function that is meant to be spendable by anyone, such as a public puzzle.

Reported on the function's name, so an attribute on the function or the contract applies to it.
