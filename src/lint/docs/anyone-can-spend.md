A covenant function that checks no transaction signature (`checkSig`, `checkMultisig`), constrains no output and checks no other input's script.

Whoever satisfies such a function chooses the whole transaction, so they can send the coins anywhere. A revealed hash preimage or a `checkSigFromStack` message authorizes nothing about the outputs: anyone who sees it can reuse it.

Fix: require a transaction signature from the party the coins belong to, or pin the outputs.

```solidity
function claim(signature sig) {
  require(checkSig(sig, owner));
}
```

Allow it only for a function that is meant to be spendable by anyone, such as a public puzzle.
