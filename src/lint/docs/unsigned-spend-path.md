A covenant function with a spending path that checks no transaction signature (`checkSig`, `checkMultisig`).

A check holds on every path when it sits outside any `if`, or in both arms of one. An arm that never passes, such as one with `require(1 == 2)`, leaves only the other arm. An empty arm, such as an absent `else`, is taken to be covered by sibling `if`s, so a signature checked only in an `if` without `else` counts for the path.

Each tapscript leaf whose key is tweaked to the function, as a leaf named after it is, is a way to spend it, and so is the synthesized leaf the function gets when no leaf signs for it with the emulator key. A leaf that also needs the signature of an untweaked constructor key signs every path through the function. A signature from `server` or `emulator` does not, since they co-sign every offchain spend, so the function is reported when any leaf that spends it needs no other signature.

Such a path is not necessarily wrong: a hash lock, a stateful covenant or a public puzzle is authorized by its other conditions. Introspection, a hash preimage and a `checkSigFromStack` message do not count as a signature, so whoever meets those conditions builds the rest of the transaction. Check that they pin everything the spend must not choose.

Fix: require a transaction signature from the party the coins belong to, or allow the lint with a reason that names what authorizes the path instead.

```solidity
@allow(unsigned-spend-path, "the preimage holder claims, and the outputs are pinned")
function claim(bytes preimage) {
  require(sha256(preimage) == hash);
  require(tx.outputs[0].scriptPubKey == new SingleSig(receiver));
  require(tx.outputs[0].value >= tx.input.current.value);
}
```

Reported on the function's name, so an attribute on the function or the contract applies to it.
