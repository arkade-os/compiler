A function without a transaction signature that constrains outputs at fixed indexes, but does not bound `tx.numInputs`, compare `this.activeInputIndex` or read an outpoint.

Two coins locked by the same contract can be spent in one transaction, and each covenant is satisfied by the same output (double satisfaction). The spender pays once and keeps the other coin's value.

Fix: tie each input to its own output, or allow one input.

```solidity
require(tx.outputs[this.activeInputIndex].value >= tx.input.current.value);
// or
require(tx.numInputs == 1);
```

Allow it when a singleton asset or another invariant already makes a second such input impossible, and say which in the reason.
