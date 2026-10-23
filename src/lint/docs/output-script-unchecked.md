A function without a transaction signature that checks the value of `tx.outputs[N]` but not its `scriptPubKey`.

The value is then paid to whatever script the spender chooses. With a transaction signature the signer chooses the outputs, so signed functions are not reported.

Fix: pin the script as well as the value.

```solidity
require(tx.outputs[this.activeInputIndex].scriptPubKey == new SingleSig(receiver));
require(tx.outputs[this.activeInputIndex].value >= tx.input.current.value);
```
