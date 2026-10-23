A function that checks the `scriptPubKey` of `tx.outputs[N]`, including a recreated `new Self(...)`, but not its value or assets.

The right script then receives a dust amount, and the rest of the input's value goes elsewhere.

Fix: check the value, or the assets the output must carry.

```solidity
require(tx.outputs[0].scriptPubKey == new Vault(owner));
require(tx.outputs[0].value >= tx.input.current.value);
```
