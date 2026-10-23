A `checkSigFromStack` message that is a witness parameter used nowhere else.

The signature then proves only that someone signed some message, not that it is about this spend, so one signed message authorizes any spend, forever.

Fix: derive the message from what the spend must match, such as the input's outpoint, the amount and the recipient.

```solidity
let outpoint = tx.input.current.outpoint;
let message = sha256(outpoint.txid + num2bin(outpoint.vout, 4) + num2bin(amount, 8) + recipient);
require(checkSigFromStack(sig, oracle, message));
```
