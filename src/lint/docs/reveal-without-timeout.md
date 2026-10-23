A hash preimage check when every function and tapscript has one.

Every spending path then needs the preimage, so if it is never revealed the coins stay locked forever.

Fix: add a path that needs no preimage, typically after a timeout.

```solidity
function refund(signature sig) {
  require(checkTime(refundTime));
  require(checkSig(sig, sender));
}
```
