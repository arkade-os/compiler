A hash preimage check when every spending path needs one.

Each tapscript leaf is a spending path. A leaf that signs with a key tweaked to a covenant, as a leaf named after its covenant does, also needs that covenant to pass, so a preimage checked by either one counts for the path. A covenant that no leaf signs for with the emulator key gets a synthesized leaf of its own, and a leaf tweaked to a covenant that never passes cannot be spent. A covenant needs the preimage when every path through it checks one.

Every spending path then needs the preimage, so if it is never revealed the coins stay locked forever.

Fix: add a path that needs no preimage, typically after a timeout.

```solidity
function refund(signature sig) {
  require(checkTime(refundTime));
  require(checkSig(sig, sender));
}
```

Reported on each hash preimage check, so an attribute on the statement holding it, its function or the contract applies to it. Since every such check is reported, only an attribute on the contract silences them all.
