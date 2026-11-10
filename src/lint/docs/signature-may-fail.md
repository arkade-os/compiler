`checkSig`, `checkSigFromStack` or `checkMultisig` used as a value that can be false: an `if` condition, a `||` operand, a negation or a comparison.

The VM fails the whole spend on an invalid non-empty signature, so the check is false only for an empty one.

Fix: pass an empty signature on the path where the check may fail, or `require` the check where it must hold.

```solidity
if (checkSig(sig, owner)) { ... } // sig must be empty, not wrong, to take the else arm
```

Reported on the signature check, so an attribute on the statement holding it, its function or the contract applies to it.
