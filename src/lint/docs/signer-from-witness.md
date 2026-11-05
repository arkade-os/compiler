A `checkSig`, `checkSigFromStack` or `checkMultisig` key, or a multisig threshold, that is a witness parameter used nowhere else.

The spender then chooses who must sign, or how many, so the check authorizes nothing.

The lint follows the witness only within the function it belongs to: a witness passed to a helper that checks it is not reported.

Fix: take the key or threshold from a constructor parameter, or bind the witness key to one, for example with `hash160(key) == keyHash`.

```solidity
contract Vault(pubkey owner) {
  function spend(signature sig) {
    require(checkSig(sig, owner));
  }
}
```

Reported on the signature check that takes the key or threshold, so an attribute on the statement holding it, its function or the contract applies to it.
