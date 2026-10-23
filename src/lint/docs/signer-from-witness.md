A `checkSig`, `checkSigFromStack` or `checkMultisig` key, or a multisig threshold, that is a witness parameter used nowhere else.

The spender then chooses who must sign, or how many, so the check authorizes nothing.

Fix: take the key or threshold from a constructor parameter, or bind the witness key to one, for example with `hash160(key) == keyHash`.

```solidity
contract Vault(pubkey owner) {
  function spend(signature sig) {
    require(checkSig(sig, owner));
  }
}
```
