A hash of two or more `bytes` parameters joined with `+`.

Their lengths vary, so `a + b` and `a' + b'` can be the same bytes for different values. A signature or commitment over the hash then also covers the other values.

Fix: give the parts a fixed length, such as `bytes32`, or hash each part separately.

```solidity
require(sha256(sha256(a) + sha256(b)) == commitment);
```
