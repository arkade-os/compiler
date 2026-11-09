# Hashprice beacon

`hashprice_beacon.ark` publishes one integer, the current hashprice, as an asset amount. A second asset is a monotonic height so an oracle signature cannot be replayed. The oracle signs:

```text
sha256(outpoint || num2bin(hashprice, 8) || num2bin(height, 8))
```

`update` keeps the beacon script and its bitcoin value, and sets the two amounts to the signed values. `passthrough` forwards the coin unchanged. That is the read path: another input in the same transaction inspects the beacon.

`hashprice_option.ark` is the consumer. Input 0 is the beacon and input 1 is the note. It checks that input 0 is this beacon, reads the hashprice amount, and requires output 0 to carry the same script, value, hashprice, and height. The payoff is a covered call on that integer. `hashprice` and `strike` share one scale, which the contracts leave to the issuer.

```text
hashprice > strike → holder gets collateral * (hashprice - strike) / hashprice
otherwise           → holder gets 0
```

A leg of 330 sats or less is folded into the other output.

Run both covenants on the Arkade VM with:

```bash
./examples/hashprice/test.sh
```

The script compiles the example and runs `TestHashprice` in `tests/e2e`, once with the optimizer and once without.
