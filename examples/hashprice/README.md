# Hashprice beacon

`hashprice_beacon.ark` publishes a hashprice derived from Bitcoin headers. The issuer fixes one header as the checkpoint (`hash256`, height, and compact `nBits`) and a control asset that singles out the coin. Packet 16 carries the moving state:

```text
hash256(tip header) || num2bin(height, 8) || num2bin(hashprice, 16)
```

The tip hash is the raw `hash256` digest, the same bytes the next header stores at offset 4.

`update` takes the next six headers. Each one must name the previous hash, repeat the checkpoint `nBits`, and hash at or under that compact target. The six heights stay inside one 2016-block difficulty epoch and one halving era. A trailing `0x00` on the digest keeps it a positive integer: Arkade integers use the high bit as a sign. The newest header's timestamp has to be in the past (`checkTime`).

The published integer is a subsidy-only forward quote, in sats per PH/s per day:

```text
span      = time[5] - time[0]                 // five intervals
clamped   = min(max(span, 750), 12000)        // Bitcoin's 4× band around 3000s
subsidy   = 5_000_000_000 >> (height / 210_000)
target    = compact(nBits)
hashprice = subsidy * 86400 * 10^15 * clamped * target
          / ((65535 << 208) * 3000 * 2^32)
```

At a ten-minute pace `clamped / 3000` is 1, so this is `subsidy * 86400 * 10^15 / (difficulty * 2^32)`. A faster window projects a higher difficulty and a lower hashprice. The miner of the six headers picks the pace, and the clamp holds that choice to the same 4× band as a Bitcoin retarget. A fee-inclusive quote needs a merkle proof of the coinbase. nBits stays at the checkpoint value: a retarget needs the epoch's first timestamp, which is outside this window, so a crossing window fails closed. The six headers show work extending this tip. Heavier-chain selection needs a longer header chain.

`passthrough` copies the script, value, control asset, and packet. That is the read path.

`hashprice_option.ark` is the consumer. Input 0 is the beacon and input 1 is the note. It checks that input 0 is this beacon, that the packet is unchanged, and that the height is past the checkpoint (so `update` produced the number). The payoff is a covered call on that integer. `hashprice` and `strike` share the scale above.

```text
hashprice > strike → holder gets collateral * (hashprice - strike) / hashprice
otherwise           → holder gets 0
```

A leg of 330 sats or less is folded into the other output.

Run both covenants on the Arkade VM with:

```bash
./examples/hashprice/test.sh
```

The script compiles the example and runs `TestHashprice` in `tests/e2e`, once with the optimizer and once without. The test mines the six headers at `nBits` `0x1f00ffff` (about 2^16 hashes each). The covenant evaluates the same formula it would for a mainnet epoch.
