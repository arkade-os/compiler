# Bitcoin header and hashprice beacons

Bitcoin mainnet BlockHeaderCoins (BHCs) and HashPriceCoins (HPCs), issued sequentially:

```text
6 headers --> BlockHeaderBeacon --> BHC (header + chain context)
                                    |
     SP1 coinbase sum + index-0 branch --> HashPriceBeacon --> HPC
                                                                         |
                                                   reward/difficulty + accumulator
```

[BlockHeaderBeacon](block_header_beacon.ark) and [HashPriceBeacon](hashprice_beacon.ark)
provide `mint`, `challenge`, `burn`. BHCs and HPCs are separate instances of
[BeaconCoin](beacon_coin.ark), with `continue` and `burn`.

## Initialization

One transaction `T`; trusted epoch-start checkpoint `H > 388381`, `H % 2016 == 0`:

```text
vout  asset  contract           initial state / issuance authority
0     T:0    BlockHeaderBeacon  H, checkpoint hash/nBits/time, count=0, work floor=0
1     T:1    BeaconCoin (BHC)   H, header, nBits/time, work(H..H+5); control=T:0
2     T:2    HashPriceBeacon    H, A=0, count=0
3     T:3    BeaconCoin (HPC)   H, q=0, A=0, checkpoint hash, mintedAt; control=T:2
4     -      Extension         issuance and state packets
```

Exactly one initial unit of each asset; controls are non-reissuable. Each series
can reissue only while spending its control. The index starts at `H+1`.

| Contract | Parameters |
| --- | --- |
| BlockHeaderBeacon | `coinGidx=1`, BHC script |
| HashPriceBeacon | `coinGidx=3`, `sourceGidx=1`, BHC script, HPC script |
| BeaconCoin (BHC) | `controlGidx=0` |
| BeaconCoin (HPC) | `controlGidx=2` |

Consumers audit the checkpoint, initial states, supplies, control
relationships and complete script trees. Scripts are 32-byte Taproot programs;
include every spend path and the collaborative leaves, with no covenant-bypassing
exit or usable key path. Identities match both `T` and group index. Reissuance
packets omit `ControlAsset`; arkd validates the registered relationship.

## State

Fields are in byte order; widths and totals are bytes. `q` is the hashprice
numerator, `A` its cumulative sum, `count` the recovery count, `floor` the minimum
replacement proof work.

```text
BlockHeaderBeacon [89]
  height:8 | count:8 | lastHash:32 | nextNBits:4 | epochStart:4 | floor:33
BHC [129]
  height:8 | header:80 | nextNBits:4 | epochStart:4 | proofWork:33
HashPriceBeacon [80]
  height:8 | count:8 | A:64
HPC [176]
  height:8 | q:64 | A:64 | blockHash:32 | mintedAt:8

output state = tx.packet(32 + vout)                  # vout: 0..223
input state  = input.packet(32 + input.outpoint.vout)
```

All state packets start with height at offset 0 and have no tag prefix; the
authenticated asset identity determines the layout. Both beacons have recovery
count at offset 8.

Reserve packet types 32–255. Integers use nonnegative, fixed-width little-endian
ScriptNum; heights/counts/times fit 63 bits and numerators fit 511. The SP1 reward is an unsigned 64-bit value bounded by MAX_MONEY. Headers
are raw; `nextNBits` and `epochStart` are raw unsigned little-endian bytes; hashes
are raw SHA256d digests. `nextNBits` applies to `height+1`; `epochStart` is the
start timestamp of the epoch containing `height`. `mintedAt` is Unix seconds.

## Lifecycle

```text
Normal (count=0) -- mint(h+1) -------> Normal
Normal          -- challenge(g) ----> Recovery (height=g, count=h-g)
Recovery        -- burn(k<count) --> Recovery
Recovery        -- burn(k=count) --> Normal

BHC recovery --> replacement BHC --> HPC hash mismatch --> HPC recovery
```

Mint and challenge require Normal mode. Every beacon spend preserves its script,
Bitcoin value and single control unit from input 0 to output 0. Observations must
match their series identity, script and state schema; each carries one asset unit.
Minting adds exactly one unit, with zero input units of the minted series.
Transaction arrays below give input/output positions; evidence coins use `continue`.

```text
continue(coin at input i):
  output[i] = same script, Bitcoin value, asset identity and complete state

burn(beacon at input 0, suffix coins):
  require matching control identity and count > 0
  require each coin.height > beacon.height
  k = series.sumInputs
  require 0 < k <= count and series.sumOutputs == 0
  beacon.count -= k                         # other fields unchanged
```

Burns may be batched in any order; funding inputs carry no series units. The entire
suffix must be available and burned before minting resumes. Challenges preserve
the evidence coins. Unburned coins remain readable during recovery, including
stale BHCs used for HPC minting. Further rewinds can follow completed recovery.

## BlockHeaderBeacon

`verifyHeaders(context, headers)` checks exactly six linked 80-byte headers,
starting from the context's hash and `nextNBits`, with signed 32-bit version >= 4
(the checkpoint is after BIP65 activation):

```text
T1 = 65535 * 256^26                         # mainnet PoW limit
require each header uses the expected nBits and 0 < decoded target <= T1
require uintLE(SHA256d(header)) <= target
at a subsequent epoch boundary inside the window:
  elapsed = clamp(epochEnd.time - context.epochStart, 302400, 4838400)
  nextNBits = compactEncode(min(floor(oldTarget * elapsed / 1209600), T1))
  require headers from that boundary use nextNBits  # exact compact encoding
return sum(floor(2^256 / (target + 1)))      # six headers' work

MINT       inputs [beacon[h]] --> outputs [beacon[n], BHC[n]]
  n = h + 1
  W = verifyHeaders(beacon, headers[n..n+5])
  require W >= beacon.floor
  nextNBits = header[n+1].nBits
  epochStart = header[n].time if n % 2016 == 0 else beacon.epochStart
  BHC[n] = (n, header[n], nextNBits, epochStart, W)
  beacon = (n, SHA256d(header[n]), nextNBits, epochStart, count=0, floor=0)

CHALLENGE  inputs [beacon[h], BHC[g], BHC[g+1]]
           --> outputs [beacon[g], same BHC[g], same BHC[g+1]]
  require h > g and BHC[g+1].header links to BHC[g].header
  W = verifyHeaders(BHC[g], replacementHeaders[g+1..g+6])
  require replacement hash at g+1 != SHA256d(BHC[g+1].header)
  require W > BHC[g+1].proofWork > 0
  beacon = (g, SHA256d(BHC[g].header), BHC[g].nextNBits, BHC[g].epochStart,
            count=h-g, floor=W)
```

Work is frozen at minting; the challenge compares six-header windows. The first
replacement mint accepts any valid proof meeting the floor and clears it.

## HashPriceBeacon

BHCs supply authenticated headers and chain-recovery context. They contain no
reward, transaction or Merkle-proof data and can be consumed by other applications.
HashPriceBeacon authenticates the coinbase and its reward at minting.

```text
MINT       inputs [beacon[h], BHC[n]] --> outputs [beacon[n], same BHC[n], HPC[n]]
  require n == h+1
  require mintedAt >= 0 and abs(mintedAt - emulator.now) <= 3600
  verify SP1 Groth16 proof of coinbaseTxid and rewardSats
  require coinbaseTxid at transaction index 0 in BHC[n].header.merkleRoot
  q = rewardSats * decodeTarget(BHC[n].header.nBits)
  A = beacon.A + q
  HPC[n] = (n, q, A, SHA256d(BHC[n].header), mintedAt)
  beacon = (n, A, count=0)

CHALLENGE  inputs [beacon[h], HPC[n], BHC[n]]
           --> outputs [beacon[n-1], same HPC[n], same BHC[n]]
  require 0 < n <= h and HPC[n].blockHash != SHA256d(BHC[n].header)
  require HPC[n].A >= HPC[n].q >= 0
  beacon = (n-1, HPC[n].A - HPC[n].q, count=h-n+1)
```

Replacement HPCs receive fresh minting timestamps. Histories can remain stale or
mixed until challenged and burned.

## Coinbase proof and witness

`HashPriceBeacon.mint` takes:

```text
mint(mintedAt, coinbaseTxid, reward, merkleDepth, bytes32[20] siblings, Groth16Proof proof)
Groth16Proof = A:G1 (2 integers), B:G2 (4 integers), C:G1 (2 integers)
```

The pinned SP1 guest is
[`coinbase.rs`](sp1/program/src/bin/coinbase.rs), with
SDK 6.10.0 and the published v6.1.0 Groth16 wrapper. It accepts at most 1,048,576
wire bytes, validates canonical Bitcoin serialization, requires exactly one null
prevout input and a 2–100 byte coinbase scriptSig, strips SegWit for SHA256d, and
checks each output and their sum against `MAX_MONEY`. Its only public bytes are:

```text
coinbase txid in internal Bitcoin byte order[32] || reward uint64 little-endian[8]
```

The guest key is
`0077a029932c562085f49d781fe0b39b5e6d98569cac99c5f5eb0031512dc532`.
The approved ELF's SHA256 is
`0627b6dad82b0ff690f398233e88578811b62bb6dd1b01f95dbf627b3a280db4`.
The VM verifier fixes this program key, successful exit, the official recursion
key root and default nonce zero. It uses the published Groth16 key: no new trusted
setup or ceremony is needed for this guest or for different transaction lengths.
It executes three BN254 scalar multiplications, three additions and one pairing
product over four pairs. Proof coordinates use minimally encoded positive
little-endian Script numbers; SDK proof words use 32-byte big-endian encoding.

The Merkle branch starts at the proven txid. At every active level it computes
`SHA256d(current || sibling)`, so the transaction is always at index zero. The
result must equal the authenticated header's Merkle root (BHC offset 44).
`merkleDepth` is 0–20; unused siblings must be zero bytes32. Depth zero covers
one-transaction blocks. Coinbase structure is checked independently by the guest as well as its
leftmost position.

The 20 siblings occupy 640 bytes **across 20 stack items**, rather than one
oversized element. The mint witness has exactly 32 items: timestamp, txid,
reward, depth, 20 siblings and eight proof coordinates. Its largest element is
32 bytes. Its serialized upper bound is **977 bytes** (944 payload bytes plus
33 count/length-prefix bytes), including maximum-width valid timestamp/reward
numbers. No raw coinbase bytes enter the covenant witness. VM ceilings are 520
bytes per element, 1,000 combined stack items, 128 KiB combined stack bytes and
10,000 script bytes. The regression test exercises a full depth-20 branch with
the actual Groth16 proof under the default VM compute limits.

Measured with the checked-in deployment parameters: the optimized mint covenant
is **2,879 bytes**, with compiler-reported peak stack **117 items**. Both the real
13-level branch and a full 20-level branch serialize to **970 witness bytes**;
unused siblings retain their 32-byte zero padding. The unoptimized covenant is
2,495 bytes and passes the same VM cases. Even the conservative byte bound
`117 * 520 = 60,840` remains below the 128 KiB combined-stack ceiling.

The self-contained fixture uses the real coinbase of mainnet block 976289,
its 13-sibling index-zero branch and a real SP1 proof. Header PoW/recovery tests
use real mined headers. Hashprice recovery tests also use synthetic authenticated
BHCs to isolate rollback behavior while retaining the valid coinbase proof.

The guest, transaction parser, CPU prover and pinned Cargo lockfiles live in
[`sp1/`](sp1/README.md). Its README covers Nix tools, building the guest,
checking the pinned program key and generating a Groth16 proof. The
[benchmark runner](../../benchmarks/sp1-sha256d/run.py) uses that same workspace.

The [witness converter](../../benchmarks/sp1-sha256d/arkade/export_witness.py)
converts the SDK envelope to named proof-coordinate inputs. For this contract,
use its `outputSum` value as `reward`, its `expectedTxid` as `coinbaseTxid`, and
add the timestamp, depth and 20 branch siblings. Always pin the program key of
the reviewed guest build. The generic transaction benchmark guest has a different
key and is deliberately rejected by HashPriceBeacon.

## Settlement

Example consumer policy for inclusive interval `s..e`, `H < s <= e`, output scale `P`:

```text
authenticate identities, scripts and heights of HPC[s-1] and HPC[e]
continue both coins in distinct input/output slots
require HPC[e].mintedAt + 24 hours < now

hashprice[n]   = q[n] / T1                          # satoshis / difficulty unit
average        = (A[e] - A[s-1]) / ((e-s+1) * T1)
average_scaled = floor(P * (A[e] - A[s-1]) / ((e-s+1) * T1))
BTC_average    = average / 100000000
```

The timestamp tolerance permits a minimum actual age just over 23 hours.
Watchtowers must obtain replacement BHC evidence, challenge the HPC beacon and
burn the affected endpoint before settlement. Recovery alone leaves it spendable;
completed settlements are irreversible. Replacement issuance restarts its age.

## Limits

| Area | Bound |
| --- | --- |
| Chain evidence | Six-header work; equal-work challenges fail. Global greatest-work chain and full block validity are unproven. |
| Consensus checks | Median-time-past, future-time bound, subsidy/fee ceiling and coinbase BIP34 height checks are omitted. SP1 enforces coinbase shape, scriptSig length and monetary ranges. |
| Reward | Proven coinbase output sum; fees and the full block are not independently validated. |
| Witness | Header mint: six separate 80-byte headers. Hashprice mint: 32 items, serialized ≤977 bytes, including SP1 proof coordinates and a depth 0–20 index-zero branch. |
| Capacity | Private coinbase input ≤1 MiB. BHC state 129 bytes; HPC state 176 bytes. State packets fit 520 bytes; scripts must fit 10,000 bytes. |
| Availability | Honest relaying, competing-work cost and timely watchtower burns are required assumptions; challenges have no expiry. |
| Client work | Initialization, transaction building, settlement/payout contracts, BTC/USD pricing and per-hashrate-per-day conversion. |

## Verification

[Contract interfaces](../../tests/examples/hashprice.rs) ·
[Emulator and asset validation](../../tests/e2e/hashprice_test.go)

From the repository root:

```sh
cargo test --test examples hashprice
./scripts/e2e.sh -run TestHashprice -count=1
```
