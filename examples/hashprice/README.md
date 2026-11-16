# Bitcoin header and hashprice beacon contracts

First implementation of [SPEC.md](SPEC.md), for Bitcoin mainnet. The three
contracts use unchanged scripts and mutable transaction state packets:

| Contract | Constructor | Spend paths |
| --- | --- | --- |
| `BlockHeaderBeacon` | `coinGidx: int`, `blockCoinScript: bytes32` | `mint`, `clone` |
| `HashPriceBeacon` | `coinGidx: int`, `sourceGidx: int`, `blockCoinScript: bytes32`, `hashPriceCoinScript: bytes32` | `mint`, `clone` |
| `BeaconCoin` | `stateTag: bytes`, `stateLength: int` | `continue` |

BlockHeaderCoin and HashPriceCoin are observation roles implemented by
`BeaconCoin(0x0102, 99)` and `BeaconCoin(0x0104, 138)` respectively. Their
constructor parameters fix the state schema; packet IDs come from output
positions, not constructor parameters.

The script arguments are 32-byte Taproot witness programs. Arkd enforces Taproot
for these VTXOs; the contracts check the programs. Each issuer's Taproot tree
must contain both spend leaves; observation trees contain only `continue`.
The compiler supplies the normal collaborative server/emulator leaves; there is
no additional owner key or unilateral exit. `beacon_state.ark` and `bitcoin.ark`
are imported libraries.

## Integer arithmetic

The emulator's `int` operations promote to arbitrary-precision integers. No
floating-point value or rounded difficulty is used. After validating the
retarget and decoding the actual compact targets:

```text
delta = max(newTarget - oldTarget, 0)
C = 6 + (8 * delta + oldTarget - 1) / oldTarget
```

Division truncates. With positive targets this is exactly
`max(6, ceil(8 * newTarget / oldTarget - 2))`: unchanged difficulty requires
6 headers; a maximum fourfold target increase requires 30. Only an epoch-end
mint uses the adaptive count; other heights require 6.

Hashprice uses a shared, implicit denominator:

```text
T1 = 65535 * 256^26
q[n] = rewardSats[n] * target[n]
A[n] = A[n-1] + q[n]
BTC hashprice[n] = q[n] / T1             # satoshis per difficulty unit
period average = (A[end] - A[start-1]) / ((end-start+1) * T1)
```

Neither per-block hashprice nor the accumulator is rounded. Multiply the
denominator by 100,000,000 to express the result in BTC rather than satoshis.

## Initialization

All four asset IDs originate in the **same transaction** `T`, with different
asset group indices. Each control asset has a fixed supply of one and no
`ControlAsset` of its own. Each observation asset starts with one unit and
references its beacon's control asset:

| Group | Asset ID | Purpose | Initial supply | ControlAsset |
| --- | --- | --- | --- | --- |
| 0 | `T:0` | BlockHeaderBeacon control | 1 | Absent (non-reissuable) |
| 1 | `T:1` | BlockHeaderCoin series | 1 | Group 0 |
| 2 | `T:2` | HashPriceBeacon control | 1 | Absent (non-reissuable) |
| 3 | `T:3` | HashPriceCoin series | 1 | Group 2 |

| Output | Contract | Identity | State |
| --- | --- | --- | --- |
| 0 | BlockHeaderBeacon | `T:0`, amount 1 | Trusted height `H`, its hash, its `nBits`, its timestamp |
| 1 | BeaconCoin (BlockHeaderCoin) | `T:1`, amount 1 | `H`, trusted header, authenticated coinbase reward |
| 2 | HashPriceBeacon | `T:2`, amount 1 | `H`, accumulator 0 |
| 3 | BeaconCoin (HashPriceCoin) | `T:3`, amount 1 | `H`, numerator 0, accumulator 0 |
| 4 | Extension | None | Asset issuance and state packets |

Use `H >= 2016` and `H % 2016 == 0`. For this layout, BlockHeaderBeacon takes
`coinGidx = 1`; HashPriceBeacon takes `coinGidx = 3` and `sourceGidx = 1`.
Each beacon derives its observation ID as `(inputControlAsset.txid, coinGidx)`.
HashPriceBeacon derives the BHC ID using `sourceGidx` and the same txid. This
avoids embedding `T` into scripts that themselves determine `T`.

Reissuance packets omit `ControlAsset`; arkd checks the immutable relationship
from issuance and requires the controlling asset to be spent. Only the beacon
holds that asset, forcing its mint or clone covenant to execute. BeaconCoin
checks preservation and has no issuer or supply-increase check.

Consumers must verify initialization: trusted checkpoint and reward, these
scripts and their complete spend trees, initial state, the control relationships,
exactly one unit of each control asset exclusively under its beacon, and one
initial observation unit per series under its pinned BeaconCoin script.
The contracts maintain this invariant; they cannot retroactively validate their
deployment. Baseline HPC[H] has zero numerator and accumulator; observations
start at `H+1`. Initialization and transaction-building tooling are not included.

## State packets

Reserve packet types **32 through 255** for this format. Output `vout` uses one
packet of type `32 + vout`, limiting stateful outputs to indices 0 through 223.
When spending, select the previous transaction's packet using the input's
**prevout vout**, not its current vin. Do not combine this layout with another
protocol using the same packet types.

Every record starts with a one-byte version `01`, a one-byte kind, and an
8-byte height. The sizes below include those fields:

| Kind | Contract | Fields in serialization order | Bytes |
| --- | --- | --- | --- |
| `01` | BlockHeaderBeacon | `0101`, height:8, lastMintedHash:32, nextNBits:4, epochStartTimestamp:4 | 50 |
| `02` | BlockHeaderCoin | `0102`, height:8, header:80, rewardSats:9 | 99 |
| `03` | HashPriceBeacon | `0103`, height:8, accumulatorNumerator:64 | 74 |
| `04` | HashPriceCoin | `0104`, height:8, hashpriceNumerator:64, accumulatorNumerator:64 | 138 |

Heights, reward and numerators use positive fixed-width ScriptNum
(`num2bin`): little-endian sign-magnitude, zero padded, with the sign bit clear.
Heights are limited to `2^63-1`; reward sums to `2^64-1`. The 64-byte fields
allow positive 511-bit values, more than the sum of height-many reward/target
products under these bounds. Encoding fails rather than truncating.

Headers retain Bitcoin's exact 80-byte serialization. `nextNBits` and timestamp
are four raw little-endian unsigned bytes. Hashes are raw SHA256d digest bytes,
the order used in serialized header links, **not** display-order hex. Each
state record fits the emulator's 520-byte packet introspection limit.

## Mint and continuation layouts

`BlockHeaderBeacon.mint` spends the issuer at input 0 and recreates it at output 0,
then creates BHC[n] at output 1. It takes no parent or window-start BHC input.
Its witnesses, in source/ABI order, are:

1. `headers: bytes[30]`: `n ... n+C-1`, each exactly 80 bytes, followed by empty
   slots through index 29.
2. `coinbase: bytes`: the complete **non-witness** transaction serialization.
3. `merkleDepth: int`: 0 through 20.
4. `siblings: bytes32[20]`: raw digest bytes, from leaf to root; unused slots
   are exactly 32 zero bytes. Position zero is the left child at every level.

The verifier checks the stored parent link and required difficulty, every
header's PoW, applicable mainnet version rules, any crossed retarget, and the
coinbase inclusion proof. Parsing authenticates the single coinbase input/null
outpoint, sums all outputs, and requires the complete stripped serialization.
The new verifier state stores the minted header's hash, the following header's
`nBits`, and the epoch timestamp updated only when minting an epoch start.

`HashPriceBeacon.mint` takes no witnesses. Spend issuer at input 0 and
BHC[n] at input 1 through `continue`; recreate both at outputs 0 and 1 and
create HPC[n] at output 2. It advances exactly one height and updates the
accumulator from the authenticated reward and target. No preceding HPC input
is needed. Each mint preserves one control unit and creates exactly one
observation unit, with no input units of the minted series.

Additional funding inputs may carry no involved control or observation assets.
Mint transactions may have funding change outputs and include the required
extension and anchor outputs. Issuers retain their exact BTC value. New
observations require at least 330 sats and exactly one identity unit.

`continue` takes no witnesses and maps **input index `i` to output index `i`**.
It preserves the full script, BTC value, asset allocation and state. This
injective mapping prevents two identical inputs from sharing one continuation
output. Consumers must arrange their transaction accordingly. There is no burn
path. Supply increases require the issuer at input 0, and that issuer's mint or
clone checks constrain every newly issued unit. Arkd enforces issuance authority;
BeaconCoin only checks its own continuation.

## Cloning

Both issuers expose `clone()` without witnesses:

```text
vin 0: issuer, clone                 -> vout 0: issuer unchanged
vin 1: observation, continue         -> vout 1: observation unchanged
optional funding inputs             -> vout 2 ... m+1: identical observations
                                       vout m+2: extension, zero BTC/assets
                                       vout m+3: arkd anchor
```

The first pass allows **1 through 8 additional clones**. All copies preserve
state, script, BTC value and one identity unit. There is no change output on
this path; callers must select funding accordingly. The issuer height and
accumulator/header state do not change. The control asset has one input and one
output unit; the observation asset has one input and `1 + m` output units.

## Capacity and verification

First-pass limits are 30 headers, a 4,096-byte stripped coinbase with at most
16 outputs, 20 Merkle siblings, and 8 clones per transaction. Larger coinbases
are rejected and stall the consecutive series until the design is extended;
there is no skipped-block or substitute-reward behavior. These are prototype
capacity limits, not Bitcoin consensus limits.

The complete coinbase is supplied as one witness item and hashed directly.
The tested emulator loads initial witnesses through `SetStack`, so the
520-byte script-push/concatenation limit does not prohibit this. No operation
concatenates the whole transaction. Expanding capacity or changing emulator
versions requires rechecking stack, witness and script limits; streaming
hashing alone does not establish support for arbitrary Bitcoin coinbases.

The test suite compiles all three contracts, exercises the actual emulator
and arkd asset validation, and includes public mainnet fixtures at heights
2017, 4031, 689467, 689471 and
689472. Each fixture records its Blockstream source URL. Tests cover ordinary
issuance, lookahead across a boundary, a difficulty decrease requiring 10
headers, the next epoch's first block, malformed witnesses and output state,
big-integer retarget/confirmation arithmetic, accumulator transitions, cloning,
continuation, non-burning, and rejection of issuance without the control asset.
The arithmetic is independently compared against btcd's compact-target
encoding. Both optimized and unoptimized contracts fit
the 10,000-byte script limit.

Compile from the repository root:

```sh
cargo run -- examples/hashprice/block_header_beacon.ark -o /tmp/block-header-beacon.json
cargo run -- examples/hashprice/hashprice_beacon.ark -o /tmp/hashprice-beacon.json
cargo run -- examples/hashprice/beacon_coin.ark -o /tmp/beacon-coin.json
cargo test --test examples hashprice
./scripts/e2e.sh
```

The fixtures test covenant execution and arkd's asset accounting against a known
initialization registry. Transaction funding and deployment authentication remain
separate platform/client checks.
The security model remains the spec's work-race assumption: no most-work fork
selection, rollback, MTP history, future-time check, or full Bitcoin block
validation is added. USD prices and consumer option contracts remain out of
scope.
