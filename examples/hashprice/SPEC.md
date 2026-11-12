# Bitcoin header and hashprice beacon

Status: draft protocol specification with a first contract implementation.
[README.md](README.md) specifies its packet encoding, witnesses, deployment
requirements and bounded capacity.

## Purpose and scope

Issue authenticated Bitcoin mainnet block data as reusable Arkade coins, derive
a cumulative BTC hashprice series, and calculate period averages using two
observations from that series. USD hashprice is a later extension.

The pipeline is:

```text
trusted checkpoint + linked headers + coinbase inclusion proof
    -> BlockHeaderCoin[n]
    -> HashPriceCoin[n] with cumulative hashprice
    -> period average using two HashPriceCoins
```

Minting `BlockHeaderCoin[n]` requires a linked proof of `C` headers, including
block `n` itself. Normally `C = 6`, meaning `n` plus five descendants. At an
epoch end, the next epoch's difficulty determines `C`, from 6 to 30, under the
rule below. Confirmation checking belongs to BlockHeaderCoin issuance;
HashPriceCoin issuance does not repeat it.

The security assumption is that producing a competing branch satisfying the
required proof before the honest branch is issued is economically infeasible
for an adversary. The protocol accepts the residual risk that a private branch
wins that race. The verifier permits one accepted header state per height.

Minting and cloning are permissionless on both `BlockHeaderBeacon` and
`HashPriceBeacon`. Any caller may supply the required witnesses and fund
the additional BTC outputs and transaction fees. The beacon protocol requires
no administrator signature; authorization comes from the contract checks and
asset rules.

Each issuer has a single control coin, so its mint and clone operations are
serialized. If two transactions spend the same issuer output, only one can
succeed; the other caller must rebuild against the recreated issuer output
and any observation continuation outputs its transaction needs, if the requested
operation is still permitted. A BHC or HPC height already minted cannot be minted
again; unchanged cloning remains available. The two issuers have separate control
coins and advance independently.

## Identity, state, and initialization

Each beacon holds a unique, non-reissuable control asset. Observation coins
carry a separate series asset whose `ControlAsset` references that control
asset. Initialization creates four asset IDs, each with one unit, in the same
transaction `T`:

| Output | Contract/role | Asset ID | ControlAsset |
| --- | --- | --- | --- |
| 0 | BlockHeaderBeacon | `T:0` | Absent (fixed supply) |
| 1 | Initial trusted BlockHeaderCoin | `T:1` | `T:0` |
| 2 | HashPriceBeacon | `T:2` | Absent (fixed supply) |
| 3 | Baseline HashPriceCoin | `T:3` | `T:2` |

The identity is `<initialization txid>:<asset group index>`; the group index is
distinct from an output index. Consumers pin the observation asset IDs and
expected scripts after verifying initialization, including singleton control
supplies, their exclusive allocation to the corresponding beacons, and both
control relationships. Control assets cannot be reissued and every beacon
spend preserves its control token under the same script.

BlockHeaderCoin and HashPriceCoin use one contract, `BeaconCoin`, instantiated
with their respective state tag and length. Their `continue` paths preserve
script, value, asset allocation, and state. Arkd requires the dedicated control
asset to be spent for every observation supply increase, forcing the matching
beacon's mint or clone path to validate the new outputs.

The trusted checkpoint is at height `H >= 2016`, the start of a difficulty window
(`H % 2016 == 0`). No preceding timestamp history is required.
The checkpoint is a trust anchor, exempt from the confirmation proof rule.
Its difficulty must provide the intended cost of producing competing headers;
six headers at an early, low-difficulty checkpoint do not provide the same cost
as six headers at a recent checkpoint.

The BlockHeaderBeacon's state is:

| Field | Meaning | Initial value |
| --- | --- | --- |
| `lastMintedHeight` | Height of the most recently issued BlockHeaderCoin | `H` |
| `lastMintedHash` | SHA256d of that coin's serialized header | Hash of the trusted header at `H` |
| `nextNBits` | Verified required `nBits` for height `lastMintedHeight + 1` | Trusted header `[H].nBits` |
| `epochStartTimestamp` | Timestamp of the first block in the epoch containing `lastMintedHeight` | Trusted header `[H].timestamp` |

Every mint advances the height by exactly one and updates the hash to the newly
issued header. It stores the verified `nBits` of the immediately following
header as `nextNBits`, and updates `epochStartTimestamp` only when the minted
height starts an epoch. The counter and epoch timestamp track issued
observations, not confirmation-proof tips. Cloning preserves all four fields.
Historical coins remain readable and cloneable; header minting uses the issuer
state instead of spending those coins.

Initialization authenticates all four values against the trusted checkpoint.
Since `H` starts an epoch, `H+1` has the same required `nBits` as `H`. Thereafter,
the issuer's state transitions authenticate the cached difficulty and epoch
timestamp; caller-supplied metadata cannot replace them.

Each BlockHeaderCoin has the following logical state:

| Field | Meaning |
| --- | --- |
| `height` | Bitcoin block height |
| `header` | Complete 80-byte Bitcoin header |
| `rewardSats` | Sum of all outputs of the coinbase transaction authenticated against the header's Merkle root |

Coinbase data for the initial coin must also be authenticated against its trusted
header. Raw transaction bytes and Merkle branches are issuance witnesses. The
txid is computed during issuance to verify inclusion; only the extracted
`rewardSats` is retained as coinbase-derived state.

State packets are transaction-level data. Every read must select the record
bound to the spent coin's **prevout output index**, not its current input index.
The first implementation's packet encoding and witness limits are in
[README.md](README.md#state-packets).

## BlockHeaderCoin issuance

To mint height `n`, use the following layout:

| Input | Output |
| --- | --- |
| 0: BlockHeaderBeacon, `mint` path | 0: BlockHeaderBeacon with identical script, one control unit, and updated four-field state |
| | 1: New BlockHeaderCoin[n], one observation unit |

The control asset has one input unit and one output unit, preserved at output 0.
The observation asset has no input units and exactly one output unit, allocated
to output 1. Additional funding and change carry neither asset. The beacon
accounts for every observation unit and rejects unchecked allocations. Every
header output uses the expected complete script. Neither the parent BHC nor a
window-start BHC is spent; existing observation coins remain untouched.

The witness supplies headers `n…n+C-1` and the coinbase inclusion proof for `n`.
Starting from the spent issuer's authenticated state, the verifier:

1. Requires `n == lastMintedHeight + 1`,
   `header[n].prevHash == lastMintedHash`, and
   `header[n].nBits == nextNBits`.
2. Checks every header's proof of work and applicable mainnet version rules.
   Each subsequent header must link to the preceding supplied header and have
   the required `nBits`, including any retarget inside the lookahead.
3. Determines `C` using the rule below and requires exactly that many linked
   headers. Carries height and difficulty-window context through the full proof.
4. Authenticates the coinbase at transaction index zero against header `n`.
5. Constructs the new coin's state from header `n` and its coinbase data, and
   enforces the following returned issuer state. All validation, state updates,
   and issuance occur in one transaction:

```text
lastMintedHeight' = n
lastMintedHash' = SHA256d(header[n])
nextNBits' = header[n+1].nBits
epochStartTimestamp' = header[n].timestamp  if n % 2016 == 0
                     = epochStartTimestamp otherwise
```

`header[n+1]` is present in every proof and must be fully validated before its
`nBits` can be retained. Do not take `nextNBits` from the proof tip or advance
the persistent epoch timestamp merely because the lookahead enters a new epoch.

Only height `n` is issued. Its state describes `n`, not the end of the lookahead
proof. The issuer caches the next required `nBits`, but no lookahead header hash
or suffix commitment. Each mint still verifies its entire supplied confirmation
proof. If `n` starts an epoch, its required retarget result was authenticated by
the preceding mint and is enforced through `nextNBits`; it need not be
recalculated.
Retargets later in the supplied proof must still be calculated and checked.

Under the proof-of-work security assumption, the beacon relies on Bitcoin
network validation for median-time-past and the future-time bound. The draft
keeps no rolling timestamp history and applies no `OP_CHECKTIME` bound.
Difficulty retargeting uses the retained epoch-start timestamp and the epoch-end
header in the witness. The retarget-boundary analysis below describes the work
margin and remaining limits.

### Confirmation count

For an ordinary height, `(n+1) % 2016 != 0`, require `C = 6`.
For an epoch-end height, `(n+1) % 2016 == 0`, use:

```text
reductionFactor = oldDifficulty / newDifficulty
C = max(6, ceil(8 * reductionFactor - 2))
```

Here `oldDifficulty` applies to header `n` and `newDifficulty` to header `n+1`.
Both come from validated targets; a witness-supplied difficulty or count is not
trusted. First validate the retarget, including compact encoding, then calculate
the count from the targets decoded from the headers' actual `nBits` fields.

Since difficulty is inversely proportional to target, an exact integer form is:

```text
oldTarget = DecodeCompact(header[n].nBits)
newTarget = DecodeCompact(header[n+1].nBits)
delta = max(newTarget - oldTarget, 0)
C = 6 + floor((8 * delta + oldTarget - 1) / oldTarget)
```

Use arbitrary-precision arithmetic without intermediate rounding of difficulty
or the ratio. This integer form implements the ceiling exactly. It uses the
decoded new target, not the unencoded retarget intermediate or a rounded work
ratio. Bitcoin's retarget clamp bounds the count to 6 through 30.

| Difficulty reduction factor | Required headers, including `n` |
| --- | --- |
| 1 or less (unchanged or increased difficulty) | 6 |
| 1.5 | 10 |
| 2 | 14 |
| 3 | 22 |
| 4 | 30 |

Granularity is one header. Any difficulty reduction requires at least seven:
`1 < reductionFactor <= 1.125` requires seven, and
`1.125 < reductionFactor <= 1.25` requires eight. Round upward at every
threshold. At the maximum reduction, minting `BHC[n]` requires `n...n+29`.

Only issuance of the epoch-end coin uses this adaptive count. Earlier heights
whose six-header lookahead crosses the boundary still require six headers and
must validate the retarget. After the epoch-end coin is issued, height `n+1`
again requires six headers. No later height can bypass the epoch-end mint
because the issuer counter advances one height at a time.

### Difficulty boundaries

A proof of at most 30 consecutive headers crosses at most one boundary.
The first header's required `nBits` always comes from issuer state, including
when that header starts an epoch. The remaining headers are validated in order.

Initialize the proof's local epoch-start timestamp from issuer state, except
when `n % 2016 == 0`, when it is `header[n].timestamp`. If a later proof header
at height `r > n` starts an epoch, use that local timestamp and the already
verified predecessor header `[r-1]` to calculate the retarget:

```text
elapsed   = clamp(header[r-1].timestamp - localEpochStartTimestamp, 302400, 4838400)
oldTarget = DecodeCompact(header[r-1].nBits)
newTarget = min(mainnetPowLimit, floor(oldTarget * elapsed / 1209600))
nBits[r]  = GetCompact(newTarget)
```

After validating header `r`, update the proof's local epoch-start timestamp to
`header[r].timestamp`. This local context is separate from the returned issuer's
`epochStartTimestamp`, which advances only when the minted height starts an
epoch.

For example, when minting an epoch-end block `r-1`, use the retained old epoch's
start timestamp to validate the retarget at `r`, apply the adaptive confirmation
count, and return `nextNBits = header[r].nBits`. Retain the old epoch timestamp.
When subsequently minting `r`, check its previous hash and cached `nextNBits`,
validate its six-header proof, and set the returned `epochStartTimestamp` to
`header[r].timestamp`. Neither operation requires historical BHC inputs.

Between boundaries after the first proof header, `nBits` equals the preceding
header's value. Target decoding and compact encoding must match Bitcoin Core,
including sign, overflow, and
truncation behavior. See [Core's difficulty rules](https://github.com/bitcoin/bitcoin/blob/master/src/pow.cpp)
and [compact conversion](https://github.com/bitcoin/bitcoin/blob/master/src/arith_uint256.cpp).

### Coinbase authentication and reward definition

The witness supplies the complete non-witness transaction serialization and a
Merkle inclusion proof at transaction index zero. Under the proof-of-work
security assumption, Bitcoin's full nodes enforce block and transaction consensus
rules; the beacon authenticates the committed data and extracts the reward.

The supplied transaction is stripped: version, input count and input, output
count and outputs, and locktime. SegWit marker, flag, and input witness data are
omitted, as specified by [BIP141's txid definition](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#transaction-id).
The Arkade issuance witness carries these stripped bytes and the inclusion proof;
it is distinct from the omitted Bitcoin transaction witness.

The verifier must:

1. Compute the txid using SHA256d of the supplied non-witness serialization,
   excluding any SegWit marker, flag, and witness data.
2. Verify that txid at **transaction index zero** against header `n`'s Merkle root,
   using Bitcoin's ordered transaction Merkle tree. See
   [Core's Merkle construction](https://github.com/bitcoin/bitcoin/blob/master/src/consensus/merkle.cpp).
3. Parse those same authenticated bytes and sum **all** output values into
   `rewardSats`. Consume the complete serialization, reject malformed lengths
   and truncated fields, and prevent integer truncation or overflow. Witness
   offsets or separately supplied amounts cannot substitute for parsing.

Retain one structural check: exactly one input whose previous outpoint is:

```text
previous transaction hash = 32 zero bytes
previous output index     = 0xffffffff
```

This is [Core's coinbase predicate](https://github.com/bitcoin/bitcoin/blob/master/src/primitives/transaction.h).
Here it also protects the proof: Bitcoin hashes both transactions and pairs of
Merkle children with SHA256d, without distinguishing their types. A 64-byte
internal-node preimage could otherwise be presented as a transaction with a
shorter proof. Requiring coinbase structure makes this substitution
computationally infeasible. See the [Merkle ambiguity analysis in BIP53](https://github.com/bitcoin/bips/blob/master/bip-0053.mediawiki#block-malleability).
More confirmations do not repair an ambiguous proof against a valid block root.

The beacon does not repeat BIP34 height checks, the consensus `scriptSig` length
limit, or subsidy/fee and monetary-range validation. Those belong to full-node
validation; the parser still enforces its own arithmetic and memory bounds.
Parsing, proof depth, and transaction size must have explicit supported bounds.

**Index definition:** use the actual claimed coinbase reward `rewardSats`, the
sum of all coinbase output values. Any unclaimed subsidy or fees are excluded.
For example, if a miner could claim 3.2 BTC but the coinbase outputs total
3.1 BTC, the index uses 310,000,000 satoshis. Bitcoin rejects overclaiming but
permits underclaiming; coinbase data alone cannot recover unclaimed fees.
See [Core's reward check](https://github.com/bitcoin/bitcoin/blob/master/src/validation.cpp).

### Coinbase witness capacity

Coinbase size means the byte length of the non-witness transaction serialization
supplied to the verifier. Its output count and script lengths vary. The first
implementation accepts at most 4,096 stripped bytes and 16 outputs, with up to
20 Merkle siblings. These are implementation limits rather than Bitcoin rules.

The current sibling emulator and compiler impose these relevant constraints:

| Resource | Current constraint |
| --- | --- |
| Compiled Arkade script | 10,000 bytes |
| Combined data and alt stacks | 1,000 items and 131,072 bytes, checked after each opcode |
| Script data pushes, `OP_CAT` results, and encoded `BigNum` values | 520 bytes per element |
| `OP_INSPECTPACKET` / `OP_INSPECTINPUTPACKET` result | 520 bytes for the complete selected packet content |
| Serialized emulator witness | 1,000,000 bytes per input entry |
| Emulator packet's combined scripts and serialized witnesses | 1,010,000 bytes across all entries |
| Compiler loops | Statically bounded and unrolled; more parser iterations increase script size |

Sources: [engine limits](../../../emulator/pkg/arkade/engine.go),
[emulator packet limits](../../../emulator/pkg/arkade/emulator_packet.go),
[byte and packet opcodes](../../../emulator/pkg/arkade/opcode.go),
[BigNum encoding](../../../emulator/pkg/arkade/bignum.go), and
[loop emission](../../src/compiler/mod.rs). These are implementation constraints
to recheck against the deployment versions, not new Bitcoin consensus rules.
The 520-byte checks above are not a blanket limit on initial Arkade witness
items: the current execution path loads them through `SetStack`. The witness
decoder and the operations applied to each item also constrain the usable format.

The first implementation supplies the complete stripped transaction as one
initial witness item, parses it directly and applies SHA256 twice. It does not
concatenate the complete transaction. The compiler also exposes
`sha256Initialize`, `sha256Update`, and `sha256Finalize` for a future chunked
format. Such a format must initialize the context inside the verifier, hash
every ordered chunk and parse values from those same chunks. An unauthenticated
witness-supplied midstate cannot replace processing earlier bytes.

Streaming hashing avoids concatenating the whole transaction into one element.
It does not make the witness arrive incrementally: `ArkadeScript.Execute` loads
the witness before running the script. The supported size must leave room for
up to 30 headers, Merkle proof, hash context, and parser temporaries within the
live stack limits, and the complete verifier must fit the script limit.
Likewise, state-packet encoding must accommodate continuation and clone records
within the packet introspection limit.

Bitcoin's [transaction size check](https://github.com/bitcoin/bitcoin/blob/master/src/consensus/tx_check.cpp)
and [consensus constants](https://github.com/bitcoin/bitcoin/blob/master/src/consensus/consensus.h)
give an upper bound of 1,000,000 non-witness transaction bytes, with block overhead
reducing the available space. Thus full coinbase coverage is not established by
streaming SHA256 support alone. Before claiming an implementation's supported
range, validate its maximum transaction bytes, chunks, outputs, and Merkle depth
against the complete mint path. A valid coinbase outside that range prevents
minting its BlockHeaderCoin and advancing the consecutive hashprice series.
Supporting such a block requires a different verification design; skipping it
or substituting a reward would change the index definition.

## HashPriceCoin issuance

A HashPriceCoin series fixes its source beacon identity, checkpoint, and exact
arithmetic rules. The series must have its own asset ID, distinct from the
BlockHeaderCoin asset ID.

`HashPriceBeacon` holds the unique control asset required to increase the
HashPriceCoin series supply. The control asset has a fixed supply of one and
is distinct from the observation asset. Its `mint` path verifies the transition
and authorizes the new observation; the spent beacon supplies the authenticated
height and accumulator state.

The HashPriceBeacon's mutable state is:

| Field | Meaning | Initial value |
| --- | --- | --- |
| `lastMintedHeight` | Height of the most recently issued HashPriceCoin | `H` |
| `accumulatorNumerator` | Exact cumulative numerator through `lastMintedHeight` | `0` |

The source beacon identity, checkpoint, and arithmetic rules remain fixed series
parameters. Every mint advances the height by exactly one and adds that block's
hashprice numerator to the retained accumulator. Cloning preserves both fields,
including when the source observation is older than the issuer's current height.
Historical HPCs remain available for reading and cloning without being spent
to issue the next observation.

All control and observation assets are created in the shared initialization
transaction described above. Identity checks compare the complete `(txid,
groupIdx)` pair. Each beacon derives its series txid from its control asset;
its `coinGidx` selects the observation group. HashPriceBeacon's `sourceGidx`
selects the BlockHeaderCoin group in that same transaction.

Minting `HashPriceCoin[n]` uses:

| Input | Output |
| --- | --- |
| 0: HashPriceBeacon, `mint` path | 0: Same issuer script and one control unit, with updated height and accumulator |
| 1: BlockHeaderCoin[n], `continue` path | 1: Same BlockHeaderCoin[n], script and state unchanged |
| | 2: New HashPriceCoin[n], one series unit |

The issuer checks the BHC input's source beacon identity, observation script,
and one-unit asset allocation, and requires:

```text
n = lastMintedHeight + 1
BlockHeaderCoin.height == n
```

Sequential BHC issuance supplies one authenticated observation state per height
on one linked history, so no additional block-hash linkage is required at this
layer. The issuer computes the new hashprice and accumulator from the BHC and
its own retained state. It enforces the new observation's script and state and
the returned issuer's state, control unit, and fixed series parameters. The BHC
is recreated unchanged through its `continue` path. No previous HPC is spent.
Creating a new hashprice observation requires the issuer; continuing an existing
observation does not. Each height is issued once, while unchanged clones remain
permitted.

The HashPriceCoin asset has no input units and exactly one output unit at
output 2. The HashPriceBeacon control asset and BlockHeaderCoin asset each have
one input unit and one output unit. Reject unchecked asset-bearing outputs or
any attempt to duplicate or release the beacon control unit. Additional funding
and change carry none of these three assets.

The returned BlockHeaderCoin remains available for other readers and cloning.
Hashprice issuance may lag the header beacon and requires only the next BHC in
its series, without spending BlockHeaderBeacon or a confirmation-tip BHC.

For target `target_n` decoded from header `n`:

```text
T1  = 65535 * 2^208
D_n = T1 / target_n
q_n = rewardSats_n * target_n
A_n = issuer.accumulatorNumerator + q_n
HP_n = q_n / T1
```

The input issuer's accumulator is `A_(n-1)`. The same transaction must set:

```text
issuer.lastMintedHeight' = n
issuer.accumulatorNumerator' = A_n
newHPC.height = n
newHPC.hashpriceNumerator = q_n
newHPC.accumulatorNumerator = A_n
```

The returned issuer and new observation must agree on the height and cumulative
numerator. Neither an old HPC nor witness-supplied accumulator data can replace
the authenticated input issuer state.

`D_n` and `HP_n` denote exact ratios, not integer divisions performed during
issuance. Store the integer numerator `q_n` and accumulate it without division
or rounding. The common denominator `T1` is implicit and constant across
difficulty windows. `HP_n` is the claimed reward in satoshis per unit of
difficulty; a conventional per-hashrate-per-day quotation would require an
additional defined conversion.

Each HashPriceCoin stores `height`, `hashpriceNumerator = q_n`, and
`accumulatorNumerator = A_n`. Thus `A_n / T1` is the exact cumulative hashprice
from `H+1` through `n`. Its identity fixes the series parameters. Initialize the
issuer alongside a distinguished baseline `HashPriceCoin[H]` with `height = H`,
`hashpriceNumerator = 0`, and `accumulatorNumerator = 0`. The baseline's zero
numerator is a placeholder, not an observation for block `H`. Initialization
pins the issuer parameters, its state `(H, 0)`, and the baseline coin's state.
The first observation is at `H+1`, with `A_(H+1) = q_(H+1)`; block `H` does not
contribute to the index. The baseline coin remains a readable endpoint for
averages starting at `H+1`; it is not spent to mint the first observation.

Use the emulator's arbitrary-precision `BigNum` arithmetic for multiplication
and accumulation. No series precision factor or per-block rounding is needed.
Numeric encoding must respect the VM's stack-element size limit and preserve
the integers exactly; truncation or wrapping is invalid.

## Coin preservation and cloning

BlockHeaderCoins and HashPriceCoins are non-burnable and have only a `continue`
path. Every permitted spend preserves each input observation in a distinct
output carrying one unit of the same asset, the identical complete script, and
identical state. Two inputs cannot share a continuation output, even when their
observations are identical.

An ordinary read uses `continue` without the coin's issuer and must preserve
that asset's total supply. Every identity-bearing output must be accounted for
by a distinct input continuation. Every supply increase requires the matching
issuer's control coin: `BlockHeaderBeacon` for BlockHeaderCoins, or
`HashPriceBeacon` for HashPriceCoins. Both issuer contracts have `mint` and
`clone` paths. Arkd enforces the control relationship established at issuance.
Observation coins have no issuer check: the beacon alone holds the controlling
asset and its covenant validates every newly issued observation.

The issuer's `clone` path uses this layout, with `m >= 1` additional copies:

| Input | Output |
| --- | --- |
| 0: Matching issuer, `clone` path | 0: Same issuer coin unchanged |
| 1: Observation to clone, `continue` path | 1: Same observation coin unchanged |
| Optional funding inputs without identity assets | 2 through m+1: Identical clones of output 1 |
| | m+2: Extension, zero BTC/assets |
| | m+3: Arkd anchor |

The issuer checks that its active input is `vin:0` and that `vin:1` has the
expected observation script and one unit of its asset. Outputs 0 and 1 preserve
their respective inputs' complete scripts, native BTC values, assets, and state.
Every clone has the same complete script, native BTC value, one-unit asset
allocation, and state as output 1. State equality is checked per output record.

The required extension `OP_RETURN` output carries the asset and state packets
and no identity assets. It and arkd's final anchor are the exceptions to the
clone-output rule. All other outputs after output 1 must be clones, with no
arbitrary change output.
The observation asset has exactly one input unit and `1 + m` output units. The
separate control asset has one input unit and one output unit. The beacon checks
every new observation allocation and preserves its unique control output.

Cloning copies an already authenticated observation and requires no new header
proof or hashprice calculation. It cannot change state, manufacture another
issuer, or merge existing coins. BlockHeaderBeacon cloning preserves all four
state fields, and HashPriceBeacon cloning preserves its current
height and accumulator, even when cloning an older observation.
Both issuers retain their control units under their original scripts on every
spend. Clones provide additional independently spendable copies for concurrent
readers.

## Reading a period average

For a period starting at height `s > H`, lasting `L > 0` blocks, let
`e = s + L - 1`. Its inclusive average is:

```text
average = (A_e - A_(s-1)) / (L * T1)
```

This is an exact ratio. If a consumer needs an integer result at a positive
integer scale `P`, round once at the final division:

```text
average_scaled = floor(P * (A_e - A_(s-1)) / (L * T1))
```

Multiply before dividing. `P` is a consumer conversion parameter and does not
affect the authenticated series or require a different series identity.

The calculation uses **HashPriceCoin[s-1] and HashPriceCoin[e]** from the
same series. Sequential BHC and HPC issuance, the fixed baseline, and
deterministic issuer accumulator transitions bind them to the same issued
observation history. This consistency does not by itself establish that the
issued history is Bitcoin's greatest-work chain.
For `L = 1`, the numerator difference is exactly `q_s`, giving `HP_s = q_s / T1`.
Using `A_e - A_s` alone omits the first observation; if the endpoint coins are
instead `s` and `e`, the numerator must be `A_e - A_s + q_s`.

A consumer pins the series identity and script, `s`, and `L`, and checks both
endpoint heights. It reads the two endpoint coins through their `continue` paths
and recreates both HashPriceCoins unchanged in distinct outputs. The HashPriceCoin
asset has two input units and two output units; both observations remain available
for subsequent use. Consumer-specific contracts and payout formulas are outside
this specification's scope.

## Security assumption and open decisions

BlockHeaderBeacon selects one linked observation history by accepting the first valid
mint at each next height. The counter prevents reissuing an old height or
replacing an issued header. Clones retain the same authenticated state.
If a private branch wins issuance, the counter and parent-hash check also prevent
later switching to an unrelated genuine branch. This can leave the series on a
private or stale history, or unable to advance.

Confirmation proofs establish depth and work on the supplied branch. They do
not establish that it is Bitcoin's greatest-work valid chain, or prove validity
of all block transactions. The coinbase inclusion proof does not establish
that the claimed reward is permitted by the block's actual fees. Reliance on
full-node validation rests on the economic assumption that an adversary cannot
win issuance with a fabricated qualifying branch.

There is no timed challenge, pending proposal, or separate finalization path.
An accepted mint issues the observation and advances the issuer immediately.
There is no automatic replacement or rollback of issued non-burnable coins.
The race depends on honest relaying, available hashrate, private mining leads,
and transaction acceptance as well as the work required by the proof.

### Retarget work margin

Let `n` be the last block of an epoch. An attacker can try to mine an alternative
header `n` with a later timestamp. It must still satisfy the old target, but its
timestamp affects the retarget through:

```text
elapsed = timestamp[n] - timestamp[n-2015]
```

The start timestamp comes from the authenticated issuer state. Increasing
elapsed can increase the next epoch's target by up to fourfold under Bitcoin's
clamp, subject to the PoW limit and compact encoding. With the claimed reward
held fixed, derived hashprice increases by the same target ratio.

The selected confirmation function compensates for cheaper descendant headers
and adds a work margin. For an epoch-end proof of `C` headers:

```text
work(target) = floor(2^256 / (target + 1))
proofWork = work(oldTarget) + (C - 1) * work(newTarget)
```

The per-header work formula is the quantity calculated by
[Core's work function](https://github.com/bitcoin/bitcoin/blob/master/src/chain.cpp).
At unchanged difficulty, six headers represent approximately `6 * Wold`.
At a fourfold reduction, the required 30 headers represent approximately
`Wold + 29 * Wold/4 = 8.25 * Wold`: 37.5 percent more expected work than that
unchanged-difficulty baseline. Merely restoring six old-difficulty blocks'
worth of work would not provide the selected extra margin.

For constant honest and attacker hashrates, starting from the same parent with
no private lead, the expected proof production time ratio in that example is:

```text
attackerTime / honestTime = 1.375 * Hhonest / Hattacker
```

These are expected work and time comparisons, not guarantees about a mining
race. For other honest retargets, compare the rule's required work on both
branches. A genuine difficulty reduction imposes the same additional depth on
honest issuance. The rule uses the preceding epoch's difficulty as its reference;
it is not a permanent work floor across successive epochs.

Earlier observations whose lookahead crosses the boundary still use six
headers. Their proofs can contain less than six old-difficulty blocks' worth
of work and can fix an earlier branch choice in the sequential issuer. The
adaptive rule protects issuance of the epoch-end observation; it does not
remove this limitation for earlier observations.

Subsequent mints recheck their proofs, but overlapping headers can reuse work
already performed for the longer epoch-end proof. Attack cost must therefore
be evaluated across distinct forged headers, not by adding every mint's proof
cost. The effect on an average also depends on period length and the number
and size of altered observations: before consumer rounding, the average's
change is the sum of per-block changes within the period divided by its length.

### Implementation encoding and remaining extensions

The first implementation fixes packet and witness encoding, numeric
serialization, and supported coinbase and Merkle-proof sizes in
[README.md](README.md). It includes all 30 confirmation-header slots alongside
the bounded coinbase parser; it never lowers the required count to fit a proof.
Increasing transaction or clone capacity requires revisiting the generated
script and execution limits. The HashPriceBeacon constructor supports assets
initialized together in one transaction with different group indices.

For USD hashprice, issuance would additionally read an authenticated BTC/USD
oracle observation. The extension must fix feed identity, units, deterministic
round selection, missing-data behavior, and multiplication/rounding rules.
The suggested ±30-second window must specify comparison with Bitcoin header
time; allowing any quote in that window permits cherry-picking.

## Acceptance examples for implementation

- Permit unrelated callers to mint and clone with valid witnesses and funding,
  without an additional beacon administrator signature. Rebuild a conflicting
  request against the recreated issuer and observation outputs only if it is
  still valid at the current counter.
- Initialize all four BlockHeaderBeacon fields from the trusted epoch-start
  checkpoint: height `H`, its header hash, its `nBits`, and its timestamp. Mint only `H+1`
  next, then update each field exactly as specified. Reject repeated or skipped
  heights, a first header whose previous hash differs from `lastMintedHash`,
  counter rollback, or an issuer hash taken from the proof tip instead of `n`.
- Mint BHCs with BlockHeaderBeacon and non-identity funding inputs only, including
  at epoch boundaries. Preserve one control unit at output 0 and require zero
  input observation units and one new BHC unit at output 1. No parent
  or window-start BHC continuation output is required.
- Require the first header's `nBits` to equal the authenticated `nextNBits`,
  including at an epoch start. Reject returned issuer fields that do not follow
  the specified updates, and reject unauthenticated witness metadata offered
  in place of issuer state.
- Require six headers for ordinary heights and calculate retargets at every
  possible later position in their proof. At an epoch-start first header,
  enforce the already verified cached retarget. Require the adaptive count only
  when `(n+1) % 2016 == 0`; reject missing or extra confirmation headers.
- At epoch end, check counts 6, 10, 14, 22, and 30 for reduction factors
  1, 1.5, 2, 3, and 4. Increased difficulty still requires six. Test exact
  integer count arithmetic at, immediately below, and immediately above each
  threshold; a tiny positive reduction requires seven, factor 1.125 requires
  seven, and a factor just above 1.125 requires eight.
- Use validated, compact-decoded targets for the count. Reject an arbitrary
  witness count, an invalid retarget even if its claimed count is sufficient,
  or any attempt to calculate the ratio with truncated integer difficulties.
- At the maximum reduction, verify `n...n+29`, issue only `BHC[n]`, and advance
  the issuer to `n`. A subsequent mint of `n+1` requires six headers and may
  reuse already mined descendants; it must still validate its complete proof.
- When a lookahead first crosses retarget height `r` while minting `r-5`, keep
  the persistent old epoch timestamp and cache `header[r-4].nBits`, not the
  proof tip's new difficulty. When minting `r-1`, cache the validated new
  `header[r].nBits` but retain the old epoch timestamp. Only minting `r` changes
  the persistent epoch timestamp to `header[r].timestamp`.
- Reject invalid header linkage, proof of work, difficulty, and coinbase
  inclusion. A cached target never substitutes for validating the new proof's
  actual headers or the new observation's coinbase data.
- Verify reward extraction for legacy and witness-stripped SegWit coinbases.
  Reject extra inputs, non-null previous outpoints, nonzero Merkle positions,
  internal nodes presented as coinbases, malformed serialization, and arithmetic
  overflow. Changing an output amount must invalidate the inclusion proof.
- Use the actual coinbase output total when a miner underclaims; do not add
  unclaimed subsidy or fees to `rewardSats` or the derived hashprice.
- Verify complete stripped-transaction hashing and reward parsing. A future
  chunked witness format must also test length and amount fields crossing chunk
  boundaries, omitted/reordered bytes, and unauthenticated hash midstates.
  Measure the complete mint path at its declared byte, output-count, and
  proof-depth bounds (and chunk bounds if introduced), including stack
  usage and compiled script size; reject unsupported witnesses without issuing
  a partial or substitute observation.
- Reject altered continuation state and unchecked identity-bearing outputs.
- Reject reissuance without the matching control asset, with the other beacon's
  control asset, or with a forged input allocation. Reject reissuance of either
  fixed-supply control asset. BeaconCoin continuation itself requires no issuer.
- Reject burns, missing continuation outputs, and attempts to use one output to
  continue multiple input coins. Ordinary reads must preserve asset supply.
- Require the matching issuer at input 0 and source observation at input 1 for
  cloning. Reject changed issuer/source outputs, nonidentical clones, unchecked
  non-clone outputs, and incorrect supply increases. Cloning an old BHC must
  preserve all four current issuer fields, including `nextNBits` and
  `epochStartTimestamp`.
- Require HashPriceBeacon for every new hashprice observation; reject an
  incorrect issuer identity or script, loss or duplication of its control unit,
  and incorrect hashprice or accumulator updates.
- Initialize HashPriceBeacon with `lastMintedHeight = H` and
  `accumulatorNumerator = 0`. Mint `H+1` using the issuer and BHC[H+1], without
  spending the baseline HPC. Thereafter require the BHC height to equal the
  issuer height plus one; reject repeated, skipped, or stale heights.
- Enforce `A_n = inputIssuer.accumulatorNumerator + q_n` and identical height
  and accumulator values in the returned issuer and new HPC. Reject a reset,
  an incorrect update, or substitution of an accumulator supplied by a witness
  or an old observation. Cloning an old HPC preserves the issuer's current
  height and accumulator.
- For HPC minting, preserve the control unit at input/output 0 and require zero
  input series units and one new HPC unit at output 2. Require the single BHC
  unit to continue unchanged from input 1 to output 1. No previous HPC input is required.
- Preserve state correctly when a coin changes input or output position.
- Verify a one-block and multi-block average, including the baseline endpoint.
- Preserve fractional contributions in the exact numerator accumulator across
  difficulty changes. Verify multiplication and accumulation beyond 64 bits,
  with any consumer scaling and rounding applied only at the final division.
- Initialize the zero baseline at `H` and verify that the first observation at
  `H+1` starts the accumulator without including block `H`'s reward.
- Return both endpoint coins unchanged when reading an average and preserve the
  BlockHeaderCoin during HashPriceCoin issuance.
- Reject mismatched series or incorrect endpoint heights when reading an average.
