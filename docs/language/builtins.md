# Built-ins

`arkadec --builtins` prints every builtin function and `tx`/`this` member, with its signature and docs, as JSON. Each doc states when the builtin fails the spend; [When evaluation fails](expressions.md#when-evaluation-fails) summarizes the common cases.

Unless a section says otherwise, the builtins below are available in Arkade Script functions. Tapscript bodies have their own [restricted shape](tapscript.md).

## Signatures

| Builtin | Returns |
|---|---|
| `checkSig(sig, key)` | `bool` |
| `checkSigFromStack(sig, key, message)` | `bool` |
| `checkMultisig(keys, sigs, threshold?)` | `bool`, using `OP_CHECKSIGADD` |
| `checkSigFromStackVerify(sig, key, message)` | `true`, failing the spend unless the signature is valid; directly inside `require` it emits only the check |

All four accept computed operands. The `checkSigFromStack` message must be 32 bytes, and a message of another known width is a compile error.

Keys and signatures must have the formats in [Keys and signatures](types.md#keys-and-signatures).

**Multisig.** `keys` and `sigs` are equal-length fixed arrays of 1 to 999 elements, including array literals, bindings, and helper results.

- A threshold k passes when at least k signatures are valid. Omitting it means N-of-N.
- Thresholds accept `int` expressions and must be between 1 and N, with runtime bounds checks for computed thresholds.

**Checks that may fail.** A non-empty signature that fails verification fails the spend instead of returning `false`. So a check that may fail, such as a quorum count in `if (checkSigFromStack(...))` or either side of `||`, needs an empty signature for every key that does not sign.

The compiler warns where a check's result is used that way (`signature-may-fail`). The warning follows direct expressions and does not track results through boolean bindings or helper returns.

**In tapscripts.** Tapscript signature checks retain their closure syntax. `tweak(base, fn)` is a tapscript-only key expression: `base` is `operator` or a constructor pubkey, and the key is tweaked by `fn`'s Arkade Script. See [Keys](tapscript.md#keys).

## Hashes

| Builtin | Returns |
|---|---|
| `sha256(x)`, `hash256(x)` | `bytes32` |
| `sha1(x)`, `hash160(x)`, `ripemd160(x)` | `bytes20` |

All five accept computed byte operands and work in bindings, helper returns, nested calls, and comparisons. A hash comparison's expected value matches the digest width (`bytes32` or `bytes20`) or is unbounded `bytes`.

> [!WARNING]
> Use `sha1` only for legacy interoperability. Its [collision resistance is broken](https://www.nist.gov/news-events/news/2022/12/nist-retires-sha-1-cryptographic-algorithm), so do not use it for commitments, hashlocks, or other security-critical purposes; prefer `sha256` or `hash256`.

Tapscript hashlocks use `require(hashFn(preimage) == hash)` with `sha256`, `hash256`, `hash160`, or `ripemd160`.

**Streaming SHA-256.**

- `sha256Initialize(data)` and `sha256Update(ctx, chunk)` return an opaque `bytes` context, which can also arrive as a `bytes` input.
- `sha256Finalize(ctx, lastChunk)` returns the `bytes32` digest.

**Runtime-selected.** `digest(data, hashType)` returns `bytes`, and `sighash(hashType)` returns `bytes32`.

## Merkle proofs

`merkleRoot(leafTag, branchTag, proof, leaf)` returns the `bytes32` root that `OP_MERKLEBRANCHROOT` computes with BIP-341 tagged hashes:

- the leaf is `tagged_hash(leafTag, leaf)`;
- each 32-byte sibling in `proof` is combined in sorted order as `tagged_hash(branchTag, min || max)`;
- an empty `leafTag` (`""`) takes a 32-byte `leaf` as already hashed.

Compare the result yourself, e.g. `require(merkleRoot("leaf", "branch", proof, leaf) == root)`.

The VM fails the spend when `proof` is not a multiple of 32 bytes, `branchTag` is empty, or a prehashed `leaf` is not exactly 32 bytes.

## Time

| In | Use |
|---|---|
| Arkade Script functions | `checkTime(timestamp)` |
| Tapscripts | `older(n)` for CSV and `after(n)` for CLTV |

### `checkTime`

`checkTime(timestamp)` returns whether the emulator's wall clock has reached a Unix timestamp in seconds, including equality. Use `require(checkTime(unlockAt))` to enforce it.

- A future timestamp returns false.
- A negative timestamp fails the spend.
- The check is independent of transaction locktime and sequence.

`tx.locktime` reads the transaction nLockTime using `OP_INSPECTLOCKTIME` as a plain `int`. It is not a clock, and it is not available in tapscripts. Reading it in an Arkade Script function is an error by default (the `offchain-locktime` [lint](../lints.md)), because arkd rebuilds offchain spends with nLockTime 0.

### `older` and `after`

`older(n)` emits CSV and `after(n)` emits CLTV. Both are tapscript-only.

Wrap a literal or constant in `blocks(n)` or `seconds(n)` to state its unit:

| Expression | Accepts | Pushes |
|---|---|---|
| `older(blocks(n))` | 1 to 65535 blocks | `n`, so `older(blocks(144))` pushes `144` |
| `older(seconds(n))` | A multiple of 512 seconds, from 512 to 33553920 | The BIP68 time-based sequence, so `older(seconds(1024))` pushes `4194306` |
| `after(blocks(n))` | A block height from 1 to 499999999 | `n` |
| `after(seconds(n))` | A Unix timestamp from 500000000 to 4294967295 | `n` |
| `older(n)` | A raw BIP68 sequence that sets only the 16 value bits and the type flag (bit 22) | `n` |
| `after(n)` | A raw nLockTime from 0 to 4294967295 | `n` |

A parameter, or a literal without a unit, is pushed as the raw BIP68 sequence or nLockTime. The compiler warns on a literal or constant without a unit, and rejects a raw `older(n)` literal or constant that sets any bit besides the 16 value bits and the type flag (bit 22).

arkd rejects block-based timelocks unless the operator allows them, so arkd exit leaves should use `older(operatorExitDelay)`.

## Transaction

| Member | Value |
|---|---|
| `tx.version` | Transaction version |
| `tx.locktime` | nLockTime; see [Time](#time) |
| `tx.numInputs`, `tx.inputs.length` | Input count |
| `tx.numOutputs`, `tx.outputs.length` | Output count |
| `tx.weight` | Transaction weight without witness data: 4 × the stripped size |
| `tx.id` | Transaction id, in internal byte order (the reverse of its hex display) |
| `this.activeInputIndex` | Index of the input being spent |
| `this.expiry` | The executing VTXO's Unix expiry timestamp in seconds, through `OP_PUSHEXPIRY`; fails the spend when expiry is unavailable |

## Inputs and outputs

| Expression | Members |
|---|---|
| `tx.inputs[i]` | `value`, `witnessVersion`, `sequence`, `outpoint`, `arkadeScriptHash`, `arkadeWitnessHash`, `script` |
| `tx.input.current` (the input being spent) | `value`, `witnessVersion`, `sequence`, `outpoint`, `arkadeScriptHash`, `arkadeWitnessHash`, `script` |
| `tx.outputs[o]` | `value`, `witnessVersion`, `script` |

`script` is a `ScriptPubKey {program, version}` holding both values from one inspection.

- Native witness versions are 0–16. Non-witness scripts return their SHA256 hash as `program` and `-1` as `version`.
- `witnessVersion` reads the version alone.
- Bind a script to inspect its fields: `let s = tx.outputs[0].script; require(s.program == p); require(s.version == 1);`.

The compiler warns when a function inspects the same script, indexed asset, or asset lookup more than once, and names the whole read to bind instead.

## Assets

### Asset IDs

Every Asset ID operand is one `AssetId` expression:

- a parameter, a binding or field;
- a literal such as `AssetId { txid: t, gidx: 0 }` or `{ txid: t, gidx: 0 }`;
- `.assets[t].assetId`;
- `controlAssetId`;
- a helper result.

A constant `gidx` outside 0 to 65535 is rejected in any `AssetId` literal.

### On an input or output

| Member | Value |
|---|---|
| `.assets.lookup(id)` | The amount; fails the spend when absent |
| `.assets.has(id)` | Whether the asset is present |
| `.assets.tryLookup(id)` | An `AssetLookup` with `amount` and `found`, from one inspection |
| `.assets.length` | Number of assets |
| `.assets[t].assetId`, `.assets[t].amount` | Fields of the asset at position `t` |
| `.assets[t]` | An `AssetEntry` with `assetId` and `amount`, from one inspection |

### Asset groups

| Expression | Value |
|---|---|
| `tx.assetGroups.lookup(id)` | An `AssetGroup`; fails the spend when absent |
| `tx.assetGroups[k]` | The `AssetGroup` at packet position `k` |
| `tx.assetGroups.has(id)` | Whether the group is in the packet |
| `tx.assetGroups.length` | Number of groups in the packet |

Every `AssetGroup` value, whether bound, a parameter, an array element, or inline such as `tx.assetGroups[k].delta`, has these members:

| Member | Value |
|---|---|
| `numInputs`, `inputs.length` | Number of input records |
| `numOutputs`, `outputs.length` | Number of output records |
| `sumInputs`, `sumOutputs` | Total amount of the group's inputs or outputs |
| `delta` | `sumOutputs` minus `sumInputs`: positive when minting, negative when burning |
| `hasControl` | Whether the group has a control asset |
| `controlIs(id)` | Whether the group's control asset is `id` |
| `controlAssetId` | The control asset; fails the spend when the group has none |
| `metadataHash` | Merkle root of the group's metadata; 32 zero bytes when it has none |
| `assetId` | The group's Asset ID; a fresh issuance's is `{tx.id, the group's index}` |
| `isFresh` | Whether the group issues a new asset |

An `int` has no group members; turn a position into a group with `tx.assetGroups[k]`.

### Group records

A group's `inputs[j]` and `outputs[j]` records have `amount`, `type` and `index`. An index outside the group's records fails the spend.

| Record | `type` | `index` |
|---|---|---|
| Output | 1 | Its vout |
| Local input | 1 | Its vin |
| Intent input | 2 | The output it references in the intent transaction |

An intent input also has `txid`, the intent transaction.

- `txid` fails the spend on a local input, so read it behind a type check when the kind is not fixed, such as `g.inputs[j].type == 1 || g.inputs[j].txid == t`.
- `txid` does not exist on outputs.

A whole record, `g.inputs[j]` or `g.outputs[j]`, is an `AssetGroupInput` or `AssetGroupOutput` with `type`, `index` and `amount` from one inspection. It can be bound, compared with `==`, passed to a helper or returned: `let r = g.inputs[0]; require(r.amount >= 100);`. Records leave out the txid, so read it directly with `g.inputs[j].txid`.

## Bytes

| Builtin | Returns |
|---|---|
| `substr(data, offset, size)` | `size` bytes from `offset` |
| `left(data, count)`, `right(data, count)` | The first or last `count` bytes |
| `cat(a, b)` | `a` followed by `b` |
| `bytes2int(bytes)` | Script-number bytes as an `int`: the top bit of the last byte is the sign, so `bytes2int(0xff)` is `-127` and `bytes2int(0x80)` is `0` |
| `bytes2uint(bytes)` | Unsigned little-endian bytes as an `int`, so `bytes2uint(0xff)` is `255` |
| `int2bytes(value, size)` | Fixed-width bytes |
| `reverseBytes(bytes)` | The bytes reversed |
| `size(bytes)`, `bytes.length` | Byte length |

- Use `bytes2uint` for unsigned fixed-width fields, after `reverseBytes` when they are big-endian.
- In Arkade Script functions, `left` and `right` with a zero count return empty bytes. Negative counts and counts exceeding the data length fail the spend.

Byte builtins (`substr`, `cat`, `bytes2int`, `bytes2uint`, `reverseBytes`, `size`, `digest`, and the `checkSigFromStack` message) take bytes-like operands. Sizes, offsets, indexes, packet types, hash types, and tapscript timelocks take `int`.

## Packets

| Expression | Value |
|---|---|
| `tx.packet(type)`, `tx.inputs[i].packet(type)` | The raw extension packet bytes; fails the spend when the packet is absent |
| `tx.packet.has(type)`, `tx.inputs[i].packet.has(type)` | Whether the packet is present |

Both forms still fail the spend for a type outside `0..255`, an input index out of range, or a packet over 520 bytes.

## Intent messages

- `tx.intent.field("type")` returns the encoded field bytes and fails the spend when it is absent.
- `tx.intent.has("type")` returns presence without keeping the value.

**Paths** use dot-separated lowercase keys or canonical decimal indexes, such as `"cosigners.0"`. Queries, wildcards, leading-zero indexes, and indexes at or above 1048576 are invalid:

- for a quoted literal path, they are rejected at compile time;
- for a path from any other `bytes` expression, such as a witness `path`, `field` and `has` fail the spend inside an intent proof.

**Values.**

- Present false, zero, and empty strings still count as present.
- Integer fields use Script-number encoding: `bytes2int(tx.intent.field("expire_at"))`.
- Require `tx.intent.field("type") == "register"` before relying on register-specific fields.
- Missing context, null, missing fields, and non-integer numbers are misses: `field` fails the spend on a miss and `has` returns false.
- Both use the emulator's result-size and compute limits.

## Continuation

`require(this.tunnel(outputIndex))` preserves the current input's script program and version, bitcoin value, and assets at the selected output.

An explicit policy supplies all three compile-time boolean fields:

```solidity
this.tunnel(outputIndex, {script: true, value: true, assets: false})
```

With asset preservation enabled, an optional fixed list excludes specific `AssetId` values:

```solidity
this.tunnel(outputIndex, {script: true, value: true, assets: true}, [feeAsset])
```

- At least one property must be selected.
- A mismatch fails the spend; success returns true.
- Tunneling is only available in Arkade Script functions.
- It does not establish intent type, timing, packet preservation, or a unique input-to-output mapping.

## Arithmetic and curves

| Builtin | Returns |
|---|---|
| `abs(value)`, `min(a, b)`, `max(a, b)` | `int`, from `int` operands |
| `within(value, lower, upper)` | `bool` for `lower <= value && value < upper`; empty or reversed ranges return false |
| `modExp(base, exp, mod)` | `base` raised to `exp`, modulo `mod`, as an `int` |
| `ecAdd(P, Q, curve)`, `ecMul(P, k, curve)` | An `ECPoint`, from `ECPoint` operands |
| `ecPairing(g1, g2, curve)` | `bool`: whether the product of the pairings of aligned `ECPoint[n]` and `G2Point[n]` arrays is the identity, for curve id 2 and 1–16 pairs |
| `ecMulScalarVerify(k, P, Q)`, `tweakVerify(P, k, Q)` | `true`, failing the spend when the check does not hold, like `checkSigFromStackVerify` |

## Instantiation

`new Contract(args...)` returns a `ScriptPubKey` with witness version `1`. It is usable on either side of a `.script` comparison against `tx.outputs[o]`, `tx.inputs[i]`, or `tx.input.current`.

- Arguments are whole constructor parameters, constants or literals, resolved when the contract is instantiated. A witness value or a computed expression, such as a struct field, is rejected.
- A contract cannot instantiate itself, directly or through other contracts.
- The result can be bound with `let` or compared with a `ScriptPubKey` binding, and its `.program` read.
- Zero-argument constructors are allowed.
- Array and struct arguments flatten to scalar fields.
- Destination parameters use `ScriptPubKey`, for example `ScriptPubKey destination = {program: p, version: 1}; require(tx.outputs[0].script == destination);`.
- Comparing script structs enforces their versions too.

[Imports](modules.md#instantiating-an-imported-contract) and the [tour](../tour.md#recursive-vtxos-with-new) cover how the child contract is resolved.

## Constant operand ranges

These constant operands are checked at compile time, and a value outside the range is a compile error. Other constant operands that the VM rejects, such as an empty `merkleRoot` `branchTag`, compile and fail the spend.

| Operand | Accepted |
|---|---|
| `digest` hash type | 1 to 5 |
| `sighash` type | 0 to 3 and 129 to 131 |
| `ecAdd`/`ecMul` curve id | 0 to 2 |
| `ecPairing` curve id | 2 |
| Packet type | 0 to 255 |
| `int2bytes` size | 0 to 520 |
| `checkTime` timestamp, `modExp` exponent | 0 or more |
| `modExp` modulus | 1 or more |
| Any `modExp` operand | At most 64 Script-number bytes |
| `merkleRoot` proof | A multiple of 32 bytes |

The compiler rejects emitted constant pushes over 520 bytes. Constructor and witness values still need validation when the artifact is instantiated or executed.
