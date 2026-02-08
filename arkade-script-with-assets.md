# Arkade Script Opcodes

This document outlines the introspection opcodes available in Arkade Script for interacting with Arkade Assets, along with the high-level API structure and example contracts.

For base opcodes (transaction introspection, arithmetic, cryptographic, etc.), see [arkd PR #577](https://github.com/arkade-os/arkd/pull/577).

---

## Arkade Asset Introspection Opcodes

These opcodes provide access to the Arkade Asset V1 packet embedded in the transaction.

All Asset IDs are represented as **two stack items**: `(txid32, gidx_u16)`.

### Packet & Groups

| Opcode | Stack Effect | Description |
|--------|--------------|-------------|
| `OP_INSPECTNUMASSETGROUPS` | → `K` | Number of groups in the Arkade Asset packet |
| `OP_INSPECTASSETGROUPASSETID` `k` | → `txid32 gidx_u16` | Resolved AssetId of group `k`. Fresh groups use `this_txid`. |
| `OP_INSPECTASSETGROUPCTRL` `k` | → `-1` \| `txid32 gidx_u16` | Control AssetId if present, else -1 |
| `OP_FINDASSETGROUPBYASSETID` `txid32 gidx_u16` | → `-1` \| `k` | Find group index, or -1 if absent |

### Per-Group Metadata

| Opcode | Stack Effect | Description |
|--------|--------------|-------------|
| `OP_INSPECTASSETGROUPMETADATAHASH` `k` | → `hash32` | Immutable metadata Merkle root (set at genesis) |

### Per-Group Inputs/Outputs

| Opcode | Stack Effect | Description |
|--------|--------------|-------------|
| `OP_INSPECTASSETGROUPNUM` `k source_u8` | → `count_u16` or `in_u16 out_u16` | Count of inputs/outputs. `source`: 0=inputs, 1=outputs, 2=both |
| `OP_INSPECTASSETGROUP` `k j source_u8` | → `type_u8 data... amount_u64` | j-th input/output of group `k`. `source`: 0=input, 1=output |
| `OP_INSPECTASSETGROUPSUM` `k source_u8` | → `sum_u64` or `in_u64 out_u64` | Sum of amounts. `source`: 0=inputs, 1=outputs, 2=both |

**`OP_INSPECTASSETGROUP` return values by type:**

| Type | `type_u8` | Additional Data |
|------|-----------|-----------------|
| LOCAL input | `0x01` | `input_index_u32 amount_u64` |
| INTENT input | `0x02` | `txid_32 output_index_u32 amount_u64` |
| LOCAL output | `0x01` | `output_index_u32 amount_u64` |
| INTENT output | `0x02` | `output_index_u32 amount_u64` |

### Cross-Output (Multi-Asset per UTXO)

| Opcode | Stack Effect | Description |
|--------|--------------|-------------|
| `OP_INSPECTOUTASSETCOUNT` `o` | → `n` | Number of asset entries assigned to output `o` |
| `OP_INSPECTOUTASSETAT` `o t` | → `txid32 gidx_u16 amount_u64` | t-th asset at output `o` |
| `OP_INSPECTOUTASSETLOOKUP` `o txid32 gidx_u16` | → `amount_u64` \| `-1` | Amount of asset at output `o`, or -1 if not found |

### Cross-Input (Packet-Declared)

| Opcode | Stack Effect | Description |
|--------|--------------|-------------|
| `OP_INSPECTINASSETCOUNT` `i` | → `n` | Number of assets declared for input `i` |
| `OP_INSPECTINASSETAT` `i t` | → `txid32 gidx_u16 amount_u64` | t-th asset declared for input `i` |
| `OP_INSPECTINASSETLOOKUP` `i txid32 gidx_u16` | → `amount_u64` \| `-1` | Declared amount for asset at input `i`, or -1 if not found |

### Intent-Specific

| Opcode | Stack Effect | Description |
|--------|--------------|-------------|
| `OP_INSPECTGROUPINTENTOUTCOUNT` `k` | → `n` | Number of INTENT outputs in group `k` |
| `OP_INSPECTGROUPINTENTOUT` `k j` | → `output_index_u32 amount_u64` | j-th INTENT output in group `k` |
| `OP_INSPECTGROUPINTENTINCOUNT` `k` | → `n` | Number of INTENT inputs in group `k` |
| `OP_INSPECTGROUPINTENTIN` `k j` | → `txid_32 output_index_u32 amount_u64` | j-th INTENT input in group `k` |

---

## High-Level API (Arkade Compile Sugar)

The following API provides syntactic sugar for Arkade Script contracts. Each property/method is documented with its translation to underlying opcodes.

### Asset Groups

```javascript
tx.assetGroups.length      // → OP_INSPECTNUMASSETGROUPS

tx.assetGroups.find(assetId)
                           // → OP_FINDASSETGROUPBYASSETID assetId.txid assetId.gidx
                           //   Returns: group index, or -1 if not found

tx.assetGroups[k].assetId  // → OP_INSPECTASSETGROUPASSETID k
                           //   Returns: { txid: bytes32, gidx: int }

tx.assetGroups[k].isFresh  // → OP_INSPECTASSETGROUPASSETID k
                           //   OP_DROP OP_TXID OP_EQUAL
                           //   True if assetId.txid == this_txid (new asset)

tx.assetGroups[k].control  // → OP_INSPECTASSETGROUPCTRL k
                           //   Returns: AssetId (txid32, gidx_u16), or -1 if no control

// Metadata hash (immutable, set at genesis)
tx.assetGroups[k].metadataHash
                           // → OP_INSPECTASSETGROUPMETADATAHASH k
                           //   Returns the immutable metadata Merkle root

// Counts
tx.assetGroups[k].numInputs
                           // → OP_INSPECTASSETGROUPNUM k 0

tx.assetGroups[k].numOutputs
                           // → OP_INSPECTASSETGROUPNUM k 1

// Sums
tx.assetGroups[k].sumInputs
                           // → OP_INSPECTASSETGROUPSUM k 0

tx.assetGroups[k].sumOutputs
                           // → OP_INSPECTASSETGROUPSUM k 1

// Computed: delta = sumOutputs - sumInputs
tx.assetGroups[k].delta    // → OP_INSPECTASSETGROUPSUM k 2 OP_SUB64
                           //   Positive = mint, Negative = burn, Zero = transfer

// Per-group inputs/outputs
tx.assetGroups[k].inputs[j]
                           // → OP_INSPECTASSETGROUP k j 0
                           //   Returns: AssetInput object

tx.assetGroups[k].outputs[j]
                           // → OP_INSPECTASSETGROUP k j 1
                           //   Returns: AssetOutput object
```

### Asset Inputs/Outputs

```javascript
// AssetInput (from OP_INSPECTASSETGROUP k j 0)
tx.assetGroups[k].inputs[j].type       // LOCAL (0x01) or INTENT (0x02)
tx.assetGroups[k].inputs[j].amount     // Asset amount (u64)

// LOCAL input additional fields:
tx.assetGroups[k].inputs[j].inputIndex // Transaction input index (u32)

// INTENT input additional fields:
tx.assetGroups[k].inputs[j].txid       // Intent transaction ID (bytes32)
tx.assetGroups[k].inputs[j].outputIndex // Output index in intent tx (u32)

// AssetOutput (from OP_INSPECTASSETGROUP k j 1)
tx.assetGroups[k].outputs[j].type       // LOCAL (0x01) or INTENT (0x02)
tx.assetGroups[k].outputs[j].amount     // Asset amount (u64)

// LOCAL output additional fields:
tx.assetGroups[k].outputs[j].outputIndex // Transaction output index (u32)
tx.assetGroups[k].outputs[j].scriptPubKey
                           // → OP_INSPECTASSETGROUP k j 1
                           //   (extract output index)
                           //   OP_INSPECTOUTPUTSCRIPTPUBKEY

// INTENT output additional fields:
tx.assetGroups[k].outputs[j].outputIndex // Output index in same tx (u32)
```

### Cross-Input Asset Lookups

```javascript
tx.inputs[i].assets.length
                           // → OP_INSPECTINASSETCOUNT i

tx.inputs[i].assets[t].assetId
tx.inputs[i].assets[t].amount
                           // → OP_INSPECTINASSETAT i t

tx.inputs[i].assets.lookup(assetId)
                           // → OP_INSPECTINASSETLOOKUP i assetId.txid assetId.gidx
                           //   Returns: amount (> 0) or -1 if not found
```

### Cross-Output Asset Lookups

```javascript
tx.outputs[o].assets.length
                           // → OP_INSPECTOUTASSETCOUNT o

tx.outputs[o].assets[t].assetId
tx.outputs[o].assets[t].amount
                           // → OP_INSPECTOUTASSETAT o t

tx.outputs[o].assets.lookup(assetId)
                           // → OP_INSPECTOUTASSETLOOKUP o assetId.txid assetId.gidx
                           //   Returns: amount (> 0) or -1 if not found
```

---

## Type Definitions

```javascript
// Asset ID - identifies an asset by its genesis transaction and group index
struct AssetId {
    txid: bytes32,
    gidx: int
}

// Asset reference for control assets
struct AssetRef {
    byId: bool,              // true for BY_ID, false for BY_GROUP
    assetId: AssetId,        // Used when byId = true
    groupIndex: int          // Used when byId = false (references group in same tx)
}

// Input types
enum AssetInputType { LOCAL = 0x01, INTENT = 0x02 }

struct AssetInputLocal {
    type: AssetInputType,    // LOCAL
    inputIndex: int,         // Transaction input index
    amount: bigint
}

struct AssetInputIntent {
    type: AssetInputType,    // INTENT
    txid: bytes32,           // Intent transaction ID
    outputIndex: int,        // Output index in intent tx
    amount: bigint
}

// Output types
enum AssetOutputType { LOCAL = 0x01, INTENT = 0x02 }

struct AssetOutputLocal {
    type: AssetOutputType,   // LOCAL
    outputIndex: int,        // Transaction output index
    amount: bigint
}

struct AssetOutputIntent {
    type: AssetOutputType,   // INTENT
    outputIndex: int,        // Output index in same tx (locked for claim)
    amount: bigint
}

```

---

## Common Patterns

### Checking Asset Presence

```javascript
// Check if an asset is present in transaction
let groupIndex = tx.assetGroups.find(assetId);
require(groupIndex != null, "Asset not found");

// Check if asset is at a specific output
let amount = tx.outputs[o].assets.lookup(assetId);
require(amount > 0, "Asset not at output");
```

### Checking if Asset is Fresh (New Issuance)

```javascript
// Check if group creates a new asset (txid matches this transaction)
let group = tx.assetGroups[k];
require(group.isFresh, "Must be fresh issuance");

// Equivalent low-level check:
// OP_INSPECTASSETGROUPASSETID k → txid gidx
// OP_DROP OP_TXID OP_EQUAL → bool
```

### Checking Delta (Mint/Burn/Transfer)

```javascript
let group = tx.assetGroups[k];

// Transfer (no supply change)
require(group.delta == 0, "Must be transfer");

// Mint (supply increase)
require(group.delta > 0, "Must be mint");

// Burn (supply decrease)
require(group.delta < 0, "Must be burn");
```

### Verifying Control Asset

```javascript
let group = tx.assetGroups.find(assetId);
require(group != null, "Asset not found");
require(group.control == expectedControlId, "Wrong control asset");
```
