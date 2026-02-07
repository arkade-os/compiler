# Arkade Compiler — Contract Primitives Plan

The compiler today handles simple spending-path contracts (checkSig, checkMultisig, hashlock, timelock). Real contracts need more: asset introspection, arithmetic with operator precedence, control flow, and compile-time loop unrolling. This plan adds six primitives that, together, make recursive covenants, controlled minting/burning, fee calculations, epoch-based rate limiting, read-only beacons, and threshold signature verification expressible in Arkade Script.

Single PR on `claude/add-contract-support-crNr1`, one commit per primitive.
Each commit adds grammar + parser + AST + compiler + example `.ark` + test.
Existing tests must pass after every commit.

| # | Primitive | What it unlocks |
|---|-----------|-----------------|
| 1 | Asset lookups on inputs/outputs | Covenant token accounting, control asset checks |
| 2 | Asset group introspection | Mint/burn verification, delta enforcement, supply locks |
| 3 | Arithmetic expressions | Fee calculations, complex comparisons, operator precedence |
| 4 | If/else + variable reassignment | Conditional logic, epoch reset vs accumulate |
| 5 | For loops (compile-time unrolled) | Iterate asset groups, beacon passthrough |
| 6 | Array types + indexing | Threshold signature schemes, N-of-M verification |

---

## Type System

The compiler must track three numeric representations and insert conversions at every boundary.
This is the most critical invariant — every 64-bit opcode requires exactly two `u64le` operands.

| Type | Width | Format | Produced by | Consumed by |
|---|---|---|---|---|
| `csn` | 1-4 bytes | CScriptNum (signed, variable) | Witness inputs, `OP_0`..`OP_16`, `OP_PICK` | `OP_PICK`, `OP_IF`, `OP_EQUAL`, `OP_VERIFY` |
| `u32le` | 4 bytes | Unsigned little-endian | `OP_INSPECTLOCKTIME` | `OP_LE32TOLE64` |
| `u64le` | 8 bytes | Signed little-endian | `OP_INSPECTASSETGROUPSUM`, `OP_ADD64`, `OP_INSPECTINASSETLOOKUP` (non-sentinel) | `OP_ADD64`, `OP_GREATERTHAN64`, `OP_EQUAL` |
| `sentinel` | 1 byte | CScriptNum `-1` | `OP_INSPECTINASSETLOOKUP` (not found), `OP_INSPECTOUTASSETLOOKUP` (not found) | Must branch before arithmetic |

### Conversion opcodes

```
csn    → u64le : OP_SCRIPTNUMTOLE64
u32le  → u64le : OP_LE32TOLE64
u64le  → csn   : OP_LE64TOSCRIPTNUM
sentinel → u64le : Illegal. Must branch on OP_1NEGATE OP_EQUAL first.
```

### Asset ID decomposition

Asset IDs are 34 bytes (`txid:bytes32` + `gidx:u16`). In constructor params they decompose into two fields:

```solidity
// Source syntax
bytes32 ctrlAssetId

// Compiled constructor params
{ "name": "ctrlAssetId_txid", "type": "bytes32" }
{ "name": "ctrlAssetId_gidx", "type": "int" }
```

The compiler auto-decomposes any `bytes32` param used in `.assets.lookup()` or `tx.assetGroups.find()` into the `_txid`/`_gidx` pair. Source code refers to the short name; the ABI exposes the decomposed form.

### Sentinel guard pattern

Every `assets.lookup()` result must be guarded before use in arithmetic:

```asm
OP_INSPECTINASSETLOOKUP           ; → result(sentinel-or-u64le)
OP_DUP
OP_1NEGATE
OP_EQUAL
OP_NOT
OP_VERIFY                         ; fails if -1 (not found)
; now safe to use as u64le
```

The compiler emits this guard automatically for every lookup used in a comparison (`> 0`, `>= amount`, etc.). For `== 0` comparisons, the sentinel case is a valid "not present" check and the guard is skipped.

---

## Compiler Invariants

These apply across all commits:

1. **Every `u64le` arithmetic operand is exactly 8 bytes.** Insert `OP_SCRIPTNUMTOLE64` or `OP_LE32TOLE64` at every `csn`/`u32le` → `u64le` boundary.
2. **Every asset lookup result is guarded before arithmetic.** Emit the sentinel guard pattern above.
3. **Every `OP_ADD64`/`OP_SUB64`/`OP_MUL64` overflow flag is consumed by `OP_VERIFY` immediately.**
4. **Both branches of `OP_IF`/`OP_ELSE`/`OP_ENDIF` must leave identical stack depth and type layout.** The compiler inserts `OP_DROP`/`OP_SWAP` to equalize.
5. **`OP_PICK`/`OP_ROLL` indices are computed from a virtual stack model** that tracks every push, pop, and branch point.
6. **Constructor params used in `u64le` context are pre-converted to 8-byte LE at compile time** (literal push, no runtime conversion).

---

## Commit 1 — Asset Lookups on Inputs/Outputs

### Primitive

```solidity
tx.inputs[i].assets.lookup(assetId)   // → u64le amount or sentinel -1
tx.outputs[o].assets.lookup(assetId)  // → u64le amount or sentinel -1
```

### Opcodes

| Arkade Script | Opcode | Result type |
|---|---|---|
| `tx.inputs[i].assets.lookup(id)` | `OP_INSPECTINASSETLOOKUP i id_txid id_gidx` | `u64le` or `sentinel` |
| `tx.outputs[o].assets.lookup(id)` | `OP_INSPECTOUTASSETLOOKUP o id_txid id_gidx` | `u64le` or `sentinel` |

### Changes

- **Grammar:** Extend `tx_property_access` to parse `.assets.lookup(expr)` after `inputs[i]` / `outputs[o]`.
- **AST:** Add `AssetLookup { source: InputOrOutput, index: Expression, asset_id: String }` to `Expression`.
- **Compiler:** Emit lookup opcode with decomposed asset ID. Emit sentinel guard when result feeds into arithmetic. Use `OP_GREATERTHAN64` / `OP_GREATERTHANOREQUAL64` for 64-bit comparisons.

### Example: `token_vault.ark`

Recursive covenant that holds tokens. Control asset must be retained across every spend.

```solidity
options {
  server = serverPk;
  exit = 288;
}

contract TokenVault(
  bytes32 tokenAssetId,
  bytes32 ctrlAssetId,
  pubkey  ownerPk,
  pubkey  serverPk
) {
  // Deposit: lock tokens into the vault, control asset gates the operation
  function deposit(int amount, signature ownerSig) {
    require(tx.inputs[0].assets.lookup(ctrlAssetId) > 0, "no ctrl");
    require(tx.outputs[0].assets.lookup(tokenAssetId) >=
            tx.inputs[0].assets.lookup(tokenAssetId) + amount, "not locked");
    require(tx.outputs[0].scriptPubKey == tx.input.current.scriptPubKey, "broken");
    require(tx.outputs[0].assets.lookup(ctrlAssetId) >=
            tx.inputs[0].assets.lookup(ctrlAssetId), "ctrl leaked");
    require(checkSig(ownerSig, ownerPk), "bad sig");
  }

  // Withdraw: release tokens to a recipient
  function withdraw(int amount, pubkey recipientPk, signature ownerSig) {
    require(tx.outputs[1].assets.lookup(tokenAssetId) >= amount, "short");
    require(tx.outputs[1].scriptPubKey == new P2TR(recipientPk), "wrong dest");
    require(tx.outputs[0].scriptPubKey == tx.input.current.scriptPubKey, "broken");
    require(checkSig(ownerSig, ownerPk), "bad sig");
  }
}
```

#### Expected assembly for `deposit` (server variant, annotated)

```asm
; Witness: [serverSig, amount(csn), ownerSig]

; --- Server co-signature ---
OP_2 OP_ROLL                            ; [amount, ownerSig, serverSig]
<serverPk>
OP_CHECKSIGVERIFY                        ; [amount(c), ownerSig]

; --- Convert amount to u64le ---
OP_SWAP                                  ; [ownerSig, amount(c)]
OP_SCRIPTNUMTOLE64                       ; [ownerSig, amount(u)]

; --- require(inputs[0].lookup(ctrl) > 0) ---
OP_0 <ctrlAssetId_txid> <ctrlAssetId_gidx>
OP_INSPECTINASSETLOOKUP                  ; [ownerSig, amount(u), ctrlAmt(s)]
OP_DUP OP_1NEGATE OP_EQUAL OP_NOT OP_VERIFY  ; sentinel guard
OP_DROP                                  ; only needed presence, drop value

; --- require(outputs[0].lookup(token) >= inputs[0].lookup(token) + amount) ---
OP_0 <tokenAssetId_txid> <tokenAssetId_gidx>
OP_INSPECTOUTASSETLOOKUP                 ; [ownerSig, amount(u), outToken(s)]
OP_DUP OP_1NEGATE OP_EQUAL OP_NOT OP_VERIFY
OP_0 <tokenAssetId_txid> <tokenAssetId_gidx>
OP_INSPECTINASSETLOOKUP                  ; [ownerSig, amount(u), outToken(u), inToken(s)]
OP_DUP OP_1NEGATE OP_EQUAL OP_NOT OP_VERIFY
OP_2 OP_PICK                             ; [ownerSig, amount(u), outToken(u), inToken(u), amount(u)]
OP_ADD64 OP_VERIFY                       ; [ownerSig, amount(u), outToken(u), expected(u)]
OP_SWAP                                  ; [ownerSig, amount(u), expected(u), outToken(u)]
OP_GREATERTHANOREQUAL64 OP_VERIFY        ; [ownerSig, amount(u)]

; --- require(outputs[0].scriptPubKey == current.scriptPubKey) ---
OP_0 OP_INSPECTOUTPUTSCRIPTPUBKEY
OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTSCRIPTPUBKEY
OP_EQUAL OP_VERIFY

; --- require(outputs[0].lookup(ctrl) >= inputs[0].lookup(ctrl)) ---
OP_0 <ctrlAssetId_txid> <ctrlAssetId_gidx>
OP_INSPECTOUTASSETLOOKUP
OP_DUP OP_1NEGATE OP_EQUAL OP_NOT OP_VERIFY
OP_0 <ctrlAssetId_txid> <ctrlAssetId_gidx>
OP_INSPECTINASSETLOOKUP
OP_DUP OP_1NEGATE OP_EQUAL OP_NOT OP_VERIFY
OP_GREATERTHANOREQUAL64 OP_VERIFY

; --- require(checkSig(ownerSig, ownerPk)) ---
; ownerSig is on the stack from witness
<ownerPk>
OP_CHECKSIGVERIFY

; Clean stack
OP_DROP                                  ; drop amount
OP_TRUE
```

### Test: `tests/token_vault_test.rs`

- Contract parses and compiles.
- 4 functions emitted (2 functions x 2 variants).
- Assembly contains `OP_INSPECTOUTASSETLOOKUP`, `OP_INSPECTINASSETLOOKUP`.
- Sentinel guard pattern present for every lookup used in arithmetic.
- 64-bit comparison opcodes used (`OP_GREATERTHANOREQUAL64`).

---

## Commit 2 — Asset Groups

### Primitive

```solidity
let group = tx.assetGroups.find(assetId);  // locate group by ID → csn index or -1
tx.assetGroups.length                       // → csn group count
tx.assetGroups[k].sumInputs                 // → u64le
tx.assetGroups[k].sumOutputs                // → u64le
tx.assetGroups[k].delta                     // → u64le (sumOutputs - sumInputs)
tx.assetGroups[k].control                   // → assetId or -1
tx.assetGroups[k].metadataHash              // → bytes32
tx.assetGroups[k].isFresh                   // → bool (assetId.txid == current txid)
```

### Opcodes

| Arkade Script | Opcode | Result type |
|---|---|---|
| `tx.assetGroups.find(id)` | `OP_FINDASSETGROUPBYASSETID txid gidx` | `csn` (index or -1) |
| `tx.assetGroups.length` | `OP_INSPECTNUMASSETGROUPS` | `csn` |
| `group.sumInputs` | `OP_INSPECTASSETGROUPSUM k 0` | `u64le` |
| `group.sumOutputs` | `OP_INSPECTASSETGROUPSUM k 1` | `u64le` |
| `group.delta` | `sumOutputs` then `sumInputs` then `OP_SUB64` | `u64le` |
| `group.control` | `OP_INSPECTASSETGROUPCTRL k` | `assetId` or `-1` |
| `group.metadataHash` | `OP_INSPECTASSETGROUPMETADATAHASH k` | `bytes32` |
| `group.assetId` | `OP_INSPECTASSETGROUPASSETID k` | `(txid32, gidx_u16)` |

### Changes

- **Grammar:** Add `assetGroups` as a `tx_special_property`. Parse `.find(expr)`, `[k]` indexing, and group property access (`.delta`, `.control`, etc.). Add `let_binding` statement: `let identifier = expr;`.
- **AST:** Add `LetBinding { name, value }` to statement types. Add `GroupFind`, `GroupProperty` to `Expression`.
- **Compiler:** Emit group introspection opcodes. Derive `.delta` from two `OP_INSPECTASSETGROUPSUM` calls + `OP_SUB64`. Track group index on virtual stack for subsequent property access.

### Example: `controlled_mint.ark`

Three supply operations: mint (delta > 0, control asset required by consensus), burn (delta < 0, no control needed), and permanent supply lock (burn the control asset itself).

```solidity
options {
  server = serverPk;
  exit = 288;
}

contract ControlledMint(
  bytes32 tokenAssetId,
  bytes32 ctrlAssetId,
  pubkey  issuerPk,
  pubkey  serverPk
) {
  // Mint: delta > 0, control asset present and retained
  function mint(int amount, pubkey recipientPk, signature issuerSig) {
    let tokenGroup = tx.assetGroups.find(tokenAssetId);
    require(tokenGroup.delta == amount, "delta mismatch");
    require(tokenGroup.control == ctrlAssetId, "wrong control");

    let ctrlGroup = tx.assetGroups.find(ctrlAssetId);
    require(ctrlGroup.delta == 0, "ctrl supply changed");

    require(tx.outputs[0].assets.lookup(tokenAssetId) >= amount, "mint short");
    require(tx.outputs[0].scriptPubKey == new P2TR(recipientPk), "wrong dest");
    require(checkSig(issuerSig, issuerPk), "bad sig");
  }

  // Burn: delta < 0, no control asset needed
  function burn(int amount, signature ownerSig, pubkey ownerPk) {
    let tokenGroup = tx.assetGroups.find(tokenAssetId);
    require(tokenGroup.sumInputs >= tokenGroup.sumOutputs + amount, "burn short");
    require(checkSig(ownerSig, ownerPk), "bad sig");
  }

  // Lock supply forever: burn the control asset
  function lockSupply(signature issuerSig) {
    let ctrlGroup = tx.assetGroups.find(ctrlAssetId);
    require(ctrlGroup.sumOutputs == 0, "ctrl not burned");
    require(checkSig(issuerSig, issuerPk), "bad sig");
  }
}
```

### Test: `tests/controlled_mint_test.rs`

- 6 functions emitted (3 x 2 variants).
- `mint` assembly contains `OP_FINDASSETGROUPBYASSETID`, `OP_INSPECTASSETGROUPSUM`, `OP_INSPECTASSETGROUPCTRL`.
- `lockSupply` checks `sumOutputs == 0` using 8-byte LE zero literal.
- `burn` uses `OP_SUB64` to verify delta without requiring control asset.

---

## Commit 3 — Arithmetic Expressions

### Primitive

Operator precedence and parenthesized sub-expressions.

```solidity
int net = amount - (amount * feeBps / 10000);
```

`*` and `/` bind tighter than `+` and `-`. Parentheses override.

All arithmetic on asset amounts uses 64-bit opcodes:

| Source | Opcode | Overflow |
|---|---|---|
| `a + b` | `OP_ADD64` | Pushes flag, must `OP_VERIFY` |
| `a - b` | `OP_SUB64` | Pushes flag, must `OP_VERIFY` |
| `a * b` | `OP_MUL64` | Pushes flag, must `OP_VERIFY` |
| `a / b` | `OP_DIV64` | Pushes flag, must `OP_VERIFY` |

Witness inputs (`int` params) arrive as `csn` and must be converted to `u64le` via `OP_SCRIPTNUMTOLE64` before 64-bit math. Constructor constants are emitted as 8-byte LE literals directly.

### Changes

- **Grammar:** Rewrite expression rules with precedence levels:
  ```pest
  expression          = { comparison_expr }
  comparison_expr     = { additive_expr ~ (comparison_op ~ additive_expr)? }
  additive_expr       = { multiplicative_expr ~ (("+" | "-") ~ multiplicative_expr)* }
  multiplicative_expr = { unary_expr ~ (("*" | "/") ~ unary_expr)* }
  unary_expr          = { atom ~ postfix* }
  atom                = { "(" ~ expression ~ ")" | function_call | number_literal | identifier | ... }
  ```
- **AST:** Add `BinaryOp { left: Box<Expression>, op: String, right: Box<Expression> }` to `Expression`.
- **Compiler:** Recursive codegen — emit left, emit right, emit 64-bit opcode. Insert `OP_SCRIPTNUMTOLE64` at `csn`→`u64le` boundaries. Emit overflow `OP_VERIFY` after every arithmetic op.

### Example: `fee_adapter.ark`

Adapter covenant that deducts a fee on every deposit.

```solidity
options {
  server = serverPk;
  exit = 288;
}

contract FeeAdapter(
  bytes32 tokenAssetId,
  bytes32 ctrlAssetId,
  pubkey  serverPk,
  int     feeBps
) {
  function deposit(int amount, signature userSig, pubkey userPk) {
    require(amount > 0, "zero");
    int net = amount - (amount * feeBps / 10000);

    require(tx.inputs[0].assets.lookup(ctrlAssetId) > 0, "no ctrl");
    require(tx.outputs[0].assets.lookup(tokenAssetId) >=
            tx.inputs[0].assets.lookup(tokenAssetId) + amount, "not locked");
    require(tx.outputs[1].assets.lookup(tokenAssetId) >= net, "mint short");
    require(tx.outputs[1].scriptPubKey == new P2TR(userPk), "wrong dest");
    require(tx.outputs[0].scriptPubKey == tx.input.current.scriptPubKey, "broken");
    require(checkSig(userSig, userPk), "bad sig");
  }
}
```

#### Expected assembly fragment for `net = amount - (amount * feeBps / 10000)`

```asm
; amount(u) already on stack from witness conversion
OP_DUP                                   ; [amount(u), amount(u)]
<feeBps_u64le>                           ; [amount(u), amount(u), feeBps(u)]
OP_MUL64 OP_VERIFY                       ; [amount(u), product(u)]
0x1027000000000000                       ; [amount(u), product(u), 10000(u)]  -- 8-byte LE
OP_DIV64 OP_VERIFY                       ; [amount(u), fee(u)]
OP_SUB64 OP_VERIFY                       ; [net(u)]
```

### Test: `tests/fee_adapter_test.rs`

- Variable `net` computed with correct precedence.
- Assembly contains `OP_MUL64`, `OP_DIV64`, `OP_SUB64` in correct order.
- Each 64-bit arithmetic op followed by `OP_VERIFY`.
- `feeBps` emitted as 8-byte LE constructor constant.

---

## Commit 4 — If/Else + Variable Reassignment

### Primitive

```solidity
if (condition) {
  // then
} else {
  // else
}

x = x + 1;  // reassignment (not declaration)
```

### Changes

- **Grammar:** Add `if_stmt`, `block`, `var_assign`:
  ```pest
  if_stmt    = { "if" ~ "(" ~ expression ~ ")" ~ block ~ ("else" ~ block)? }
  block      = { "{" ~ statement* ~ "}" }
  var_assign = { identifier ~ "=" ~ expression ~ ";" }
  ```
- **AST:** Add `IfElse { condition, then_body, else_body }` and `VarAssign { name, value }` to statements.
- **Compiler:** Emit `OP_IF ... OP_ELSE ... OP_ENDIF`. Track virtual stack in both branches. Insert `OP_DROP`/`OP_SWAP` to normalize stack depth at `OP_ENDIF`. Variable reassignment updates the virtual stack slot.

### Branch normalization

Both branches of `OP_IF`/`OP_ELSE`/`OP_ENDIF` **must** leave identical stack depth and type layout. The compiler:
1. Snapshots the virtual stack at `OP_IF`.
2. Runs codegen for the then-branch, recording final stack state.
3. Restores the snapshot and runs codegen for the else-branch.
4. Compares both final states. Inserts padding `OP_DROP` or `OP_0` to equalize.

### Example: `epoch_limiter.ark`

Rate limiter that resets or accumulates per epoch. State carried as asset quantities.

```solidity
options {
  server = adminServerPk;
  exit = 288;
}

contract EpochLimiter(
  bytes32 epochStartAssetId,
  bytes32 epochTotalAssetId,
  bytes32 ctrlAssetId,
  int     epochLimit,
  int     epochBlocks,
  pubkey  adminPk,
  pubkey  adminServerPk
) {
  function check(int transferAmount, int epochStartIdx, int epochTotalIdx) {
    require(transferAmount > 0, "zero");

    int epochStart = tx.assetGroups[epochStartIdx].sumInputs;
    int epochTotal = tx.assetGroups[epochTotalIdx].sumInputs;

    require(tx.inputs[0].assets.lookup(ctrlAssetId) > 0, "no ctrl");

    if (tx.time >= epochStart + epochBlocks) {
      int newStart = tx.time;
      require(tx.assetGroups[epochStartIdx].sumOutputs == newStart, "start not reset");
      require(tx.assetGroups[epochTotalIdx].sumOutputs == transferAmount, "total wrong");
      require(transferAmount <= epochLimit, "exceeds limit");
    } else {
      int newTotal = epochTotal + transferAmount;
      require(tx.assetGroups[epochStartIdx].sumOutputs == epochStart, "start mutated");
      require(tx.assetGroups[epochTotalIdx].sumOutputs == newTotal, "total wrong");
      require(newTotal <= epochLimit, "exceeds limit");
    }

    require(tx.outputs[0].assets.lookup(ctrlAssetId) >=
            tx.inputs[0].assets.lookup(ctrlAssetId), "ctrl leaked");

    require(tx.outputs[0].scriptPubKey == tx.input.current.scriptPubKey, "broken");
  }
}
```

### Reference assembly: server variant

The full opcode listing for this contract serves as the reference implementation for the compiler's stack model, type conversions, and branch normalization.

```asm
; ═══════════════════════════════════════════════
; SERVER CO-SIGNATURE
; ═══════════════════════════════════════════════
; Witness: [serverSig, tA(c), eSI(c), eTI(c)]
; Stack reads bottom-to-top, eTI is on top.

OP_3 OP_ROLL                            ; [tA, eSI, eTI, serverSig]
<adminServerPk>                          ; [tA, eSI, eTI, serverSig, pk]
OP_CHECKSIGVERIFY                        ; [tA(c), eSI(c), eTI(c)]

; ═══════════════════════════════════════════════
; PHASE 1: CONVERT WITNESS INPUTS
; ═══════════════════════════════════════════════
; transferAmount → u64le upfront.
; epochStartIdx and epochTotalIdx stay csn (used as opcode arguments only).

OP_2 OP_ROLL                            ; [eSI(c), eTI(c), tA(c)]
OP_SCRIPTNUMTOLE64                      ; [eSI(c), eTI(c), tA(u)]

; ═══════════════════════════════════════════════
; PHASE 2: VALIDATE transferAmount > 0
; ═══════════════════════════════════════════════

OP_DUP                                  ; [eSI, eTI, tA(u), tA(u)]
0x0000000000000000                      ; [eSI, eTI, tA(u), tA(u), 0(u)]
OP_GREATERTHAN64                        ; [eSI, eTI, tA(u), flag(c)]
OP_VERIFY                               ; [eSI, eTI, tA(u)]

; ═══════════════════════════════════════════════
; PHASE 3: READ EPOCH STATE
; ═══════════════════════════════════════════════

; epochStart = tx.assetGroups[epochStartIdx].sumInputs
OP_2 OP_PICK                            ; [eSI, eTI, tA(u), eSI(c)]
OP_0                                    ; source=inputs
OP_INSPECTASSETGROUPSUM                 ; [eSI, eTI, tA(u), epochStart(u)]

; epochTotal = tx.assetGroups[epochTotalIdx].sumInputs
OP_2 OP_PICK                            ; [eSI, eTI, tA(u), eS(u), eTI(c)]
OP_0                                    ; source=inputs
OP_INSPECTASSETGROUPSUM                 ; [eSI, eTI, tA(u), eS(u), eT(u)]

; ═══════════════════════════════════════════════
; PHASE 4: VERIFY CONTROL ASSET PRESENT
; ═══════════════════════════════════════════════

OP_0                                    ; input index 0
<ctrlAssetId_txid>
<ctrlAssetId_gidx>
OP_INSPECTINASSETLOOKUP                 ; [.., ctrlAmt(s)]
OP_DUP OP_1NEGATE OP_EQUAL OP_NOT OP_VERIFY  ; sentinel guard
OP_DROP                                 ; [eSI, eTI, tA(u), eS(u), eT(u)]

; ═══════════════════════════════════════════════
; PHASE 5: READ tx.time AND COMPUTE DEADLINE
; ═══════════════════════════════════════════════

OP_INSPECTLOCKTIME                      ; [.., locktime(4)]
OP_LE32TOLE64                           ; [.., txTime(u)]

; deadline = epochStart + epochBlocks
OP_2 OP_PICK                            ; [.., txTime(u), eS(u)]
<epochBlocks_u64le>                     ; 8-byte LE literal
OP_ADD64 OP_VERIFY                      ; [.., txTime(u), deadline(u)]

; ═══════════════════════════════════════════════
; PHASE 6: BRANCH — NEW EPOCH vs SAME EPOCH
; ═══════════════════════════════════════════════

; if (txTime >= deadline)
OP_2DUP                                 ; [.., txTime(u), deadline(u), txTime(u), deadline(u)]
OP_SWAP                                 ; [.., txTime(u), deadline(u), deadline(u), txTime(u)]
OP_GREATERTHANOREQUAL64                 ; [.., txTime(u), deadline(u), flag(c)]

OP_IF
; ─────────────────────────────────────────────
; NEW EPOCH BRANCH
; Stack: [eSI(c), eTI(c), tA(u), eS(u), eT(u), txTime(u), deadline(u)]
; ─────────────────────────────────────────────

  ; Drop deadline and epochTotal (not needed)
  OP_DROP                               ; [eSI, eTI, tA(u), eS(u), eT(u), txTime(u)]
  OP_SWAP OP_DROP                       ; [eSI, eTI, tA(u), eS(u), txTime(u)]
  ; Drop old epochStart (replaced by txTime)
  OP_SWAP OP_DROP                       ; [eSI, eTI, tA(u), txTime(u)]
                                        ; txTime is newStart

  ; require(assetGroups[eSI].sumOutputs == newStart)
  OP_3 OP_PICK                          ; [eSI, eTI, tA(u), newStart(u), eSI(c)]
  OP_1                                  ; source=outputs
  OP_INSPECTASSETGROUPSUM               ; [.., newStart(u), startOut(u)]
  OP_2DUP OP_EQUAL OP_VERIFY           ; verify equal
  OP_DROP                               ; [eSI, eTI, tA(u), newStart(u)]

  ; require(assetGroups[eTI].sumOutputs == transferAmount)
  OP_2 OP_PICK                          ; [.., newStart(u), eTI(c)]
  OP_1 OP_INSPECTASSETGROUPSUM          ; [.., newStart(u), totalOut(u)]
  OP_3 OP_PICK                          ; [.., newStart(u), totalOut(u), tA(u)]
  OP_EQUAL OP_VERIFY                    ; [eSI, eTI, tA(u), newStart(u)]

  ; require(transferAmount <= epochLimit)
  OP_SWAP                               ; [eSI, eTI, newStart(u), tA(u)]
  OP_DUP                                ; [.., tA(u), tA(u)]
  <epochLimit_u64le>                    ; [.., tA(u), tA(u), limit(u)]
  OP_LESSTHANOREQUAL64 OP_VERIFY        ; [eSI, eTI, newStart(u), tA(u)]

  ; Stack normalized: [eSI(c), eTI(c), val1(u), val2(u)]

OP_ELSE
; ─────────────────────────────────────────────
; SAME EPOCH BRANCH
; Stack: [eSI(c), eTI(c), tA(u), eS(u), eT(u), txTime(u), deadline(u)]
; ─────────────────────────────────────────────

  ; Drop deadline and txTime
  OP_DROP OP_DROP                       ; [eSI, eTI, tA(u), eS(u), eT(u)]

  ; newTotal = epochTotal + transferAmount
  OP_2 OP_PICK                          ; [.., eT(u), tA(u)]
  OP_ADD64 OP_VERIFY                    ; [eSI, eTI, tA(u), eS(u), newTotal(u)]

  ; require(assetGroups[eSI].sumOutputs == epochStart)
  OP_4 OP_PICK                          ; [.., newTotal(u), eSI(c)]
  OP_1 OP_INSPECTASSETGROUPSUM          ; [.., newTotal(u), startOut(u)]
  OP_3 OP_PICK                          ; [.., startOut(u), eS(u)]
  OP_EQUAL OP_VERIFY                    ; [eSI, eTI, tA(u), eS(u), newTotal(u)]

  ; require(assetGroups[eTI].sumOutputs == newTotal)
  OP_3 OP_PICK                          ; [.., newTotal(u), eTI(c)]
  OP_1 OP_INSPECTASSETGROUPSUM          ; [.., newTotal(u), totalOut(u)]
  OP_2DUP OP_EQUAL OP_VERIFY
  OP_DROP                               ; [eSI, eTI, tA(u), eS(u), newTotal(u)]

  ; require(newTotal <= epochLimit)
  OP_DUP
  <epochLimit_u64le>
  OP_LESSTHANOREQUAL64 OP_VERIFY        ; [eSI, eTI, tA(u), eS(u), newTotal(u)]

  ; Normalize: drop eS → [eSI, eTI, tA(u), newTotal(u)]
  OP_SWAP OP_DROP                       ; [eSI(c), eTI(c), tA(u), newTotal(u)]

OP_ENDIF

; ═══════════════════════════════════════════════
; PHASE 7: COMMON TAIL
; Stack: [eSI(c), eTI(c), val1(u), val2(u)]
; ═══════════════════════════════════════════════

OP_2DROP                                ; [eSI(c), eTI(c)]

; --- require(output[0].ctrl >= input[0].ctrl) ---
OP_0 <ctrlAssetId_txid> <ctrlAssetId_gidx>
OP_INSPECTOUTASSETLOOKUP
OP_DUP OP_1NEGATE OP_EQUAL OP_NOT OP_VERIFY
OP_0 <ctrlAssetId_txid> <ctrlAssetId_gidx>
OP_INSPECTINASSETLOOKUP
OP_DUP OP_1NEGATE OP_EQUAL OP_NOT OP_VERIFY
OP_SWAP
OP_GREATERTHANOREQUAL64 OP_VERIFY

; --- require(output[0].scriptPubKey == current.scriptPubKey) ---
OP_0 OP_INSPECTOUTPUTSCRIPTPUBKEY
OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTSCRIPTPUBKEY
OP_EQUAL OP_VERIFY

; Clean remaining witness args
OP_2DROP                                ; []
OP_TRUE                                 ; script success
```

#### Non-server variant

Replaces the server co-signature preamble with:

```asm
; Witness: [tA(c), eSI(c), eTI(c)]
0x2001                                  ; 288 as CScriptNum
OP_CHECKSEQUENCEVERIFY
OP_DROP
; ... remainder identical from PHASE 1 onward
```

### Opcode budget

| Section | Opcodes | Pushes (bytes) |
|---|---|---|
| Server sig | 4 | 33 (pubkey) |
| Phase 1: witness conversion | 3 | 0 |
| Phase 2: tA > 0 | 5 | 8 (zero literal) |
| Phase 3: read epoch state | 8 | 0 |
| Phase 4: ctrl present | 12 | 34 (assetId) |
| Phase 5: txTime + deadline | 8 | 8 (epochBlocks) |
| Phase 6: branch condition | 5 | 0 |
| New epoch branch | ~22 | 8 (epochLimit) |
| Same epoch branch | ~24 | 8 (epochLimit) |
| Phase 7: ctrl persistence | 18 | 68 (2x assetId) |
| Phase 7: covenant recursion | 5 | 0 |
| Cleanup | 3 | 0 |
| **Total (per path)** | **~75** | **~159** |

Script size: ~250 bytes. Sigops: 1. Stack peak: 10 elements.

### Test: `tests/epoch_limiter_test.rs`

- 2 functions emitted (1 x 2 variants).
- Assembly contains `OP_IF`, `OP_ELSE`, `OP_ENDIF`.
- Both branches emit `OP_INSPECTASSETGROUPSUM` with source=1 (outputs).
- Branch normalization leaves identical stack depth at `OP_ENDIF`.
- Server variant contains `OP_CHECKSIGVERIFY`; exit variant contains `OP_CHECKSEQUENCEVERIFY`.
- All 64-bit arithmetic followed by overflow `OP_VERIFY`.
- Sentinel guard present on every `assets.lookup()`.

---

## Commit 5 — For Loops (Compile-Time Unrolled)

### Primitive

```solidity
for (i, value) in array {
  // body — unrolled at compile time
}
```

`array` must have a length known at compile time (constructor parameter or literal).
The compiler unrolls the loop body N times, substituting `i` with `0, 1, 2, ...`
and `value` with `array[0], array[1], array[2], ...`.

Bitcoin Script has no loops — the unrolled form is the only form.

### Changes

- **Grammar:**
  ```pest
  for_stmt = { "for" ~ "(" ~ identifier ~ "," ~ identifier ~ ")" ~ "in" ~ expression ~ block }
  ```
- **AST:** Add `ForIn { index_var, value_var, iterable, body }` to statements.
- **Compiler:**
  1. Resolve `iterable` to determine length at compile time.
  2. For `tx.assetGroups`: use `numGroups` constructor param as bound.
  3. For array params: use array length.
  4. Emit `body` N times, substituting `index_var` with literal `k` and `value_var` with `iterable[k]`.
  5. Reject with error if length is not statically determinable.

### Example: `beacon.ark`

Read-only recursive covenant. Passthrough ensures every asset group survives intact.

```solidity
options {
  server = oracleServerPk;
  exit = 144;
}

contract PriceBeacon(
  bytes32 ctrlAssetId,
  pubkey  oraclePk,
  pubkey  oracleServerPk,
  int     numGroups
) {
  // Anyone can pass through — all groups must survive
  function passthrough() {
    require(tx.outputs[0].scriptPubKey == tx.input.current.scriptPubKey, "broken");

    for (k, group) in tx.assetGroups {
      require(group.sumOutputs >= group.sumInputs, "drained");
    }
  }

  // Oracle updates price (quantity encodes value)
  function update(signature oracleSig) {
    require(tx.inputs[0].assets.lookup(ctrlAssetId) > 0, "no ctrl");
    require(tx.outputs[0].scriptPubKey == tx.input.current.scriptPubKey, "broken");
    require(checkSig(oracleSig, oraclePk), "bad sig");
  }
}
```

#### Unrolled assembly for `passthrough` (numGroups = 3)

```asm
; --- covenant recursion ---
OP_0 OP_INSPECTOUTPUTSCRIPTPUBKEY
OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTSCRIPTPUBKEY
OP_EQUAL OP_VERIFY

; --- k = 0 ---
OP_0 OP_1 OP_INSPECTASSETGROUPSUM       ; group 0 sumOutputs → u64le
OP_0 OP_0 OP_INSPECTASSETGROUPSUM       ; group 0 sumInputs  → u64le
OP_GREATERTHANOREQUAL64 OP_VERIFY

; --- k = 1 ---
OP_1 OP_1 OP_INSPECTASSETGROUPSUM
OP_1 OP_0 OP_INSPECTASSETGROUPSUM
OP_GREATERTHANOREQUAL64 OP_VERIFY

; --- k = 2 ---
OP_2 OP_1 OP_INSPECTASSETGROUPSUM
OP_2 OP_0 OP_INSPECTASSETGROUPSUM
OP_GREATERTHANOREQUAL64 OP_VERIFY

OP_TRUE
```

### `for` over `tx.assetGroups`

When the iterable is `tx.assetGroups`, the compiler uses the constructor param `numGroups` as the unroll bound. The `group` variable binds to `tx.assetGroups[k]` at each iteration, so `group.sumOutputs` becomes `OP_INSPECTASSETGROUPSUM k 1`.

### Test: `tests/beacon_test.rs`

- `passthrough` assembly length scales with `numGroups`.
- Each unrolled iteration contains `OP_INSPECTASSETGROUPSUM` x2 + `OP_GREATERTHANOREQUAL64`.
- `update` assembly contains `OP_INSPECTINASSETLOOKUP` with sentinel guard and `OP_CHECKSIG`.

---

## Commit 6 — Array Types + Threshold Verification

### Primitive

```solidity
pubkey[] signers       // array type in constructor
signature[] sigs       // array type in function params
signers[i]             // indexing
signers.length         // compile-time known length
```

Arrays in constructor params have length known at compile time (baked into the script). Arrays in function params are witness data with length matching a constructor-defined bound.

### Changes

- **Grammar:** Extend `data_type` to allow `[]` suffix. Add `.length` as a property on identifiers.
  ```pest
  data_type = @{ base_type ~ ("[]")? }
  ```
- **AST:** Flag array types on `Parameter`. Add `ArrayIndex` and `ArrayLength` to `Expression`.
- **Compiler:** Flatten `pubkey[] signers` with length N into `signers_0, signers_1, ..., signers_N-1` in the compiled ABI. `signers[i]` resolves to `signers_{i}` when `i` is a literal or unrolled index. `signers.length` resolves to the literal N.

### Example: `threshold_oracle.ark`

Generic threshold signature verifier. N oracles, require M valid signatures over a message. Uses `for` to iterate and `if` to count.

```solidity
options {
  server = serverPk;
  exit = 288;
}

contract ThresholdOracle(
  bytes32 tokenAssetId,
  bytes32 ctrlAssetId,
  pubkey  serverPk,
  pubkey[] oracles,
  int     threshold
) {
  function attest(
    int amount,
    bytes32 messageHash,
    pubkey recipientPk,
    signature[] oracleSigs
  ) {
    require(amount > 0, "zero");

    int valid = 0;
    for (i, sig) in oracleSigs {
      if (checkSigFromStack(sig, oracles[i], messageHash)) {
        valid = valid + 1;
      }
    }
    require(valid >= threshold, "quorum failed");

    require(tx.inputs[0].assets.lookup(ctrlAssetId) > 0, "no ctrl");
    require(tx.outputs[1].assets.lookup(tokenAssetId) >= amount, "short");
    require(tx.outputs[1].scriptPubKey == new P2TR(recipientPk), "wrong dest");
    require(tx.outputs[0].scriptPubKey == tx.input.current.scriptPubKey, "broken");
  }
}
```

#### Unrolled assembly for quorum check (oracles.length = 3)

```asm
; valid = 0
OP_0                                     ; [valid(c)]

; --- i = 0 ---
<oracleSigs_0> <oracles_0> <messageHash>
OP_CHECKSIGFROMSTACK                     ; [valid(c), result(c)]
OP_IF
  OP_1 OP_ADD                            ; valid++
OP_ENDIF

; --- i = 1 ---
<oracleSigs_1> <oracles_1> <messageHash>
OP_CHECKSIGFROMSTACK
OP_IF
  OP_1 OP_ADD
OP_ENDIF

; --- i = 2 ---
<oracleSigs_2> <oracles_2> <messageHash>
OP_CHECKSIGFROMSTACK
OP_IF
  OP_1 OP_ADD
OP_ENDIF

; require(valid >= threshold)
<threshold>
OP_GREATERTHANOREQUAL OP_VERIFY          ; csn comparison (small numbers)
```

Note: The quorum counter `valid` stays as `csn` because it counts 0..N (small values), not asset amounts. `OP_GREATERTHANOREQUAL` (not the 64-bit variant) is correct here.

### ABI flattening

Constructor `pubkey[] oracles` with 3 elements becomes:

```json
{
  "constructorInputs": [
    { "name": "oracles_0", "type": "pubkey" },
    { "name": "oracles_1", "type": "pubkey" },
    { "name": "oracles_2", "type": "pubkey" }
  ]
}
```

Similarly, witness `signature[] oracleSigs` becomes `oracleSigs_0`, `oracleSigs_1`, `oracleSigs_2` in `witnessInputs`.

### Test: `tests/threshold_oracle_test.rs`

- `pubkey[]` and `signature[]` parsed correctly.
- Constructor ABI contains flattened `oracles_0`, `oracles_1`, `oracles_2`.
- Assembly contains N copies of `OP_CHECKSIGFROMSTACK` blocks.
- Threshold comparison uses `OP_GREATERTHANOREQUAL` (csn, not 64-bit).
- `for (i, sig) in oracleSigs` unrolls correctly.

---

## Commit Order and Dependencies

```
1. Asset Lookups            (no dependencies)
2. Asset Groups             (uses lookups from 1)
3. Arithmetic Expressions   (uses lookups from 1)
4. If/Else + Reassignment   (uses groups from 2, arithmetic from 3)
5. For Loops + Unrolling    (uses groups from 2, reassignment from 4)
6. Array Types + Threshold  (uses lookups from 1, if from 4, for from 5)
```

Each commit is independently testable. All six land in a single PR.

---

## Example Contracts Summary

| Commit | Example | Pattern Demonstrated |
|---|---|---|
| 1 | `token_vault.ark` | Recursive covenant, control asset retention, sentinel guards |
| 2 | `controlled_mint.ark` | Issuance (delta > 0), burn (delta < 0), supply lock (burn ctrl) |
| 3 | `fee_adapter.ark` | 64-bit arithmetic with operator precedence, overflow checks |
| 4 | `epoch_limiter.ark` | If/else branching, stack normalization, full reference assembly |
| 5 | `beacon.ark` | Compile-time loop unrolling, passthrough covenant |
| 6 | `threshold_oracle.ark` | Array flattening, for..in unrolling, quorum counting |
