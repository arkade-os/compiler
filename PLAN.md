# Arkade Asset Primitives — Implementation Plan

Single PR on `claude/add-contract-support-crNr1`, one commit per feature.
Each commit adds grammar + parser + AST + compiler + example `.ark` + test.
Existing tests must pass after every commit.

---

## Commit 1 — Asset Lookups on Inputs/Outputs

### Primitive

```solidity
tx.inputs[i].assets.lookup(assetId)   // → amount or -1
tx.outputs[o].assets.lookup(assetId)  // → amount or -1
```

### Opcodes

| Arkade Script | Opcode |
|---|---|
| `tx.inputs[i].assets.lookup(id)` | `OP_INSPECTINASSETLOOKUP i id.txid id.gidx` |
| `tx.outputs[o].assets.lookup(id)` | `OP_INSPECTOUTASSETLOOKUP o id.txid id.gidx` |

### Changes

- **Grammar:** Extend `tx_property_access` to parse `.assets.lookup(expr)` after `inputs[i]` / `outputs[o]`.
- **AST:** Add `AssetLookup { source: InputOrOutput, index: Expression, asset_id: Expression }` to `Expression`.
- **Compiler:** Emit the corresponding lookup opcode with the resolved asset ID.

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

### Test: `tests/token_vault_test.rs`

- Contract parses and compiles.
- 4 functions emitted (2 functions x 2 variants).
- Assembly contains `OP_INSPECTOUTASSETLOOKUP` and `OP_INSPECTINASSETLOOKUP`.

---

## Commit 2 — Asset Groups

### Primitive

```solidity
let group = tx.assetGroups.find(assetId);  // locate group by ID
tx.assetGroups.length                       // group count in packet
tx.assetGroups[k].sumInputs                 // total input amounts
tx.assetGroups[k].sumOutputs                // total output amounts
tx.assetGroups[k].delta                     // sumOutputs - sumInputs
tx.assetGroups[k].control                   // control asset ID or -1
tx.assetGroups[k].metadataHash              // immutable genesis metadata root
tx.assetGroups[k].isFresh                   // true if new genesis
```

### Opcodes

| Arkade Script | Opcode |
|---|---|
| `tx.assetGroups.find(id)` | `OP_FINDASSETGROUPBYASSETID txid gidx` |
| `tx.assetGroups.length` | `OP_INSPECTNUMASSETGROUPS` |
| `group.sumInputs` | `OP_INSPECTASSETGROUPSUM k 0` |
| `group.sumOutputs` | `OP_INSPECTASSETGROUPSUM k 1` |
| `group.delta` | `OP_INSPECTASSETGROUPSUM k 1` `OP_INSPECTASSETGROUPSUM k 0` `OP_SUB` |
| `group.control` | `OP_INSPECTASSETGROUPCTRL k` |
| `group.metadataHash` | `OP_INSPECTASSETGROUPMETADATAHASH k` |
| `group.assetId` | `OP_INSPECTASSETGROUPASSETID k` |

### Changes

- **Grammar:** Add `assetGroups` as a `tx_special_property`. Parse `.find(expr)`, `[k]` indexing, and group property access (`.delta`, `.control`, etc.). Add `let_binding` statement: `let identifier = expr;`.
- **AST:** Add `LetBinding { name, value }` to statement types. Add `GroupFind`, `GroupProperty` to `Expression`.
- **Compiler:** Emit group introspection opcodes. Derive `.delta` from two `OP_INSPECTASSETGROUPSUM` calls.

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
- `lockSupply` assembly contains `OP_INSPECTASSETGROUPSUM k 1` with literal `0` comparison.

---

## Commit 3 — Arithmetic Expressions

### Primitive

Operator precedence and parenthesized sub-expressions.

```solidity
int net = amount - (amount * feeBps / 10000);
```

`*` and `/` bind tighter than `+` and `-`. Parentheses override.

### Changes

- **Grammar:** Rewrite expression rules with precedence levels:
  ```pest
  expression       = { comparison_expr }
  comparison_expr  = { additive_expr ~ (comparison_op ~ additive_expr)? }
  additive_expr    = { multiplicative_expr ~ (("+" | "-") ~ multiplicative_expr)* }
  multiplicative_expr = { unary_expr ~ (("*" | "/") ~ unary_expr)* }
  unary_expr       = { atom ~ postfix* }
  atom             = { "(" ~ expression ~ ")" | function_call | number_literal | identifier | ... }
  ```
- **AST:** Add `BinaryOp { left: Box<Expression>, op: String, right: Box<Expression> }` to `Expression`.
- **Compiler:** Recursive codegen — emit left, emit right, emit opcode (`OP_ADD`, `OP_SUB`, `OP_MUL`, `OP_DIV`).

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

### Test: `tests/fee_adapter_test.rs`

- Variable `net` is computed from `amount - (amount * feeBps / 10000)`.
- Assembly contains `OP_MUL`, `OP_DIV`, `OP_SUB` in correct precedence order.

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
- **Compiler:** Emit `OP_IF ... OP_ELSE ... OP_ENDIF`.

### Example: `epoch_limiter.ark`

Rate limiter that resets or accumulates per epoch. State carried as asset quantities.

```solidity
options {
  server = serverPk;
  exit = 288;
}

contract EpochLimiter(
  bytes32 epochAssetId,
  bytes32 totalAssetId,
  int     epochLimit,
  int     epochBlocks,
  pubkey  adminPk,
  pubkey  serverPk
) {
  function check(int transferAmount) {
    require(transferAmount > 0, "zero");

    int epochStart = tx.assetGroups.find(epochAssetId).sumInputs;
    int epochTotal = tx.assetGroups.find(totalAssetId).sumInputs;

    if (tx.time >= epochStart + epochBlocks) {
      // New epoch: reset
      require(tx.assetGroups.find(epochAssetId).sumOutputs == tx.time, "not reset");
      require(tx.assetGroups.find(totalAssetId).sumOutputs == transferAmount, "total wrong");
      require(transferAmount <= epochLimit, "exceeds limit");
    } else {
      // Same epoch: accumulate
      int newTotal = epochTotal + transferAmount;
      require(tx.assetGroups.find(epochAssetId).sumOutputs == epochStart, "start mutated");
      require(tx.assetGroups.find(totalAssetId).sumOutputs == newTotal, "total wrong");
      require(newTotal <= epochLimit, "exceeds limit");
    }

    require(tx.outputs[0].scriptPubKey == tx.input.current.scriptPubKey, "broken");
  }
}
```

### Test: `tests/epoch_limiter_test.rs`

- 2 functions emitted (1 x 2 variants).
- Assembly contains `OP_IF`, `OP_ELSE`, `OP_ENDIF`.
- Both branches emit correct asset group sum checks.

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
  for_stmt = { "for" ~ "(" ~ identifier ~ "," ~ identifier ~ ")" ~ "in" ~ identifier ~ block }
  ```
- **AST:** Add `ForIn { index_var, value_var, array, body }` to statements.
- **Compiler:**
  1. Resolve `array` to a constructor parameter.
  2. Determine length (from type annotation or companion `length` param).
  3. Emit `body` N times with `index_var` replaced by literal and `value_var` replaced by `array[i]`.
  4. Error if length is not statically known.

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

    int k = 0;
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

With `numGroups = 3`, the compiler unrolls `passthrough` into:

```
// k = 0
OP_INSPECTASSETGROUPSUM 0 1    // group 0 sumOutputs
OP_INSPECTASSETGROUPSUM 0 0    // group 0 sumInputs
OP_GREATERTHANOREQUAL
OP_VERIFY
// k = 1
OP_INSPECTASSETGROUPSUM 1 1
OP_INSPECTASSETGROUPSUM 1 0
OP_GREATERTHANOREQUAL
OP_VERIFY
// k = 2
OP_INSPECTASSETGROUPSUM 2 1
OP_INSPECTASSETGROUPSUM 2 0
OP_GREATERTHANOREQUAL
OP_VERIFY
```

### `for` over `tx.assetGroups`

When the iterable is `tx.assetGroups`, the compiler uses `numGroups` (or `tx.assetGroups.length` resolved from a constructor param) as the unroll bound. The `group` variable binds to `tx.assetGroups[k]` at each iteration.

### Test: `tests/beacon_test.rs`

- `passthrough` assembly length scales with `numGroups`.
- `update` assembly contains `OP_INSPECTINASSETLOOKUP` and `OP_CHECKSIG`.

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
- **Compiler:** Flatten `pubkey[] signers` with length N into `signers_0, signers_1, ..., signers_N-1` in the compiled output. `signers[i]` resolves to `signers_{i}` when `i` is a literal or unrolled index. `signers.length` resolves to the literal N.

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

With `oracles.length = 3`, the compiler unrolls into:

```
0                                       // valid = 0
<oracleSigs_0> <oracles_0> <messageHash> OP_CHECKSIGFROMSTACK
OP_IF 1 OP_ADD OP_ENDIF
<oracleSigs_1> <oracles_1> <messageHash> OP_CHECKSIGFROMSTACK
OP_IF 1 OP_ADD OP_ENDIF
<oracleSigs_2> <oracles_2> <messageHash> OP_CHECKSIGFROMSTACK
OP_IF 1 OP_ADD OP_ENDIF
<threshold> OP_GREATERTHANOREQUAL OP_VERIFY
```

### Test: `tests/threshold_oracle_test.rs`

- `pubkey[]` and `signature[]` parsed correctly.
- Assembly contains N copies of `OP_CHECKSIGFROMSTACK` blocks.
- Threshold comparison emitted after the unrolled loop.

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
|--------|---------|---------------------|
| 1 | `token_vault.ark` | Recursive covenant, control asset retention, token accounting |
| 2 | `controlled_mint.ark` | Issuance (delta > 0), burn (delta < 0), supply lock (burn ctrl) |
| 3 | `fee_adapter.ark` | Fee calculation with operator precedence |
| 4 | `epoch_limiter.ark` | Conditional state mutation, epoch reset vs accumulate |
| 5 | `beacon.ark` | Read-only beacon, iterate all groups, passthrough covenant |
| 6 | `threshold_oracle.ark` | Generic N-of-M threshold signature verification |
