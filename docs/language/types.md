# Types

| Type | Meaning |
|---|---|
| `pubkey` | Alias of `bytes` for public keys; signature checks need the formats in [Keys and signatures](#keys-and-signatures) |
| `signature` | A signature; see [Keys and signatures](#keys-and-signatures) |
| `bytes`, `bytes20`, `bytes32` | Byte arrays, unsized or fixed |
| `int` | CScriptNum integer |
| `bool` | Boolean; an Arkade Script function's witness must be empty (false) or `0x01` (true), and any other encoding fails the spend |
| `AssetGroup` | An asset group of the transaction; a witness or constructor value is its packet position |
| `T[n]` | Fixed-size array of a scalar, struct or array type, `n` a positive integer literal or `int` constant; `T[a][b]` is `a` arrays of `T[b]` |
| `struct` | User-declared; nested structs and fixed-size arrays allowed |

## Keys and signatures

A `pubkey` holds any bytes, and the compiler checks the length only of constant keys. A key must have the format its signature check accepts:

| Where | Accepted keys |
|---|---|
| Tapscript leaf | 32-byte x-only keys |
| Arkade Script | 32-byte x-only keys (Schnorr), or 34-byte keys: a `0x10` (secp256k1 ECDSA) or `0x11` (P-256 ECDSA) tag byte and a 33-byte compressed point |

> [!WARNING]
> Instantiate every constructor `pubkey` a tapscript leaf uses with a 32-byte x-only key. BIP342 treats a key of any other non-zero length as an unknown key type and accepts any non-empty signature for it, and the compiler cannot check values supplied at instantiation. In Arkade Script, a key of another length fails the spend for any non-empty signature.

A `signature` is a 64-byte signature, or 65 bytes whose last byte is a non-zero sighash type. The compiler emits no length check for `signature` witnesses; the VM rejects other lengths when it verifies them.

## Native structs

| Struct | Fields |
|---|---|
| `AssetId` | `{txid: bytes32, gidx: int}` |
| `Outpoint` | `{txid: bytes32, vout: int}` |
| `ECPoint` | `{x, y}`, all `int` |
| `G2Point` | `{xC1, xC0, yC1, yC0}`, all `int` |
| `ScriptPubKey` | `{program: bytes, version: int}` |
| `AssetEntry` | `{assetId: AssetId, amount: int}` |
| `AssetLookup` | `{amount: int, found: bool}` |
| `AssetGroupInput` | `{type, index, amount}`, all `int` |
| `AssetGroupOutput` | `{type, index, amount}`, all `int` |

## Structs and arrays

- Arrays and structs can be constructor parameters, Arkade Script function parameters, or locals.
- Arrays contain scalars, structs, or arrays. Structs contain scalars, arrays, and nested structs, and need at least one field.
- Sizes read in index order: `int[2][3] m` has `m.length == 2`, each `m[i]` is an `int[3]`, `m[1][2]` is its last element, and `[[1, 2, 3], [4, 5, 6]]` is an `int[2][3]` literal.
- Tapscript inputs are scalars.

### Struct literals

Struct literals work wherever an expression does, for any user-declared or native struct: `let id = AssetId { txid: t, gidx: 0 };`, as a call argument, nested in another literal, or compared with `==`.

An unnamed literal such as `{ txid: t, gidx: 0 }` takes the type its position expects:

- a typed declaration or assignment;
- a helper parameter or return type;
- a builtin operand;
- an enclosing literal's field;
- the other side of `==`.

### Field and index access

- Indexed fields support literal and runtime indexes, such as `items[0].value` and `items[index].value`.
- Helper results and native structs take the same suffixes, such as `make().value`, `getArray()[i]` and `tx.outputs[0].script.version`, evaluating each base and index once.

### Assignment

Local arrays, structs, and Arkade Script function parameters support whole-value reassignment from matching values, helper results, and literals, such as `values = [1, 2, 3];` or `sc = ecAdd(sc, point, 0);`.

- Array element types and lengths must match the destination.
- Nested fields and indexed composite elements support the same assignments.
- The full right-hand side is evaluated before replacing any fields.
- Constructor parameters remain immutable.

### Comparison

Whole arrays and structs support `==` and `!=` when both sides have the same declared type. These comparisons return `bool` and work in bindings, conditions, helper returns, and short-circuit expressions such as `require(left == right || fallback);`.

## Casts and widening

Type errors are fatal. Equality needs matching types, except that `bytes20`, `bytes32`, `pubkey`, and `signature` widen implicitly to `bytes`, including in bindings, arguments, and `+` concatenation. Two different sized types, such as `bytes20` and `bytes32`, never compare.

| Cast | Effect |
|---|---|
| `bytes20(x)`, `bytes32(x)` | Narrows a `bytes` value and verifies the length at runtime with `OP_SIZE <n> OP_EQUALVERIFY` |
| `pubkey(x)`, `signature(x)` | Narrows a `bytes` value with no opcodes, because the VM validates keys and signatures when they are consumed |
| `int(0x...)` | Reads a hex literal big-endian and folds it to a decimal constant, so `int(0x0100)` is `256` |
| `int(flag)`, `bool(n)` | Emits `OP_0NOTEQUAL`, so the result is always `0` or `1`, even for a spender-supplied witness value |
| `bytes(n)` of an `int` | Minimal little-endian signed-magnitude Script-number bytes, normalizing spender-supplied encodings: `bytes(0)` is empty, `bytes(128)` is `0x8000`, and `bytes(-128)` is `0x8080` |
| `bytes(flag)` of a `bool` | Empty bytes for false or `0x01` for true, emitting `OP_0NOTEQUAL` to normalize numeric truth values; inputs must be minimally encoded, as for `int(flag)` |
| `bytes(x)`, `pubkey(x)` of a bytes-like value | Widens it unchanged, signatures included, with no additional opcodes |

Casting a value to its own type, such as `int(42)` or `bytes20(hash)`, is a no-op.

For other conversions:

- use `bytes2int` or `bytes2uint` to convert bytes to an integer, and `int2bytes(n, width)` for fixed-width output (see [Bytes](builtins.md#bytes));
- compare `bool` values with `true` or `false`.
