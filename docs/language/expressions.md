# Expressions

## Operators

| Operators | Operands | Notes |
|---|---|---|
| `+`, `-`, `*`, `/`, unary `-` | `int` | |
| `%` | `int` | Takes the sign of the dividend, so `-7 % 2 == -1` |
| `<<`, `>>` | `int` | The count must not be negative; `>>` is arithmetic, rounding toward negative infinity |
| `&`, `\|`, `^` | bytes | Operands must have equal length, checked at compile time when both lengths are known and by the VM otherwise |
| unary `~` | bytes | |
| `+` | bytes | Concatenation; see [Byte concatenation](#byte-concatenation) |
| `==`, `!=`, `<`, `<=`, `>`, `>=` | | See [Comparison](#comparison) |
| `!`, `&&`, `\|\|` | `bool` | In Arkade Script functions; see [Short-circuit evaluation](#short-circuit-evaluation) |

### Precedence

From highest to lowest:

1. unary operators
2. `*`, `/`, `%`
3. `+`, `-`
4. `<<`, `>>`
5. `&`
6. `^`
7. `|`
8. comparisons
9. `&&`
10. `||`

Parentheses override it. `a & mask == b` means `(a & mask) == b`.

### Comparison

- `==` and `!=` compare `int`, `bool`, and `AssetGroup` values as numbers (`OP_NUMEQUAL`, `OP_NUMNOTEQUAL`), so a spender-supplied number that is not minimally encoded fails the spend.
- Bytes-like values compare byte for byte.
- Structs and arrays compare corresponding scalar leaves using the same rule.
- `<`, `<=`, `>` and `>=` take only `int`.
- Comparisons do not chain: `a < b < c` is a syntax error.

### Short-circuit evaluation

Logical operators evaluate left to right and short-circuit:

- `&&` skips the right operand when the left is false.
- `||` skips the right operand when the left is true.

Both operands must be valid boolean expressions even when one is skipped.

### Byte concatenation

`+` on byte operands is concatenation. Mixing an `int` into a byte concatenation is an error until you convert it explicitly, because the encoding is consensus-visible:

- `bytes(value)` for minimal Script-number encoding;
- `int2bytes(value, width)` for fixed-width encoding.

### Lengths and indexes

- `arr.length` folds to the declared size.
- `.length` on a bytes-like value is its byte length, the same as `size(value)`.
- Array reads and writes accept `int` index expressions. Runtime indices emit bounds checks.

## When evaluation fails

Evaluation yields a value or fails the spend, and nothing catches a failure. `&&`, `||` and `if` avoid one only by not evaluating the skipped operand or branch.

Each builtin function and `tx`/`this` member states in its doc when it fails the spend, and `arkadec --builtins` prints them all. Neither the docs nor this page cover integer encoding or every VM size and compute limit.

### Signature checks

- `checkSig` and `checkMultisig` fail the spend on an empty pubkey, and otherwise return `false` for an empty signature.
- `checkSigFromStack` returns `false` for an empty signature whatever the pubkey.
- All three fail the spend on an invalid non-empty signature.

### Value reads

Each value read fails the spend when the value is absent. Its presence test reports absence instead:

| Read | Presence test |
|---|---|
| `.assets.lookup(id)` | `.assets.has(id)`, `.assets.tryLookup(id).found` |
| `tx.assetGroups.lookup(id)` | `tx.assetGroups.has(id)` |
| `controlAssetId` | `hasControl` |
| `tx.packet(type)` | `tx.packet.has(type)` |
| `tx.inputs[i].packet(type)` | `tx.inputs[i].packet.has(type)` |
| `tx.intent.field(path)` | `tx.intent.has(path)` |

### Outside the builtins

These fail the spend:

- `require` of a false condition;
- `/` or `%` by zero;
- a negative shift count;
- bytewise operands of unequal length;
- a byte concatenation over 520 bytes;
- a runtime index out of range;
- `bytes20(x)` or `bytes32(x)` of another length;
- an Arkade Script function's witness value, including a struct field or array element, that is a `bytes20` or `bytes32` of another length, or a `bool` other than empty or `0x01`.

A literal zero divisor, a negative literal shift count, or bytewise operands of known unequal lengths are a compile error instead.
