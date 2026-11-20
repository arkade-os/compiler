# Syntax, literals and constants

## File layout

```solidity
pragma arkade ^0.1.0;        // optional, before imports and declarations
import "./other.ark";        // zero or more; imports a file's declarations
struct Name { ... }          // zero or more, before the contract or library
contract Name(<params>) {    // entry files require a contract
  function ...
}
// Imported files may declare a library instead, or just structs:
// library Name { ... }
```

[Imports and libraries](modules.md) covers how files see each other. A contract, library, function or statement may be preceded by [lint attributes](../lints.md#in-source) such as `@allow(...)`.

## Lexical rules

- **Comments** run from `//` to the end of the line, or from `/*` to the next `*/`. Block comments do not nest.
- **Identifiers** start with an ASCII letter and contain ASCII letters, digits, and underscores.
- **Number literals** are decimal integers without leading zeros. `_` may separate two digits, as in `1_000_000`, which is the value `1000000`.
- **Trailing commas** are accepted once after the last element of every comma-separated list, such as parameters, call arguments, array and struct literals, and attribute arguments.
- **Double-quoted strings** are `bytes` literals in expressions and declarations (see [Byte literals](#byte-literals)). They also serve as `import` paths and `require` messages.
- **Reserved names.** Parameters, locals, loop variables and tapscript inputs cannot be named after a keyword or type (`int`, `bool`, `bytes`, `bytes20`, `bytes32`, `pubkey`, `signature`, `contract`, `library`, `function`, `struct`, `require`, `if`, `else`, `for`, `in`, `return`, `const`, `let`, `import`, `pragma`, `true`, `false`, `tapscript`, `private`, `static`, `tx`, `this`) or a placeholder (`OPERATOR_KEY`, `OPERATOR_EXIT_DELAY`). Helpers cannot be named after a builtin or cast. [Tapscript functions](tapscript.md#reserved-names) reserves `operator` and `operatorExitDelay` too.

## Version pragma

Each source file, including imported libraries and struct-only files, may start with one `pragma arkade <constraint>;` directive. It is optional, and files compile without one. Comments and whitespace may precede it.

Use three-component versions such as `0.1.0`:

| Constraint | Matches |
|---|---|
| `0.1.0`, `=0.1.0` | Exactly that version |
| `>`, `>=`, `<`, `<=` | By comparison |
| `^1.2.3` | Changes that keep the first nonzero component: `^1.2.3` is `>=1.2.3 <2.0.0`, `^0.1.2` is `>=0.1.2 <0.2.0`, `^0.0.3` is `>=0.0.3 <0.0.4` |
| `~1.2.3` | Patch changes: `>=1.2.3 <1.3.0` |
| `>=0.1.0 <0.2.0` | All space-separated constraints |
| `^0.1.0 \|\| ^0.2.0` | Any alternative separated by `\|\|` |

Version components cannot have leading zeroes. Partial versions, wildcards, prerelease versions, and build metadata are not supported.

The compiler checks the pragma of every file it loads, the entry and each import, against its own version:

- It rejects a file whose pragma it does not satisfy with an error at that pragma.
- It checks the pragma before parsing the rest of the file, so a file written for a newer compiler reports the version mismatch rather than syntax this compiler does not know.
- Only the compiler's major.minor.patch counts, so `0.1.0-rc.1` satisfies `^0.1.0`.

Pragmas apply to their own file, remain verbatim in the artifact's source bundle, and do not affect generated scripts.

## Byte literals

Double-quoted strings and `0x` hex literals have type `bytes20` or `bytes32` when their encoded length is exactly 20 or 32 bytes, and `bytes` otherwise.

- Strings use UTF-8 and JSON escapes (`\"`, `\\`, `\n`, `\r`, `\t`, `\b`, `\f`, `\/`, and `\uXXXX`).
- Hex literals accept either digit case and require at least one complete byte pair.
- `""` is empty bytes.

```ark
bytes x = "hello";
bytes y = 0xdeadbeef;
bytes z = 0xDEADBEEF;
require(x == 0x68656c6c6f);
require(size("ž") == 2);
require(sha256("hello" + 0x00) == expectedHash);
```

Literals work in byte expressions, calls, comparisons, arrays, structs, and constants.

- Sized literals widen implicitly to `bytes`, including its `pubkey` alias, and casts to their inferred type add no runtime length check.
- Literals do not implicitly become `int` or `signature`.
- Assembly stores byte data as `0x`-prefixed hex tokens and empty bytes as `OP_0`. Consumers must decode these tokens as data pushes, preserving leading zeros.

## Constants

```solidity
const int EXIT_DELAY = 144;
const int HALF_DELAY = EXIT_DELAY / 2;
const int KEY_COUNT = 2;
const bool STRICT = HALF_DELAY > 0;
const bytes32 LOCK_HASH = 0x2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824;
```

Constants are compile-time expressions of type `int`, `bool`, `bytes`, `bytes20`, `bytes32`, or `pubkey`, declared anywhere in the contract body. The compiler substitutes their values before validation, so they occupy no constructor or witness inputs.

Constants are immutable, and their names must be distinct from all other bindings and function names in the contract.

### Initializers

An initializer may use:

- literals;
- references to local or imported constants, including forward references;
- parentheses;
- arithmetic: `+`, `-`, `*`, `/`, `%`, `<<`, `>>`, unary `-`;
- comparisons;
- boolean logic: `!`, `&&`, `||`;
- `int(0x...)` of a hex literal.

Byte constants accept a literal or another byte constant.

- A `bytes20` or `bytes32` initializer must be exactly 20 or 32 bytes.
- `pubkey` is an alias of `bytes` that must not be empty.
- A reference has the type of its value, so a `bytes32` constant is accepted where `bytes32` is expected.

### Evaluation

- Integer literals, negation, and equality are unbounded like BigNum literals.
- Arithmetic and ordering use checked signed 128-bit values. Division truncates toward zero, and `%` takes the sign of the dividend.
- Cycles, runtime values, and type mismatches are rejected, even in skipped operands.
- Division or modulo by zero and arithmetic overflow are rejected when evaluated.

### Where constants are allowed

A constant is readable in:

- Arkade Script function bodies and private and static helpers;
- array indices, including crypto operands;
- multisig thresholds;
- `new Contract(...)` arguments;
- a tapleaf's `older(...)` or `after(...)` operand, hashlock value, or signature key.

So a delay shared by an Arkade Script function and its L1 exit is written once.

Array sizes accept positive integer literals or `int` constants, such as `pubkey[KEY_COUNT]`, `int[Config.SIZE]` or `int[ROWS][COLS]`, in constructor parameters, function parameters, struct fields, and local declarations.

```solidity
contract Vault(pubkey owner) {
    const int EXIT_DELAY = 144;

    static function pct(int amount, int bps) int {
        return amount * bps / 10000;
    }

    function spend(signature sig, int amount) {
        require(checkSig(sig, owner));
        require(pct(amount, 50) > 0);
    }

    function exit(signature sig) tapscript {
        require(older(EXIT_DELAY));
        require(checkSig(sig, owner));
    }
}
```
