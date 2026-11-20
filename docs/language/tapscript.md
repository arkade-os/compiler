# Tapscript functions

A `function name(<params>) tapscript { ... }` compiles to an L1 tapleaf of plain Bitcoin Script. [Spend groups](functions.md#spend-groups) explains how leaves join Arkade Script functions.

## Body shape

A tapscript body is `require` statements only, and must follow the closure template in source order:

1. an optional single hash condition;
2. an optional single timelock;
3. exactly one `checkSig` or `checkMultisig`.

Hash plus CSV is a recognized shape. Hash plus CLTV is not, so split it into two leaves.

arkd accepts only N-of-N leaves, so a tapscript `checkMultisig([keys], [sigs])` takes no threshold, and each signature must be a declared `signature` input aligned 1:1 with its key.

## Fixed values and witness values

The leaf script is fixed when the address is made, and the witness is supplied when it is spent. So:

| Element | Must be |
|---|---|
| Hash value | A byte literal or constant of the digest's width, or a scalar constructor parameter |
| Timelock | A number, a scalar constructor parameter, or `operatorExitDelay` in `older(...)` without a unit |
| Key | One of the [keys](#keys) below |

A tapscript input used as a key, hash value or timelock is an error. The hash preimage and the signatures are tapscript inputs, which the leaf consumes from the witness, so a leaf may use each tapscript input only once.

Tapscript hashlocks use `require(hashFn(preimage) == hash)` with `sha256`, `hash256`, `hash160`, or `ripemd160`. A `bytes32` or `bytes20` preimage input makes the leaf check its length with `OP_SIZE <n> OP_EQUALVERIFY`; a `bytes` preimage may have any length.

Timelocks use `older(n)` and `after(n)`; see [Time](builtins.md#time).

## Keys

| Key | Pushes |
|---|---|
| A constructor `pubkey` parameter `k`, or a struct field or array element of one | `<k>`, `<k.field>` or `<k.0>` |
| A 32-byte `pubkey` constant | Its bytes |
| `operator` | The untweaked `<OPERATOR_KEY>` |
| `tweak(operator, fn)` | `<OPERATOR_KEY:fn>` |
| `tweak(k, fn)`, for a constructor pubkey parameter named `k` | `<TWEAK:k:fn>` |

A constant key must be a 32-byte x-only key: a tapscript signature check accepts any signature for a key of another non-zero length, so other lengths are a compile error. The compiler cannot check constructor keys, so instantiate them with 32-byte x-only keys too; see [Keys and signatures](types.md#keys-and-signatures).

## Binding a leaf to an Arkade Script function

- Any leaf without a CSV delay is a forfeit path and must include `operator` or `tweak(operator, fn)`. Any `older(...)` counts as a CSV delay, even one whose delay is zero; `blocks(n)` and `seconds(n)` reject zero.
- A leaf whose name matches an Arkade Script function must tweak at least one key to that function, so it binds the function's Arkade Script. Bare `operator` is never tweaked implicitly.
- Such a leaf must also have no CSV delay. A CSV leaf sits beside the function's synthesized leaf, which carries the function's name, so give it another name. It still joins the function's spend group through its tweak.
- A leaf with no matching Arkade Script function either stays standalone or binds to one Arkade Script function with `tweak(operator, fn)` or `tweak(constructorPubkey, fn)`.
- Every tweak in a tapscript must name that same function.

## Reserved names

- `operator` is the reserved key role the Arkade operator signs for.
- `older(operatorExitDelay)` uses the operator's unilateral exit delay and lowers to `<OPERATOR_EXIT_DELAY>`, which the SDK fills from the operator's config.

Constructor parameters, constants and tapscript inputs named `operator` or `operatorExitDelay` are rejected. Arkade Script function parameters may use those names.
