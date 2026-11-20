# Functions and statements

## Kinds of function

```solidity
function name(<params>) { ... }                // Arkade Script function: an Arkade transaction entrypoint
private function name(<params>) { ... }        // Void helper
private function name(<params>) bool { ... }   // Helper with a typed result
static function name(<params>) int { ... }     // Helper without access to constructor state
function name(<params>) tapscript { ... }      // L1 tapleaf, plain Bitcoin Script
```

Public functions define entrypoints:

- **Arkade Script functions** have no modifier and define transaction entrypoints.
- **Tapscript functions** define L1 leaves; see [Tapscript functions](tapscript.md).

Private and static functions are [helpers](#helpers). Functions can be declared in any order; call graphs must be acyclic.

- An Arkade Script function cannot declare a return type or be called.
- Every parameter of an Arkade Script function or helper, and every tapscript input, must be read; an unread one is an error (see the `unused-variable` [lint](../lints.md)).

## Spend groups

An Arkade Script function and its tapscript functions form one spend group. Its tapscript functions are:

- a tapscript function whose name matches it;
- a tapscript function that tweaks a key to it.

The group keeps a synthesized `checkSig(operatorSig, tweak(operator, name))` leaf unless one of those tapscripts has no CSV delay. An offchain spend sets nSequence final, so a CSV leaf is never an offchain path. It sits beside the synthesized leaf, which keeps the Arkade Script reachable offchain.

A tapscript that tweaks nothing is a standalone leaf, which is how unilateral exits are written.

## Every path must `require`

Every spend path must contain at least one `require`, directly or through a helper that enforces a requirement on every path. A path through an `if` without `else`, or through an `else` with no `require`, is rejected as a bare path unless a `require` before or after the `if` covers it.

## Helpers

Private functions are helpers called from Arkade Script functions and other private helpers in the same contract. Calls inline into the caller's script.

| Helper | Sees |
|---|---|
| `private function` | Its own parameters and locals, plus immutable constructor state |
| `static function` | Only its own parameters, locals, and compile-time constants |

- Static helpers can call other static helpers and are accessible through imports.
- Both kinds use the same inlining and return rules.
- Arguments are evaluated once, left to right, and passed by value. Modifying a parameter changes the helper's local copy.

### Return values

- A helper's return type follows its parameter list and can be a scalar, fixed-size array, or struct.
- Every path through a value-returning helper must return a compatible value, and each call's result must be used.
- Void helpers use `return;` or fall through. `return` is allowed only in helpers.
- Early returns exit the helper and resume the caller.
- To enforce a boolean result, use `require(predicate(...));`.

```solidity
contract Minimum(int minimum) {
    private function sufficient(int amount) bool {
        return amount >= minimum;
    }

    function spend(int amount) {
        require(sufficient(amount));
    }
}
```

## Statements

Arkade Script function bodies accept these statements. Tapscript bodies are more restricted; see [Tapscript functions](tapscript.md).

```solidity
require(<expr>);
require(<expr>, "message");
let x = <expr>;                    // inferred type
int fee = amount / 100;            // declared type
int result;                       // no value or stack slot until assignment
Policy p = { primary: {...}, limits: [1, 2], exitDelay: 10 };
let q = Point { x: 1, y: 2 };      // named struct literal
int[3] scale = [1, 2, 3];
x = <expr>;                        // reassignment keeps the declared type
scale[x + 1] = 10;                 // runtime index with bounds checking
p.primary.weight = 5;
if (<expr>) { ... } else if (<expr>) { ... } else { ... }
for (i, item) in arr { ... }       // unrolled at compile time
for (COUNT) { ... }                // COUNT is a positive compile-time int expression
for (i) in START..END { ... }      // i is START, START + 1, ..., END - 1
check(amount);                     // void helper call
Fees.check(amount);                // void library function call
```

- Each live binding has a unique name.
- Constructor parameters are immutable.
- `if` conditions must be `bool`.
- A `require` message emits nothing into the script; it appears only in the [debug file](../artifact.md#debug-file). Tapscript functions drop it.
- `for (i, item) in arr` evaluates a helper result or literal `arr` once, and checks a runtime index when the loop starts. Each use of `item` reads `arr[i]` as it currently is, so writes to `arr` in the body are seen.
- `for (i) in START..END` binds only the read-only `int` index, a literal in each unrolled copy. `START` and `END` are non-negative compile-time int expressions with `START < END`; `END` is exclusive. A range is valid only there, and `for (i) in arr` or `for (i, item) in START..END` is an error.
- A loop that runs zero times, such as `for (0)` or `for (i) in N..N`, is a compile error, because its body and every check in it would be silently dropped.
- A loop may unroll at most 10,000 iterations, counting the loops nested in it and in the helpers it calls, so `for (101) { for (100) { ... } }` is a compile error.

### Declaring without a value

Typed locals may omit the initializer: `int result;`, `Policy policy;`, or `int[3] values;`. Inferred `let` bindings still require an initializer.

- A declaration emits no assembly. The first assignment binds the computed value directly, without zero filling or replacing a placeholder.
- Every read must follow initialization on all paths that reach it.
- Both continuing branches of an `if` must initialize the binding.
- Separate conditions are checked independently, even if their predicates match.
- Arrays and structs must first receive a whole value before their fields or elements can be read or reassigned. Their static `.length` is available before initialization.
