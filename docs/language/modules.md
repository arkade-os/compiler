# Imports and libraries

## Imports

Imports use explicit `.ark` paths relative to the importing file. Paths use `/` and contain no `\` or `:`. With in-memory sources, as in the WASM and Rust `compile_sources` APIs, they cannot leave the source root.

- Each file may declare top-level structs and at most one contract or library.
- An import exposes those structs, the declaration's constants and exported helpers, and a contract's constructor through `new Contract(...)`.
- The entry contract defines the artifact's spend groups; imported files supply reusable definitions.

```solidity
// types.ark
struct Policy { int maximum; }
```

```solidity
// fees.ark
library Fees {
    const int MINIMUM = 10;
    function calculate(int amount) int { return amount / 100; }
}
```

```solidity
// vault.ark
import "./types.ark";
import "./fees.ark";

contract Vault(Policy policy) {
    function spend(int amount) {
        require(amount >= Fees.MINIMUM);
        require(Fees.calculate(amount) <= policy.maximum);
    }
}
```

### Scope

- Structs use their declared names; constants and exported helpers use `Name.member`.
- Each file sees its own declarations and its direct imports.
- Dependencies load recursively, and imported code keeps its defining scope.
- Helpers inline into Arkade Script functions. Constants fold into literals, including in tapscript timelocks.

### Loading

- Struct, contract, and library names must be unique across loaded files.
- The compiler loads each normalized path once.
- Missing files, unknown members, namespace collisions, and circular imports are errors.
- Import chains have a maximum depth of 128 files, including the entry file.

### Instantiating an imported contract

`new Contract(args...)` refers to a directly imported contract, which must compile as an entry file would, its own lint attributes included. The compiler checks constructor argument counts and types and emits a contract placeholder for the runtime to resolve. See [Instantiation](builtins.md#instantiation).

## Libraries

A `library Name { ... }` groups reusable constants and functions without constructor parameters or spend entrypoints. Import its `.ark` file and call exported functions as `Name.function(...)`.

A library cannot be instantiated with `new`, declare tapscripts, or serve as the compilation entry file.

```solidity
library Fees {
    const int BASIS = 10000;

    function calculate(int amount, int bps) int {
        checkRate(bps);
        return amount * bps / BASIS;
    }

    private function checkRate(int bps) {
        require(bps >= 0);
        require(bps <= BASIS);
    }
}
```

### Library functions

- A plain `function` is exported; a `private function` is callable only within its defining library.
- Local helper calls can be unqualified or use the library's own name, including calls to private helpers.
- Library functions take no `static` modifier, since all of them are stateless. They see their parameters, locals, and constants, and can inspect the transaction and enforce `require` checks.
- They cannot capture a calling contract's constructor state. Pass any required contract state as arguments.
- Calls inline using the [helper return and recursion rules](functions.md#helpers). Library functions never create ABI entrypoints or witness inputs of their own.
- Library constants can also be used in tapscripts, but helper calls remain limited to Arkade Script functions.

Libraries can import other libraries, contracts, and struct files using the same direct-import scope rules.
