A multi-result inspection, such as `tx.outputs[0].script`, read more than once in one function.

Each read runs the inspection opcode again.

Fix: bind the whole result once and read its fields.

```solidity
let script = tx.outputs[0].script;
require(script.version == 1 && script.program == expected);
```

Reported on the first of the repeated reads, so an attribute on the statement holding it, its function or the contract applies to it.
