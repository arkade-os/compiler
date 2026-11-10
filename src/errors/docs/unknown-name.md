A name that no parameter, local, constant or field in scope declares, usually a typo.

The message suggests the closest name in scope when there is one, such as `ownr` → `owner`.

Fix: use the suggested name, declare the binding before its use, or pass it in as a parameter. A local declared in an `if` or loop body is visible only inside that block.
