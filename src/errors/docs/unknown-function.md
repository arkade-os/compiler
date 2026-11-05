A call to a function that is neither a builtin nor a function of this contract or library, usually a typo such as `sha265` for `sha256`.

The message suggests the closest builtin or function name when there is one.

Fix: use the suggested name, or declare the helper as a `private function`. A function of an imported library is called as `Library.name(...)`.
