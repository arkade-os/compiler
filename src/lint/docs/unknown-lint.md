A lint attribute that names a lint that does not exist, usually a typo.

The attribute then changes nothing.

Fix: use an id from `arkadec --explain` or the README's table of lints.

Reported on the lint name inside the attribute, so only an attribute on an enclosing node, such as the contract, applies to it, because a node's span excludes its own attributes.
