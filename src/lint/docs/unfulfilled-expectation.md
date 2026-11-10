An `@expect` whose lint does not fire where it applies.

The code it excused has changed, so the expectation and its reason are stale.

Fix: remove the `@expect`, or move it to where the lint now fires.

Reported on the lint name inside the @expect attribute, so only an attribute on an enclosing node, such as the contract, applies to it, because a node's span excludes its own attributes.
