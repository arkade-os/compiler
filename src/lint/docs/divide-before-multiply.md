`(a / b) * c`.

Integer division drops the remainder before the result is scaled, so the error grows with `c`.

Fix: multiply first, as `(a * c) / b`, after checking that the product stays in range.

Reported on the multiplication, so an attribute on the statement holding it, its function or the contract applies to it.
