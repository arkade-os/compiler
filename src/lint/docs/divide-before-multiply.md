`(a / b) * c`.

Integer division drops the remainder before the result is scaled, so the error grows with `c`.

Fix: multiply first, as `(a * c) / b`, after checking that the product stays in range.
