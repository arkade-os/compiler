A comparison, `&&` or `||` whose two operands are the same.

Its result never depends on them, which usually means one side names the wrong value.

Fix: compare with the value that was meant. Allow it when the comparison is only there to check an encoding, as `x == x` does for a script number.
