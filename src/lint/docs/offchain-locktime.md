`tx.locktime` read in a covenant.

arkd rebuilds offchain spends with an nLockTime of 0, so a condition on it does not mean what it says offchain.

Fix: use `checkTime(t)` for time in covenants, and `after(t)` in tapscript leaves.
