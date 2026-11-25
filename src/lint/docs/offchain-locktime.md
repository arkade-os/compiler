`tx.locktime` read in an Arkade Script function. Denied by default.

The operator rebuilds offchain spends with an nLockTime of 0, so a condition on it does not mean what it says offchain.

Fix: use `checkTime(t)` for time in Arkade Script functions, and `after(t)` in tapscript functions.

Reported on the tx.locktime read, or on the call to the imported helper that reads it, so an attribute on the statement holding it, its function or the contract applies to it.
