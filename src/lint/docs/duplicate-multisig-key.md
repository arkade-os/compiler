A key listed more than once in `checkMultisig`, in a covenant or a tapscript.

One signature then counts once for each listing, so its holder alone can reach a higher threshold than intended.

Fix: list each key once. Allow it only when the duplicate deliberately gives that key more weight, and say so in the reason.

Reported on the checkMultisig call, so an attribute on the statement holding it, its function or the contract applies to it. In a tapscript it is reported on the tapscript, so an attribute on the tapscript or the contract applies to it.
