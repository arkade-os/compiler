A key listed more than once in `checkMultisig`, in a covenant or a tapscript.

One signature then counts once for each listing, so its holder alone can reach a higher threshold than intended.

Fix: list each key once. Allow it only when the duplicate deliberately gives that key more weight, and say so in the reason.
