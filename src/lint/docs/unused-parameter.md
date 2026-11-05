A constructor parameter that no function or tapscript reads.

It is pruned from the script, so it costs nothing and cannot be malleated, but it usually means a check is missing.

Fix: use the parameter, or remove it.

Reported on the constructor parameter, so only an attribute on the contract applies to it.
