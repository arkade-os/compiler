A local variable that nothing reads, where a read by a local or assignment nothing later reads does not count unless it calls a helper, and neither does an `if` condition or loop target whose arms or body do nothing. Denied by default.

It costs script bytes and stack, and usually means a check is missing. An unread function parameter or tapscript input is an error instead, since anyone relaying the spend could replace an unread witness element.

Fix: use the variable, or remove it.

Reported on the variable's declaration, so an attribute on the statement holding it, its function or the contract applies to it.
