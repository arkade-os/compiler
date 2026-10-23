A local variable that nothing reads. Denied by default.

It costs script bytes and stack, and usually means a check is missing. An unread function parameter or tapscript input is an error instead, since anyone relaying the spend could replace an unread witness element.

Fix: use the variable, or remove it.
