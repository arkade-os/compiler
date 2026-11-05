A name used as a contract or library, as in `new Name(...)` or `Name.member`, that no imported file declares.

The message suggests the closest contract or library name when there is one.

Fix: use the suggested name, or add `import "./path/to/file.ark";` for the file that declares it.
