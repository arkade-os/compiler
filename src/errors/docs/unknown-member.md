`Name.member` where `Name` is an imported contract or library that declares no exported function or constant called `member`.

The message suggests the closest member when there is one.

Fix: use the suggested name, or export the member from the imported file. A `private function` is callable only inside its own library.
