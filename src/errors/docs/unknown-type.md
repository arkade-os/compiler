A type that is neither a builtin type, a builtin struct nor a struct declared in this file or an imported one.

The message suggests the closest type name when there is one.

Fix: use the suggested name, declare the struct, or import the file that declares it. Builtin types are `int`, `bool`, `bytes`, `bytes20`, `bytes32`, `pubkey`, `signature`, `asset` and `AssetGroup`; builtin structs include `AssetId`, `Outpoint`, `ECPoint`, `G2Point`, `ScriptPubKey`, `AssetEntry` and `AssetLookup`.
