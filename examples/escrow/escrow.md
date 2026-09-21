# Escrow

Party A locks coins. An oracle releases `amount` to party B, or the timeout returns the coins to party A.

[Explore the interactive Escrow flow](https://arkade-os.github.io/compiler/?example=escrow&view=flow) to see the outcomes first and expand their technical details on demand.

`partyAScript` and `partyBScript` are the 32-byte witness program an output reports.

The contract commits `sha256` of the one message the oracle signs. A surplus of 330 sats or less fails `complete`.
