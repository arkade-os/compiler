# NonInteractiveSwap
#
#

# Function: swap
## arkade covenant
<takerPk>
<takerSig>
OP_CHECKSIG
0
<wantAssetIdTxid>
<wantAssetIdGidx>
OP_INSPECTOUTASSETLOOKUP
OP_VERIFY
<wantAmount>
OP_GREATERTHANOREQUAL64
OP_VERIFY
0
OP_INSPECTOUTPUTSCRIPTPUBKEY
<VTXO:SingleSig(<makerPk>,<exit>)>
OP_EQUAL
1
<offerAssetIdTxid>
<offerAssetIdGidx>
OP_INSPECTOUTASSETLOOKUP
OP_VERIFY
<offerAmount>
OP_GREATERTHANOREQUAL64
OP_VERIFY
1
OP_INSPECTOUTPUTSCRIPTPUBKEY
<VTXO:SingleSig(<takerPk>,<exit>)>
OP_EQUAL
## leaf: swap
<SERVER_KEY>
OP_CHECKSIGVERIFY
<EMULATOR_KEY:swap>
OP_CHECKSIG

# Function: cancel
## arkade covenant
<expirationTime>
OP_CHECKLOCKTIMEVERIFY
OP_DROP
<makerPk>
<makerSig>
OP_CHECKSIG
## leaf: cancel
<SERVER_KEY>
OP_CHECKSIGVERIFY
<EMULATOR_KEY:cancel>
OP_CHECKSIG

# Function: unilateral
## leaf: unilateral
<exit>
OP_CHECKSEQUENCEVERIFY
OP_DROP
<makerPk>
OP_CHECKSIG

